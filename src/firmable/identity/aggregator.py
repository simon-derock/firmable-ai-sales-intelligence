"""Account aggregator — resolves raw Shodan observations into org-level accounts.

Strategy (evidence-based from M1 profiling):
  Primary key  : `org` field (99.8% coverage in sample)
  Secondary keys: `asn`, `domains` for enrichment and deduplication
  Fallback key  : `asn` when org is missing
  Last resort   : IP /24 subnet grouping

Identity resolution is deterministic. No LLM involved.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import TYPE_CHECKING

from firmable.identity.models import Account, AccountSignals

if TYPE_CHECKING:
    from collections.abc import Iterable

    from firmable.data.models import Observation

# Ports considered risky databases or management interfaces
_DB_PORTS: frozenset[int] = frozenset({3306, 5432, 6379, 27017, 9200, 5984, 1521, 27018})
_ADMIN_PORTS: frozenset[int] = frozenset(
    {8080, 8443, 8888, 9000, 9090, 10000, 2375, 2376, 3389, 5900, 5985}
)
_STANDARD_PORTS: frozenset[int] = frozenset(
    {
        20,
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        143,
        389,
        443,
        445,
        465,
        587,
        636,
        993,
        995,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        27017,
    }
)


def _make_account_id(org: str) -> str:
    """Create a stable, URL-safe account ID from an org name."""
    slug = org.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_-]+", "-", slug)
    slug = slug.strip("-")
    return slug or "unknown"


def _resolve_key(obs: Observation) -> str:
    """Determine the grouping key for one observation.

    Priority: org > asn > /24 subnet.
    """
    if obs.org:
        return obs.org
    if obs.asn:
        return f"asn:{obs.asn}"
    # Fall back to /24 subnet
    parts = obs.ip_str.split(".")
    if len(parts) == 4:
        return f"subnet:{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return f"ip:{obs.ip_str}"


def _update_signals(signals: AccountSignals, obs: Observation) -> None:
    """Merge one observation's signals into an account's signal accumulator."""
    signals.total_observations += 1
    signals.exposed_ports.add(obs.port)

    if obs.port in _DB_PORTS:
        signals.exposed_db_ports.add(obs.port)
    if obs.port in _ADMIN_PORTS:
        signals.exposed_admin_ports.add(obs.port)
    if obs.port not in _STANDARD_PORTS:
        signals.non_standard_port_count += 1

    if obs.product:
        signals.products.add(obs.product)

    for tag in obs.tags:
        if tag in {"eol", "end-of-life"}:
            signals.eol_observation_count += 1

    if obs.ssl:
        if obs.ssl.self_signed:
            signals.self_signed_cert_count += 1
        if obs.ssl.expired:
            signals.expired_cert_count += 1

    if obs.cloud_provider:
        signals.cloud_providers.add(obs.cloud_provider)
        signals.is_cloud = True
    if not signals.is_cloud and "cloud" in obs.tags:
        signals.is_cloud = True

    if obs.country_code:
        signals.countries.add(obs.country_code)

    for cve_id, vuln in obs.vulns.items():
        signals.cve_ids.add(cve_id)
        if vuln.cvss is not None:
            if signals.max_cvss is None or vuln.cvss > signals.max_cvss:
                signals.max_cvss = vuln.cvss
            if vuln.cvss >= 9.0:
                signals.critical_cve_count += 1
            elif vuln.cvss >= 7.0:
                signals.high_cve_count += 1


def aggregate_observations(observations: Iterable[Observation]) -> list[Account]:
    """Aggregate a stream of Observations into a list of Accounts.

    Groups by org (primary), asn (fallback), or /24 subnet (last resort).
    Each account accumulates signals deterministically from all its observations.

    Args:
        observations: Iterable of validated Observation objects.

    Returns:
        List of Account objects, one per resolved organisation.
    """
    # Per-group accumulators
    signals_by_key: dict[str, AccountSignals] = defaultdict(AccountSignals)
    org_by_key: dict[str, str] = {}
    domains_by_key: dict[str, set[str]] = defaultdict(set)
    asns_by_key: dict[str, set[str]] = defaultdict(set)
    ips_by_key: dict[str, set[str]] = defaultdict(set)

    for obs in observations:
        key = _resolve_key(obs)

        # Capture canonical org name (first seen wins)
        if key not in org_by_key:
            org_by_key[key] = obs.org or key

        # Accumulate identity fields
        domains_by_key[key].update(obs.domains)
        if obs.asn:
            asns_by_key[key].add(obs.asn)
        ips_by_key[key].add(obs.ip_str)

        # Accumulate signals
        _update_signals(signals_by_key[key], obs)

    # Finalise accounts
    accounts: list[Account] = []
    for key, signals in signals_by_key.items():
        org_name = org_by_key[key]
        signals.product_count = len(signals.products)
        signals.unique_ips = len(ips_by_key[key])

        account = Account(
            account_id=_make_account_id(org_name),
            org_name=org_name,
            domains=sorted(domains_by_key[key]),
            asns=sorted(asns_by_key[key]),
            signals=signals,
        )
        accounts.append(account)

    return accounts
