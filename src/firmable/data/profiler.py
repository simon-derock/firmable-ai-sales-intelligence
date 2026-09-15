"""Dataset profiler — empirical analysis of the Shodan dataset.

Answers the dataset archaeology questions:
- Scale: record count, throughput, average record size
- Schema: field frequency, nullability, nested structures, schema variants
- Identity: IP uniqueness, hostname/domain relationships, org/ASN consistency
- Security: vuln prevalence, CVSS distribution, service distribution, EOL tags
- Sales relevance: which signal combinations appear and how often
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from firmable.data.reader import ReaderConfig, ReadStats, stream_observations

if TYPE_CHECKING:
    from pathlib import Path

    from firmable.data.models import Observation


@dataclass
class SchemaProfile:
    """Field presence and nullability across observed records."""

    field_counts: Counter[str] = field(default_factory=Counter)
    total_records: int = 0

    def observe(self, obs: Observation) -> None:
        self.total_records += 1
        d = obs.model_dump()
        for k, v in d.items():
            if v is not None and v != [] and v != {}:
                self.field_counts[k] += 1

    def frequency(self) -> dict[str, float]:
        if self.total_records == 0:
            return {}
        return {k: round(v / self.total_records, 4) for k, v in self.field_counts.most_common()}


@dataclass
class IdentityProfile:
    """Identity field quality and relationship analysis."""

    unique_ips: set[str] = field(default_factory=set)
    unique_domains: set[str] = field(default_factory=set)
    unique_orgs: set[str] = field(default_factory=set)
    unique_asns: set[str] = field(default_factory=set)
    unique_countries: set[str] = field(default_factory=set)

    ips_with_hostname: int = 0
    ips_with_domain: int = 0
    ips_with_org: int = 0
    ips_with_asn: int = 0
    ips_with_cloud: int = 0
    total: int = 0

    # Domain → set of orgs (to detect identity ambiguity)
    domain_to_orgs: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def observe(self, obs: Observation) -> None:
        self.total += 1
        self.unique_ips.add(obs.ip_str)
        if obs.domains:
            self.unique_domains.update(obs.domains)
            self.ips_with_domain += 1
        if obs.hostnames:
            self.ips_with_hostname += 1
        if obs.org:
            self.unique_orgs.add(obs.org)
            self.ips_with_org += 1
            for d in obs.domains:
                self.domain_to_orgs[d].add(obs.org)
        if obs.asn:
            self.unique_asns.add(obs.asn)
            self.ips_with_asn += 1
        if obs.country_code:
            self.unique_countries.add(obs.country_code)
        if obs.is_cloud:
            self.ips_with_cloud += 1

    def summary(self) -> dict[str, Any]:
        ambiguous_domains = sum(1 for orgs in self.domain_to_orgs.values() if len(orgs) > 1)
        return {
            "unique_ips": len(self.unique_ips),
            "unique_domains": len(self.unique_domains),
            "unique_orgs": len(self.unique_orgs),
            "unique_asns": len(self.unique_asns),
            "unique_countries": len(self.unique_countries),
            "pct_with_hostname": round(self.ips_with_hostname / max(self.total, 1), 4),
            "pct_with_domain": round(self.ips_with_domain / max(self.total, 1), 4),
            "pct_with_org": round(self.ips_with_org / max(self.total, 1), 4),
            "pct_with_asn": round(self.ips_with_asn / max(self.total, 1), 4),
            "pct_cloud": round(self.ips_with_cloud / max(self.total, 1), 4),
            "domains_with_multiple_orgs": ambiguous_domains,
        }


@dataclass
class SecurityProfile:
    """Security signal distributions."""

    records_with_vulns: int = 0
    total_cves: Counter[str] = field(default_factory=Counter)
    cvss_scores: list[float] = field(default_factory=list)
    port_counts: Counter[int] = field(default_factory=Counter)
    product_counts: Counter[str] = field(default_factory=Counter)
    tag_counts: Counter[str] = field(default_factory=Counter)
    cloud_provider_counts: Counter[str] = field(default_factory=Counter)
    country_counts: Counter[str] = field(default_factory=Counter)
    transport_counts: Counter[str] = field(default_factory=Counter)
    total: int = 0

    # High-signal indicators
    records_with_critical_cve: int = 0  # CVSS >= 9.0
    records_with_high_cve: int = 0  # CVSS >= 7.0
    records_eol: int = 0
    records_self_signed_cert: int = 0
    records_exposed_db: int = 0
    records_exposed_admin: int = 0

    # Risky ports (database, admin, remote management)
    RISKY_PORTS: frozenset[int] = field(
        default_factory=lambda: frozenset(
            {
                21,
                23,
                3306,
                5432,
                6379,
                27017,
                9200,
                8080,
                8443,
                8888,
                9000,
                2375,
                2376,
                5900,
                3389,
                5985,
            }
        )
    )
    DB_PORTS: frozenset[int] = field(
        default_factory=lambda: frozenset({3306, 5432, 6379, 27017, 9200, 5984})
    )
    ADMIN_PORTS: frozenset[int] = field(
        default_factory=lambda: frozenset({8080, 8443, 8888, 9000, 9090, 10000})
    )

    def observe(self, obs: Observation) -> None:
        self.total += 1
        self.port_counts[obs.port] += 1

        if obs.transport:
            self.transport_counts[obs.transport] += 1
        if obs.product:
            self.product_counts[obs.product] += 1
        if obs.country_code:
            self.country_counts[obs.country_code] += 1
        if obs.cloud_provider:
            self.cloud_provider_counts[obs.cloud_provider] += 1

        for tag in obs.tags:
            self.tag_counts[tag] += 1
            if tag in {"eol", "end-of-life"}:
                self.records_eol += 1

        if obs.ssl and obs.ssl.self_signed:
            self.records_self_signed_cert += 1

        if obs.port in self.DB_PORTS:
            self.records_exposed_db += 1
        if obs.port in self.ADMIN_PORTS:
            self.records_exposed_admin += 1

        if obs.has_vulns:
            self.records_with_vulns += 1
            for cve_id, vuln in obs.vulns.items():
                self.total_cves[cve_id] += 1
                if vuln.cvss is not None:
                    self.cvss_scores.append(vuln.cvss)

        max_cvss = obs.max_cvss
        if max_cvss is not None:
            if max_cvss >= 9.0:
                self.records_with_critical_cve += 1
            elif max_cvss >= 7.0:
                self.records_with_high_cve += 1

    def cvss_distribution(self) -> dict[str, Any]:
        if not self.cvss_scores:
            return {}
        scores = sorted(self.cvss_scores)
        n = len(scores)
        return {
            "count": n,
            "min": scores[0],
            "max": scores[-1],
            "p25": scores[n // 4],
            "p50": scores[n // 2],
            "p75": scores[3 * n // 4],
            "critical_count": sum(1 for s in scores if s >= 9.0),
            "high_count": sum(1 for s in scores if 7.0 <= s < 9.0),
            "medium_count": sum(1 for s in scores if 4.0 <= s < 7.0),
        }

    def summary(self) -> dict[str, Any]:
        return {
            "records_with_vulns": self.records_with_vulns,
            "pct_with_vulns": round(self.records_with_vulns / max(self.total, 1), 4),
            "unique_cves": len(self.total_cves),
            "records_with_critical_cve": self.records_with_critical_cve,
            "records_with_high_cve": self.records_with_high_cve,
            "records_eol": self.records_eol,
            "records_self_signed_cert": self.records_self_signed_cert,
            "records_exposed_db": self.records_exposed_db,
            "records_exposed_admin": self.records_exposed_admin,
            "top_10_ports": self.port_counts.most_common(10),
            "top_10_products": self.product_counts.most_common(10),
            "top_10_tags": self.tag_counts.most_common(10),
            "top_10_countries": self.country_counts.most_common(10),
            "top_5_cloud_providers": self.cloud_provider_counts.most_common(5),
            "top_10_cves": self.total_cves.most_common(10),
            "cvss_distribution": self.cvss_distribution(),
        }


@dataclass
class DatasetProfile:
    """Complete profile of the dataset."""

    schema: SchemaProfile = field(default_factory=SchemaProfile)
    identity: IdentityProfile = field(default_factory=IdentityProfile)
    security: SecurityProfile = field(default_factory=SecurityProfile)
    read_stats: ReadStats = field(default_factory=ReadStats)

    def observe(self, obs: Observation) -> None:
        self.schema.observe(obs)
        self.identity.observe(obs)
        self.security.observe(obs)

    def to_dict(self) -> dict[str, Any]:
        return {
            "read_stats": self.read_stats.summary(),
            "schema": {
                "total_records": self.schema.total_records,
                "field_frequency": self.schema.frequency(),
            },
            "identity": self.identity.summary(),
            "security": self.security.summary(),
        }


def profile_dataset(
    path: Path,
    max_records: int | None = None,
    batch_size: int = 5000,
) -> DatasetProfile:
    """Stream the dataset and build a complete empirical profile.

    Args:
        path: Path to the .zst compressed file.
        max_records: Limit records for sampling. None = full dataset.
        batch_size: Internal batch size for streaming.

    Returns:
        DatasetProfile with all profiling results.
    """
    config = ReaderConfig(
        batch_size=batch_size,
        max_records=max_records,
        skip_malformed=True,
        log_every=500_000,
    )

    profile = DatasetProfile()

    for result in stream_observations(path, config):
        # Accumulate read stats
        profile.read_stats.records_read += 1
        if result.is_valid:
            profile.read_stats.records_valid += 1
        elif "JSON" in (result.error or ""):
            profile.read_stats.records_malformed_json += 1
        else:
            profile.read_stats.records_malformed_schema += 1

        if result.is_valid and result.observation is not None:
            profile.observe(result.observation)

    return profile


def save_profile(profile: DatasetProfile, output_path: Path) -> None:
    """Save profile results to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as f:
        json.dump(profile.to_dict(), f, indent=2, default=str)
