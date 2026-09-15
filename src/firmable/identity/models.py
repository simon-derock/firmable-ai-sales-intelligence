"""Account entity model — the stable unit of sales intelligence.

An Account represents one real-world organisation aggregated from
multiple Shodan observations. It is the primary deliverable of M2
and the input to all downstream scoring and LLM stages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AccountSignals:
    """Raw signal counts aggregated from observations for one account."""

    # Port exposure
    exposed_ports: set[int] = field(default_factory=set)
    exposed_db_ports: set[int] = field(default_factory=set)
    exposed_admin_ports: set[int] = field(default_factory=set)
    non_standard_port_count: int = 0

    # Products / services
    products: set[str] = field(default_factory=set)
    product_count: int = 0

    # Vulnerabilities
    cve_ids: set[str] = field(default_factory=set)
    max_cvss: float | None = None
    critical_cve_count: int = 0
    high_cve_count: int = 0

    # TLS/SSL
    self_signed_cert_count: int = 0
    expired_cert_count: int = 0

    # Software age
    eol_observation_count: int = 0

    # Cloud
    cloud_providers: set[str] = field(default_factory=set)
    is_cloud: bool = False

    # Geography
    countries: set[str] = field(default_factory=set)

    # Observation volume
    total_observations: int = 0
    unique_ips: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "exposed_ports": sorted(self.exposed_ports),
            "exposed_db_ports": sorted(self.exposed_db_ports),
            "exposed_admin_ports": sorted(self.exposed_admin_ports),
            "non_standard_port_count": self.non_standard_port_count,
            "products": sorted(self.products),
            "product_count": self.product_count,
            "cve_ids": sorted(self.cve_ids),
            "max_cvss": self.max_cvss,
            "critical_cve_count": self.critical_cve_count,
            "high_cve_count": self.high_cve_count,
            "self_signed_cert_count": self.self_signed_cert_count,
            "expired_cert_count": self.expired_cert_count,
            "eol_observation_count": self.eol_observation_count,
            "cloud_providers": sorted(self.cloud_providers),
            "is_cloud": self.is_cloud,
            "countries": sorted(self.countries),
            "total_observations": self.total_observations,
            "unique_ips": self.unique_ips,
        }


@dataclass
class Account:
    """A resolved organisation account aggregated from Shodan observations.

    This is the stable interface passed to the scoring and AI layers.
    All fields are derived deterministically from raw observations.
    """

    # Identity
    account_id: str  # slugified org name (primary key)
    org_name: str
    domains: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)

    # Aggregated signals
    signals: AccountSignals = field(default_factory=AccountSignals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "org_name": self.org_name,
            "domains": self.domains,
            "asns": self.asns,
            "signals": self.signals.to_dict(),
        }
