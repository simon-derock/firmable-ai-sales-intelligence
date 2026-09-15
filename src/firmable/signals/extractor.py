"""Deterministic security signal extraction.

Signals are facts derived directly from observed data. No LLM.
Each signal has: a name, a boolean flag, an evidence string,
and a numeric weight for the baseline scorer.

Design rules:
- Every signal must be traceable to a specific observation field.
- No inference beyond what the data directly supports.
- Weights are hypotheses until validated against a labeled eval set.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from firmable.identity.models import Account

# ── Signal weights (hypotheses — to be calibrated against eval set in M4) ──
# Scale: 0.0 (irrelevant) → 1.0 (strongest possible indicator)
SIGNAL_WEIGHTS: dict[str, float] = {
    "critical_cve_exposure": 1.00,  # CVSS >= 9.0 — unambiguous urgent need
    "high_cve_exposure": 0.80,  # CVSS 7.0-8.9 -- strong need
    "exposed_database": 0.75,  # DB port open to internet — data breach risk
    "eol_software": 0.70,  # End-of-life software — patch gap
    "expired_ssl_cert": 0.60,  # Expired cert — visible negligence
    "self_signed_cert": 0.50,  # Self-signed cert — low PKI hygiene
    "exposed_admin_panel": 0.45,  # Admin port exposed — attack surface
    "multi_country_presence": 0.30,  # Operations in 3+ countries — compliance scope
    "high_port_diversity": 0.25,  # Many unique ports — complex attack surface
    "cloud_presence": 0.15,  # Cloud infra — cloud security tooling fit
}

# Thresholds
_MULTI_COUNTRY_THRESHOLD = 3
_HIGH_PORT_DIVERSITY_THRESHOLD = 10


@dataclass
class Signal:
    """One extracted security signal for an account."""

    name: str
    present: bool
    weight: float
    evidence: str  # Human-readable justification, traceable to data
    evidence_detail: Any = None  # Raw value (count, list, score) for traceability

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "present": self.present,
            "weight": self.weight,
            "evidence": self.evidence,
            "evidence_detail": self.evidence_detail,
        }


@dataclass
class SignalSet:
    """Complete signal extraction result for one account."""

    account_id: str
    signals: list[Signal] = field(default_factory=list)

    @property
    def active_signals(self) -> list[Signal]:
        """Signals that are present (flag=True)."""
        return [s for s in self.signals if s.present]

    @property
    def total_weight(self) -> float:
        """Sum of weights for all active signals (raw score, pre-normalisation)."""
        return sum(s.weight for s in self.active_signals)

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "active_signal_count": len(self.active_signals),
            "total_weight": round(self.total_weight, 4),
            "signals": [s.to_dict() for s in self.signals],
        }


def extract_signals(account: Account) -> SignalSet:
    """Extract all security signals from an aggregated account.

    Every signal is derived deterministically from account.signals.
    No LLM, no probabilistic inference — only what the data directly shows.

    Args:
        account: A fully aggregated Account from the identity layer.

    Returns:
        SignalSet with all signals evaluated (present or absent).
    """
    s = account.signals
    result = SignalSet(account_id=account.account_id)

    # ── CVE signals ─────────────────────────────────────────────────

    result.signals.append(
        Signal(
            name="critical_cve_exposure",
            present=s.critical_cve_count > 0,
            weight=SIGNAL_WEIGHTS["critical_cve_exposure"],
            evidence=(
                f"{s.critical_cve_count} critical CVE(s) observed (CVSS ≥ 9.0)"
                if s.critical_cve_count > 0
                else "No critical CVEs observed"
            ),
            evidence_detail={"critical_cve_count": s.critical_cve_count, "max_cvss": s.max_cvss},
        )
    )

    result.signals.append(
        Signal(
            name="high_cve_exposure",
            present=s.high_cve_count > 0,
            weight=SIGNAL_WEIGHTS["high_cve_exposure"],
            evidence=(
                f"{s.high_cve_count} high-severity CVE(s) observed (CVSS 7.0-8.9)"
                if s.high_cve_count > 0
                else "No high-severity CVEs observed"
            ),
            evidence_detail={"high_cve_count": s.high_cve_count},
        )
    )

    # ── Exposure signals ─────────────────────────────────────────────

    result.signals.append(
        Signal(
            name="exposed_database",
            present=len(s.exposed_db_ports) > 0,
            weight=SIGNAL_WEIGHTS["exposed_database"],
            evidence=(
                f"Database port(s) exposed: {sorted(s.exposed_db_ports)}"
                if s.exposed_db_ports
                else "No database ports observed"
            ),
            evidence_detail={"exposed_db_ports": sorted(s.exposed_db_ports)},
        )
    )

    result.signals.append(
        Signal(
            name="exposed_admin_panel",
            present=len(s.exposed_admin_ports) > 0,
            weight=SIGNAL_WEIGHTS["exposed_admin_panel"],
            evidence=(
                f"Admin/management port(s) exposed: {sorted(s.exposed_admin_ports)}"
                if s.exposed_admin_ports
                else "No admin ports observed"
            ),
            evidence_detail={"exposed_admin_ports": sorted(s.exposed_admin_ports)},
        )
    )

    # ── TLS/PKI signals ──────────────────────────────────────────────

    result.signals.append(
        Signal(
            name="expired_ssl_cert",
            present=s.expired_cert_count > 0,
            weight=SIGNAL_WEIGHTS["expired_ssl_cert"],
            evidence=(
                f"{s.expired_cert_count} expired SSL certificate(s) observed"
                if s.expired_cert_count > 0
                else "No expired certificates observed"
            ),
            evidence_detail={"expired_cert_count": s.expired_cert_count},
        )
    )

    result.signals.append(
        Signal(
            name="self_signed_cert",
            present=s.self_signed_cert_count > 0,
            weight=SIGNAL_WEIGHTS["self_signed_cert"],
            evidence=(
                f"{s.self_signed_cert_count} self-signed certificate(s) observed"
                if s.self_signed_cert_count > 0
                else "No self-signed certificates observed"
            ),
            evidence_detail={"self_signed_cert_count": s.self_signed_cert_count},
        )
    )

    # ── Software hygiene signals ──────────────────────────────────────

    result.signals.append(
        Signal(
            name="eol_software",
            present=s.eol_observation_count > 0,
            weight=SIGNAL_WEIGHTS["eol_software"],
            evidence=(
                f"End-of-life software observed in {s.eol_observation_count} service(s)"
                if s.eol_observation_count > 0
                else "No end-of-life software observed"
            ),
            evidence_detail={"eol_observation_count": s.eol_observation_count},
        )
    )

    # ── Infrastructure complexity signals ─────────────────────────────

    country_count = len(s.countries)
    result.signals.append(
        Signal(
            name="multi_country_presence",
            present=country_count >= _MULTI_COUNTRY_THRESHOLD,
            weight=SIGNAL_WEIGHTS["multi_country_presence"],
            evidence=(
                f"Infrastructure observed in {country_count} countries: {sorted(s.countries)}"
                if country_count >= _MULTI_COUNTRY_THRESHOLD
                else f"Infrastructure in {country_count} country/countries"
            ),
            evidence_detail={"country_count": country_count, "countries": sorted(s.countries)},
        )
    )

    port_count = len(s.exposed_ports)
    result.signals.append(
        Signal(
            name="high_port_diversity",
            present=port_count >= _HIGH_PORT_DIVERSITY_THRESHOLD,
            weight=SIGNAL_WEIGHTS["high_port_diversity"],
            evidence=(
                f"High port diversity: {port_count} unique ports observed"
                if port_count >= _HIGH_PORT_DIVERSITY_THRESHOLD
                else f"{port_count} unique port(s) observed"
            ),
            evidence_detail={"unique_port_count": port_count},
        )
    )

    result.signals.append(
        Signal(
            name="cloud_presence",
            present=s.is_cloud,
            weight=SIGNAL_WEIGHTS["cloud_presence"],
            evidence=(
                f"Cloud infrastructure detected: {sorted(s.cloud_providers)}"
                if s.cloud_providers
                else "Cloud presence via tag"
                if s.is_cloud
                else "No cloud infrastructure observed"
            ),
            evidence_detail={"cloud_providers": sorted(s.cloud_providers), "is_cloud": s.is_cloud},
        )
    )

    return result
