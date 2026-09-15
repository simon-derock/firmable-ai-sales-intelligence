"""Baseline account scorer — deterministic ranking without LLM.

Produces a priority score and priority tier for each account
based solely on extracted signals. This is the baseline that
the LLM layer (M3) must measurably beat to justify its cost.

Scoring approach:
  raw_score = sum(signal.weight for active signals)
  normalised_score = raw_score / max_possible_raw_score  → [0.0, 1.0]
  priority_tier = {HIGH, MEDIUM, LOW, MONITOR} based on thresholds
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from firmable.signals.extractor import SIGNAL_WEIGHTS, SignalSet

# Maximum possible raw score = sum of all signal weights
MAX_RAW_SCORE: float = sum(SIGNAL_WEIGHTS.values())

# Normalised score thresholds → priority tier
# These are hypotheses until validated against a labeled eval set in M4
_TIER_THRESHOLDS: dict[str, float] = {
    "HIGH": 0.45,  # >= 45% of max possible score
    "MEDIUM": 0.20,  # >= 20%
    "LOW": 0.05,  # >= 5%
    # below 5% → MONITOR
}


class PriorityTier(StrEnum):
    """Sales priority tier for an account."""

    HIGH = "HIGH"  # Immediate outreach recommended
    MEDIUM = "MEDIUM"  # Schedule within this quarter
    LOW = "LOW"  # Monitor for signal improvement
    MONITOR = "MONITOR"  # No actionable signal yet


@dataclass
class AccountScore:
    """Complete scoring result for one account."""

    account_id: str
    org_name: str
    raw_score: float
    normalised_score: float
    priority_tier: PriorityTier
    active_signal_names: list[str] = field(default_factory=list)
    top_signal: str | None = None  # Highest-weight active signal
    top_evidence: str | None = None  # Evidence for top signal

    def to_dict(self) -> dict[str, Any]:
        return {
            "account_id": self.account_id,
            "org_name": self.org_name,
            "raw_score": round(self.raw_score, 4),
            "normalised_score": round(self.normalised_score, 4),
            "priority_tier": self.priority_tier.value,
            "active_signal_names": self.active_signal_names,
            "top_signal": self.top_signal,
            "top_evidence": self.top_evidence,
        }


def score_account(
    signal_set: SignalSet,
    org_name: str = "",
) -> AccountScore:
    """Score one account from its extracted signal set.

    Args:
        signal_set: Output of signals.extractor.extract_signals()
        org_name: Human-readable org name for the result.

    Returns:
        AccountScore with raw score, normalised score, and priority tier.
    """
    active = signal_set.active_signals
    raw_score = signal_set.total_weight
    normalised = raw_score / MAX_RAW_SCORE if MAX_RAW_SCORE > 0 else 0.0

    # Determine tier
    if normalised >= _TIER_THRESHOLDS["HIGH"]:
        tier = PriorityTier.HIGH
    elif normalised >= _TIER_THRESHOLDS["MEDIUM"]:
        tier = PriorityTier.MEDIUM
    elif normalised >= _TIER_THRESHOLDS["LOW"]:
        tier = PriorityTier.LOW
    else:
        tier = PriorityTier.MONITOR

    # Top signal = highest weight active signal
    top_signal = None
    top_evidence = None
    if active:
        top = max(active, key=lambda s: s.weight)
        top_signal = top.name
        top_evidence = top.evidence

    return AccountScore(
        account_id=signal_set.account_id,
        org_name=org_name,
        raw_score=raw_score,
        normalised_score=normalised,
        priority_tier=tier,
        active_signal_names=[s.name for s in active],
        top_signal=top_signal,
        top_evidence=top_evidence,
    )


def rank_accounts(scored: list[AccountScore]) -> list[AccountScore]:
    """Sort accounts by normalised score descending.

    Stable sort: equal scores preserve input order.

    Args:
        scored: List of AccountScore objects.

    Returns:
        Same list, sorted highest priority first.
    """
    return sorted(scored, key=lambda a: a.normalised_score, reverse=True)
