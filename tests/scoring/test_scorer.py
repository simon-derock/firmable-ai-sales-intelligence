"""Tests for the baseline deterministic scorer."""

from __future__ import annotations

import pytest

from firmable.scoring.scorer import (
    MAX_RAW_SCORE,
    AccountScore,
    PriorityTier,
    rank_accounts,
    score_account,
)
from firmable.signals.extractor import Signal, SignalSet, extract_signals


def _signal_set(account_id: str, signals: list[Signal]) -> SignalSet:
    ss = SignalSet(account_id=account_id)
    ss.signals = signals
    return ss


def _active(name: str, weight: float, evidence: str = "test evidence") -> Signal:
    return Signal(name=name, present=True, weight=weight, evidence=evidence)


def _inactive(name: str, weight: float) -> Signal:
    return Signal(name=name, present=False, weight=weight, evidence="not present")


class TestMaxRawScore:
    def test_max_raw_score_is_positive(self) -> None:
        assert MAX_RAW_SCORE > 0

    def test_max_raw_score_is_sum_of_all_weights(self) -> None:
        from firmable.signals.extractor import SIGNAL_WEIGHTS

        assert abs(MAX_RAW_SCORE - sum(SIGNAL_WEIGHTS.values())) < 1e-9


class TestScoreAccount:
    """Unit tests for score_account()."""

    def test_no_signals_gives_monitor_tier(self) -> None:
        ss = _signal_set("empty", [_inactive("x", 0.5)])
        result = score_account(ss, "Empty Corp")
        assert result.priority_tier == PriorityTier.MONITOR
        assert result.raw_score == 0.0
        assert result.normalised_score == 0.0
        assert result.top_signal is None
        assert result.active_signal_names == []

    def test_all_signals_gives_high_tier(self) -> None:
        # Full score = normalised 1.0 → HIGH
        from firmable.signals.extractor import SIGNAL_WEIGHTS

        signals = [_active(name, weight) for name, weight in SIGNAL_WEIGHTS.items()]
        ss = _signal_set("full", signals)
        result = score_account(ss, "Full Risk Corp")
        assert result.priority_tier == PriorityTier.HIGH
        assert abs(result.normalised_score - 1.0) < 1e-6

    def test_top_signal_is_highest_weight_active(self) -> None:
        ss = _signal_set(
            "top",
            [
                _active("low_signal", 0.15, "low evidence"),
                _active("high_signal", 0.80, "high evidence"),
                _active("mid_signal", 0.50, "mid evidence"),
            ],
        )
        result = score_account(ss, "X")
        assert result.top_signal == "high_signal"
        assert result.top_evidence == "high evidence"

    def test_normalised_score_within_bounds(self) -> None:
        ss = _signal_set("bounded", [_active("a", 0.50)])
        result = score_account(ss)
        assert 0.0 <= result.normalised_score <= 1.0

    def test_active_signal_names_listed(self) -> None:
        ss = _signal_set(
            "named",
            [
                _active("sig_a", 0.3),
                _inactive("sig_b", 0.5),
                _active("sig_c", 0.2),
            ],
        )
        result = score_account(ss)
        assert set(result.active_signal_names) == {"sig_a", "sig_c"}

    def test_to_dict_includes_all_fields(self) -> None:
        ss = _signal_set("dict-test", [_active("a", 0.5)])
        result = score_account(ss, "Dict Corp")
        d = result.to_dict()
        assert "account_id" in d
        assert "org_name" in d
        assert "raw_score" in d
        assert "normalised_score" in d
        assert "priority_tier" in d
        assert "active_signal_names" in d
        assert "top_signal" in d
        assert "top_evidence" in d

    @pytest.mark.parametrize(
        ("normalised", "expected_tier"),
        [
            (1.00, PriorityTier.HIGH),
            (0.45, PriorityTier.HIGH),
            (0.44, PriorityTier.MEDIUM),
            (0.20, PriorityTier.MEDIUM),
            (0.19, PriorityTier.LOW),
            (0.05, PriorityTier.LOW),
            (0.04, PriorityTier.MONITOR),
            (0.00, PriorityTier.MONITOR),
        ],
    )
    def test_tier_thresholds(self, normalised: float, expected_tier: PriorityTier) -> None:
        """Verify tier boundaries match defined thresholds exactly."""
        raw = normalised * MAX_RAW_SCORE
        ss = _signal_set("tier-test", [_active("a", raw)])
        result = score_account(ss)
        assert result.priority_tier == expected_tier


class TestRankAccounts:
    """Tests for rank_accounts()."""

    def test_sorts_highest_first(self) -> None:
        scores = [
            AccountScore("c", "C", 0.1, 0.10, PriorityTier.LOW, [], None, None),
            AccountScore("a", "A", 0.9, 0.90, PriorityTier.HIGH, [], None, None),
            AccountScore("b", "B", 0.5, 0.50, PriorityTier.MEDIUM, [], None, None),
        ]
        ranked = rank_accounts(scores)
        assert [r.account_id for r in ranked] == ["a", "b", "c"]

    def test_stable_sort_on_equal_scores(self) -> None:
        scores = [
            AccountScore("x", "X", 0.5, 0.5, PriorityTier.MEDIUM, [], None, None),
            AccountScore("y", "Y", 0.5, 0.5, PriorityTier.MEDIUM, [], None, None),
        ]
        ranked = rank_accounts(scores)
        # Input order preserved for equal scores
        assert [r.account_id for r in ranked] == ["x", "y"]

    def test_empty_input_returns_empty(self) -> None:
        assert rank_accounts([]) == []


class TestEndToEndPipeline:
    """Integration test: observations → aggregation → signals → score → rank."""

    def test_full_pipeline_produces_ranked_accounts(self) -> None:
        # critical(1.0) + exposed_db(0.75) + expired_ssl(0.60)
        # + self_signed(0.50) + eol(0.70) = 3.55 / 5.5 = 0.645 → HIGH
        from firmable.data.models import Observation, SSLCert, VulnerabilityRecord
        from firmable.identity.aggregator import aggregate_observations

        observations = [
            # HIGH: critical CVE + exposed DB + expired cert + self-signed + EOL
            Observation(
                ip_str="1.1.1.1",
                port=3306,
                org="Risky Corp",
                vulns={"CVE-2024-CRIT": VulnerabilityRecord(cvss=9.8)},
                ssl=SSLCert(self_signed=True, expired=True),
                tags=["eol"],
            ),
            # MONITOR: plain HTTP only
            Observation(ip_str="2.2.2.2", port=80, org="Safe Corp"),
            # LOW: self-signed cert only — 0.50 / 5.5 = 0.09
            Observation(
                ip_str="3.3.3.3",
                port=443,
                org="Mid Corp",
                ssl=SSLCert(self_signed=True),
            ),
        ]

        accounts = aggregate_observations(observations)
        signal_sets = [extract_signals(a) for a in accounts]
        scores = [
            score_account(ss, next(a.org_name for a in accounts if a.account_id == ss.account_id))
            for ss in signal_sets
        ]
        ranked = rank_accounts(scores)

        assert len(ranked) == 3
        # Risky Corp must be ranked first with HIGH tier
        assert ranked[0].org_name == "Risky Corp"
        assert ranked[0].priority_tier == PriorityTier.HIGH
        # Safe Corp with only HTTP should be MONITOR
        safe = next(r for r in ranked if r.org_name == "Safe Corp")
        assert safe.priority_tier == PriorityTier.MONITOR
        # Mid Corp (self-signed only) → LOW
        mid = next(r for r in ranked if r.org_name == "Mid Corp")
        assert mid.priority_tier == PriorityTier.LOW
