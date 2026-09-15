"""Tests for the deterministic security signal extractor."""

from __future__ import annotations

from firmable.identity.models import Account, AccountSignals
from firmable.signals.extractor import SIGNAL_WEIGHTS, Signal, SignalSet, extract_signals


def _make_account(
    org: str = "Test Corp",
    **signal_kwargs,  # type: ignore[no-untyped-def]
) -> Account:
    """Build an Account with specified signals for testing."""
    signals = AccountSignals(**signal_kwargs)
    signals.product_count = len(signals.products)
    signals.unique_ips = 1
    return Account(
        account_id=org.lower().replace(" ", "-"),
        org_name=org,
        signals=signals,
    )


class TestSignalModel:
    """Contract tests for Signal and SignalSet."""

    def test_signal_to_dict_fields(self) -> None:
        sig = Signal(
            name="exposed_database",
            present=True,
            weight=0.75,
            evidence="DB port 3306 exposed",
            evidence_detail={"ports": [3306]},
        )
        d = sig.to_dict()
        assert d["name"] == "exposed_database"
        assert d["present"] is True
        assert d["weight"] == 0.75
        assert "evidence" in d
        assert "evidence_detail" in d

    def test_signal_set_active_signals(self) -> None:
        ss = SignalSet(account_id="test")
        ss.signals = [
            Signal("a", present=True, weight=0.5, evidence=""),
            Signal("b", present=False, weight=0.8, evidence=""),
            Signal("c", present=True, weight=0.3, evidence=""),
        ]
        active = ss.active_signals
        assert len(active) == 2
        assert all(s.present for s in active)

    def test_signal_set_total_weight(self) -> None:
        ss = SignalSet(account_id="test")
        ss.signals = [
            Signal("a", present=True, weight=0.5, evidence=""),
            Signal("b", present=False, weight=0.8, evidence=""),  # not counted
            Signal("c", present=True, weight=0.3, evidence=""),
        ]
        assert abs(ss.total_weight - 0.8) < 1e-9

    def test_signal_set_to_dict(self) -> None:
        ss = SignalSet(account_id="acme")
        ss.signals = [Signal("x", present=True, weight=1.0, evidence="test")]
        d = ss.to_dict()
        assert d["account_id"] == "acme"
        assert d["active_signal_count"] == 1
        assert d["total_weight"] == 1.0
        assert len(d["signals"]) == 1


class TestExtractSignals:
    """Comprehensive tests for extract_signals() against known account states."""

    def test_no_signals_all_absent(self) -> None:
        """Account with no risk factors — all signals absent."""
        account = _make_account(total_observations=5)
        result = extract_signals(account)
        assert result.account_id == "test-corp"
        # All signals present in output (but as absent)
        assert len(result.signals) == len(SIGNAL_WEIGHTS)
        assert len(result.active_signals) == 0
        assert result.total_weight == 0.0

    def test_critical_cve_signal(self) -> None:
        account = _make_account(critical_cve_count=2, max_cvss=9.8)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "critical_cve_exposure")
        assert sig.present is True
        assert sig.weight == SIGNAL_WEIGHTS["critical_cve_exposure"]
        assert "9.0" in sig.evidence
        assert sig.evidence_detail["critical_cve_count"] == 2

    def test_critical_cve_absent_when_zero(self) -> None:
        account = _make_account(critical_cve_count=0)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "critical_cve_exposure")
        assert sig.present is False

    def test_high_cve_signal(self) -> None:
        account = _make_account(high_cve_count=3)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "high_cve_exposure")
        assert sig.present is True
        assert sig.evidence_detail["high_cve_count"] == 3

    def test_exposed_database_signal(self) -> None:
        account = _make_account(exposed_db_ports={3306, 5432})
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "exposed_database")
        assert sig.present is True
        assert 3306 in sig.evidence_detail["exposed_db_ports"]
        assert 5432 in sig.evidence_detail["exposed_db_ports"]

    def test_exposed_admin_signal(self) -> None:
        account = _make_account(exposed_admin_ports={8080})
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "exposed_admin_panel")
        assert sig.present is True

    def test_expired_cert_signal(self) -> None:
        account = _make_account(expired_cert_count=1)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "expired_ssl_cert")
        assert sig.present is True
        assert sig.evidence_detail["expired_cert_count"] == 1

    def test_self_signed_cert_signal(self) -> None:
        account = _make_account(self_signed_cert_count=5)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "self_signed_cert")
        assert sig.present is True

    def test_eol_software_signal(self) -> None:
        account = _make_account(eol_observation_count=2)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "eol_software")
        assert sig.present is True
        assert "2 service" in sig.evidence

    def test_multi_country_signal_at_threshold(self) -> None:
        account = _make_account(countries={"US", "AU", "GB"})  # exactly 3
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "multi_country_presence")
        assert sig.present is True
        assert sig.evidence_detail["country_count"] == 3

    def test_multi_country_signal_below_threshold(self) -> None:
        account = _make_account(countries={"US", "AU"})  # 2, below threshold
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "multi_country_presence")
        assert sig.present is False

    def test_high_port_diversity_signal(self) -> None:
        ports = set(range(100, 110))  # exactly 10 ports
        account = _make_account(exposed_ports=ports)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "high_port_diversity")
        assert sig.present is True
        assert sig.evidence_detail["unique_port_count"] == 10

    def test_cloud_presence_signal_via_provider(self) -> None:
        account = _make_account(is_cloud=True, cloud_providers={"Amazon", "Azure"})
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "cloud_presence")
        assert sig.present is True
        assert "Amazon" in sig.evidence_detail["cloud_providers"]

    def test_cloud_absent_when_not_cloud(self) -> None:
        account = _make_account(is_cloud=False)
        result = extract_signals(account)
        sig = next(s for s in result.signals if s.name == "cloud_presence")
        assert sig.present is False

    def test_high_risk_account_accumulates_weight(self) -> None:
        """A maximally risky account should have high total weight."""
        account = _make_account(
            critical_cve_count=3,
            max_cvss=9.9,
            high_cve_count=5,
            exposed_db_ports={3306, 5432},
            exposed_admin_ports={8080},
            expired_cert_count=2,
            self_signed_cert_count=1,
            eol_observation_count=4,
            countries={"US", "AU", "GB", "DE"},
            exposed_ports=set(range(100, 115)),
            is_cloud=True,
            cloud_providers={"Amazon"},
        )
        result = extract_signals(account)
        # All 10 signals should be active
        assert len(result.active_signals) == len(SIGNAL_WEIGHTS)
        # Total weight should be the sum of all signal weights
        expected = sum(SIGNAL_WEIGHTS.values())
        assert abs(result.total_weight - expected) < 1e-6

    def test_evidence_is_always_non_empty_string(self) -> None:
        """Every signal must produce a non-empty evidence string."""
        account = _make_account(total_observations=1)
        result = extract_signals(account)
        for sig in result.signals:
            assert isinstance(sig.evidence, str)
            assert len(sig.evidence) > 0

    def test_output_covers_all_defined_signal_weights(self) -> None:
        """extract_signals must produce exactly one signal per weight key."""
        account = _make_account()
        result = extract_signals(account)
        extracted_names = {s.name for s in result.signals}
        assert extracted_names == set(SIGNAL_WEIGHTS.keys())
