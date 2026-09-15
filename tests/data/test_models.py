"""Tests for the canonical observation data contract."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from firmable.data.models import Observation, ParseResult, VulnerabilityRecord


class TestObservation:
    """Contract tests for the Observation model."""

    def test_minimal_valid_record(self) -> None:
        """Observation requires only ip_str and port."""
        obs = Observation(ip_str="1.2.3.4", port=80)
        assert obs.ip_str == "1.2.3.4"
        assert obs.port == 80

    def test_optional_fields_default_to_empty(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=443)
        assert obs.hostnames == []
        assert obs.domains == []
        assert obs.tags == []
        assert obs.vulns == {}
        assert obs.cpe == []

    def test_invalid_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Observation(ip_str="1.2.3.4", port=99999)

    def test_negative_port_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Observation(ip_str="1.2.3.4", port=-1)

    def test_port_zero_is_valid(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=0)
        assert obs.port == 0

    def test_has_vulns_false_when_empty(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=80)
        assert obs.has_vulns is False

    def test_has_vulns_true_when_cves_present(self) -> None:
        obs = Observation(
            ip_str="1.2.3.4",
            port=443,
            vulns={"CVE-2024-1234": VulnerabilityRecord(cvss=9.8)},
        )
        assert obs.has_vulns is True

    def test_max_cvss_returns_highest(self) -> None:
        obs = Observation(
            ip_str="1.2.3.4",
            port=443,
            vulns={
                "CVE-2024-0001": VulnerabilityRecord(cvss=7.5),
                "CVE-2024-0002": VulnerabilityRecord(cvss=9.8),
                "CVE-2024-0003": VulnerabilityRecord(cvss=5.0),
            },
        )
        assert obs.max_cvss == 9.8

    def test_max_cvss_none_when_no_vulns(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=80)
        assert obs.max_cvss is None

    def test_critical_cves_filters_correctly(self) -> None:
        obs = Observation(
            ip_str="1.2.3.4",
            port=443,
            vulns={
                "CVE-2024-CRITICAL": VulnerabilityRecord(cvss=9.8),
                "CVE-2024-HIGH": VulnerabilityRecord(cvss=7.5),
                "CVE-2024-MEDIUM": VulnerabilityRecord(cvss=5.0),
                "CVE-2024-NO-SCORE": VulnerabilityRecord(cvss=None),
            },
        )
        assert obs.critical_cves == ["CVE-2024-CRITICAL"]

    def test_is_cloud_via_provider(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=443, cloud_provider="Amazon")
        assert obs.is_cloud is True

    def test_is_cloud_via_tag(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=443, tags=["cloud"])
        assert obs.is_cloud is True

    def test_is_not_cloud_by_default(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=443)
        assert obs.is_cloud is False


class TestParseResult:
    """Contract tests for ParseResult."""

    def test_valid_result(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=80)
        result = ParseResult(observation=obs, is_valid=True)
        assert result.is_valid is True
        assert result.is_malformed is False

    def test_invalid_result(self) -> None:
        result = ParseResult(error="missing ip_str", is_valid=False)
        assert result.is_valid is False
        assert result.is_malformed is True
        assert result.observation is None
