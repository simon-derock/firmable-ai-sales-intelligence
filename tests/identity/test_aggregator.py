"""Tests for the account aggregator — entity resolution and signal accumulation."""

from __future__ import annotations

from firmable.data.models import Observation, SSLCert, VulnerabilityRecord
from firmable.identity.aggregator import _make_account_id, _resolve_key, aggregate_observations


class TestMakeAccountId:
    """Unit tests for slug generation."""

    def test_lowercases_and_slugifies(self) -> None:
        assert _make_account_id("Acme Corp") == "acme-corp"

    def test_strips_special_characters(self) -> None:
        assert _make_account_id("Widgets & Co. (Pty) Ltd") == "widgets-co-pty-ltd"

    def test_collapses_whitespace(self) -> None:
        assert _make_account_id("  Multi   Space  ") == "multi-space"

    def test_empty_string_returns_unknown(self) -> None:
        assert _make_account_id("") == "unknown"

    def test_already_slugified_unchanged(self) -> None:
        assert _make_account_id("cloudflare-inc") == "cloudflare-inc"


class TestResolveKey:
    """Unit tests for the observation grouping key."""

    def test_uses_org_when_present(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=80, org="Acme Corp")
        assert _resolve_key(obs) == "Acme Corp"

    def test_falls_back_to_asn_when_no_org(self) -> None:
        obs = Observation(ip_str="1.2.3.4", port=80, asn="AS12345")
        assert _resolve_key(obs) == "asn:AS12345"

    def test_falls_back_to_subnet_when_no_org_or_asn(self) -> None:
        obs = Observation(ip_str="192.168.1.100", port=80)
        assert _resolve_key(obs) == "subnet:192.168.1.0/24"

    def test_falls_back_to_ip_for_malformed_ip(self) -> None:
        obs = Observation(ip_str="::1", port=80)
        assert _resolve_key(obs) == "ip:::1"


class TestAggregateObservations:
    """Integration tests for the full aggregation pipeline."""

    def _make_obs(
        self,
        org: str,
        port: int,
        ip: str = "1.2.3.4",
        **kwargs,  # type: ignore[no-untyped-def]
    ) -> Observation:
        return Observation(ip_str=ip, port=port, org=org, **kwargs)

    def test_groups_by_org(self) -> None:
        obs = [
            self._make_obs("Acme Corp", 80, ip="1.1.1.1"),
            self._make_obs("Acme Corp", 443, ip="1.1.1.2"),
            self._make_obs("Widgets Inc", 80, ip="2.2.2.2"),
        ]
        accounts = aggregate_observations(obs)
        assert len(accounts) == 2
        org_names = {a.org_name for a in accounts}
        assert "Acme Corp" in org_names
        assert "Widgets Inc" in org_names

    def test_accumulates_ports_per_account(self) -> None:
        obs = [
            self._make_obs("Acme Corp", 80),
            self._make_obs("Acme Corp", 443),
            self._make_obs("Acme Corp", 3306),
        ]
        accounts = aggregate_observations(obs)
        assert len(accounts) == 1
        signals = accounts[0].signals
        assert {80, 443, 3306} <= signals.exposed_ports
        assert 3306 in signals.exposed_db_ports

    def test_accumulates_unique_ips(self) -> None:
        obs = [
            self._make_obs("Acme Corp", 80, ip="1.1.1.1"),
            self._make_obs("Acme Corp", 443, ip="1.1.1.2"),
            self._make_obs("Acme Corp", 8080, ip="1.1.1.1"),  # same IP
        ]
        accounts = aggregate_observations(obs)
        assert accounts[0].signals.unique_ips == 2
        assert accounts[0].signals.total_observations == 3

    def test_accumulates_domains_and_asns(self) -> None:
        obs = [
            self._make_obs("Acme Corp", 80, domains=["acme.com"], asn="AS1111"),
            self._make_obs("Acme Corp", 443, domains=["acme.io"], asn="AS2222"),
        ]
        accounts = aggregate_observations(obs)
        acc = accounts[0]
        assert "acme.com" in acc.domains
        assert "acme.io" in acc.domains
        assert "AS1111" in acc.asns
        assert "AS2222" in acc.asns

    def test_accumulates_cve_signals(self) -> None:
        obs = [
            self._make_obs(
                "Vuln Corp",
                443,
                vulns={
                    "CVE-2024-CRIT": VulnerabilityRecord(cvss=9.8),
                    "CVE-2024-HIGH": VulnerabilityRecord(cvss=7.5),
                },
            ),
            self._make_obs(
                "Vuln Corp",
                80,
                vulns={"CVE-2024-MED": VulnerabilityRecord(cvss=5.0)},
            ),
        ]
        accounts = aggregate_observations(obs)
        signals = accounts[0].signals
        assert len(signals.cve_ids) == 3
        assert signals.max_cvss == 9.8
        assert signals.critical_cve_count == 1
        assert signals.high_cve_count == 1

    def test_detects_cloud_via_provider(self) -> None:
        obs = [self._make_obs("Cloud Co", 443, cloud_provider="Amazon")]
        accounts = aggregate_observations(obs)
        assert accounts[0].signals.is_cloud is True
        assert "Amazon" in accounts[0].signals.cloud_providers

    def test_detects_cloud_via_tag(self) -> None:
        obs = [self._make_obs("Cloud Co", 443, tags=["cloud"])]
        accounts = aggregate_observations(obs)
        assert accounts[0].signals.is_cloud is True

    def test_detects_eol_tag(self) -> None:
        obs = [self._make_obs("Old Corp", 80, tags=["eol"])]
        accounts = aggregate_observations(obs)
        assert accounts[0].signals.eol_observation_count == 1

    def test_detects_self_signed_cert(self) -> None:
        obs = [
            self._make_obs(
                "Sketchy Corp",
                443,
                ssl=SSLCert(self_signed=True, expired=True),
            )
        ]
        accounts = aggregate_observations(obs)
        signals = accounts[0].signals
        assert signals.self_signed_cert_count == 1
        assert signals.expired_cert_count == 1

    def test_non_standard_port_count(self) -> None:
        obs = [
            self._make_obs("Weird Corp", 80),  # standard
            self._make_obs("Weird Corp", 443),  # standard
            self._make_obs("Weird Corp", 12304),  # non-standard
            self._make_obs("Weird Corp", 14903),  # non-standard
        ]
        accounts = aggregate_observations(obs)
        assert accounts[0].signals.non_standard_port_count == 2

    def test_empty_observations_returns_empty_list(self) -> None:
        assert aggregate_observations([]) == []

    def test_account_id_is_slugified_org(self) -> None:
        obs = [self._make_obs("Acme Corp Pty Ltd", 80)]
        accounts = aggregate_observations(obs)
        assert accounts[0].account_id == "acme-corp-pty-ltd"

    def test_fallback_to_asn_key_when_no_org(self) -> None:
        obs = [
            Observation(ip_str="10.0.0.1", port=80, asn="AS9999"),
            Observation(ip_str="10.0.0.2", port=443, asn="AS9999"),
        ]
        accounts = aggregate_observations(obs)
        assert len(accounts) == 1
        assert accounts[0].signals.total_observations == 2
