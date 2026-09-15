"""Tests for the account identity model."""

from __future__ import annotations

from firmable.identity.models import Account, AccountSignals


class TestAccountSignals:
    """Contract tests for AccountSignals."""

    def test_defaults_are_empty(self) -> None:
        s = AccountSignals()
        assert s.exposed_ports == set()
        assert s.cve_ids == set()
        assert s.max_cvss is None
        assert s.total_observations == 0
        assert s.is_cloud is False

    def test_to_dict_serialises_sets_as_sorted_lists(self) -> None:
        s = AccountSignals()
        s.exposed_ports = {443, 80, 8080}
        s.cve_ids = {"CVE-2024-B", "CVE-2024-A"}
        d = s.to_dict()
        assert d["exposed_ports"] == [80, 443, 8080]
        assert d["cve_ids"] == ["CVE-2024-A", "CVE-2024-B"]


class TestAccount:
    """Contract tests for the Account model."""

    def test_to_dict_round_trips_identity_fields(self) -> None:
        acc = Account(
            account_id="acme-corp",
            org_name="Acme Corp",
            domains=["acme.com", "acme.io"],
            asns=["AS12345"],
        )
        d = acc.to_dict()
        assert d["account_id"] == "acme-corp"
        assert d["org_name"] == "Acme Corp"
        assert d["domains"] == ["acme.com", "acme.io"]
        assert d["asns"] == ["AS12345"]
        assert "signals" in d

    def test_default_domains_and_asns_are_empty(self) -> None:
        acc = Account(account_id="x", org_name="X Corp")
        assert acc.domains == []
        assert acc.asns == []
