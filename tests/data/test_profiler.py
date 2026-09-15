"""Tests for the dataset profiler."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import zstandard as zstd

from firmable.data.models import Observation, VulnerabilityRecord
from firmable.data.profiler import (
    IdentityProfile,
    SchemaProfile,
    SecurityProfile,
    profile_dataset,
    save_profile,
)

if TYPE_CHECKING:
    from pathlib import Path


def _make_sample_observation() -> Observation:
    """Helper to create a fully populated sample observation."""
    return Observation(
        ip_str="1.2.3.4",
        port=443,
        transport="tcp",
        hostnames=["api.example.com"],
        domains=["example.com"],
        org="Example Corp",
        asn="AS13335",
        country_code="US",
        cloud_provider="Cloudflare",
        product="nginx",
        tags=["cloud"],
        vulns={
            "CVE-2023-1234": VulnerabilityRecord(cvss=9.5, verified=True),
            "CVE-2023-5678": VulnerabilityRecord(cvss=7.2, verified=False),
        },
    )


class TestSchemaProfile:
    """Unit tests for SchemaProfile."""

    def test_observes_field_presence(self) -> None:
        profile = SchemaProfile()
        obs = _make_sample_observation()
        profile.observe(obs)

        freq = profile.frequency()
        assert profile.total_records == 1
        assert freq["ip_str"] == 1.0
        assert freq["port"] == 1.0
        assert freq["org"] == 1.0
        assert freq["domains"] == 1.0

    def test_frequency_empty(self) -> None:
        profile = SchemaProfile()
        assert profile.frequency() == {}


class TestIdentityProfile:
    """Unit tests for IdentityProfile."""

    def test_tracks_uniqueness_and_coverage(self) -> None:
        profile = IdentityProfile()
        obs1 = _make_sample_observation()
        obs2 = Observation(
            ip_str="5.6.7.8",
            port=80,
            domains=["example.com"],
            org="Other Corp",  # ambiguous domain!
        )

        profile.observe(obs1)
        profile.observe(obs2)
        summary = profile.summary()

        assert summary["unique_ips"] == 2
        assert summary["unique_domains"] == 1
        assert summary["unique_orgs"] == 2
        assert summary["pct_with_domain"] == 1.0
        assert summary["domains_with_multiple_orgs"] == 1


class TestSecurityProfile:
    """Unit tests for SecurityProfile."""

    def test_tracks_vulnerabilities_and_risks(self) -> None:
        profile = SecurityProfile()
        obs = _make_sample_observation()
        profile.observe(obs)
        summary = profile.summary()

        assert summary["records_with_vulns"] == 1
        assert summary["records_with_critical_cve"] == 1
        assert summary["records_with_high_cve"] == 0
        assert summary["unique_cves"] == 2

        cvss_dist = summary["cvss_distribution"]
        assert cvss_dist["max"] == 9.5
        assert cvss_dist["min"] == 7.2
        assert cvss_dist["critical_count"] == 1

    def test_detects_risky_ports(self) -> None:
        profile = SecurityProfile()
        db_obs = Observation(ip_str="10.0.0.1", port=3306)
        admin_obs = Observation(ip_str="10.0.0.2", port=8080)
        profile.observe(db_obs)
        profile.observe(admin_obs)
        summary = profile.summary()

        assert summary["records_exposed_db"] == 1
        assert summary["records_exposed_admin"] == 1


class TestDatasetProfileAndSave:
    """Integration test for full dataset profiling and serialization."""

    def test_profile_dataset_end_to_end(self, tmp_path: Path) -> None:
        records: list[dict[str, Any]] = [
            {
                "ip_str": "1.1.1.1",
                "port": 53,
                "transport": "udp",
                "org": "Cloudflare, Inc.",
                "domains": ["cloudflare.com"],
            },
            {
                "ip_str": "8.8.8.8",
                "port": 53,
                "transport": "udp",
                "org": "Google LLC",
                "domains": ["google.com"],
            },
        ]
        ndjson = "\n".join(json.dumps(r) for r in records).encode()
        cctx = zstd.ZstdCompressor()
        data_path = tmp_path / "sample.json.zst"
        data_path.write_bytes(cctx.compress(ndjson))

        profile = profile_dataset(data_path)

        assert profile.read_stats.records_valid == 2
        assert profile.identity.summary()["unique_ips"] == 2

        # Test save_profile
        out_path = tmp_path / "profile.json"
        save_profile(profile, out_path)

        with out_path.open() as f:
            saved_data = json.load(f)

        assert "read_stats" in saved_data
        assert "schema" in saved_data
        assert "identity" in saved_data
        assert "security" in saved_data
        assert saved_data["read_stats"]["records_valid"] == 2
