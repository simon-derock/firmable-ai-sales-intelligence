"""Tests for the streaming dataset reader."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import zstandard as zstd

from firmable.data.models import Observation
from firmable.data.reader import (
    ReaderConfig,
    _parse_record,
    stream_batches,
    stream_observations,
)


def _compress_ndjson(content: bytes) -> Path:
    """Compress raw bytes with zstd into a named temp file."""
    with tempfile.NamedTemporaryFile(suffix=".json.zst", delete=False) as tmp:
        cctx = zstd.ZstdCompressor()
        tmp.write(cctx.compress(content))
        return Path(tmp.name)


def _make_zst_fixture(records: list[dict[str, Any]]) -> Path:
    """Create a temp .zst NDJSON file from a list of dicts."""
    ndjson = "\n".join(json.dumps(r) for r in records).encode()
    return _compress_ndjson(ndjson)


# ── Fixtures ──────────────────────────────────────────────────────

VALID_RECORD: dict[str, Any] = {
    "ip_str": "1.2.3.4",
    "port": 443,
    "transport": "tcp",
    "org": "Acme Corp",
    "asn": "AS12345",
    "domains": ["acme.com"],
    "hostnames": ["web.acme.com"],
    "tags": ["cloud"],
    "cloud": {"provider": "Amazon", "region": "ap-southeast-2"},
    "vulns": {
        "CVE-2024-1234": {
            "cvss": 9.8,
            "cvss_version": "3.1",
            "references": [],
            "verified": True,
        },
    },
}

RECORD_WITH_NESTED_LOCATION: dict[str, Any] = {
    "ip_str": "5.6.7.8",
    "port": 80,
    "org": "Widgets Inc",
    "location": {
        "country_code": "AU",
        "country_name": "Australia",
        "city": "Melbourne",
    },
}

RECORD_MISSING_IP: dict[str, Any] = {"port": 80, "org": "Mystery Org"}


class TestParseRecord:
    """Unit tests for the _parse_record function."""

    def test_valid_record_parses(self) -> None:
        result = _parse_record(VALID_RECORD)
        assert result.is_valid is True
        assert result.observation is not None
        assert result.observation.ip_str == "1.2.3.4"
        assert result.observation.port == 443

    def test_cloud_extracted_from_nested(self) -> None:
        result = _parse_record(VALID_RECORD)
        assert result.observation is not None
        assert result.observation.cloud_provider == "Amazon"
        assert result.observation.cloud_region == "ap-southeast-2"

    def test_location_extracted_from_nested(self) -> None:
        result = _parse_record(RECORD_WITH_NESTED_LOCATION)
        assert result.observation is not None
        assert result.observation.country_code == "AU"
        assert result.observation.city == "Melbourne"

    def test_vulns_parsed(self) -> None:
        result = _parse_record(VALID_RECORD)
        assert result.observation is not None
        assert result.observation.has_vulns is True
        assert result.observation.max_cvss == 9.8

    def test_missing_ip_returns_invalid(self) -> None:
        result = _parse_record(RECORD_MISSING_IP)
        assert result.is_valid is False
        assert "missing ip" in (result.error or "").lower()

    def test_ip_field_normalized(self) -> None:
        record = {"ip": "10.0.0.1", "port": 22}
        result = _parse_record(record)
        assert result.is_valid is True
        assert result.observation is not None
        assert result.observation.ip_str == "10.0.0.1"


class TestStreamObservations:
    """Integration tests for the streaming reader against fixture files."""

    def test_reads_valid_records(self) -> None:
        path = _make_zst_fixture([VALID_RECORD, RECORD_WITH_NESTED_LOCATION])
        results = list(stream_observations(path))
        valid = [r for r in results if r.is_valid]
        assert len(valid) == 2

    def test_skips_malformed_json_by_default(self) -> None:
        """Malformed JSON is skipped when skip_malformed=True (default)."""
        content = (
            json.dumps(VALID_RECORD).encode()
            + b"\nthis is bad json\n"
            + json.dumps(RECORD_WITH_NESTED_LOCATION).encode()
        )
        path = _compress_ndjson(content)

        cfg = ReaderConfig(skip_malformed=True)
        results = list(stream_observations(path, cfg))
        assert all(r.is_valid for r in results)
        assert len(results) == 2

    def test_yields_errors_when_not_skipping(self) -> None:
        """Malformed records are yielded when skip_malformed=False."""
        content = json.dumps(VALID_RECORD).encode() + b"\nbad json here\n"
        path = _compress_ndjson(content)

        cfg = ReaderConfig(skip_malformed=False)
        results = list(stream_observations(path, cfg))
        invalid = [r for r in results if not r.is_valid]
        assert len(invalid) == 1
        assert "JSON" in (invalid[0].error or "")

    def test_max_records_limits_output(self) -> None:
        records = [VALID_RECORD] * 10
        path = _make_zst_fixture(records)
        cfg = ReaderConfig(max_records=3)
        results = list(stream_observations(path, cfg))
        assert len(results) <= 3

    def test_empty_file_produces_no_results(self) -> None:
        path = _compress_ndjson(b"")
        results = list(stream_observations(path))
        assert results == []


class TestStreamBatches:
    """Tests for the batched streaming interface."""

    def test_yields_batches_of_correct_size(self) -> None:
        records = [VALID_RECORD] * 25
        path = _make_zst_fixture(records)
        cfg = ReaderConfig(batch_size=10)
        batches = list(stream_batches(path, cfg))
        sizes = [len(b) for b in batches]
        assert sizes[:-1] == [10, 10]
        assert sizes[-1] == 5

    def test_all_items_are_observations(self) -> None:
        path = _make_zst_fixture([VALID_RECORD, RECORD_WITH_NESTED_LOCATION])
        for batch in stream_batches(path):
            for item in batch:
                assert isinstance(item, Observation)
