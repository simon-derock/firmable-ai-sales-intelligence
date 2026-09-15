"""Streaming dataset reader for Zstandard-compressed NDJSON.

Design constraints:
- Never fully decompress the archive to disk.
- Memory usage must not grow linearly with dataset size.
- Malformed records are counted and observable, never silently dropped.
- Caller receives bounded batches of validated Observation objects.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import zstandard as zstd

from firmable.data.models import Observation, ParseResult

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ReadStats:
    """Running statistics for one streaming pass."""

    records_read: int = 0
    records_valid: int = 0
    records_malformed_json: int = 0
    records_malformed_schema: int = 0
    records_missing_ip: int = 0
    bytes_read: int = 0

    @property
    def records_total(self) -> int:
        return self.records_read

    @property
    def error_rate(self) -> float:
        if self.records_read == 0:
            return 0.0
        bad = self.records_malformed_json + self.records_malformed_schema
        return bad / self.records_read

    def summary(self) -> dict[str, Any]:
        return {
            "records_read": self.records_read,
            "records_valid": self.records_valid,
            "records_malformed_json": self.records_malformed_json,
            "records_malformed_schema": self.records_malformed_schema,
            "records_missing_ip": self.records_missing_ip,
            "error_rate": round(self.error_rate, 6),
            "bytes_read": self.bytes_read,
        }


@dataclass
class ReaderConfig:
    """Configuration for the streaming reader."""

    batch_size: int = 1000
    max_records: int | None = None  # None = read all
    skip_malformed: bool = True
    log_every: int = 100_000


def _parse_record(raw: dict[str, Any]) -> ParseResult:
    """Parse and validate one raw Shodan record into an Observation."""
    if "ip_str" not in raw and "ip" not in raw:
        return ParseResult(
            raw=raw,
            error="missing ip_str/ip field",
            is_valid=False,
        )

    # Normalize ip field name
    if "ip_str" not in raw and "ip" in raw:
        raw = {**raw, "ip_str": str(raw["ip"])}

    # Extract nested cloud info
    if "cloud" in raw and isinstance(raw["cloud"], dict):
        cloud = raw["cloud"]
        raw = {
            **raw,
            "cloud_provider": cloud.get("provider"),
            "cloud_region": cloud.get("region"),
            "cloud_service": cloud.get("service"),
        }

    # Extract nested SSL cert info
    ssl_data = None
    if "ssl" in raw and isinstance(raw["ssl"], dict):
        ssl = raw["ssl"]
        cert = ssl.get("cert", {})
        subject = cert.get("subject", {})
        issuer = cert.get("issuer", {})
        ssl_data = {
            "issued": cert.get("issued"),
            "expires": cert.get("expires"),
            "expired": cert.get("expired"),
            "self_signed": cert.get("self_signed"),
            "subject_cn": subject.get("CN"),
            "issuer_cn": issuer.get("CN"),
        }

    # Extract HTTP info
    http_data = None
    if "http" in raw and isinstance(raw["http"], dict):
        http = raw["http"]
        http_data = {
            "status": http.get("status"),
            "title": http.get("title"),
            "server": http.get("server"),
            "redirect_location": http.get("redirects", [{}])[-1].get("location")
            if http.get("redirects")
            else None,
        }

    # Extract location and shodan module dicts
    loc = raw.get("location") if isinstance(raw.get("location"), dict) else {}
    shodan_mod = raw.get("_shodan") if isinstance(raw.get("_shodan"), dict) else {}

    # Build clean observation dict
    obs_dict: dict[str, Any] = {
        "ip_str": raw.get("ip_str", ""),
        "port": raw.get("port", 0),
        "transport": raw.get("transport"),
        "timestamp": raw.get("timestamp"),
        "hostnames": raw.get("hostnames", []),
        "domains": raw.get("domains", []),
        "os": raw.get("os"),
        "tags": raw.get("tags", []),
        "asn": raw.get("asn"),
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "country_code": loc.get("country_code") if loc else raw.get("country_code"),
        "country_name": loc.get("country_name") if loc else raw.get("country_name"),
        "city": loc.get("city") if loc else raw.get("city"),
        "cloud_provider": raw.get("cloud_provider"),
        "cloud_region": raw.get("cloud_region"),
        "cloud_service": raw.get("cloud_service"),
        "product": raw.get("product"),
        "version": raw.get("version"),
        "cpe": raw.get("cpe", []) or raw.get("cpe23", []),
        "banner": raw.get("data"),
        "http": http_data,
        "ssl": ssl_data,
        "vulns": raw.get("vulns", {}),
        "module": shodan_mod.get("module") if shodan_mod else raw.get("module"),
    }

    try:
        obs = Observation.model_validate(obs_dict)
        return ParseResult(observation=obs, raw=raw, is_valid=True)
    except Exception as exc:
        return ParseResult(
            raw=raw,
            error=str(exc),
            is_valid=False,
        )


def stream_observations(
    path: Path,
    config: ReaderConfig | None = None,
) -> Generator[ParseResult, None, None]:
    """Stream observations from a Zstandard-compressed NDJSON file.

    Yields one ParseResult per line. Never loads the full file into memory.

    Args:
        path: Path to the .zst compressed NDJSON file.
        config: Reader configuration. Uses defaults if not provided.

    Yields:
        ParseResult — valid observation or error record.
    """
    cfg = config or ReaderConfig()
    stats = ReadStats()

    dctx = zstd.ZstdDecompressor()

    with path.open("rb") as fh, dctx.stream_reader(fh) as reader:
        buffer = b""
        records_yielded = 0

        while True:
            # Read in 64KB chunks — bounded memory
            chunk = reader.read(65536)
            if not chunk:
                # Flush remaining buffer
                if buffer.strip():
                    lines = [buffer]
                else:
                    break
                buffer = b""
            else:
                stats.bytes_read += len(chunk)
                buffer += chunk
                lines_raw = buffer.split(b"\n")
                buffer = lines_raw[-1]  # incomplete line kept
                lines = lines_raw[:-1]

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                stats.records_read += 1

                if cfg.max_records and stats.records_read > cfg.max_records:
                    return

                if stats.records_read % cfg.log_every == 0:
                    logger.info(
                        "streaming_progress",
                        extra={
                            "records_read": stats.records_read,
                            "error_rate": stats.error_rate,
                        },
                    )

                # Parse JSON
                try:
                    raw = json.loads(line)
                except json.JSONDecodeError as exc:
                    stats.records_malformed_json += 1
                    result = ParseResult(
                        raw={},
                        error=f"JSON decode error: {exc}",
                        is_valid=False,
                    )
                    if not cfg.skip_malformed:
                        yield result
                    continue

                if not isinstance(raw, dict):
                    stats.records_malformed_schema += 1
                    continue

                # Parse + validate
                result = _parse_record(raw)

                if result.is_valid:
                    stats.records_valid += 1
                elif "missing ip" in (result.error or ""):
                    stats.records_missing_ip += 1
                    stats.records_malformed_schema += 1
                else:
                    stats.records_malformed_schema += 1

                if not result.is_valid and cfg.skip_malformed:
                    continue

                records_yielded += 1
                yield result

            if not chunk:
                break

    logger.info("streaming_complete", extra=stats.summary())


def stream_batches(
    path: Path,
    config: ReaderConfig | None = None,
) -> Generator[list[Observation], None, None]:
    """Stream validated observations in bounded batches.

    Args:
        path: Path to the .zst compressed NDJSON file.
        config: Reader configuration.

    Yields:
        List of valid Observation objects (size <= config.batch_size).
    """
    cfg = config or ReaderConfig()
    batch: list[Observation] = []

    for result in stream_observations(path, cfg):
        if result.is_valid and result.observation is not None:
            batch.append(result.observation)
            if len(batch) >= cfg.batch_size:
                yield batch
                batch = []

    if batch:
        yield batch
