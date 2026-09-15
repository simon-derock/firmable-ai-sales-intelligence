"""Canonical data contracts for raw Shodan observations.

These Pydantic models define what the ingestion layer guarantees
to downstream consumers. Optional fields are truly optional —
no downstream code may assume they exist.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class VulnerabilityRecord(BaseModel):
    """A single CVE observed on a host."""

    cvss: float | None = None
    cvss_version: str | None = None
    references: list[str] = Field(default_factory=list)
    summary: str | None = None
    verified: bool = False


class SSLCert(BaseModel):
    """TLS/SSL certificate metadata."""

    issued: str | None = None
    expires: str | None = None
    expired: bool | None = None
    self_signed: bool | None = None
    subject_cn: str | None = None
    issuer_cn: str | None = None


class HTTPInfo(BaseModel):
    """HTTP service metadata."""

    status: int | None = None
    title: str | None = None
    server: str | None = None
    redirect_location: str | None = None


class Observation(BaseModel):
    """Normalized Shodan observation record.

    This is the stable contract between raw ingestion and all
    downstream processing. Unknown fields are captured in extras
    for observability but not used in business logic.
    """

    # Core identity
    ip_str: str
    port: int
    transport: str | None = None
    timestamp: datetime | None = None

    # Host identity
    hostnames: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    os: str | None = None
    tags: list[str] = Field(default_factory=list)

    # Network identity
    asn: str | None = None
    org: str | None = None
    isp: str | None = None
    country_code: str | None = None
    country_name: str | None = None
    city: str | None = None

    # Cloud
    cloud_provider: str | None = None
    cloud_region: str | None = None
    cloud_service: str | None = None

    # Service
    product: str | None = None
    version: str | None = None
    cpe: list[str] = Field(default_factory=list)
    banner: str | None = None

    # HTTP
    http: HTTPInfo | None = None

    # TLS/SSL
    ssl: SSLCert | None = None

    # Vulnerabilities
    vulns: dict[str, VulnerabilityRecord] = Field(default_factory=dict)

    # Module / data source
    module: str | None = None

    @field_validator("port")
    @classmethod
    def port_must_be_valid(cls, v: int) -> int:
        if not (0 <= v <= 65535):
            msg = f"Invalid port: {v}"
            raise ValueError(msg)
        return v

    @property
    def has_vulns(self) -> bool:
        """True if any CVEs were observed."""
        return len(self.vulns) > 0

    @property
    def max_cvss(self) -> float | None:
        """Highest CVSS score across all observed CVEs."""
        scores = [v.cvss for v in self.vulns.values() if v.cvss is not None]
        return max(scores) if scores else None

    @property
    def critical_cves(self) -> list[str]:
        """CVE IDs with CVSS >= 9.0."""
        return [cve_id for cve_id, v in self.vulns.items() if v.cvss is not None and v.cvss >= 9.0]

    @property
    def is_cloud(self) -> bool:
        """True if observation is tagged as cloud-hosted."""
        return self.cloud_provider is not None or "cloud" in self.tags


class ParseResult(BaseModel):
    """Result of parsing one raw record."""

    observation: Observation | None = None
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    is_valid: bool = True

    @property
    def is_malformed(self) -> bool:
        return not self.is_valid
