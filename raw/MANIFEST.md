# Dataset Manifest

**Source:** `2026-09-14T10_00_00.json.zst`
**Format:** Zstandard-compressed NDJSON (Shodan snapshot)
**Compressed size:** 11.51 GB
**Profiled:** 2026-09-15

---

## Scale (100k sample, first pass)

| Metric | Value |
|---|---|
| Records sampled | 96,199 |
| Error rate | 0.00% |
| Data quality | Clean — no malformed JSON or schema violations |

> ⚠️ Full-dataset profile in progress. Numbers below are sample estimates.

---

## Identity Field Coverage

| Field | Coverage |
|---|---|
| `org` | **99.8%** — primary account identity field |
| `ip_str` | 100% — always present |
| `domains` | 76.0% — usable but not universal |
| `asn` | ~99% (estimated) |
| `country_code` | via `location` nested object |
| `cloud_provider` | 42.1% — large cloud footprint |

**Key finding:** `org` is the most reliable grouping key. Domain is present on ~3/4 of records but has identity ambiguity (768 domains map to >1 org in 100k sample — ~5.7% ambiguity rate).

### Cardinality (100k sample)

| Key | Unique count | Observations per key |
|---|---|---|
| IPs | 83,490 | ~1.15 obs/IP |
| Domains | 13,347 | ~7.2 obs/domain |
| Orgs | 5,058 | ~19 obs/org |
| ASNs | 3,365 | ~28 obs/ASN |
| Countries | 156 | — |

**Account aggregation strategy:** Group by `org` as primary key, with `asn` and `domains` as secondary enrichment. IP-level grouping would produce too many accounts (~83k accounts from 96k records).

---

## Security Signal Distribution

### Vulnerability Coverage
- **% with CVEs:** 0.0% in first 100k records
- **Interpretation:** Vulnerability data is either sparsely distributed across the full dataset or concentrated in specific scan modules. Full-dataset profile required before drawing conclusions.
- **Action:** Do not weight vulnerability signals until full scan confirms distribution.

### Risky Exposure (deterministic, no CVE required)

| Signal | Count (100k) | Rate |
|---|---|---|
| Exposed DB ports (3306/5432/6379/27017/9200) | 286 | 0.30% |
| Exposed admin ports (8080/8443/8888/9000/9090) | 928 | 0.96% |
| Self-signed certificates | 0 | — (not in sample) |
| EOL software tags | 0 | — (not in sample) |

---

## Service Distribution

### Top Ports

| Port | Count | Notes |
|---|---|---|
| 80 | 12,351 | HTTP |
| 12304 | 10,507 | ⚠️ Non-standard — investigate |
| 443 | 6,473 | HTTPS |
| 14903 | 2,319 | Non-standard |
| 18113 | 2,032 | Non-standard |
| 8568 | 1,849 | Non-standard |
| 5503 | 1,811 | Non-standard |
| 1023 | 1,436 | Reserved range |
| 3333 | 1,392 | Non-standard |
| 9188 | 1,326 | Non-standard |

**Finding:** High volume on non-standard ports (12304, 14903, 18113) — likely IoT or embedded devices. Standard HTTP/HTTPS are top-2 expected. Port 1023 (reserved range) is notable.

### Top Products

| Product | Count |
|---|---|
| nginx | 3,217 |
| CloudFront httpd | 2,049 |
| Apache httpd | 1,200 |
| AWS ELB | 1,145 |
| AkamaiGHost | 831 |

**Finding:** Heavy CDN/cloud-proxy presence (CloudFront, Akamai, AWS ELB). These represent infra in front of actual services — need org-level aggregation to de-duplicate.

---

## Architecture Implications

### Entity Resolution Strategy
- **Primary key:** `org` field (99.8% coverage)
- **Secondary keys:** `asn`, `domains` for enrichment
- **IP → Account ratio:** ~1.15 observations/IP → accounts will have multiple services
- **Domain ambiguity:** ~5.7% of domains span multiple orgs — resolve by majority-vote or ASN agreement

### Scoring Signal Hierarchy (pre-full-scan hypothesis)
1. **Deterministic signals first:** exposed ports, non-standard ports, risky service combinations
2. **CVE signals:** sparse in sample — weight heavily when present, don't penalise absence
3. **Cloud presence (42%):** flag for cloud security product fit
4. **Product diversity:** varied products = larger attack surface

### What to Build Next (M2)
1. Account aggregator: `org` → aggregated observations
2. Deterministic signal engine: port exposure, product fingerprint, cloud detection
3. Baseline scorer: sum of weighted signal hits, no LLM
4. Full profile results will validate/adjust weights

---

## Open Questions (Pending Full-Dataset Profile)
- [ ] What % of records contain CVE data across full 7.5M records?
- [ ] What is full cardinality of unique orgs across the dataset?
- [ ] Do non-standard high-volume ports (12304, 14903) belong to specific product families?
- [ ] What is the SSL/TLS expiry and self-signed certificate rate at scale?
- [ ] Are vuln-heavy records clustered by country, ASN, or product?

---

*Profile JSON: `raw/profile_sample_100k.json`*
*Full profile: `raw/profile_full.json` (in progress)*
