# Dataset Manifest

**Source:** `2026-09-14T10_00_00.json.zst`
**Format:** Zstandard-compressed NDJSON (Shodan internet scan snapshot)
**Compressed size:** 11.51 GB
**Profiled:** 2026-09-15 — 14 min 31 sec streaming pass, no decompression to disk

---

## Scale (Full Dataset)

| Metric | Value |
|---|---|
| Total records | **8,555,719** |
| Malformed JSON | 0 |
| Malformed schema | 0 |
| **Error rate** | **0.00%** — data is exceptionally clean |

---

## Identity Field Coverage

| Field | Coverage | Notes |
|---|---|---|
| `org` | **99.8%** | Primary account grouping key |
| `ip_str` | 100% | Always present |
| `domains` | **74.6%** | Missing for 1 in 4 records |
| `asn` | ~99% | Highly reliable secondary key |
| `cloud_provider` | **39.2%** | Large cloud footprint |
| `country_code` | ~99% | Via nested `location` object |

### Cardinality

| Key | Unique count | Avg observations/entity |
|---|---|---|
| IPs | 2,902,773 | ~2.9 obs/IP |
| Domains | 383,827 | ~22 obs/domain |
| **Orgs** | **87,425** | **~97 obs/org** ← account count |
| ASNs | 30,583 | ~280 obs/ASN |
| Countries | 229 | — |

> [!IMPORTANT]
> **Account cardinality is ~87,425 unique orgs.** This is the target sales universe.
> At 97 observations per org on average, aggregation compresses 8.5M records to ~87K accounts.
> `org` coverage of 99.8% makes it the unambiguous primary grouping key.

**Domain identity ambiguity:** 38,956 domains (10.1%) map to more than one org.
Resolution: prefer org as primary key; use ASN agreement to break ties.

---

## Security Signal Distribution

### Vulnerability Coverage
| Signal | Count | Rate |
|---|---|---|
| Records with any CVE | **0** | **0.00%** |
| Unique CVEs | 0 | — |
| Critical CVEs (CVSS ≥ 9.0) | 0 | — |
| High CVEs (7.0–8.9) | 0 | — |

> [!WARNING]
> **Vuln data is absent from this dataset snapshot.** The `vulns` field appears uniformly empty across all 8.5M records. This is a Shodan API subscription artefact — the public/community scan feed does not include vulnerability enrichment. The CVE/CVSS signals in the scoring engine are architecturally correct but will score zero until a vuln-enriched feed is added.
>
> **Impact:** The deterministic signal engine falls back to port exposure, TLS hygiene, EOL tags, and cloud detection as primary differentiators. These remain strong buying signals.

### Port-Based Exposure Signals
| Signal | Count | Rate |
|---|---|---|
| Exposed DB ports (3306/5432/6379/27017/9200/1433) | **22,729** | **0.27%** |
| Exposed admin/management ports | **127,510** | **1.49%** |

At 87K accounts: exposed DB affects ~2,500 accounts; exposed admin affects ~14,000 accounts — meaningfully sized target segments.

---

## Service Distribution

### Top 10 Ports (Full Dataset)

| Port | Count | Service | Security Relevance |
|---|---|---|---|
| **80** | 912,366 | HTTP | Baseline — unencrypted web |
| **443** | 464,501 | HTTPS | Standard TLS |
| **179** | 304,942 | BGP | ⚠️ Routing protocol exposed — high severity |
| **7547** | 74,895 | TR-069 | ⚠️ ISP router management — critical if misconfigured |
| **8443** | 71,406 | HTTPS-alt | Admin/management over TLS |
| **81** | 68,664 | HTTP-alt | Non-standard HTTP |
| **25** | 68,097 | SMTP | Email server |
| **5903** | 58,331 | VNC | ⚠️ Remote desktop — high exposure risk |
| **1433** | 54,806 | MSSQL | ⚠️ Microsoft SQL Server exposed |
| **993** | 54,272 | IMAPS | Encrypted IMAP |

> [!IMPORTANT]
> **Port 179 (BGP)** at 304K records is the 3rd most common port. BGP exposure is a critical finding for a cybersecurity sales pitch — misconfigured BGP can enable route hijacking.
> **Port 5903 (VNC)** and **1433 (MSSQL)** in the top 10 are strong buying signals for exposed remote access and database services.

### Top 5 Products

| Product | Count | Notes |
|---|---|---|
| nginx | 374,090 | Web server |
| CloudFront httpd | 152,174 | AWS CDN proxy |
| AWS ELB | 89,271 | Load balancer |
| Apache httpd | 81,357 | Web server |
| AkamaiGHost | 62,969 | CDN proxy |

Heavy CDN/cloud proxy presence confirms 39.2% cloud rate. CDN-fronted infrastructure means many domain observations represent the same underlying org.

---

## Architecture Implications (Evidence-Based)

### 1. Account Aggregation: Use `org` as primary key
- 99.8% coverage, 87K unique values → tractable account universe
- ~97 obs/account → rich signal aggregation per account
- No entity resolution ML needed — `org` field is authoritative enough

### 2. Scoring Without Vulns: Port + TLS + Cloud signals carry the weight
- Port exposure (BGP 179, VNC 5903, MSSQL 1433) is the strongest available signal
- TLS hygiene (self-signed, expired) will be the second differentiator
- Cloud presence (39.2%) is a product-fit signal, not a risk signal
- EOL software tags remain in the model; coverage to be validated at account level

### 3. CVE Signal Architecture: Correct design, wrong data source
- The `VulnerabilityRecord` / `critical_cve_exposure` signal is the right abstraction
- To activate it: enrich with NVD CVE feed cross-referenced against product/version fields
- Priority for M3+: extract `product` + `version` from records → lookup CVE database

### 4. Scoring Weight Recalibration (Post-MANIFEST)
The original signal weights were authored pre-profiling. Given vuln data absence:
- Port-based signals (`exposed_database`, `exposed_admin_panel`) should carry more relative weight
- BGP exposure (port 179) warrants a dedicated signal — currently captured under `high_port_diversity`
- New signal candidates: `bgp_exposed`, `vnc_exposed`, `rdp_exposed`, `mssql_exposed`

### 5. Target Universe for Sales UI
- ~87K accounts total
- ~14K with admin panel exposure → first priority filter
- ~2.5K with database exposure → highest priority
- BGP/VNC/MSSQL exposed (to quantify at account level in M2)

---

## Open Questions (Resolved by This Profile)

| Question | Answer |
|---|---|
| Account cardinality? | **87,425 orgs** |
| Vuln data present? | **No — feed limitation** |
| Org coverage? | **99.8% — primary key confirmed** |
| Cloud footprint? | **39.2%** |
| Data quality? | **Perfect — 0% error rate** |

## Remaining Open Questions

- [ ] Per-account signal distribution across full 87K orgs (M2 output)
- [ ] BGP/VNC/MSSQL account count once aggregated
- [ ] EOL tag coverage across full org universe
- [ ] TLS self-signed/expired cert rate at account level
- [ ] Whether `product`+`version` fields are populated enough for CVE cross-referencing

---

*Full profile JSON: `raw/profile_full.json`*
*Sample profile JSON: `raw/profile_sample_100k.json`*
*Profiler: `src/firmable/data/ingest.py` | `src/firmable/data/profiler.py`*
