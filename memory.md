# Project Memory

<!-- ============================================================
     AGENT TRANSFER INITIALIZATION PROMPT
     Copy-paste this entire XML block to start a new agent session
     ============================================================ -->

```xml
<agent_init>
  <project>
    <name>Firmable AI Sales Intelligence Platform</name>
    <repo>https://github.com/simon-derock/firmable-ai-sales-intelligence.git</repo>
    <local_path>/media/simon/hdd/firmable-ai-sales-intelligence</local_path>
    <dataset_path>/media/simon/hdd/firmable-ai-sales-intelligence/2026-09-14T10_00_00.json.zst</dataset_path>
    <venv_path>/home/simon/.cache/firmable-venv/.venv</venv_path>
    <filesystem_note>HDD is exFAT — no symlinks. venv lives at venv_path above. All make commands export UV_PROJECT_ENVIRONMENT automatically.</filesystem_note>
  </project>

  <persona>
    Principal Data Engineer + AI Systems Architect + Staff Product Engineer.
    Building a real take-home assignment for Firmable (Series A, Melbourne).
    Evidence-driven: inspect → hypothesize → test → implement → verify → document → commit → push.
    Zero tolerance for: red tests, lint failures, untraceable claims, fabricated metrics.
  </persona>

  <mission>
    Transform 11.51 GB Zstandard-compressed Shodan dataset (8,555,719 NDJSON records, 0% error rate)
    into a hosted cybersecurity sales intelligence platform.
    Answer for salespeople: WHO to target → WHY → WHY NOW → WHAT evidence → WHAT to do next.
  </mission>

  <initialization_steps>
    1. git log --oneline -5 and git status --short
    2. export UV_PROJECT_ENVIRONMENT=/home/simon/.cache/firmable-venv/.venv and make verify
    3. Read: memory.md, PLAN.md, ARCHITECTURE.md, SPEC.md, raw/MANIFEST.md
    4. Identify current milestone and immediate next task.
    5. Read relevant src/ code before touching anything.
    6. Write test first, implement, make verify (green), update memory.md, commit, push.
  </initialization_steps>

  <dataset_facts>
    <!-- CONFIRMED by full streaming profile — 2026-09-15 -->
    <fact>Total records: 8,555,719 — 0.00% error rate</fact>
    <fact>Unique orgs: 87,425 — this is the account universe (salesable targets)</fact>
    <fact>Unique IPs: 2,902,773 — avg 2.9 obs/IP</fact>
    <fact>Unique domains: 383,827 — 10.1% domain-to-org ambiguity</fact>
    <fact>Org coverage: 99.8% — confirmed primary grouping key</fact>
    <fact>Cloud presence: 39.2%</fact>
    <fact>CVE/vuln data: ABSENT — Shodan community feed does not include vuln enrichment</fact>
    <fact>Exposed DB ports: 22,729 records (0.27%)</fact>
    <fact>Exposed admin ports: 127,510 records (1.49%)</fact>
    <fact>Port 179 (BGP): 304,942 records — 3rd most common, high security signal</fact>
    <fact>Port 5903 (VNC): 58,331 records — remote desktop exposure</fact>
    <fact>Port 1433 (MSSQL): 54,806 records — database exposure</fact>
    <fact>Top products: nginx, CloudFront, AWS ELB, Apache httpd, AkamaiGHost</fact>
  </dataset_facts>

  <completed_milestones>
    <milestone id="M0" commit="7125eae">Bootstrap: pyproject.toml, Makefile, CI. make verify passes.</milestone>
    <milestone id="M1_data_layer" commit="cb6456a">Pydantic observation models, streaming zstd reader, dataset profiler. 36 tests.</milestone>
    <milestone id="M1_ingest_cli" commit="02ac43f">Ingestion CLI with rich progress display and structured report.</milestone>
    <milestone id="M1_identity" commit="fddd503">Account aggregator (org→account), AccountSignals model, MANIFEST.md. 20 tests.</milestone>
    <milestone id="M1_signals" commit="8bd41cc">10-signal deterministic extractor with evidence provenance. 20 tests.</milestone>
    <milestone id="M1_scorer" status="UNCOMMITTED">Baseline scorer: normalised score, HIGH/MEDIUM/LOW/MONITOR tiers, rank_accounts. 21 tests (103 total). Needs commit.</milestone>
  </completed_milestones>

  <current_milestone>M2 — Deterministic Intelligence (scorer committed, then expand signals + pipeline)</current_milestone>

  <immediate_next_tasks>
    <task priority="1">Commit scorer: git add -A and commit feat(scoring): add deterministic baseline scorer and rank_accounts</task>
    <task priority="2">Add port-specific high-value signals: bgp_exposed (port 179), vnc_exposed (5903), mssql_exposed (1433) — data-driven from MANIFEST findings</task>
    <task priority="3">Add pipeline integration: src/firmable/scoring/pipeline.py — end-to-end stream → aggregate → signal → score → rank in one call</task>
    <task priority="4">Run the full pipeline against real dataset and export ranked account list to raw/accounts_ranked.json</task>
    <task priority="5">Begin M3: labeled eval set (25-30 manually labeled accounts), LLM classifier</task>
  </immediate_next_tasks>

  <architecture_decisions_locked>
    <decision id="1">LangGraph REJECTED. Lightweight LangChain only: ChatModel + PydanticOutputParser + callbacks.</decision>
    <decision id="2">RAG NOT IMPLEMENTED. LLM receives pre-aggregated structured account data directly.</decision>
    <decision id="3">No vector DB, no HNSW, no BM25. DuckDB/Parquet SQL for all structured queries.</decision>
    <decision id="4">No RAGAS. Custom pytest eval: classification + ranking + LLM-as-judge + A/B comparison.</decision>
    <decision id="5">Dataset never fully decompressed. Streaming only via zstd reader.</decision>
    <decision id="6">Deterministic baseline first. LLM must measurably beat it or stays off production path.</decision>
    <decision id="7">LLM providers: Gemini (primary) + Mistral (fallback). Behind provider abstraction.</decision>
    <decision id="8">CVE signals architecturally correct but inactive — Shodan community feed has no vuln data. Will activate via NVD cross-reference in M3+.</decision>
  </architecture_decisions_locked>

  <active_risks>
    <risk priority="HIGH">CVE signals inactive — vuln data absent from dataset. Port/TLS/cloud signals carry scoring weight.</risk>
    <risk priority="MEDIUM">Signal weights are hypotheses — not validated against labeled eval set until M4.</risk>
    <risk priority="MEDIUM">LLM value over deterministic baseline not established — do not skip baseline evaluation.</risk>
    <risk priority="LOW">10.1% domain-to-org ambiguity — currently resolved by org-first grouping; monitor at account level.</risk>
  </active_risks>

  <stack>
    <item>Python 3.12, uv</item>
    <item>zstandard — streaming decompression</item>
    <item>Polars + DuckDB + PyArrow — data processing</item>
    <item>Pydantic v2 — validation and contracts</item>
    <item>LangChain (langchain-core, langchain-google-genai, langchain-mistralai) — LLM layer</item>
    <item>FastAPI + uvicorn — REST API</item>
    <item>structlog — structured logging</item>
    <item>click + rich — CLI</item>
    <item>ruff + mypy + bandit + pytest — quality gates (103 tests passing)</item>
  </stack>

  <key_commands>
    <cmd>make verify                    -- full quality gate (must pass before every commit)</cmd>
    <cmd>make format                    -- auto-format</cmd>
    <cmd>make test                      -- unit tests only</cmd>
    <cmd>make eval                      -- evaluation harness (requires LLM keys)</cmd>
    <cmd>make ingest                    -- run dataset ingestion</cmd>
    <cmd>export UV_PROJECT_ENVIRONMENT=/home/simon/.cache/firmable-venv/.venv  -- for manual uv run</cmd>
  </key_commands>

  <dev_protocol>
    EVERY feature: inspect -> hypothesize -> test first -> implement -> make verify (GREEN) -> update memory.md -> atomic commit -> push.
    Commit format: type(scope): short imperative phrase   [NO long bodies]
    Types: feat / test / fix / refactor / docs / chore / ci
    Scopes: data / identity / signals / scoring / ai / api / eval / obs
    NEVER commit red. NEVER fabricate metrics. NEVER add deps without justification.
  </dev_protocol>
</agent_init>
```

---

## PROJECT
Firmable AI Sales Intelligence Platform

## CURRENT MILESTONE
M2 — Deterministic Intelligence

## PAST
- M0 DONE (`7125eae`): Bootstrap, quality gates, CI.
- M1 DONE:
  - Data layer: Pydantic models, streaming reader, profiler (`cb6456a`)
  - Ingest CLI (`02ac43f`)
  - Identity: Account aggregator, AccountSignals (`fddd503`)
  - Signals: 10-signal deterministic extractor (`8bd41cc`)
  - Scorer: normalised score, tier classification, ranking (UNCOMMITTED)
  - Full dataset profiled: 8,555,719 records, 87,425 orgs, 0% vuln data

## PRESENT
- 103 tests passing. make verify green.
- Scorer needs commit. 
- Signal weights are hypotheses pending eval calibration.
- CVE signals inactive (no vuln data in dataset).

## NEXT
1. Commit scorer.
2. Add BGP/VNC/MSSQL port-specific signals (evidence from MANIFEST).
3. Pipeline integration (stream → aggregate → signal → score → rank).
4. Export ranked account list from real dataset.
5. M3: labeled eval set + LLM classifier.

## DECISIONS
- Dataset: 8,555,719 records, 87,425 orgs, 0% error rate.
- Vuln data absent — port/TLS/cloud signals own the scoring.
- org = primary grouping key (99.8% coverage confirmed).
- No LangGraph, no RAG, no vector DB, no RAGAS.
- Custom eval stack. Deterministic baseline before LLM.

## ACTIVE RISKS
- CVE signals inactive (dataset limitation).
- Signal weights unvalidated against labeled set.
- LLM value over baseline unestablished.

## LAST VERIFIED
103 tests, make verify green. Last commit: `8bd41cc` (signals extractor).
