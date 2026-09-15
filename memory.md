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

  <mission>
    Transform a 12.36 GB compressed Shodan dataset (~7.5M records, NDJSON.zst) into a
    hosted sales intelligence platform for cybersecurity salespeople.
    Answer: WHO to target → WHY this company → WHY NOW → WHAT evidence → WHAT to do next.
  </mission>

  <current_milestone>M1 — Dataset Archaeology</current_milestone>

  <completed_milestones>
    <milestone id="M0" status="DONE" commit="7125eae">
      Bootstrap uv project. make verify passes (ruff, mypy, bandit, pytest).
      GitHub Actions CI live. Repo pushed to GitHub.
    </milestone>
  </completed_milestones>

  <architecture_decisions>
    <decision id="1">LangGraph REJECTED. Use lightweight LangChain only: ChatModel + PydanticOutputParser + callbacks.</decision>
    <decision id="2">RAG NOT IMPLEMENTED. LLM receives pre-aggregated structured account data directly. DuckDB/Parquet handles all queries.</decision>
    <decision id="3">No vector DB, no HNSW, no BM25 index. Structured SQL filters sufficient.</decision>
    <decision id="4">No RAGAS. Custom pytest-based eval: classification metrics + LLM-as-judge + A/B comparison + regression detection.</decision>
    <decision id="5">Dataset NEVER fully decompressed to disk. Streaming only (zstd → NDJSON → bounded batches).</decision>
    <decision id="6">Deterministic baseline FIRST. LLM must beat it measurably or stays off production path.</decision>
    <decision id="7">LLM providers: Gemini (primary) + Mistral (fallback). Behind provider abstraction.</decision>
  </architecture_decisions>

  <active_risks>
    <risk>Actual account/entity cardinality not yet known — pending M1 profiling.</risk>
    <risk>Dataset identity relationships (domain/org/ASN quality) — pending M1.</risk>
    <risk>Final scoring weights not yet justified — pending M1 + M2.</risk>
    <risk>LLM value over deterministic baseline not yet established — pending M3.</risk>
  </active_risks>

  <stack>
    <item>Python 3.12, uv package manager</item>
    <item>Polars + DuckDB + PyArrow + zstandard — data processing</item>
    <item>Pydantic v2 — validation and contracts</item>
    <item>LangChain (langchain-core, langchain-google-genai, langchain-mistralai) — LLM layer</item>
    <item>FastAPI + uvicorn — API</item>
    <item>structlog — logging</item>
    <item>ruff + mypy + bandit + pytest — quality gates</item>
  </stack>

  <key_commands>
    <cmd>make verify       — run all quality gates (must pass before every commit)</cmd>
    <cmd>make test         — unit tests only</cmd>
    <cmd>make eval         — run evaluation harness</cmd>
    <cmd>make eval-compare VARIANT_A=v1/gemini VARIANT_B=v2/gemini — A/B compare</cmd>
    <cmd>make run          — start FastAPI app</cmd>
    <cmd>make ingest       — run dataset ingestion</cmd>
    <cmd>export UV_PROJECT_ENVIRONMENT=/home/simon/.cache/firmable-venv/.venv  — required for manual uv run</cmd>
  </key_commands>

  <project_structure>
    src/firmable/
      data/       — streaming ingestion, validation, normalization, profiling
      identity/   — entity resolution, account aggregation
      signals/    — deterministic security signal extraction
      scoring/    — account scoring and ranking
      ai/         — LLM provider abstraction, structured output, tracing, cost
      api/        — FastAPI app
    tests/        — mirrors src/ + eval/
    prompts/      — versioned prompt files (security_signal/v1.md, sales_brief/v1.md)
    skills/       — SKILL.md reusable AI workflow
    evals/        — labeled dataset, judges, metrics, harness, results
    docs/adr/     — Architecture Decision Records
  </project_structure>

  <dev_protocol>
    Every feature: inspect → hypothesize → test → implement → make verify → update memory.md → atomic commit → push.
    Convention: Conventional Commits (feat/test/chore/docs/ci/fix).
    Definition of done: requirement + test + implementation + quality gates + observability + eval (if AI) + docs + memory.md + commit + push.
  </dev_protocol>

  <next_tasks>
    <task priority="1">M1: Implement streaming dataset reader (src/firmable/data/reader.py) with zstd decompression, NDJSON parsing, bounded batches, malformed record counting.</task>
    <task priority="2">M1: Implement dataset profiler (src/firmable/data/profiler.py) — schema, field frequency, cardinality, identity field quality, security signal distributions.</task>
    <task priority="3">M1: Write dataset manifest (raw/MANIFEST.md) with findings.</task>
    <task priority="4">M2: Account aggregation once identity strategy is clear from profiling.</task>
  </next_tasks>

  <eval_strategy>
    Classification: Precision / Recall / F1 / confusion matrix per class (security_need, urgency, abstention).
    Ranking: NDCG@K, Precision@K, Spearman rank correlation vs human ranking.
    Generation (LLM-as-judge): groundedness, faithfulness, actionability, hallucination detection, completeness.
    A/B: prompt v1 vs v2, model A vs B — metric deltas + cost deltas + regression detection.
    Deterministic baseline always evaluated alongside LLM variants.
    Harness: make eval (one command, reproducible, records eval_run_id + metrics + cost + latency).
  </eval_strategy>
</agent_init>
```

---

## PROJECT
Firmable AI Sales Intelligence Platform

## CURRENT MILESTONE
M1 — Dataset Archaeology

## PAST
- M0 DONE (commit `7125eae`): uv project, quality gates, CI, project structure, docs updated.
- Architecture decisions locked: no LangGraph, no RAG, no vector DB, no RAGAS.
- make verify passes: ruff ✅ mypy ✅ bandit ✅ pytest ✅
- Pushed to GitHub.

## PRESENT
- M1 in progress.
- Implementing streaming dataset reader + profiler.
- Dataset: `/media/simon/hdd/firmable-ai-sales-intelligence/2026-09-14T10_00_00.json.zst`

## NEXT
1. `feat(data): add streaming dataset reader` — zstd → NDJSON → bounded batches.
2. `feat(data): add dataset profiler` — schema, cardinality, identity, security distributions.
3. `docs: add dataset manifest` — empirical findings.
4. Begin M2 account aggregation once identity strategy is known.

## DECISIONS
- Raw dataset is the source of truth.
- Full decompression to disk is prohibited.
- Deterministic logic owns factual security signals.
- LLMs used only where semantic interpretation adds measurable value.
- LangChain (lightweight) only. No LangGraph.
- RAG not implemented. No vector DB / BM25 / HNSW.
- Custom eval stack. No RAGAS/DeepEval.

## ACTIVE RISKS
- Actual account/entity cardinality not yet known.
- Dataset identity relationships require empirical analysis.
- Final scoring weights not yet justified.
- LLM value over deterministic baseline not yet established.

## LAST VERIFIED
M0 ✅ — `make verify` passes. Commit `7125eae` pushed to `main`.
