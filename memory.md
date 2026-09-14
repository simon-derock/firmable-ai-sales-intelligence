# Project Memory

## PROJECT
Firmable AI Sales Intelligence Platform

## CURRENT MILESTONE
M0 — Repository Foundation

## PAST
- Assignment requirements reviewed.
- Dataset dossier reviewed.
- Initial architecture defined.
- Repository name selected: `firmable-ai-sales-intelligence`.
- Architecture decisions made:
  - LangGraph rejected → lightweight LangChain only.
  - RAG rejected → structured filters over DuckDB/Parquet sufficient.
  - No vector DB, no HNSW, no BM25 index needed.
  - No RAGAS → custom pytest-based eval with LLM-as-judge.
  - Evaluation is primary quality mechanism: classification metrics, ranking metrics, LLM-as-judge, A/B comparison, regression detection.

## PRESENT
- M0 bootstrap in progress.
- `pyproject.toml`, `Makefile`, CI workflow, project structure created.
- Running `uv sync` to install dependencies.
- Next: verify quality gates pass (`make verify`).

## NEXT
1. Complete M0: verify `uv sync && make verify` passes.
2. M1: Implement streaming dataset reader and profile schema.
3. M1: Profile cardinality, identity fields, security-signal distributions.

## DECISIONS
- Raw dataset is the source of truth.
- Full decompression to disk is prohibited.
- Deterministic logic owns factual security signals.
- LLMs are used only where semantic interpretation adds measurable value.
- LangChain (lightweight) for LLM integration. No LangGraph.
- RAG is not implemented. Structured data pipeline provides LLM inputs directly.
- No unnecessary infrastructure.
- Custom eval stack: pytest + LLM-as-judge. No RAGAS/DeepEval.

## ACTIVE RISKS
- Actual account/entity cardinality is not yet known.
- Dataset identity relationships require empirical analysis.
- Final scoring weights are not yet justified.
- LLM value over deterministic baseline is not yet established.

## LAST VERIFIED
M0 in progress — not yet verified.
