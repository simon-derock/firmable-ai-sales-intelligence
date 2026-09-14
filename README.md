# Firmable AI Sales Intelligence Platform

> Transform raw Internet infrastructure observations into evidence-backed cybersecurity prospect prioritization.

## Quick Start

```bash
# Clone
git clone https://github.com/simon-derock/firmable-ai-sales-intelligence.git
cd firmable-ai-sales-intelligence

# Setup
cp .env.example .env
# Edit .env with your API keys
uv sync --all-extras

# Verify
make verify

# Run
make run
```

## Architecture

```text
.zst dataset (12 GB, streaming only)
    ↓
Streaming ingestion (zstd → NDJSON → validate → normalize)
    ↓
Account aggregation (IP/domain/org/ASN → accounts)
    ↓
Deterministic security signals + scoring
    ↓
DuckDB/Parquet analytical store
    ↓
Selective LLM interpretation (LangChain, Gemini/Mistral)
    ↓
FastAPI + Sales UI
```

## Project Structure

```text
src/firmable/
├── data/          # Streaming ingestion, validation, normalization
├── identity/      # Entity resolution, account aggregation
├── signals/       # Security signal extraction
├── scoring/       # Account scoring and ranking
├── ai/            # LLM integration (LangChain, provider abstraction)
└── api/           # FastAPI application

tests/             # Mirrors src/ structure
prompts/           # Versioned prompt files (v1.md, v2.md)
skills/            # Reusable AI workflow (SKILL.md)
evals/             # Labeled dataset, judges, metrics, harness
docs/adr/          # Architecture Decision Records
```

## Commands

| Command | Description |
|---|---|
| `make verify` | Run all quality gates (lint, format, typecheck, security, test) |
| `make eval` | Run evaluation harness |
| `make eval-compare` | A/B compare prompt/model variants |
| `make run` | Start the application |
| `make ingest` | Run dataset ingestion |

## Documentation

- [PLAN.md](PLAN.md) — Project plan, milestones, scope
- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture, design decisions
- [SPEC.md](SPEC.md) — Engineering specification, requirements
- [memory.md](memory.md) — Current project state (agentic memory)

## License

MIT
