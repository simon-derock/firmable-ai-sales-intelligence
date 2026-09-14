.PHONY: install test lint format typecheck security verify eval eval-compare run ingest clean help

# exFAT workaround: venv lives on local disk (HDD doesn't support symlinks)
export UV_PROJECT_ENVIRONMENT := /home/simon/.cache/firmable-venv/.venv

# ── Setup ─────────────────────────────────────────────────────────
install: ## Install all dependencies
	uv sync --all-extras

# ── Quality Gates ─────────────────────────────────────────────────
test: ## Run unit tests
	uv run pytest tests/ -m "not slow and not eval" --tb=short -q

test-all: ## Run all tests including slow
	uv run pytest tests/ --tb=short -q

lint: ## Lint with ruff
	uv run ruff check src/ tests/

format: ## Format with ruff
	uv run ruff format src/ tests/

format-check: ## Check formatting without changes
	uv run ruff format --check src/ tests/

typecheck: ## Type check with mypy
	uv run mypy src/

security: ## Security scan with bandit
	uv run bandit -r src/ -c pyproject.toml -q

verify: lint format-check typecheck security test ## Run all quality gates
	@echo "✅ All quality gates passed"

# ── Evaluation ────────────────────────────────────────────────────
eval: ## Run evaluation harness
	uv run python -m firmable.eval.harness

eval-compare: ## A/B compare two variants (VARIANT_A=v1/gemini VARIANT_B=v2/gemini)
	uv run python -m firmable.eval.ab_compare --a $(VARIANT_A) --b $(VARIANT_B)

# ── Application ───────────────────────────────────────────────────
run: ## Run the application
	uv run uvicorn firmable.api.app:app --reload --host 0.0.0.0 --port 8000

ingest: ## Run dataset ingestion
	uv run python -m firmable.data.ingest

# ── Utilities ─────────────────────────────────────────────────────
clean: ## Remove generated artifacts
	rm -rf __pycache__ .pytest_cache .mypy_cache .ruff_cache htmlcov
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

.DEFAULT_GOAL := help
