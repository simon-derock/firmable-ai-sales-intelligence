# Firmable AI Sales Intelligence Platform — Architecture

**Repository:** `firmable-ai-sales-intelligence`  
**Status:** Initial architecture; implementation decisions must remain data-driven.

---

# 1. Architecture Objective

Build the smallest architecture capable of transforming a very large heterogeneous Internet-observation dataset into:

```text
Evidence-backed cybersecurity account intelligence
```

The architecture prioritizes:

1. correctness;
2. reproducibility;
3. explainability;
4. evaluation;
5. cost control;
6. operational simplicity.

---

# 2. High-Level Architecture

```text
                         RAW DATASET
                    JSONL / Zstandard
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Streaming Ingestion │
                 │ zstd → NDJSON       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Validation +        │
                 │ Normalization       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Account / Entity    │
                 │ Resolution          │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Security Signal     │
                 │ Engine              │
                 └──────────┬──────────┘
                            │
                 ┌──────────┴──────────┐
                 │                     │
                 ▼                     ▼
        Deterministic Facts       Evidence Store
                 │                     │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ LLM Interpretation  │
                 │ Gemini / Mistral    │
                 │ via LangChain       │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Validation Gate     │
                 └──────────┬──────────┘
                            │
                     ┌──────┴──────┐
                     │             │
                  ABSTAIN       PRIORITIZE
                                    │
                                    ▼
                         Account Intelligence
                                    │
                                    ▼
                            Sales Application
```

---

# 3. Architectural Principle

The architecture deliberately separates:

### Facts

Owned by deterministic data processing.

Examples:

```text
CVE = CVE-XXXX
CVSS = 9.2
port = 2375
cloud = AWS
product = X
```

### Evidence

Owned by retrieval/provenance.

### Interpretation

Owned by an LLM only when ambiguity exists.

### Decision

Owned by validated scoring/business logic.

This prevents an LLM from becoming the system's source of truth.

---

# 4. Data Plane

## Raw Layer

The original compressed dataset is immutable.

It should be referenced through a dataset manifest rather than copied into the repository.

```text
raw/
  dataset manifest
```

The raw file remains external/local.

---

# 5. Streaming Ingestion

Required:

```text
zstd -dc
    ↓
Python streaming process
    ↓
JSON parser
    ↓
bounded batches
```

The parser must process records incrementally.

Memory usage should not grow linearly with total dataset size.

Malformed records should be counted and observable.

---

# 6. Normalized Layer

Normalize heterogeneous observations into stable contracts.

Conceptual structure:

```text
Observation
HostIdentity
NetworkIdentity
ServiceObservation
Vulnerability
```

Normalization must preserve the original observation ID and source fields required for provenance.

---

# 7. Analytical Layer

The analytical layer converts observations into account-level representations.

Example:

```text
7.5M observations
       ↓
hundreds/thousands/millions of identities
       ↓
accounts
       ↓
signals
```

The exact cardinality must be determined empirically.

Compact columnar storage such as Parquet is preferred for analytical artifacts when appropriate.

DuckDB/Polars may be used where they simplify analytical processing.

---

# 8. Account Resolution

Potential identity evidence:

```text
IP
Hostname
Domain
Organization
ASN
Cloud provider
```

The resolution engine must assign confidence where identity relationships are uncertain.

Conflicting evidence should not be silently discarded.

---

# 9. Security Signal Engine

The signal engine should initially be deterministic.

Example:

```python
critical_cve = max_cvss >= 9.0
eol = "eol-product" in tags
risky_service = port in risky_ports
cloud_asset = "cloud" in tags
```

Composite signals may then be constructed:

```text
critical_cve
+
public exposure
+
security-sensitive service
```

Signals must retain their evidence.

---

# 10. Scoring Engine

Initial scoring should be transparent.

```text
ICP Fit
Security Exposure
Vulnerability
Infrastructure Complexity
Urgency
Evidence Strength
Uncertainty
```

The score should expose component contributions.

A learned model may be considered later only if sufficient labelled data exists.

---

# 11. Evidence Model

Logical structure:

```text
Account
  │
  ├── Signal
  │      │
  │      └── Evidence
  │              │
  │              └── Source Observation
  │
  └── Signal
```

Evidence should contain:

```text
source_record_id
source_field
observed_value
normalized_value
observed_at
transformation
```

This creates a provenance chain:

```text
sales recommendation
       ↓
LLM decision
       ↓
signal
       ↓
evidence
       ↓
raw observation
```

---

# 12. Retrieval Architecture Decision

RAG is **not implemented**.

Reasoning:

- The LLM receives pre-aggregated, structured account data (signals, scores, evidence) directly — not raw observations.
- All query patterns (filter by domain, industry, signal type) are structured filters over DuckDB/Parquet.
- No unstructured text corpus requires semantic search.
- The assignment warns against unnecessary vector databases.

If future evidence shows retrieval improves the workflow, the architecture can accommodate it. But the current data model does not justify it.

---

# 13. LLM Layer

The LLM layer performs semantic interpretation.

It receives:

```text
account context
+
structured signals
+
retrieved evidence
+
task instructions
```

It returns structured output.

It does not receive arbitrary uncontrolled database access.

---

# 14. LLM Pipeline

The AI workflow uses lightweight LangChain — no LangGraph.

LangGraph was evaluated and rejected: the workflow is a linear pipeline with one branch point (abstain vs proceed), not a stateful graph. LangGraph would add framework complexity without architectural value.

Pipeline:

```text
load_account_data
    ↓
compute_deterministic_features
    ↓
assemble_evidence
    ↓
LLM: analyze_security_need (LangChain structured output)
    ↓
validation_gate
    ├── insufficient evidence → ABSTAIN
    └── sufficient evidence
            ↓
        calculate_priority
            ↓
        generate_sales_brief
            ↓
        END
```

Implementation uses:

- `ChatGoogleGenerativeAI` / `ChatMistralAI` — provider abstraction
- `ChatPromptTemplate` — prompt management
- `PydanticOutputParser` — structured output
- Callbacks — tracing and cost hooks
- `with_retry()` / `with_fallback()` — reliability

---

# 15. Provider Architecture

Use an internal abstraction:

```text
LLMProvider
    ├── GeminiProvider
    └── MistralProvider
```

Business logic should not depend directly on a provider SDK.

Example logical interface:

```text
generate_structured(
    request,
    model,
    prompt_version
)
```

The provider implementation owns:

- API calls;
- retries;
- timeout;
- token accounting;
- response parsing;
- provider errors.

---

# 16. Model Routing

```text
                    Account
                       │
              deterministic gate
                       │
             ┌─────────┴─────────┐
             │                   │
        straightforward       ambiguous
             │                   │
        cheap model        stronger model
```

The routing policy must be measurable.

---

# 17. Prompt Registry

Prompt files are version-controlled.

```text
prompts/
    security_signal/
        v1.md
        v2.md
    sales_brief/
        v1.md
```

Every result records the prompt version.

This enables:

```text
same input
+
different prompt
→
measurable comparison
```

---

# 18. Evaluation Architecture

Evaluation is the primary quality mechanism. No eval library (RAGAS, DeepEval) is used — custom pytest-based evaluation provides full control.

## Classification Evaluation

```text
              labelled eval set (25-30 cases)
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
    baseline        LLM v1        LLM v2
        │             │             │
        └─────────────┼─────────────┘
                      ▼
               classification metrics
               (P / R / F1 / confusion)
                      │
                      ▼
               regression report
```

Metrics:

- Precision, Recall, F1 per class (security_need, urgency)
- Confusion matrix
- Abstention precision and recall
- Per-class error analysis

## Ranking Evaluation

```text
human-ranked accounts
        vs
system-ranked accounts
        │
        ▼
  NDCG@K
  Precision@K
  Spearman correlation
  Top-K inspection
```

## Generation Quality (LLM-as-Judge)

For explanation and sales brief quality:

```text
LLM output
    +
structured evidence
    +
judge prompt
    ↓
judge LLM
    ↓
scored rubric
```

Judge dimensions:

- **Groundedness** — does the explanation reference actual evidence?
- **Faithfulness** — does it contradict the structured data?
- **Actionability** — is the sales advice concrete and useful?
- **Hallucination** — did it invent infrastructure facts?

## A/B Comparison Framework

```text
Prompt v1 + Model A         Prompt v2 + Model B
        │                           │
        └───────────┬───────────────┘
                    ▼
           same labelled set
                    │
                    ▼
        ┌───────────────────────┐
        │ Metric deltas         │
        │ Cost deltas           │
        │ Latency deltas        │
        │ Quality-cost Pareto   │
        │ Failure case diff     │
        └───────────────────────┘
```

## Eval Run Record

Each evaluation run records:

```text
eval_run_id
dataset_version
code_commit
prompt_version
model
provider
metrics
timestamp
cost
latency_p50
latency_p99
failures
known_weaknesses
```

---

# 19. Observability Architecture

All LLM calls generate structured traces.

```text
Application
    ↓
LLM call
    ↓
Trace
    ├── request
    ├── response
    ├── model
    ├── prompt version
    ├── tokens
    ├── cost
    ├── latency
    ├── decision
    └── error
```

JSONL or SQLite is sufficient initially.

---

# 20. Cost Architecture

Cost should be calculated at the request level and aggregated.

```text
LLM call
 ↓
input tokens
output tokens
model price
 ↓
request cost
 ↓
account cost
 ↓
pipeline cost
```

A deterministic pre-filter should prevent unnecessary LLM calls.

---

# 21. Caching

Use deterministic cache keys.

Conceptually:

```text
hash(
    dataset_version,
    account_id,
    evidence_hash,
    prompt_version,
    model
)
```

The cache prevents repeated identical analysis.

---

# 22. API Layer

The API should expose business concepts rather than raw database implementation.

Potential endpoints:

```text
GET /health

GET /accounts

GET /accounts/{account_id}

GET /accounts/{account_id}/signals

GET /accounts/{account_id}/evidence

POST /accounts/{account_id}/analyze

GET /segments
```

Exact API surface should remain small.

---

# 23. Frontend

The UI should optimize for sales decisions.

Primary workflow:

```text
Filter
 ↓
Rank
 ↓
Inspect
 ↓
Understand
 ↓
Act
```

The main account card should expose:

```text
Account
Priority
Why
Why now
Top signals
Evidence
Next action
```

Avoid turning the UI into a generic data explorer.

---

# 24. Security Architecture

Secrets:

```text
.env
    ↓
server-side only
```

Never expose LLM API keys to the frontend.

Untrusted dataset text must be clearly delimited before entering an LLM prompt.

LLM output must be schema validated.

Logs must be redacted.

Dependencies should be scanned.

---

# 25. CI Architecture

### Pull Request

```text
checkout
 ↓
uv sync
 ↓
lint
 ↓
format check
 ↓
typecheck
 ↓
unit tests
 ↓
integration tests
 ↓
security checks
 ↓
build
```

### Evaluation

```text
manual/scheduled
 ↓
load labelled dataset
 ↓
run selected model/prompt
 ↓
calculate metrics
 ↓
compare baseline
 ↓
publish artifact
```

### Deployment

```text
main
 ↓
CI
 ↓
build
 ↓
deploy
 ↓
health check
 ↓
smoke test
```

---

# 26. Technology Selection Rules

Potential technologies include:

| Problem | Candidate | Selection Rule |
|---|---|---|
| Python environment | uv | Use |
| Parsing | Python / PyArrow | Benchmark |
| Data processing | Polars | Use if beneficial |
| Analytics | DuckDB | Use if workload fits |
| Storage | Parquet | Preferred for analytical artifacts |
| API | FastAPI | Appropriate for small service |
| Validation | Pydantic | Use for contracts |
| LLM framework | LangChain | Use selectively (chat models, structured output, callbacks) |
| LLM | Gemini / Mistral | Evaluate |
| Evaluation | Custom pytest + LLM-as-judge | Core |
| Observability | JSONL / SQLite initially | Sufficient for prototype |

Technology choices are hypotheses until validated against the dataset.

---

# 27. Architecture Decision Records

Record meaningful architectural decisions under:

```text
docs/adr/
```

Initial candidates:

```text
001-storage-strategy.md
002-streaming-ingestion.md
003-account-identity.md
004-rule-vs-llm.md
005-scoring-strategy.md
006-retrieval-strategy.md
007-provider-abstraction.md
008-evaluation-strategy.md
```

Each ADR should document:

```text
Context
Decision
Alternatives
Trade-offs
Consequences
```

---

# 28. Expected Final Architecture

The preferred final system is:

```text
              Shodan Dataset
                    │
            Streaming Ingestion
                    │
             Normalized Data
                    │
             Entity Resolution
                    │
                Accounts
                    │
            Deterministic Signals
                    │
               Base Ranking
                    │
         Selective LLM (LangChain)
                    │
             Validation Gate
                    │
          Explainable Priorities
                    │
              Sales Interface
```

Surrounding the pipeline:

```text
        ┌─────────────────────────────┐
        │ Evaluation                  │
        │ Observability               │
        │ Cost Tracking               │
        │ Security                    │
        │ CI/CD                       │
        │ Prompt Versioning           │
        └─────────────────────────────┘
```

---

# 29. Architecture Success Criteria

The architecture succeeds if it demonstrates:

- large-file streaming;
- robust heterogeneous-data processing;
- account/entity resolution;
- meaningful security signals;
- deterministic baseline;
- selective AI;
- evidence provenance;
- measurable AI quality;
- prompt/model traceability;
- cost awareness;
- operational observability;
- salesperson-oriented product design.

The architecture fails if it becomes a collection of technologies without measurable product value.
