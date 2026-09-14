# Firmable AI Sales Intelligence Platform — Engineering Specification

**Repository:** `firmable-ai-sales-intelligence`  
**Status:** Implementation specification  
**Primary objective:** Convert large-scale Internet infrastructure observations into explainable, evidence-backed cybersecurity sales priorities.

---

## 0. Engineering Principle

> **Do not choose a technology, model, database, retrieval strategy, signal, or AI workflow because it is impressive. Every decision must be justified by the dataset, salesperson workflow, measurable evaluation evidence, operational constraints, or cost.**

Core system principle:

> **Deterministic systems establish what we know. Retrieval establishes what supports it. LLMs interpret ambiguity. Evaluation establishes whether the interpretation is trustworthy. Observability establishes what happened. The product turns the result into a sales decision.**

The system must prefer the simplest architecture that satisfies the product requirements.

---

# 1. Problem Definition

Firmable's sales problem is not simply:

> Which companies are large or technically sophisticated?

It is:

> **Which businesses appear to have a meaningful cybersecurity need right now, why do we believe that, and which accounts should sales contact first?**

The platform must transform raw Internet infrastructure observations into account-level intelligence.

### Core workflow

```text
Raw Internet Observations
        ↓
Streaming Ingestion
        ↓
Normalization + Data Quality
        ↓
Entity Resolution / Account Aggregation
        ↓
Security Signal Extraction
        ↓
Evidence Construction
        ↓
Account Scoring
        ↓
AI Interpretation where justified
        ↓
Validation / Abstention
        ↓
Sales Prioritization
        ↓
Why this account?
Why now?
What should sales do?
```

---

# 2. Dataset

The supplied dataset is the primary source of truth.

The provided dossier describes:

- approximately 12.36 GB compressed storage
- approximately 68–75 GB estimated uncompressed volume
- approximately 7.5M records
- heterogeneous Shodan observation records
- IP, port, transport and timestamp information
- hostnames and domains
- organization / ISP / ASN
- cloud information
- HTTP metadata
- products and versions
- CPEs
- TLS/SSL fingerprints
- SSH fingerprints
- security tags
- CVE vulnerability information

The dataset contains important security signals including cloud infrastructure, EOL products, self-signed certificates, honeypot/proxy/IoT tags and known CVEs.

### Source constraint

The supplied dataset remains central to the product.

External data may supplement the dataset only when:

1. it materially improves the sales use case;
2. its provenance is documented;
3. the system still works without it where practical;
4. its availability and cost are understood.

No external enrichment should silently replace the supplied dataset.

---

# 3. Dataset Versioning and Reproducibility

Every ingestion run must record:

```text
dataset_version
source_url
source_file_size
sha256
collection_timestamp
ingestion_timestamp
schema_version
record_count
code_commit
```

The dataset itself should not be copied into Git.

A reproducible ingestion process must allow a reviewer to understand exactly which source produced a derived artifact.

For local development, use small deterministic fixtures.

For full-scale processing, stream directly from the compressed source.

---

# 4. Storage Constraint

The raw archive must never be fully decompressed to disk.

Required processing pattern:

```text
.zst archive
    ↓
zstd streaming decompression
    ↓
bounded parser
    ↓
bounded batches
    ↓
normalization
    ↓
aggregation
    ↓
compact analytical storage
```

The implementation must maintain bounded memory usage.

No architecture may assume that the entire raw dataset fits into RAM or local disk.

---

# 5. Product Users

## Primary user

B2B cybersecurity salesperson / SDR / account executive.

## User jobs

### Job 1 — Find targets

> Show me the companies I should investigate first.

### Job 2 — Understand priority

> Why is this account ranked above the others?

### Job 3 — Understand timing

> What indicates that this company may need cybersecurity help now?

### Job 4 — Validate

> Show me the evidence behind the recommendation.

### Job 5 — Act

> Give me a useful next action or sales angle.

---

# 6. Product Requirements

The application must support:

- account prioritization;
- territory/geography filtering;
- industry/segment filtering where available;
- company-size or scale filtering where available;
- security-signal filtering;
- ranking;
- account detail;
- explainable score breakdown;
- evidence inspection;
- "why this account?" explanation;
- "why now?" explanation;
- recommended next action.

The product should remain small.

It is not a CRM replacement.

---

# 7. Canonical Data Model

The raw Shodan record is an observation rather than a prospect.

The logical model is:

```text
Observation
    ↓
Host / Domain Identity
    ↓
Organization
    ↓
Account
    ↓
Security Signal
    ↓
Signal Evidence
```

Recommended logical entities:

### Observation

```text
observation_id
timestamp
ip
port
transport
banner
banner_hash
```

### HostIdentity

```text
ip
hostnames
domains
os
tags
```

### NetworkIdentity

```text
asn
organization
isp
cloud_provider
cloud_region
```

### ServiceObservation

```text
product
version
service
protocol
http_metadata
ssl_metadata
ssh_metadata
```

### Vulnerability

```text
cve_id
cvss
cvss_version
references
```

### Account

```text
account_id
canonical_name
domains
ips
asns
countries
cloud_providers
observed_services
```

### SecuritySignal

```text
signal_id
account_id
signal_type
severity
confidence
first_observed
last_observed
evidence_ids
source
```

### SignalEvidence

```text
evidence_id
account_id
signal_id
source_record_id
source_field
evidence_value
normalized_value
observed_at
```

The physical storage implementation may differ from this logical model.

---

# 8. Data Quality

The ingestion layer must tolerate schema heterogeneity.

Optional fields must not be assumed to exist.

Validation must distinguish:

- missing;
- null;
- empty;
- malformed;
- valid.

Data quality checks should include:

- malformed JSON count;
- missing required fields;
- invalid IPs;
- invalid ports;
- invalid timestamps;
- duplicate observation IDs;
- invalid CVSS values;
- unexpected enum values;
- schema drift;
- record counts;
- aggregation consistency.

Bad records must be observable rather than silently disappearing.

---

# 9. Signal Taxonomy

Signals must be discovered from the actual dataset.

Do not finalize signal weights before profiling the full data.

Candidate signal classes include:

### Vulnerability signals

- critical CVE;
- high-severity CVE;
- multiple vulnerabilities;
- vulnerable exposed service;
- outdated product/version.

### Exposure signals

- risky publicly exposed service;
- exposed database;
- exposed administrative interface;
- exposed remote-management service;
- unusual high-risk port.

### Infrastructure signals

- large public cloud footprint;
- multiple cloud providers;
- distributed infrastructure;
- many exposed services;
- complex external attack surface.

### Security configuration signals

- EOL software;
- self-signed certificate;
- weak TLS configuration;
- suspicious or unusual service fingerprints.

### Technology signals

- security-sensitive technology stack;
- infrastructure components requiring specialist security controls;
- vulnerable technology concentration.

Signals must be distinguished from generic company characteristics.

For example:

> "Uses cloud infrastructure"

is generally a weak signal.

Whereas:

> "Cloud-hosted account with multiple exposed services including a vulnerable administrative service"

is potentially actionable.

---

# 10. Account Scoring

The ranking model should conceptually represent:

```text
Priority
=
ICP Fit
+ Security Exposure
+ Vulnerability Severity
+ Change / Complexity Signals
+ Urgency
+ Evidence Strength
- Uncertainty
```

The exact weights must be data-driven.

The first implementation should be deterministic and explainable.

Each account must expose its score components rather than only an opaque final number.

Example:

```text
Priority: 87 / 100

ICP Fit                 +18
Critical vulnerability  +30
Exposed service         +20
Infrastructure scale    +10
Evidence confidence     +12
Uncertainty              -3
```

The scoring system must support sensitivity analysis.

If labelled data is insufficient, do not pretend that the score represents a statistically calibrated probability.

---

# 11. AI Architecture

LLMs are optional components, not the foundation of the entire pipeline.

The system must first establish a deterministic baseline.

Required comparison:

```text
Baseline rules
      vs
LLM v1
      vs
LLM v2
```

using the same evaluation dataset.

If the LLM does not improve the decision sufficiently to justify cost and complexity, the deterministic implementation should remain the production path.

---

# 12. Core LLM Feature

The preferred core LLM capability is:

> **Interpret structured security evidence and produce an evidence-grounded account intelligence decision.**

The LLM may determine:

- security-need category;
- urgency;
- semantic interpretation of combined signals;
- explanation;
- recommended sales angle;
- whether evidence is sufficient.

The LLM must not invent infrastructure facts.

Example structured output:

```json
{
  "security_need": "high",
  "urgency": "high",
  "signal": "internet_exposed_legacy_service",
  "reason": "The account shows multiple public-facing services with an outdated component and a high-severity vulnerability.",
  "evidence": [
    "observation:...",
    "cve:..."
  ],
  "recommended_action": "Prioritize security assessment outreach.",
  "confidence": 0.91,
  "abstain": false
}
```

Structured output must be schema validated.

---

# 13. Abstention

The model must be allowed to say:

```text
insufficient_evidence
```

or:

```text
abstain = true
```

The system must never manufacture confidence when evidence is weak, contradictory or missing.

---

# 14. Retrieval / RAG — Decision: Not Implemented

RAG is not implemented in this system.

Reasoning:

1. The LLM receives pre-aggregated structured account data — signals, scores, evidence — not raw observations.
2. All user query patterns (filter by domain, signal type, geography) are structured filters over DuckDB/Parquet.
3. No unstructured text corpus requires semantic search.
4. Adding a vector database without retrieval evaluation evidence would be technology signalling.

If retrieval were justified in future, the architecture would support:

```text
Account → Signal → Evidence → Source Observation
```

with hybrid BM25 + dense retrieval. But the current data model makes this unnecessary.

---

# 15. LLM Pipeline (LangChain, No LangGraph)

LangGraph was evaluated and rejected. The AI workflow is a linear pipeline with one branch point (abstain vs proceed) — not a stateful graph requiring graph compilation.

Pipeline:

```text
START
  ↓
Load Account (structured data from DuckDB/Parquet)
  ↓
Compute Deterministic Features (rules, no LLM)
  ↓
Assemble Evidence
  ↓
LLM: Analyze Security Need (LangChain structured output)
  ↓
Validation Gate
  ├── insufficient evidence → ABSTAIN
  └── sufficient evidence
            ↓
       Calculate Priority
            ↓
       Generate Sales Brief
            ↓
          END
```

LangChain components used:

- `ChatGoogleGenerativeAI` / `ChatMistralAI` — provider swap
- `ChatPromptTemplate` — prompt management
- `PydanticOutputParser` — structured output validation
- Callbacks — tracing, cost accounting
- `with_retry()` / `with_fallback()` — reliability

Each node has explicit typed inputs and outputs (Pydantic models).

---

# 16. Provider Abstraction

LLM access must use a provider abstraction.

Initial supported providers:

- Gemini;
- Mistral.

Provider choice must be based on:

- evaluation performance;
- latency;
- cost;
- structured-output reliability;
- failure rate.

The architecture must permit model replacement without rewriting business logic.

---

# 17. Model Routing

Do not use the strongest model for every request.

Preferred routing:

```text
Deterministic pre-filter
        ↓
Cheap model for straightforward classification
        ↓
Stronger model only for:
    - ambiguous cases
    - high-value accounts
    - complex evidence
```

Every routing decision must be observable.

---

# 18. Prompt Versioning

Prompts must be stored as files.

Example:

```text
prompts/
├── security_signal/
│   ├── v1.md
│   └── v2.md
└── sales_brief/
    └── v1.md
```

Every LLM trace must contain:

```text
prompt_version
model
provider
dataset_version
```

Prompt changes must be evaluated against the same labelled dataset.

---

# 19. Skills

At least one reusable versioned skill is required.

Example:

```text
skills/security-account-intelligence/SKILL.md
```

The skill must contain:

- trigger conditions;
- inputs;
- prerequisites;
- procedure;
- tools/dependencies;
- output schema;
- failure conditions;
- evaluation expectations;
- worked invocation example.

The skill must be usable by an agent rather than being generic documentation.

---

# 20. Evaluation Strategy

Evaluation is the primary quality mechanism. No external eval library (RAGAS, DeepEval) is used. Custom pytest-based evaluation with LLM-as-judge provides full control and transparency.

## Labeled Dataset

The core AI feature requires a hand-labelled evaluation set of 25-30 representative cases.

The dataset must contain:

- clear positives (high security need, obvious urgency);
- clear negatives (no meaningful signals);
- ambiguous examples (mixed signals);
- contradictory evidence;
- missing evidence;
- weak signals;
- misleading signals;
- edge cases (single observation, massive observation count);
- abstention-appropriate cases.

Each case includes:

```text
account_id
input_evidence
expected_security_need
expected_urgency
expected_priority_tier
acceptable_signals
expected_abstain
notes
```

## Classification Metrics

For security-need and urgency classification:

- Precision per class;
- Recall per class;
- F1 per class;
- Macro F1;
- Confusion matrix;
- Abstention precision and recall.

## Ranking Metrics

For account prioritization quality:

- Precision@K (are the top-K accounts truly high-priority?);
- Recall@K;
- NDCG@K;
- Spearman rank correlation vs human ranking;
- Top-K manual inspection.

## Generation Quality — LLM-as-Judge

For explanation, "why now," and sales brief quality:

```text
LLM output
    +
structured evidence (ground truth)
    +
judge prompt (versioned)
    ↓
judge LLM (separate model)
    ↓
scored rubric (1-5 per dimension)
```

Judge dimensions:

- **Groundedness** — does the explanation reference actual observed evidence?
- **Faithfulness** — does it contradict the structured signal data?
- **Actionability** — is the sales advice concrete, specific, and useful?
- **Hallucination detection** — did it invent infrastructure facts not in the input?
- **Completeness** — did it address the key signals?

Judge prompts are versioned alongside feature prompts:

```text
evals/judges/
├── groundedness_v1.md
├── faithfulness_v1.md
├── actionability_v1.md
└── hallucination_v1.md
```

## A/B Comparison Framework

Every prompt change, model change, or pipeline change is evaluated as an A/B test:

```text
Variant A                    Variant B
(prompt v1 + model A)        (prompt v2 + model B)
        │                           │
        └───────────┬───────────────┘
                    ▼
           same labelled set
                    │
                    ▼
        Metric deltas (F1, P@K, NDCG)
        Cost deltas (tokens, $)
        Latency deltas (p50, p99)
        Quality-cost Pareto analysis
        Failure case diff
        New regressions
```

Comparisons must be reproducible:

```text
make eval-compare VARIANT_A=v1/gemini VARIANT_B=v2/gemini
```

## Deterministic Baseline vs LLM

The deterministic baseline (rules only, no LLM) is always evaluated alongside LLM variants:

```text
Baseline (rules)     LLM v1     LLM v2
     │                 │          │
     └────────┬────────┘          │
              └────────┬──────────┘
                       ▼
              same labelled set
                       │
                       ▼
              comparative report
```

If the LLM does not improve metrics sufficiently to justify cost, the deterministic baseline remains the production path.

## Eval Harness

One command reproduces an evaluation:

```bash
make eval
```

The evaluation output records:

```text
eval_run_id
dataset_version
prompt_version
provider
model
code_commit
timestamp
classification_metrics
ranking_metrics
generation_scores
cost_total
latency_p50
latency_p99
failures
known_weaknesses
```

## Regression Detection

The eval harness automatically detects regressions:

```text
IF new_f1 < baseline_f1 - threshold:
    WARN: regression detected

IF new_abstention_rate > max_acceptable:
    WARN: excessive abstention

IF new_hallucination_rate > 0:
    FAIL: hallucination detected
```

Known failure modes are documented per eval run.

Example eval comparison output:

```text
security_signal:v1 + Gemini
  F1: 0.78 | P: 0.81 | R: 0.75
  Groundedness: 4.2/5 | Faithfulness: 4.5/5
  Cost: $0.003/account | Latency p50: 1.2s

vs

security_signal:v2 + Gemini
  F1: 0.86 | P: 0.84 | R: 0.88  (+0.08 F1)
  Groundedness: 4.6/5 | Faithfulness: 4.7/5
  Cost: $0.004/account | Latency p50: 1.4s
  
  Δ F1: +0.08 ✓
  Δ Cost: +$0.001/account
  New regressions: 0
  Resolved failures: 2
```

---

# 23. LLM Observability

Every LLM invocation must produce structured telemetry.

Required fields:

```text
trace_id
account_id
workflow
node
provider
model
prompt_version
request
response
input_tokens
output_tokens
latency_ms
estimated_cost
decision
confidence
status
error
timestamp
```

Sensitive information and credentials must never be logged.

JSONL or SQLite is sufficient for the assignment.

---

# 24. Cost Model

The system must estimate:

```text
cost / account
cost / 1,000 accounts
cost / 10,000 accounts
daily cost
monthly cost
```

Cost calculation must consider:

```text
input_tokens
×
output_tokens
×
model pricing
×
request volume
```

The production strategy must include a cost ceiling.

---

# 25. Reliability

LLM/API calls must support:

- timeout;
- bounded retry;
- exponential backoff;
- structured error handling;
- provider fallback where appropriate;
- rate-limit handling;
- output validation.

Failures must remain visible in traces.

---

# 26. Caching / Idempotency

LLM analysis should be cacheable.

A cache key should incorporate relevant versions such as:

```text
account_id
input_hash
prompt_version
model
dataset_version
```

Changing the prompt or model must invalidate the corresponding result.

---

# 27. Security

Required:

- secrets through environment variables;
- `.env.example`;
- secret scanning;
- dependency security checks;
- input validation;
- structured output validation;
- log redaction;
- safe handling of untrusted dataset text;
- prompt-injection awareness;
- no client-side API keys.

Dataset text must be treated as untrusted input.

---

# 28. Testing Strategy

### Unit tests

- normalization;
- validation;
- signal extraction;
- scoring;
- ranking;
- cost calculation.

### Contract tests

- Pydantic schemas;
- LLM structured output;
- API contracts.

### Integration tests

- ingestion;
- transformation;
- evidence retrieval;
- persistence;
- LLM pipeline (LangChain).

### End-to-end

At least one complete:

```text
dataset fixture
→ account
→ signals
→ evidence
→ score
→ API
→ UI
```

### AI evaluation

AI evaluation remains separate from ordinary deterministic unit tests.

---

# 29. Quality Gates

Local:

```bash
make test
make lint
make format
make typecheck
make verify
make eval
```

Recommended verification:

```text
pytest
Ruff check
Ruff format --check
type checking
security checks
build
```

No feature is complete while the relevant quality gates are failing.

---

# 30. CI/CD

GitHub Actions should provide separate workflows for:

### CI

- dependency validation;
- lint;
- formatting;
- type checking;
- tests;
- security checks;
- build.

### Evaluation

Manual or scheduled.

Do not make expensive LLM evaluations mandatory on every pull request.

### CD

```text
main
 ↓
quality gates
 ↓
build
 ↓
deploy
 ↓
smoke test
```

Deployment failures must fail visibly.

---

# 31. Developer Interface

Use `uv` for Python environment and dependency management.

Expected commands:

```bash
make ingest
make test
make lint
make format
make typecheck
make verify
make eval
make run
```

The project must work from a clean clone.

---

# 32. Git Discipline

Use Conventional Commits.

Examples:

```text
chore: bootstrap uv project
test(data): define account contract
feat(data): add streaming ingestion
test(signals): define security signal behavior
feat(signals): implement deterministic signal extraction
feat(scoring): add account ranking baseline
feat(ai): add structured signal classifier
test(eval): add labelled evaluation set
feat(eval): add evaluation harness
feat(obs): add llm tracing
feat(cost): add token cost accounting
feat(api): expose account prioritization
feat(ui): add prospect prioritization workflow
ci: add repository quality gates
ci: add deployment workflow
docs: document architecture decisions
```

Commits should be:

- atomic;
- meaningful;
- green;
- independently understandable.

Push progressively.

Do not create meaningless one-line commits solely to inflate commit count.

---

# 33. Agentic Development Protocol

Every development agent must:

1. Read `SPEC.md`.
2. Read `memory.md`.
3. Inspect Git status and branch.
4. Identify the current milestone.
5. Read relevant existing code/tests before changing anything.
6. Define the smallest testable task.
7. Write/update the test first where practical.
8. Implement the smallest correct change.
9. Run quality gates.
10. Update `memory.md`.
11. Commit atomically.
12. Push.
13. Continue only after the repository is in a known state.

Agents must not:

- rewrite unrelated code;
- silently change architecture;
- commit secrets;
- skip failing tests;
- claim unfinished work is complete;
- introduce dependencies without justification.

---

# 34. Development Milestones

## M0 — Repository Foundation

- uv;
- project structure;
- Ruff;
- type checking;
- pytest;
- Makefile;
- GitHub CI;
- memory.md.

## M1 — Dataset Archaeology

- stream sample;
- profile schema;
- measure distributions;
- inspect identity fields;
- determine account aggregation strategy;
- record dataset manifest.

## M2 — Deterministic Intelligence

- canonical model;
- normalization;
- account aggregation;
- security signals;
- baseline scoring.

## M3 — AI Intelligence

- labelled evaluation set;
- prompt v1;
- structured LLM classifier;
- provider abstraction;
- LLM pipeline (LangChain);
- abstention.

## M4 — Evidence / Retrieval

Only if dataset analysis demonstrates value.

- evidence model;
- retrieval;
- retrieval evaluation;
- provenance.

## M5 — Evaluation

- baseline;
- LLM v1;
- prompt v2;
- regression comparison;
- known failure analysis.

## M6 — Product

- API;
- prioritization UI;
- filters;
- account detail;
- evidence;
- recommended action.

## M7 — Productionisation

- observability;
- cost model;
- security;
- CI/CD;
- deployment;
- smoke tests.

## M8 — Final Review

Perform a fresh-clone simulation:

```text
clone
→ uv sync
→ configure environment
→ tests
→ ingest fixture
→ eval
→ run
→ inspect UI
```

No undocumented manual steps should remain.

---

# 35. Scope Boundaries

The assignment does not require:

- CRM replacement;
- autonomous email sending;
- Kubernetes;
- Kafka;
- real-time distributed streaming infrastructure;
- multi-tenant authentication;
- complex user management;
- autonomous web crawling;
- unnecessary graph databases;
- unnecessary vector databases.

Technology should only be introduced when justified by the dataset or product requirement.

---

# 36. Product Success Metrics

The prototype should measure:

- precision of high-priority accounts;
- percentage of ranked accounts with supporting evidence;
- actionable signals per account;
- percentage of accounts requiring human review;
- retrieval quality where applicable;
- scoring latency;
- AI latency;
- AI cost/account;
- time required to identify a useful prospect shortlist.

The central product metric is:

> **Can a salesperson identify and understand high-value cybersecurity prospects faster than by inspecting raw company/infrastructure data manually?**

---

# 37. Final Acceptance Criteria

The project is complete when:

- the supplied dataset can be processed without full decompression;
- ingestion is reproducible;
- raw observations become account-level intelligence;
- scoring is explainable;
- security signals are evidence-backed;
- the AI feature is evaluated;
- prompt/model versions are traceable;
- every LLM call is observable;
- cost is measurable;
- abstention is supported;
- tests and quality gates pass;
- CI is operational;
- the application is hosted;
- a salesperson can understand WHO, WHY and WHY NOW;
- documentation explains architectural trade-offs;
- a fresh clone can reproduce the project.
