# Firmable AI Sales Intelligence Platform — Project Plan

**Repository:** `firmable-ai-sales-intelligence`  
**Status:** Initial implementation plan

# Engineering Persona & Operating Mode

Act as a **Principal Data Engineer + AI Systems Architect + Staff-level Product Engineer** building this assignment as if it were a small production system that could be handed to another engineering team.

Optimize for **engineering judgment, measurable product value, correctness, reproducibility, simplicity, and operational quality** — not technology count.

Before implementing any technology, ask:

1. Does the dataset require it?
2. Does the salesperson workflow benefit from it?
3. Can its value be measured?
4. What is the simplest reliable alternative?
5. What operational, cost, or failure-mode trade-off does it introduce?

Prefer deterministic systems for deterministic facts and probabilistic systems only where semantic reasoning provides measurable value.

Work in an evidence-driven loop:

**inspect → hypothesize → test → implement → evaluate → observe → document → commit → push.**

Never fabricate completeness, metrics, architectural justification, or business value. When evidence is insufficient, explicitly record the uncertainty and investigate it.


---

# 1. Objective

Build a small but production-minded sales intelligence platform that transforms Internet infrastructure observations into a ranked list of cybersecurity prospects.

The system should help a salesperson answer:

1. **Who should I target?**
2. **Why this company?**
3. **Why now?**
4. **What evidence supports the recommendation?**
5. **What should I do next?**

---

# 2. Product Hypothesis

The dataset contains infrastructure-level observations that can expose meaningful cybersecurity buying signals.

Examples include:

- exposed services;
- vulnerable software;
- critical CVEs;
- outdated/EOL products;
- cloud infrastructure;
- exposed administrative interfaces;
- unusual service configurations;
- combinations of multiple weak signals.

The central hypothesis is:

> **Aggregating multiple infrastructure observations into account-level security signals can identify more actionable cybersecurity prospects than generic firmographic filtering alone.**

The hypothesis must be tested rather than assumed.

---

# 3. Research Phase

Before implementation, research how B2B sales teams prioritize accounts.

Focus areas:

- Ideal Customer Profile (ICP);
- account-based prospecting;
- account scoring;
- buying signals;
- intent signals;
- territory segmentation;
- prioritization;
- sales qualification;
- timing/urgency;
- evidence required before outreach.

The research should be summarized in this document with sources.

The research must directly influence product decisions.

Avoid implementing sales concepts merely because they are common terminology.

---

# 4. Dataset Archaeology

First implementation milestone is dataset understanding.

Questions to answer:

### Scale

- actual record count;
- record throughput;
- average record size;
- compressed/uncompressed characteristics.

### Schema

- field frequency;
- nested structures;
- nullability;
- schema variants.

### Identity

- uniqueness of IP;
- hostname/domain relationships;
- organization consistency;
- ASN relationships;
- cloud-provider relationships.

### Security

- vulnerability prevalence;
- CVSS distribution;
- service distribution;
- EOL prevalence;
- certificate issues;
- risky exposed services.

### Sales relevance

Determine which observable combinations could plausibly represent cybersecurity demand.

No final scoring formula should be selected before this phase.

---

# 5. Data Pipeline Plan

Implement:

```text
.zst
 ↓
Streaming decompression
 ↓
NDJSON parsing
 ↓
Validation
 ↓
Normalization
 ↓
Bounded batches
 ↓
Account/entity aggregation
 ↓
Compact analytical storage
```

The full dataset must never be fully decompressed to local disk.

Use small fixtures for tests.

---

# 6. Account Construction

The fundamental transformation is:

```text
Observation → Identity → Organization → Account
```

Potential identity keys:

- domain;
- hostname;
- organization;
- ASN;
- IP relationships;
- cloud infrastructure.

The exact entity-resolution approach must be selected after profiling.

Conflicting identity evidence should be preserved rather than silently merged.

---

# 7. Deterministic Baseline

Before adding AI:

1. normalize observations;
2. aggregate observations;
3. generate security signals;
4. calculate an explainable score;
5. rank accounts.

This becomes the baseline against which AI improvements are evaluated.

---

# 8. Signal Discovery

Investigate:

### High-confidence signals

- critical CVE;
- high CVE concentration;
- EOL software;
- exposed administrative service;
- exposed database;
- risky port;
- weak security configuration.

### Composite signals

Examples:

```text
cloud infrastructure
+
exposed service
+
known vulnerability
```

or:

```text
large exposed surface
+
multiple products
+
security-sensitive services
```

Composite signals should be evaluated for whether they provide additional information beyond their individual components.

---

# 9. AI Decision

Only introduce an LLM where deterministic logic is insufficient.

Likely use case:

> Interpret multiple security observations and produce an evidence-grounded security-need and urgency assessment.

The LLM should not be used for:

- basic filtering;
- arithmetic;
- CVSS calculation;
- deterministic rule matching;
- database queries.

---

# 10. AI Evaluation

Create approximately 20–30 manually labelled cases.

Include:

- positive;
- negative;
- ambiguous;
- missing evidence;
- contradictory;
- misleading;
- edge cases.

Compare:

```text
Deterministic baseline
LLM v1
LLM v2
```

No prompt improvement should be accepted without measurable evaluation.

---

# 11. Evidence Architecture

Every AI decision should be traceable back to evidence.

Example:

```text
Account
  ↓
Signal
  ↓
Evidence
  ↓
Source Observation
```

The UI should allow the salesperson to inspect evidence supporting a recommendation.

---

# 12. RAG Decision

RAG is **not implemented**.

Decision rationale:

1. The LLM receives pre-aggregated structured account data directly.
2. All query patterns are structured filters over DuckDB/Parquet.
3. No unstructured text corpus requires semantic search.
4. Adding retrieval infrastructure without evidence it improves the workflow violates the project's evidence-first principle.

This is a legitimate engineering decision. If future profiling reveals retrieval value, the architecture can accommodate it.

---

# 13. Product Workflow

### Screen 1 — Prospect Prioritization

Show:

- priority;
- account;
- key security signals;
- urgency;
- evidence confidence;
- filters.

### Screen 2 — Account Detail

Show:

- score breakdown;
- infrastructure summary;
- security signals;
- evidence;
- why this account;
- why now;
- recommended next action.

Keep the interface focused.

---

# 14. Development Workflow

Every feature follows:

```text
Requirement
 ↓
Test
 ↓
Implementation
 ↓
Observability
 ↓
Evaluation if AI
 ↓
Documentation
 ↓
Quality gates
 ↓
memory.md
 ↓
Atomic commit
 ↓
Push
```

---

# 15. Initial Micro-Commit Sequence

```text
chore: bootstrap uv project

chore: establish repository quality gates

test(data): define canonical observation contract

feat(data): add streaming dataset reader

test(data): add malformed record handling

feat(data): add record normalization

feat(data): add dataset profiling

docs: add dataset manifest and findings

test(identity): define account aggregation behavior

feat(identity): implement account aggregation

test(signals): define security signal behavior

feat(signals): implement deterministic signals

test(scoring): define account ranking behavior

feat(scoring): implement baseline ranking

test(eval): add labelled evaluation set

feat(eval): add baseline evaluator

feat(eval): add LLM-as-judge evaluation

feat(eval): add A/B comparison framework

feat(ai): add provider abstraction

feat(ai): add structured signal analysis

feat(ai): add prompt versioning

feat(obs): add LLM trace logging

feat(cost): add token cost accounting

feat(api): add prioritization API

feat(ui): add prospect prioritization UI

ci: add evaluation workflow

ci: add deployment workflow

docs: add architecture decisions

docs: add final build reflection
```

The sequence may change as dataset findings change the architecture.

---

# 16. Milestone Gates

## M0

Repository foundation works.

```text
uv sync
make verify
```

passes.

## M1

Dataset can be streamed and profiled without full decompression.

## M2

Deterministic account-level ranking works.

## M3

AI feature demonstrably adds value over baseline. A/B comparison documented.

## M4

Evaluation is comprehensive. LLM-as-judge, A/B comparison, regression detection all operational.

## M5

Cost model documented. Quality-cost Pareto analysis complete.

## M6

Salesperson-facing workflow works.

## M7

Hosted application, CI/CD, security and observability work.

## M8

Fresh-clone and reviewer simulation passes.

---

# 17. Definition of Done

A feature is not done when the code runs.

It is done when:

```text
Requirement
✓
Test
✓
Implementation
✓
Quality gates
✓
Observability
✓
Evaluation where applicable
✓
Documentation
✓
memory.md
✓
Atomic commit
✓
Push
✓
```

---

# 18. Scope Control

Explicitly avoid building:

- CRM functionality;
- autonomous outreach;
- unnecessary infrastructure;
- unnecessary distributed systems;
- unnecessary databases;
- unvalidated ML scoring;
- LLM calls over millions of records.

The goal is **high engineering signal per unit of complexity**.

---

# 19. Final Demonstration

The final demo should tell one coherent story:

```text
Thousands/millions of raw observations
              ↓
       Account aggregation
              ↓
       Security signals
              ↓
        Priority ranking
              ↓
     Evidence-backed account
              ↓
           Why now?
              ↓
       Sales next action
```

The demo should make it immediately obvious why the product is useful to a salesperson.

---

# 20. Final Review Checklist

### Data

- [ ] Full dataset processed through streaming
- [ ] Dataset manifest recorded
- [ ] Schema profiled
- [ ] Data quality measured

### Intelligence

- [ ] Account aggregation
- [ ] Security signals
- [ ] Deterministic baseline
- [ ] Explainable scoring

### AI

- [ ] Reusable SKILL.md
- [ ] Versioned prompts
- [ ] Labelled eval set (25-30 cases)
- [ ] Classification metrics (P/R/F1)
- [ ] Ranking metrics (NDCG@K, P@K)
- [ ] LLM-as-judge (groundedness, faithfulness, actionability)
- [ ] A/B comparison framework
- [ ] Regression detection
- [ ] LLM traces
- [ ] Cost model
- [ ] Abstention

### Product

- [ ] Prioritization
- [ ] Filtering
- [ ] Account detail
- [ ] Evidence
- [ ] Why now
- [ ] Recommended action

### Engineering

- [ ] Tests
- [ ] Ruff
- [ ] Type checking
- [ ] Security checks
- [ ] CI
- [ ] CD
- [ ] Deployment
- [ ] Fresh-clone verification

### Documentation

- [ ] PLAN.md
- [ ] ARCHITECTURE.md
- [ ] SPEC.md
- [ ] memory.md
- [ ] COST_MODEL.md
- [ ] EVAL_REPORT.md
- [ ] HOW_I_BUILD.md
