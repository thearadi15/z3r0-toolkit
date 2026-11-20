# Implementation Roadmap

## Status

- **Audit:** completed as a static review of the local workspace and the linked GitHub repository.
- **Implementation:** bounded slices from Phases 1–9 are present in this
  subproject. This does not mean every phase or its acceptance criteria are
  complete.
- **Still open:** PostgreSQL migration/restart acceptance; HTTP transport
  address pinning and real-browser egress validation; live advisory and source
  ingestion; differential authenticated research; PoC execution (intentionally
  absent); dashboard; and isolated execution/fuzzing workers.
- **Repository integration:** the original shell toolkit remains at the
  repository root. This Python application is additive under `platform/`.

The progress notes below record implementation slices and their historical
acceptance criteria. A feature being present is not evidence that its full
acceptance gate has passed.

## Prioritization

The specification is broad. Implement a small, controlled end-to-end vertical slice before adding additional agents or integrations. The first release should import existing outputs and demonstrate durable scope, evidence, budget and audit behavior; it should not claim autonomous vulnerability discovery.

### Phase 0 — Audit and decisions (complete)

**Deliverables:** `ARCHITECTURE_AUDIT.md`, `EXISTING_COMPONENTS.md`, `INTEGRATION_MAP.md`, this roadmap, `TECHNICAL_DECISIONS.md`.

**Gate:** agree on the local repository baseline and initial safety boundary before platform code begins.

### Phase 1 — Repository foundation and control plane

**Deliver:** establish an actual source checkout; Python package/API skeleton; configuration and migrations; project/scope/task/budget/audit entities; test and CI baseline.

**Progress (2026-11-16):** A new Python package, single-operator local API skeleton, SQLAlchemy entities, initial Alembic migration, scope/policy service, project-level budget and iteration reservations, persisted approvals (including revocation), and offline tests are implemented. No active worker, LLM integration, or shell execution is included. The actual legacy source checkout, PostgreSQL integration test, and multi-level budget accounting remain pending; this phase is not yet complete.

**Acceptance gate:**
- A project cannot start without explicit scope records and an owner.
- Scope normalization and matching tests cover host suffix tricks, ports, schemes, IP literals, redirects and DNS changes.
- Task state and audit history survive process restart.
- Budget accounting is deterministic and rejects an over-budget action before execution.
- No model or worker can bypass the policy gateway.

**Do not yet:** connect live autonomous execution, store production credentials or enable the current rate-limit stage.

### Phase 2 — Evidence and legacy-output importer

**Deliver:** immutable artifact references and digests; parsers for recon, JS, parameter, API, secret-scan and Nuclei outputs; schema versioning; idempotent import; partial/failure coverage.

**Progress (2026-11-17):** Version-1 JSON import now persists source metadata,
normalized post-redaction digests, observations, import identity, explicit run
status and coverage notes. Common credential fields, URL userinfo, selected
query values, and token-like authorization values are redacted before persistence. Identical
normalized payloads are deduplicated per project. The typed generic importer
and SQLite migration upgrade/downgrade passed local tests. The generic import
path does not independently verify operator-supplied provenance. PostgreSQL
acceptance remains open.

**Parser progress (2026-11-17):** Bounded offline adapters now parse Nuclei
JSONL alerts and OpenAPI 3 JSON declarations into the common evidence model.
The adapters retain source-text digests, cap inputs at 2 MiB and parsed output
at 1,000 observations, omit Nuclei request/response/command fields, and do not
dereference OpenAPI references or contact their declared servers. Imported
scanner alerts remain candidates. Targeted parser tests and the full suite pass
(30 tests total); these adapters do not execute either source tool.

**Acceptance gate:**
- Fixture-based tests prove imported entities retain original provenance and hashes.
- Re-import creates no duplicate entities but preserves separate observations.
- Invalid records and secrets are handled explicitly and safely.
- A partial legacy run cannot be represented as a complete successful run.

### Phase 3 — Bounded supervisor and hypothesis lifecycle

**Deliver:** persistent state machine, task planner interface, bounded iteration/budget controls, hypothesis and observation models, stop/pause/resume and human approval queue. Use a provider interface and deterministic/mock implementation in tests; add LangGraph only if it materially supports checkpointing and transitions.

**Progress (2026-11-17):** Supervisor lifecycle, hypothesis/evidence links, proposal review, bounded investigation budgets/iterations, state-transition rules, audit events, API routes, migration, and focused tests are implemented. Live execution and model-provider integration remain disabled.

**Acceptance gate:**
- A supervisor proposal is data, never executable code.
- Every proposed action references scope, rationale, budget and evidence.
- Hypotheses include supporting and contradictory observations and retain failed history.
- State transitions, retries and approvals are tested deterministically.

### Phase 4 — Intelligent reconnaissance and endpoint intelligence

**Deliver:** normalized assets/services/technologies/endpoints; provenance-preserving import; endpoint de-duplication and relationships; prioritization based on evidence; controlled integration for selected legacy tools.

**Progress (2026-11-18):** Added project-scoped offline asset and endpoint projections derived only from imported evidence. The rebuild API consolidates duplicate URLs, retains observation links, excludes out-of-scope URLs, separates OpenAPI origin-declared-from-undeclared endpoints, and assigns deterministic evidence-based priority scores. It performs no DNS, HTTP, browser, or shell action.

**Acceptance gate:**
- Duplicate endpoint identities retain distinct methods, parameter shapes and provenance.
- Tool/version/coverage gaps are visible.
- Active discovery is disabled unless scope, rate, concurrency, timeout and operator approval are valid.
- Recon clues can queue a justified next task without expanding scope.

### Phase 5 — Safe HTTP and browser research

**Deliver:** HTTPX request/response evidence; cURL import/export; isolated Playwright contexts; approved test identities; credential references; redaction and request/redirect policy hooks.

**Progress (2026-11-18):** Added an HTTPX execution gateway and cURL export for authorized `http_request` tasks. Requests are rechecked against active scope and valid approval, iteration counts are bounded, redirects are blocked, DNS answers are screened for private/reserved addresses, loopback is opt-in, response bytes are truncated at a configured limit, credentials/transport headers are rejected, and response data is digest-preserved. Browser automation and credential-reference contexts remain not implemented.

**Progress (2026-11-18):** Completed the HTTPX/cURL gateway and added a bounded Playwright browser gateway. Browser scenarios require authorized `browser_action` tasks, approved navigation targets, active scope, and valid approval. Request routes and navigation must remain in scope; loopback is opt-in; scenarios are limited to ten actions; text entry is resolved only from named environment references; raw credential payloads are rejected; and browser outcomes/actions are persisted. Real Playwright execution is lazy and returns explicit setup/unavailable errors; deterministic tests use an injected mock browser driver.

**Acceptance gate:**
- Egress tests prove out-of-scope hosts, resolved IPs and redirect destinations are blocked.
- Credentials never enter model prompts or ordinary logs.
- Each request/action is reproducible and linked to task, scope, hypothesis and identity.
- Requests, browser actions, time, bytes and concurrency are bounded; stop conditions halt workers.
- Tests use local mock services and controlled vulnerable applications.

### Phase 6 — Evidence-led vulnerability research and validation

**Deliver:** hypothesis generation from observations, differential authorized-identity comparison, business-logic research workflow, independent validation, novelty lookup and explicit candidate/verified/rejected states.

**Progress (2026-11-19):** Added a persisted finding-candidate lifecycle and independent-validation records. Candidates begin unconfirmed and link to owned observations. Independent validators can record confirmed, rejected, or inconclusive verdicts plus supporting/contradicting evidence and reproducibility. Human review cannot mark a finding validated without reproducible independent confirmed evidence; rejected and inconclusive states remain evidence-preserving. No PoC execution or live validation action is implemented.

**Acceptance gate:**
- Status codes alone cannot create a confirmed finding.
- Validators have independent evidence and can reject the originating hypothesis.
- Findings require reproducibility, impact evidence, scope approval and human review.
- Failed hypotheses and contradictory evidence remain queryable.

### Phase 7 — CVE, source and patch research

**Deliver:** advisory/dependency correlation, repository ingestion, static-analysis leads, patch-diff analysis, local isolated reproduction, provenance for external intelligence.

**Progress (2026-11-19):** Added persisted advisory correlations and source claims with retrieval/source digests, revision/path/range facts, and candidate status. No external advisory API or repository ingestion is invoked. Reproduction records remain modeled with explicit isolation and limits; execution requires separate implementation and approval.

**Acceptance gate:**
- Version matches are candidates, not confirmations.
- External source/advisory identity and retrieval time are recorded.
- Source-to-sink and patch claims cite code ranges and tests.
- Reproduction is isolated and resource limited.

### Phase 8 — Controlled PoCs, reports and dashboard

**Deliver:** safe PoC formats limited to approved labs/targets, report generation from verified evidence, severity rationale, review workflow, dashboard for projects, endpoints, hypotheses, evidence and audit.

**Progress (2026-11-19):** Added draft-only safe-PoC templates restricted to validated findings and normalized approved targets. Templates and reports persist for human review; no PoC execution endpoint or capability exists.

**Acceptance gate:**
- Generated PoCs are reviewed, minimal and reproducible; execution stays within approved scope.
- Reports distinguish observations, hypotheses and validated findings.
- Report claims link to source evidence and disclose limitations.
- Sensitive data is redacted by default.

### Phase 9 — Fuzzing and research optimization

**Deliver:** isolated fuzzing workers, corpora/crash triage, regression cases, analytics, model cost/quality evaluation and memory retrieval tuning.

**Progress (2026-11-19):** Added persisted research profiles with CPU, memory, wall-time, process and storage limits. Profiles remain inactive and worker-enabled=false; no fuzzing process, corpus, or crash-triage worker is implemented.

**Acceptance gate:**
- CPU, memory, wall-time, process and storage limits are enforced.
- Crashes are not labeled vulnerabilities without security impact validation.
- Benchmarks measure discovery, validation and independent reproduction separately.

## Current acceptance checklist

| Work item | Status |
|---|---|
| Static architecture audit and phased roadmap | Complete |
| Project/scope/task/budget/approval control plane | Implemented; PostgreSQL and durable restart acceptance open |
| Generic evidence and Nuclei/OpenAPI offline import | Implemented; additional legacy-output adapters remain open |
| Investigation/hypothesis lifecycle and offline endpoint intelligence | Implemented as bounded persistence/derivation slices |
| HTTPX and cURL gateway | Implemented, but DNS answer screening is not transport-pinned; do not treat as secure egress enforcement |
| Playwright scenario gateway | Implemented, but real-browser egress guarantees need dedicated end-to-end testing |
| Finding candidate, independent validation, and human review | Implemented as evidence/persistence workflow; no autonomous validation action |
| Advisory/source/reproduction/report/PoC/profile records | Implemented as metadata-only or draft-only workflows |
| Live advisory feeds and repository ingestion | Not implemented |
| PoC execution and fuzzing workers | Not implemented |
| Isolated worker runtime and enforcement | Not implemented; profiles are inactive |
| Production dashboard and multi-user identity | Not implemented |
