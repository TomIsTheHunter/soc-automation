# SOC Automation Platform

An automation-first SOC workflow: ingest a synthetic security alert, enrich its indicators, apply explainable deterministic triage, and layer in bounded, validated AI-assisted investigation &mdash; with an analyst-facing demo view that makes every trust boundary visible, structured logs that make every alert traceable, and health/readiness checks that make degraded operation observable.

[![CI](https://github.com/TomIsTheHunter/soc-automation/actions/workflows/ci.yml/badge.svg)](https://github.com/TomIsTheHunter/soc-automation/actions/workflows/ci.yml)

> **This is a portfolio implementation using synthetic alerts and mock providers to demonstrate the architecture and engineering controls of a SOC automation platform &mdash; it is not production software.** See ["What Is Deliberately Mocked / Simulated"](#what-is-deliberately-mocked--simulated) and ["What Production Deployment Would Require"](#what-production-deployment-would-require) below for the honest boundary between the two.

## What Problem This Solves

SOC analysts are flooded with endpoint alerts. Most of the triage work is repetitive: pull the indicators, check if they're known-bad, decide whether this is worth a human's time. Doing that by hand at volume is slow and inconsistent; doing it with an opaque black box is dangerous. This project demonstrates a middle path:

- **Deterministic, explainable triage** handles the actual security decision, so the same evidence always produces the same, auditable outcome.
- **Enrichment is treated as fallible** external data, not ground truth &mdash; if it's unavailable, the system fails closed to analyst review rather than guessing.
- **AI assists the analyst**, summarizing evidence and suggesting investigation steps, but it is structurally incapable of closing an alert, overriding triage, or executing anything.
- **Every stage is auditable**: a processing history and structured, correlated logs show exactly what happened, and the demo UI never hides a degraded state behind a generic "success" screen.

This repository processes a **CrowdStrike-style synthetic alert**. It is not an official CrowdStrike schema, proprietary telemetry, real CrowdStrike data, or a production integration.

## What It Demonstrates

- FastAPI security alert ingestion with a bounded (256 KiB) request size limit
- Pydantic v2 validation at every boundary (severity enum, `IPvAnyAddress`, UTC-aware timestamps)
- Vendor-independent normalization behind a dedicated source adapter
- Indicator extraction (IPs, hashes) with source-field context
- An `EnrichmentProvider` abstraction with a deterministic mock and a documented lookup table
- Deterministic, precedence-ordered triage (first-match-wins rules, fully explainable)
- Bounded AI-assisted investigation behind an `InvestigationAssistant` abstraction, with an explicit failure/retry model (see [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md))
- Structured AI output validation (`extra="forbid"`, schema versioning, controlled vocabularies)
- Policy controls: vocabulary constraints, a keyword denylist, and an evidence-grounding check
- Safe failure handling for enrichment and AI failures, always failing closed to analyst review
- A server-rendered analyst investigation view reusing the exact same pipeline as the API
- Centralized, typed configuration (`pydantic-settings`) with a documented missing/invalid-value policy per setting (see [docs/configuration.md](docs/configuration.md))
- Structured JSON logging with end-to-end `alert_id` correlation, explicit degraded-mode signaling, and a `/health/ready` readiness check separate from liveness (see [docs/operations.md](docs/operations.md))
- Automated testing (unit, API, frontend, failure-path, and one full end-to-end integration test) &mdash; 104 tests, enforced offline via `pytest-socket`
- CI workflow for lint, type checks, tests, dependency vulnerability audit, a full-history secret scan, and a Docker build check

## Architecture

```
Synthetic Alert
      │
      ▼
FastAPI Ingestion
      │
      ▼
  Validation
      │
      ▼
 Source Adapter
      │
      ▼
Normalized Alert
      │
      ▼
Indicator Extraction
      │
      ▼
   Enrichment
      │
      ▼
Deterministic Triage
      │
      ├──────────────────┐
      │                  │
      ▼                  ▼
Investigation       Authoritative
   Context             Decision
      │
      ▼
 AI Assistant
      │
      ▼
Schema Validation
      │
      ▼
Policy Validation
      │
      ▼
AI-Assisted Analysis
      │
      ▼
Analyst Review
```

See [docs/architecture.md](docs/architecture.md) for components, trust boundaries, and failure behavior, [docs/ai-security-design.md](docs/ai-security-design.md) for the full AI threat model, and [docs/operations.md](docs/operations.md) for running the service, health/readiness behavior, structured logging, and troubleshooting.

## Why Deterministic Triage + AI, Not AI Alone

The triage engine (`app/triage/engine.py`) is a small set of explicit, precedence-ordered, first-match-wins rules &mdash; not a model. That is a deliberate choice, not a limitation to be fixed later:

- **Reproducibility**: the same evidence always produces the same decision. That is a hard requirement for a security control that gates escalation, not a nice-to-have.
- **Inspectability**: every decision carries `rules_triggered` and a `reason` string generated by the rule that actually fired &mdash; an analyst (or an auditor) can see exactly why, not just what.
- **No prompt-injection surface on the decision itself**: the triage engine never sees raw model output, so it cannot be manipulated by anything an AI provider (or an attacker influencing that provider) returns.

AI is layered on *top* of that decision, never inside it: `AIAssistedAnalysis.decision_authority` is a fixed `"DETERMINISTIC"` literal, and no code path can assign an AI-derived value to `triage.decision`. The AI's role is bounded to summarizing evidence, suggesting investigation steps from a fixed controlled vocabulary, and flagging when its own risk assessment disagrees with the deterministic decision (`conflicts_with_triage`) &mdash; disagreement is surfaced to an analyst, never auto-resolved by trusting either side. This is why the project is described as "AI-assisted", not "AI-driven": the AI can make an analyst faster, but it cannot make the security decision or take any action.

## Failure Handling & Resilience

Every external/fallible dependency degrades explicitly and observably rather than guessing or crashing. Full detail lives in [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md) (the failure model and retry strategy) and [docs/operations.md](docs/operations.md) (how this looks in logs and health checks) &mdash; summarized here:

- **Enrichment failure** (declared or unexpected) &rarr; the alert and indicators are preserved, enrichment is marked unavailable, and deterministic triage's Rule B routes to `ANALYST_REVIEW`. It never fabricates malicious *or* benign evidence.
- **AI timeout** &rarr; enforced with `asyncio.wait_for` at the call site (`AI_PROVIDER_TIMEOUT_SECONDS`, default 8s), independent of whatever the provider's own SDK is doing internally.
- **AI transient failures** (rate-limited, connection error, 5xx) &rarr; bounded, exponential-backoff retry delegated to the Anthropic SDK's own tested policy (`AI_LIVE_MAX_RETRIES`, default 2), not re-implemented by this application.
- **AI non-transient failures** (auth/permission, invalid request) &rarr; never retried; classified and logged distinctly so an operator can tell *why* a call failed.
- **Invalid/malformed AI output** &rarr; rejected by independent schema and policy validation (`app/investigation/validation.py`) before it can become part of the response; `ai_assisted_analysis.status="rejected"` with a specific `rejection_reason`.
- **Any AI failure or rejection** &rarr; `ai_assisted_analysis.status` becomes `unavailable`/`rejected`, `analyst_review_required` becomes `true`, and `triage.decision` is completely unaffected &mdash; it was already computed before the AI was ever called.
- **Degraded, never silently absent**: every degradation emits a structured `provider_degraded` log event (`event`, `provider`, `result`, `error_type`), and `/health/ready` reports `degraded` (still HTTP `200`) when the AI provider is unavailable &mdash; see [docs/operations.md](docs/operations.md).

## Security Design Principles

- **Deterministic authority**: `triage.decision` is produced by explicit, precedence-ordered rules and is never changed by AI output.
- **AI is advisory**: the investigation assistant summarizes, organizes evidence, and suggests investigation steps &mdash; it cannot execute or authorize any security action.
- **Structured AI output**: AI output is parsed into a strict, `extra="forbid"` Pydantic schema with a `schema_version` before it is trusted at all.
- **Policy validation**: prohibited actions are rejected via a controlled action vocabulary, a keyword denylist, and an evidence-grounding check.
- **Untrusted input**: alert content (including AI-facing fields) is always treated as untrusted telemetry, never as instructions.
- **Safe dependency failure**: enrichment and AI failures never crash the workflow and never fail open to `ESCALATE` or `LOW_RISK`.
- **Auditability**: every processing stage that actually ran is recorded with a UTC timestamp and a correlated `alert_id` in structured logs, and the demo UI renders exactly that history &mdash; nothing fabricated.
- **Testing**: failure paths (provider unavailable, timeout, malformed output, policy violations, ungrounded evidence) are tested as thoroughly as the happy path.
- **Repository hygiene**: CI runs a full-history secret scan (gitleaks) and a dependency vulnerability audit (`pip-audit`) before merge.

## Running Locally

**Prerequisites**: Python 3.12+, [`uv`](https://docs.astral.sh/uv/) (recommended) or plain `pip`.

The commands below use `make` (see [Makefile](Makefile)). `make` is not preinstalled on plain Windows PowerShell &mdash; if you don't have it (e.g. via Git Bash, WSL, or `choco install make`), each `make <target>` below has an equivalent raw command shown alongside it; both were verified directly for this release.

### Installation

```bash
uv sync --extra dev
```

If `uv` is unavailable, the fallback (used during parts of this project's own development) is:

```bash
python -m pip install -e ".[dev]"
```

### Backend + Frontend

The analyst demo view is served by the same FastAPI process &mdash; there is no separate frontend build step or process to start:

```bash
make run
# equivalent: uvicorn app.main:app --reload
```

The app is available at `http://127.0.0.1:8000`:

- `/` &mdash; demo scenario picker
- `/demo/{scenario_name}` &mdash; the analyst investigation view for one scenario
- `/docs` &mdash; interactive OpenAPI docs for `POST /api/v1/alerts`
- `/health` &mdash; liveness check (always `{"status": "ok"}` if the process is up)
- `/health/ready` &mdash; readiness check (`healthy`/`degraded`; see [docs/operations.md](docs/operations.md))

### Tests

```bash
make test
# equivalent: python -m pytest
```

### Linting / Type Checks

```bash
make lint
# equivalent: ruff check . && ruff format --check .
make typecheck
# equivalent: mypy app tests
```

### Dependency audit

```bash
make audit
# equivalent: uv export --extra dev --no-hashes -o requirements-audit.txt && pip-audit -r requirements-audit.txt
```

### Docker

```bash
docker build -t soc-automation .
docker run -p 8000:8000 soc-automation
```

Provided for local reproducibility, not as a production deployment artifact (no orchestration, health-probe wiring, or secrets management is configured) &mdash; see ["What Production Deployment Would Require"](#what-production-deployment-would-require).

### Demo

With the app running (`make run`), open `http://127.0.0.1:8000/` and click any scenario, or go directly to:

| Scenario | URL | Demonstrates |
|---|---|---|
| Successful investigation | `http://127.0.0.1:8000/demo/high_risk` | Malicious enrichment &rarr; `ESCALATE` &rarr; AI investigation assistance |
| Enrichment failure | `http://127.0.0.1:8000/demo/enrichment_failure` | Enrichment unavailable &rarr; fails closed to `ANALYST_REVIEW` |
| AI failure | `http://127.0.0.1:8000/demo/ai_failure` | AI assistant unavailable &rarr; deterministic `ESCALATE` stays intact |
| Invalid AI output | `http://127.0.0.1:8000/demo/ai_invalid` | Malformed AI output rejected by schema validation |
| Low-risk alert | `http://127.0.0.1:8000/demo/low_risk` | Benign evidence &rarr; `LOW_RISK`, no unnecessary escalation |
| Ambiguous alert | `http://127.0.0.1:8000/demo/ambiguous` | Conflicting signals &rarr; catch-all `ANALYST_REVIEW` |

The same mechanism is available as JSON via `curl`:

```bash
curl -X POST "http://127.0.0.1:8000/api/v1/alerts?scenario=enrichment_failure" \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id":"synthetic-high-001",
    "timestamp":"2026-01-15T12:00:00Z",
    "hostname":"workstation-07",
    "username":"synthetic.user",
    "severity":"HIGH",
    "process_name":"powershell.exe",
    "command_line":"powershell.exe -EncodedCommand synthetic-payload",
    "source_ip":"192.0.2.25",
    "destination_ip":"198.51.100.10",
    "file_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "detection_description":"Synthetic encoded PowerShell command contacted a known synthetic C2 indicator.",
    "source":"crowdstrike-style-synthetic"
  }'
```

`?scenario=ai_failure` swaps in the same `FailingInvestigationAssistant` test double used by the automated tests, via the existing dependency-injection seam &mdash; no hard-coded frontend results anywhere.

## API Example

`POST /api/v1/alerts` against the high-risk fixture, without any scenario override:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/alerts \
  -H "Content-Type: application/json" \
  -d '{
    "alert_id":"synthetic-high-001",
    "timestamp":"2026-01-15T12:00:00Z",
    "hostname":"workstation-07",
    "username":"synthetic.user",
    "severity":"HIGH",
    "process_name":"powershell.exe",
    "command_line":"powershell.exe -EncodedCommand synthetic-payload",
    "source_ip":"192.0.2.25",
    "destination_ip":"198.51.100.10",
    "file_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "detection_description":"Synthetic encoded PowerShell command contacted a known synthetic C2 indicator.",
    "source":"crowdstrike-style-synthetic"
  }'
```

The response includes the normalized alert, indicators, enrichment, ordered processing history, the authoritative `triage` block, and a separate, non-authoritative `ai_assisted_analysis` block:

```json
{
  "triage": {
    "decision": "ESCALATE",
    "rules_triggered": ["RULE_A_HIGH_RISK_MALICIOUS"],
    "reason": "High-risk severity is supported by malicious enrichment evidence.",
    "evidence": {"severity": "HIGH", "reputations": ["malicious"]}
  },
  "ai_assisted_analysis": {
    "status": "available",
    "result": {
      "schema_version": 1,
      "provider_name": "mock",
      "summary": "Deterministic triage returned ESCALATE for host workstation-07 (severity HIGH). The fixed mock lookup table assesses this combination as HIGH risk.",
      "key_evidence": ["hostname=workstation-07", "username=synthetic.user", "ip=198.51.100.10 (source=destination_ip)"],
      "risk_assessment": "HIGH",
      "recommended_actions": ["review_process_tree", "inspect_network_connections", "escalate_to_senior_analyst"],
      "confidence": "HIGH",
      "uncertainties": []
    },
    "rejection_reason": null,
    "decision_authority": "DETERMINISTIC",
    "conflicts_with_triage": false,
    "analyst_review_required": false
  }
}
```

Note that `triage.decision` is always the authoritative result; `ai_assisted_analysis` is advisory context only.

## Screenshots

Located in [docs/screenshots/](docs/screenshots/), regenerated on demand via:

```bash
make screenshots
```

This starts the real app, drives it with Playwright, and saves a full-page screenshot of each scenario &mdash; so the images are provably current with the UI rather than stale, hand-made artifacts. All data shown is synthetic (RFC 5737 IP ranges, placeholder hashes, `synthetic.user`, `workstation-07`).

| | |
|---|---|
| ![Successful investigation](docs/screenshots/01-successful-investigation.png) | Successful investigation: alert, enrichment, deterministic `ESCALATE`, and AI-assisted analysis, clearly labelled and separated. |
| ![Enrichment failure](docs/screenshots/02-enrichment-failure.png) | Enrichment failure: deterministic result stays intact, degraded state is visible, analyst review is required. |
| ![AI failure](docs/screenshots/03-ai-failure.png) | AI failure: AI assistance unavailable, `ESCALATE` decision is completely unaffected. |

## Testing

`make test` (or `python -m pytest`) runs the full suite (unit, API, frontend, failure-path, and integration tests) with `--disable-socket` enforced globally via `pytest-socket` &mdash; including all frontend and AI tests, so the "runs offline" claim is enforced, not just asserted. 104 tests total, covering:

- Happy path: valid alert, correct normalization, indicator extraction, enrichment matching the documented lookup table, `ESCALATE` on high-risk malicious evidence.
- Input validation: missing/empty fields, invalid severity/IP/hash, invalid/naive timestamps, malformed JSON, unsupported source, oversized payloads, unexpected nested/extra fields ([tests/test_input_validation.py](tests/test_input_validation.py)).
- Configuration: every setting's missing/invalid/valid behavior, including the two distinct fail-fast vs. graceful-degrade policies ([tests/test_config.py](tests/test_config.py)).
- Failure handling: enrichment unavailable, AI unavailable, AI timeout (actually enforced, not just claimed), classified live-provider failures (auth, rate-limit, connection, 5xx, unexpected) and their bounded retry configuration ([tests/test_live_provider.py](tests/test_live_provider.py)), malformed AI output, policy violations (both layers), ungrounded evidence, deterministic/AI conflict.
- Structured logging: alert correlation across every workflow stage, degraded-state events, sensitive-data redaction (using obviously-fake placeholder secrets), and readiness/liveness behavior ([tests/test_logging.py](tests/test_logging.py)).
- Frontend: each demo scenario renders the correct provenance labels, state banners, and processing history &mdash; via `pytest` + an in-process ASGI client, no separate JS test runner.
- Integration: [tests/test_integration_workflow.py](tests/test_integration_workflow.py) asserts on every stage boundary of the complete pipeline in one test.

CI (`.github/workflows/ci.yml`) runs this same suite plus `ruff`/`mypy --strict`/`pip-audit`/a full-history `gitleaks` secret scan/a Docker build check on every push to `master` and every pull request &mdash; see the badge at the top of this document for current status.

## What Is Deliberately Mocked / Simulated

Being explicit about this is more useful than pretending otherwise:

- **All alert data is synthetic**: fixed fixtures in [fixtures/alerts.py](fixtures/alerts.py) using RFC 5737 documentation IP ranges, placeholder SHA-256 hashes, and names like `synthetic.user`/`workstation-07`. Nothing here is a real alert, a real indicator, or real telemetry.
- **Threat-intelligence enrichment is a fixed in-memory lookup table** ([app/enrichment/table.py](app/enrichment/table.py)), not a real threat-intel feed or API. It has no real network failure modes to retry against &mdash; see [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md) for why that matters for its retry policy.
- **The default AI investigation provider is a deterministic mock** ([app/investigation/mock.py](app/investigation/mock.py)), driven by a fixed, documented lookup table &mdash; not a real LLM call. It is what CI and the full test suite run against.
- **The optional live AI provider** (Anthropic, behind the `live-ai` extra) is real, but never installed by CI, never required, and has not been exercised in this project against a real API key/account (see [docs/assumptions.md](docs/assumptions.md)) &mdash; it is an available extension point, not a validated production integration.
- **The "CrowdStrike-style" alert shape** is a plausible EDR-alert shape chosen for realism, not derived from any real CrowdStrike schema or documentation.
- **There is no persistence layer**: every alert's `processing_history` exists only in that one HTTP response. There is no database, audit log store, or cross-alert query capability.
- **There is no authentication or authorization** on any endpoint.

## What Production Deployment Would Require

None of the following exist in this repository today. Listing them explicitly is the honest complement to the section above:

- **Real provider integrations**: an actual threat-intelligence/enrichment API (with its own real failure modes, rate limits, and cost) in place of the synthetic lookup table, and a validated (not just implemented) live AI provider integration.
- **Production secrets management**: a vault/KMS-backed secret store instead of `.env`/environment variables, with rotation and access auditing.
- **Real identity and access controls**: authentication and authorization on every endpoint, most importantly `POST /api/v1/alerts`; today anyone who can reach the process can submit alerts.
- **Persistent storage**: a database or audit-log store so `processing_history` and every triage/AI decision survive past a single HTTP response and can be queried/reported on later.
- **Monitoring and alerting infrastructure**: this release adds structured logs and `/health`/`/health/ready`, but there is no metrics backend, dashboarding, or alerting on top of them (see the "Remaining observability gaps" note in [docs/engineering-hardening.md](docs/engineering-hardening.md)) &mdash; no log shipping/aggregation is configured either; logs are stdout-only today.
- **Deployment infrastructure**: the Dockerfile is for local reproducibility only &mdash; there is no orchestration (Kubernetes/ECS/etc.), no infrastructure-as-code, no CD pipeline, no environment promotion strategy.
- **High availability**: this is a single stateless process with no redundancy, load balancing, or failover strategy considered.
- **Production-scale testing**: no load testing, chaos testing, or real-world alert-volume validation has been performed; the synthetic fixtures exercise correctness and failure paths, not throughput or scale.
- **Security review**: no third-party penetration test or formal security review has been performed; the AI policy controls (keyword denylist, evidence grounding) are heuristic defense-in-depth, not a formal guarantee against a determined adversarial provider.
- **Operational ownership**: no on-call rotation, incident-response runbook beyond [docs/operations.md](docs/operations.md)'s troubleshooting flow, or SLA/SLO commitments exist for this project.

See the [Engineering Retrospective](docs/retrospective.md) for a more specific answer to "what would I do differently if this processed real customer security alerts?"

## Documentation Map

| Document | What it covers |
|---|---|
| [docs/architecture.md](docs/architecture.md) | Component overview, data flow, trust boundaries, failure behavior, testing strategy |
| [docs/ai-security-design.md](docs/ai-security-design.md) | The full AI threat model and prompt-injection defenses |
| [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md) | The failure model and retry strategy for every external/fallible dependency |
| [docs/configuration.md](docs/configuration.md) | Every setting, its default, and its documented missing/invalid-value behavior |
| [docs/operations.md](docs/operations.md) | Running the service, health/readiness semantics, the structured logging schema, common failures, degraded mode, troubleshooting flow |
| [docs/assumptions.md](docs/assumptions.md) | Explicit assumptions made during implementation, flagged `[VERIFIED]`/`[DESIGN]`/`[UNVERIFIED]` |
| [docs/engineering-hardening.md](docs/engineering-hardening.md) | The full engineering hardening audit trail: findings, fixes, and verification for every phase |
| [docs/retrospective.md](docs/retrospective.md) | An honest engineering retrospective: what improved, what remains weak, what would change for real customer data |
| [docs/cv-project-summary.md](docs/cv-project-summary.md) | A condensed project summary suitable for a CV/LinkedIn entry |
| [docs/copilot-development-notes.md](docs/copilot-development-notes.md) | Notes on how AI-generated code was reviewed during development |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## License

Released under the MIT License. See [LICENSE](LICENSE).

