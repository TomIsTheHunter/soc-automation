# Architecture

## Component Overview

- `app/api`: thin FastAPI routing for `POST /api/v1/alerts` &mdash; request-size control, dependency injection, error translation. Business logic does not live here.
- `app/web`: server-rendered analyst demo view (Jinja2 templates + a scenario registry). Reuses `app/services/workflow.py` directly; renders no results it did not actually compute.
- `app/services/workflow.py`: the single implementation of the complete pipeline (`validate -> adapt -> normalize -> extract -> enrich -> triage -> investigate -> validate AI output`). Both `app/api` and `app/web` call this one function.
- `app/adapters`: source-specific translation from the CrowdStrike-style synthetic payload to the vendor-neutral `NormalizedAlert`.
- `app/models`: typed Pydantic contracts for source, normalized, indicator, enrichment, triage, AI investigation, and processing-history data.
- `app/enrichment`: `EnrichmentProvider` interface, fixed synthetic lookup table, mock provider, and a failure test double.
- `app/triage`: precedence-ordered deterministic decision engine.
- `app/investigation`: `InvestigationAssistant` interface, the fixed mock AI lookup table, prompt/trust-boundary construction, schema + policy validation, and an optional live provider.
- `fixtures`: reusable synthetic alert fixtures (high-risk, benign, ambiguous), all using RFC 5737 IP ranges.

## Data Flow

```
Alert -> Validate -> Adapt -> Normalize -> Extract Indicators -> Enrich
      -> Deterministic Triage -> Build Investigation Context -> AI Assistant
      -> Schema Validation -> Policy Validation -> Structured Result
```

`run_alert_workflow()` executes this once, end to end, and returns a `ProcessingResponse` containing the normalized alert, indicators, enrichment, the authoritative `triage` result, the advisory `ai_assisted_analysis` result, and an ordered `processing_history`. The API route and the demo view both call this function with different provider instances (see "Demo Scenario Mechanism" below) - they never diverge in business logic.

## Trust Boundaries

1. **API boundary**: the HTTP body is untrusted. Pydantic validates required fields, enum severity, timestamp awareness, IP syntax, and bounded strings. Middleware rejects bodies above 256 KiB before parsing.
2. **Source-adapter boundary**: vendor-shaped fields are untrusted and mapped explicitly. The rest of the application only consumes the vendor-neutral `NormalizedAlert`.
3. **Enrichment-provider boundary**: enrichment is external-style evidence, untrusted and fallible. The workflow depends only on the `EnrichmentProvider` abstraction.
4. **AI boundary**: the AI investigation assistant is untrusted and fallible, in two distinct ways. First, its *input* is constructed from an explicit field allowlist (`InvestigationContext`) with alert-derived content passed as clearly delimited, non-instructional data (see `docs/ai-security-design.md`). Second, its *output* is raw, unvalidated data until it passes schema validation (`InvestigationResult`, `extra="forbid"`) and policy validation (vocabulary constraint, keyword denylist, evidence grounding). Only validated output is ever shown to an analyst as `ai_assisted_analysis`.

## Deterministic Decision Authority

The triage engine (`app/triage/engine.py`) is authoritative because its ordered rules are inspectable, reproducible, and independently testable. Rule B (unavailable enrichment) runs first, Rule A escalates high-risk malicious alerts, Rule C accepts only low/medium benign or low-confidence unknown evidence, and Rule D is an explicit analyst-review catch-all. **No AI output can change `triage.decision`.** If the AI's `risk_assessment` disagrees with `triage.decision`, that conflict is surfaced (`ai_assisted_analysis.conflicts_with_triage`) rather than resolved by trusting either side automatically - the deterministic decision always wins.

## Failure Behaviour

Two independent dependencies can fail, and both fail closed:

- **Enrichment failure**: the workflow preserves the alert and indicators, marks enrichment unavailable, and Rule B routes to `ANALYST_REVIEW`. It never fabricates malicious *or* benign evidence.
- **AI failure** (provider unavailable, timeout, unexpected exception, or invalid/policy-violating output): `ai_assisted_analysis.status` becomes `unavailable` or `rejected`, `analyst_review_required` becomes `true`, and `triage.decision` is completely unaffected - it was already computed before the AI was ever called.

Every AI call is wrapped in `asyncio.wait_for` with a configurable timeout (`AI_PROVIDER_TIMEOUT_SECONDS`, default 8s), applied at the call site in `run_alert_workflow`, not merely described as a possibility.

## Demo Scenario Mechanism

The demo view and the API's `?scenario=` query parameter both work by injecting a *different provider instance* into the exact same `run_alert_workflow()` call - the same dependency-injection seam the automated test suite already uses (`FailingEnrichmentProvider`, `FailingInvestigationAssistant`, `MalformedInvestigationAssistant`). The alert fixture, source adapter, triage engine, and response models are identical to the production path; only the provider implementation changes. This guarantees the demo can never silently drift from what the tests actually verify.

## Testing Strategy

- `tests/test_services.py`: adapter, indicator extraction, and triage unit tests, isolated from FastAPI.
- `tests/test_api.py`: API-level validation, error handling, and the enrichment-failure path.
- `tests/test_ai_investigation.py`: the full Stage 2 AI safety matrix (happy path, malformed output, timeout, both policy layers, ungrounded evidence, conflict, prompt injection).
- `tests/test_web.py`: the server-rendered view, asserting on rendered HTML for every scenario and failure state.
- `tests/test_integration_workflow.py`: one end-to-end test asserting on every stage boundary of the complete pipeline.
- `pytest-socket` enforces `--disable-socket` globally (`pyproject.toml`), so the "runs offline" claim is enforced by CI, not just asserted in prose.

## Future Extension Points

The current boundaries are deliberately positioned so a later stage could add a real analyst chat/investigation UI, additional enrichment sources, or a persistent audit store without requiring a rewrite: `run_alert_workflow()` is the single integration point, `EnrichmentProvider` and `InvestigationAssistant` are both already interfaces, and `ProcessingResponse` already separates observed fact, deterministic decision, and AI-assisted analysis into distinct typed fields.

