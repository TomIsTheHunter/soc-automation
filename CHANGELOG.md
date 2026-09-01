# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

### Added

- Sprint 2 (Enterprise Security Integrations) foundation: reusable
  integration client foundation (`app/integrations/base.py`) with
  API-key and bearer-token authentication, a dedicated `IntegrationError`
  classification hierarchy (`app/integrations/errors.py`), and a
  mock-backed `ThreatIntelEnrichmentProvider`
  (`app/integrations/enrichment/threat_intel.py`) implementing the
  existing `EnrichmentProvider` interface. Adapts a provider-specific raw
  response schema into the existing `EnrichmentResult` model - no new
  normalized model was introduced. See
  [docs/integration-architecture.md](docs/integration-architecture.md)
  and Issue #4.
- New `THREAT_INTEL_BASE_URL` / `THREAT_INTEL_API_KEY` settings
  (`app/config.py`), following the existing `Settings` conventions.
- `httpx` promoted from a dev-only dependency to a core dependency (it now
  backs the integration client, not just the test suite).

## [0.3.0] - 2026-08-26

Engineering hardening release (see [docs/engineering-hardening.md](docs/engineering-hardening.md)
for the full phase-by-phase audit trail, and [docs/retrospective.md](docs/retrospective.md)
for an honest retrospective on this work).

### Added

- Centralized, typed application configuration (`app/config.py`, via
  `pydantic-settings`) replacing scattered `os.environ` reads, with a
  documented missing/invalid-value policy per setting (fail-fast for
  `MAX_ALERT_BODY_BYTES`, graceful-degrade-with-warning for everything
  else). New settings: `MAX_ALERT_BODY_BYTES`, `AI_LIVE_MAX_RETRIES`,
  `LOG_LEVEL`. See [docs/configuration.md](docs/configuration.md).
- First Architecture Decision Record:
  [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md),
  documenting the failure model and retry strategy for every external/
  fallible dependency.
- Explicit, bounded retry configuration (`AI_LIVE_MAX_RETRIES`) for the
  live AI provider, delegating backoff to the Anthropic SDK's own tested
  retry policy instead of re-implementing it.
- Structured JSON logging (`app/observability.py`): every workflow event,
  provider degradation, and rejected request is now a single JSON log
  line with consistent fields (`event`, `alert_id`, `workflow_stage`,
  `provider`, `duration_ms`, `result`, `review_required`, `error_type`),
  making one alert's entire lifecycle traceable end to end by its
  `alert_id`.
- `GET /health/ready` readiness endpoint, reporting `healthy` vs.
  `healthy-but-degraded` (`degraded`) based on AI provider availability,
  separate from the existing lightweight `GET /health` liveness check.
- `docs/operations.md`: running the service, health/readiness semantics,
  the structured logging schema with representative (fake-data) examples,
  common failure modes, degraded-mode behavior, and a troubleshooting flow.
- `docs/retrospective.md`: an honest engineering retrospective on this
  hardening/release work.
- 53 new automated tests since `v0.2.0` (51 &rarr; 104): full malformed-
  input boundary matrix, configuration edge cases, live-provider failure
  classification, structured-logging/correlation/redaction, and more.

### Improved

- Deterministic triage Rule C no longer treats a zero-indicator alert (no
  extractable IP/hash) as benign evidence; it now falls through to the
  `ANALYST_REVIEW` catch-all instead of silently returning `LOW_RISK`.
- Rejected requests (422 validation errors, 413 oversized bodies, and other
  HTTP errors) are now logged server-side (method/path/reason only, never
  raw body content), closing a previously silent observability gap.
- `AI_PROVIDER_TIMEOUT_SECONDS` now rejects non-positive values at startup,
  falling back to the documented default with a warning instead of causing
  the AI assistant to silently and permanently time out.
- The live Anthropic provider (`app/investigation/live.py`) now classifies
  provider failures (authentication/permission, rate-limit, connection/
  status, unexpected) into distinct, structured log events instead of one
  generic catch-all, while still degrading to a single
  `InvestigationUnavailableError` application-wide; provider exception text
  is no longer interpolated into log messages, only the exception's class
  name is (`error_type`), closing a theoretical sensitive-data leak path.
  See [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md).
- `ANTHROPIC_API_KEY` is now sourced exclusively through the typed
  `Settings` model and never read directly by
  `app/investigation/live.py`.
- Error responses (`app/main.py`) are now built from the shared
  `ErrorDetail`/`ErrorResponse` Pydantic models instead of untyped literal
  dicts, and `POST /api/v1/alerts` documents its `413`/`422` error shape in
  the OpenAPI schema.
- Input-boundary and AI-output-boundary test coverage substantially
  extended (malformed/missing/oversized fields, invalid timestamps,
  unexpected nested data).
- CI now also builds the Docker image (`docker-build` job) so a broken
  `Dockerfile` can't go unnoticed.
- README rewritten: explicit "why deterministic + AI" and failure-handling
  sections, an honest "what is mocked" / "what production would require"
  split, and a documentation map linking every doc in the repository.

## [0.2.0] - 2026-08-14

First tagged release: the complete three-stage SOC Automation Vertical Slice.

### Stage 1 &mdash; Security Automation Core

- FastAPI ingestion (`POST /api/v1/alerts`, `GET /health`) with a 256 KiB request-size limit.
- Pydantic v2 validation at every boundary: severity enum, `IPvAnyAddress`, UTC-aware timestamps, `extra="forbid"`.
- CrowdStrike-style synthetic source adapter, isolated from the FastAPI route.
- Indicator extraction (IP, hash) with source-field context.
- `EnrichmentProvider` abstraction, deterministic mock provider driven by a fixed documented lookup table, and a failure test double.
- Deterministic, precedence-ordered triage engine (Rules A&ndash;D, first-match-wins).
- Structured processing history and response models.
- Offline-enforced test suite (`pytest-socket`) and GitHub Actions CI.

### Stage 2 &mdash; Bounded AI-Assisted Investigation

- `InvestigationAssistant` abstraction with an explicit, configurable timeout and no silent retries.
- Deterministic mock AI provider driven by a fixed, documented lookup table.
- Optional live provider (Anthropic) behind an isolated `live-ai` dependency extra; never required.
- Strict `InvestigationResult` schema (`extra="forbid"`, `schema_version`, controlled vocabularies).
- Data-minimized `InvestigationContext` with an explicit field allowlist.
- Prompt-injection defense: fixed system instruction, alert content passed as delimited untrusted data.
- Policy validation: vocabulary constraint, keyword denylist, and an evidence-grounding check.
- Deterministic triage remains authoritative; AI/triage conflicts are detected and surfaced, never resolved silently.
- Extended processing history (`ai_requested`, `ai_received`, `ai_validated`, `ai_rejected`, `ai_unavailable`, `analyst_review`).

### Stage 3 &mdash; Recruiter- and Interview-Ready Vertical Slice

- Server-rendered analyst investigation view (FastAPI + Jinja2), reusing the exact same pipeline as the API.
- Named demo scenarios (`high_risk`, `enrichment_failure`, `ai_failure`, `ai_invalid`, `low_risk`, `ambiguous`) driven entirely by dependency injection &mdash; no hard-coded frontend results.
- `?scenario=` query-parameter mechanism on the JSON API for the same failure-injection seam.
- Provenance-distinct UI sections (observed fact / deterministic decision / AI-assisted analysis) using both color and non-color badges.
- Frontend tests (`tests/test_web.py`) and one full end-to-end integration test (`tests/test_integration_workflow.py`).
- Regenerable screenshots (`make screenshots`, Playwright) reflecting the live application.
- CI: dependency vulnerability audit (`pip-audit`) and a full-history secret scan (`gitleaks`).
- README, architecture, and AI security documentation refreshed to describe the current system.
- `docs/cv-project-summary.md` and `docs/copilot-development-notes.md` added.
