# Changelog

All notable changes to this project are documented in this file.

## [Unreleased]

Post-release engineering hardening (see [docs/engineering-hardening.md](docs/engineering-hardening.md)).

### Fixed

- Deterministic triage Rule C no longer treats a zero-indicator alert (no
  extractable IP/hash) as benign evidence; it now falls through to the
  `ANALYST_REVIEW` catch-all instead of silently returning `LOW_RISK`.
- Rejected requests (422 validation errors, 413 oversized bodies, and other
  HTTP errors) are now logged server-side (method/path/reason only, never
  raw body content), closing a previously silent observability gap.
- `AI_PROVIDER_TIMEOUT_SECONDS` now rejects non-positive values at startup,
  falling back to the documented default with a warning instead of causing
  the AI assistant to silently and permanently time out.

### Changed

- CI now also builds the Docker image (`docker-build` job) so a broken
  `Dockerfile` can't go unnoticed.
- Error responses (`app/main.py`) are now built from the shared
  `ErrorDetail`/`ErrorResponse` Pydantic models instead of untyped literal
  dicts, and `POST /api/v1/alerts` documents its `413`/`422` error shape in
  the OpenAPI schema.
- Centralized application configuration into a typed `Settings`
  (`pydantic-settings`) model (`app/config.py`), replacing scattered
  `os.environ` reads; `ANTHROPIC_API_KEY` is now sourced exclusively
  through `Settings` and never read directly by `app/investigation/live.py`.
- The live Anthropic provider (`app/investigation/live.py`) now classifies
  provider failures (authentication/permission, rate-limit, connection/
  status, unexpected) into distinct log messages instead of one generic
  catch-all, while still degrading to a single `InvestigationUnavailableError`
  application-wide. Its bounded retry count is now explicit and
  configurable via the new `AI_LIVE_MAX_RETRIES` setting (default 2)
  instead of relying on an undocumented SDK default. See
  [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md).

### Added

- `MAX_ALERT_BODY_BYTES` and `AI_LIVE_MAX_RETRIES` settings, both
  documented in [docs/configuration.md](docs/configuration.md).
- First Architecture Decision Record:
  [docs/adr/001-failure-handling.md](docs/adr/001-failure-handling.md),
  documenting the failure model and retry strategy for external
  dependencies.

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
