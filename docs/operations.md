# Operations

This document describes how to run, observe, and troubleshoot this
application in practice. It cross-references
[docs/configuration.md](configuration.md) and
[docs/adr/001-failure-handling.md](adr/001-failure-handling.md) rather than
duplicating them - if this file and either of those disagree, treat this
file as the one that has drifted.

## Starting the service

Prerequisites: Python 3.12, [`uv`](https://docs.astral.sh/uv/).

```bash
uv sync --extra dev      # installs the base app + dev tooling
make run                 # uvicorn app.main:app --reload, http://127.0.0.1:8000
```

No configuration is required for a fresh clone - the default `AI_PROVIDER=mock`
is fully offline and deterministic. See
[docs/configuration.md](configuration.md) for every available setting and its
missing/invalid-value behavior, and the "Local configuration" section there
for enabling the optional live AI provider.

## Health checks

Two separate endpoints answer two separate questions - see
[docs/adr/001-failure-handling.md](adr/001-failure-handling.md) for why the
AI provider is treated as an optional, non-authoritative dependency rather
than a hard requirement.

### `GET /health` - liveness

*"Is the process alive and able to respond at all?"* Deliberately
lightweight: no dependency checks, always `200` if the process is up.

```json
{"status": "ok"}
```

### `GET /health/ready` - readiness

*"Is the service ready to do its intended work?"* Reports each dependency
individually and an overall `status`:

- **`healthy`** - deterministic triage (no external dependency, always
  `"available"`) and the configured AI investigation provider are both
  available.
- **`degraded`** - deterministic triage and the core alert-processing
  workflow are fully operational, but the AI investigation provider is not
  configured/available. This is a deliberate choice, not an oversight: the
  AI layer is explicitly advisory (`decision_authority: "DETERMINISTIC"`),
  so its absence never blocks the service from doing its actual job.
  `POST /api/v1/alerts` still returns `200` in this state, with
  `ai_assisted_analysis.status="unavailable"` and
  `analyst_review_required=true`.

Both states return HTTP `200` - `degraded` is not the same as `unhealthy`.
There is currently no dependency whose failure should take the whole
service down (see the ADR's Retry Strategy table), so this endpoint never
returns a non-200 status.

Example (healthy):

```json
{"status": "healthy", "checks": {"triage": "available", "ai_provider": "available"}}
```

Example (degraded - e.g. `AI_PROVIDER` set to a live provider without a
valid `ANTHROPIC_API_KEY`, or without the optional `live-ai` extra
installed):

```json
{"status": "degraded", "checks": {"triage": "available", "ai_provider": "unavailable"}}
```

## Configuration

All environment-driven configuration is documented in
[docs/configuration.md](configuration.md), including the new `LOG_LEVEL`
setting this phase introduced (default `INFO`; controls the verbosity of
the structured logs described below).

## Expected logs

Every operationally significant event is emitted as one JSON object per
line (`app/observability.py: StructuredFormatter`) with a fixed set of
fields, so the same query/grep approach works across every stage of the
pipeline:

| Field | Meaning |
|---|---|
| `event` | The specific thing that happened, e.g. `alert_received`, `provider_degraded`, `triage_completed`. |
| `alert_id` | The correlation identifier for one alert (`source_alert_id`/`alert_id` from the request) - present on every event tied to a specific alert. |
| `workflow_stage` | Which pipeline stage produced the event (`received`, `enriched`, `triaged`, `ai_requested`, `ai_validated`, ...) - matches `ProcessingStage` where applicable. |
| `provider` | Which dependency was involved (`enrichment`, or the AI assistant's class name, e.g. `MockInvestigationAssistant`/`AnthropicInvestigationAssistant`). |
| `duration_ms` | How long the operation took, where an external call or meaningful processing stage is involved. |
| `result` | The outcome (`success`, `unavailable`, `timeout`, `rejected`, `error`, or a decision value like `ESCALATE`). |
| `review_required` | Whether analyst review is required, present on the events where that's a meaningful question. |
| `error_type` | The exception class name or rejection-reason code, when the event represents a failure. |

`message` is a short, human-readable summary; `level`, `logger`, and
`timestamp` are always present. Never included: request bodies, alert
content (hostnames/usernames/command lines), enrichment payloads,
credentials, or raw provider exception text - see "Sensitive information",
below.

### Representative examples (fake data only)

Alert received and correlated through the pipeline:

```json
{"timestamp": "2026-08-25T09:00:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "Alert received", "event": "alert_received", "alert_id": "ALT-00123", "workflow_stage": "received"}
{"timestamp": "2026-08-25T09:00:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "Enrichment completed", "event": "enrichment_completed", "alert_id": "ALT-00123", "workflow_stage": "enriched", "provider": "enrichment", "result": "success", "duration_ms": 0.4}
{"timestamp": "2026-08-25T09:00:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "Triage completed", "event": "triage_completed", "alert_id": "ALT-00123", "workflow_stage": "triaged", "result": "ESCALATE"}
{"timestamp": "2026-08-25T09:00:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "AI investigation completed", "event": "ai_investigation_completed", "alert_id": "ALT-00123", "workflow_stage": "ai_validated", "provider": "MockInvestigationAssistant", "result": "available", "duration_ms": 1.2}
{"timestamp": "2026-08-25T09:00:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "Alert workflow completed", "event": "workflow_completed", "alert_id": "ALT-00123", "workflow_stage": "completed", "result": "ESCALATE", "review_required": false, "duration_ms": 3.1}
```

A degraded enrichment provider - distinguishable from "no indicators found":

```json
{"timestamp": "2026-08-25T09:05:00+0000", "level": "WARNING", "logger": "app.services.workflow", "message": "Enrichment unavailable for alert ALT-00124", "event": "provider_degraded", "alert_id": "ALT-00124", "workflow_stage": "enriched", "provider": "enrichment", "result": "unavailable", "error_type": "EnrichmentUnavailableError", "duration_ms": 0.1}
```

A degraded AI provider, forcing analyst review - distinguishable from "AI
was not required":

```json
{"timestamp": "2026-08-25T09:06:00+0000", "level": "WARNING", "logger": "app.services.workflow", "message": "AI investigation provider unavailable for alert ALT-00125", "event": "provider_degraded", "alert_id": "ALT-00125", "workflow_stage": "ai_unavailable", "provider": "AnthropicInvestigationAssistant", "result": "unavailable", "error_type": "InvestigationUnavailableError", "duration_ms": 42.7}
{"timestamp": "2026-08-25T09:06:00+0000", "level": "INFO", "logger": "app.services.workflow", "message": "Analyst review required", "event": "analyst_review_required", "alert_id": "ALT-00125", "workflow_stage": "analyst_review", "result": "unavailable", "review_required": true}
```

A rejected AI response (schema/policy/grounding failure) - the
deterministic `triage` result is unaffected either way:

```json
{"timestamp": "2026-08-25T09:07:00+0000", "level": "WARNING", "logger": "app.services.workflow", "message": "AI investigation output rejected for alert ALT-00126", "event": "ai_investigation_rejected", "alert_id": "ALT-00126", "workflow_stage": "ai_rejected", "provider": "MockInvestigationAssistant", "result": "rejected", "error_type": "policy_keyword_match", "duration_ms": 0.6}
```

A rejected request at the HTTP boundary (never includes the request body):

```json
{"timestamp": "2026-08-25T09:08:00+0000", "level": "WARNING", "logger": "app.main", "message": "Rejected invalid request: method=POST path=/api/v1/alerts errors=[{'loc': ['body', 'hostname'], 'type': 'missing'}]", "event": "request_rejected", "workflow_stage": "received", "result": "rejected", "error_type": "validation_error"}
```

## Common failures

| Failure | What an operator should expect to see | Retry/recovery rationale |
|---|---|---|
| Enrichment provider unavailable | `event=provider_degraded provider=enrichment result=unavailable`; `triage.decision` routes to `ANALYST_REVIEW` (fails closed, never guesses). | No real network dependency currently exists to retry (synthetic in-memory table) - see the ADR's Retry Strategy table. |
| AI provider unavailable (missing/invalid credentials, SDK not installed) | `provider_degraded` at startup (`select_investigation_assistant`) and/or per-alert; `ai_assisted_analysis.status="unavailable"`; `/health/ready` reports `degraded`. | Not retried - a configuration problem, not transient. Fix credentials/install the `live-ai` extra and restart. |
| AI provider timeout | `event=provider_degraded ... result=timeout error_type=TimeoutError`. | Bounded by `AI_PROVIDER_TIMEOUT_SECONDS` at the call site; internal SDK retries (if any) are already exhausted or irrelevant by then - see the ADR. |
| AI provider rate-limited / connection failure / 5xx | `event=provider_degraded` logged from `app/investigation/live.py`, `result=unavailable`, `error_type` names the classified exception. | Already bounded-retried inside the Anthropic SDK (`AI_LIVE_MAX_RETRIES`) before this is logged - see the ADR's Retry Strategy table. |
| Invalid/malformed AI response | `event=ai_investigation_rejected`, `error_type` is one of `schema_invalid`/`policy_keyword_match`/`ungrounded_evidence`. | Not retried - the same request will not produce a different (valid) response. |
| Alert validation failure (malformed/missing fields) | `event=request_rejected error_type=validation_error`, HTTP `422`. | Client's responsibility to resubmit a corrected payload. |
| Oversized request body | `event=request_rejected error_type=request_too_large`, HTTP `413`. | Client's responsibility; bounded by `MAX_ALERT_BODY_BYTES`. |
| Unsupported alert `source` | `event=request_rejected error_type=http_422`, HTTP `422`. | Client's responsibility to send a supported `source` value. |
| Unexpected/unclassified exception (any layer) | `event=unhandled_exception` (HTTP boundary) or `event=provider_degraded`/`ai_investigation_failed` (workflow stages), `level=ERROR`, full traceback via `exc_info`. | Not retried blindly - logged with enough detail to diagnose, and the affected stage degrades explicitly rather than propagating an unhandled crash. |

## Degraded mode

"Degraded" means: the deterministic security decision (`triage`) and the
core alert-processing workflow are fully operational, but the advisory AI
investigation layer is not available or its output was rejected.

- **What remains available:** ingestion, validation, normalization,
  indicator extraction, enrichment (or its documented fail-closed
  fallback), and deterministic triage - the actual security decision.
- **How it appears in logs:** a `provider_degraded` event (`provider=ai` or
  `provider=enrichment`), never silently absent.
- **Is analyst review required?** Yes, always, whenever the AI layer is
  unavailable or rejected (`analyst_review_required=true`) - the system
  never presents "AI didn't run" as equivalent to "AI said this is fine".
- **How recovery is detected:** the next alert processed after the
  underlying issue is fixed (credentials restored, provider reachable
  again) will show `ai_investigation_completed`/`result=available` instead
  of `provider_degraded`; `/health/ready` will report `healthy` again on
  its next poll (it re-evaluates the current state on every request, with
  no caching).

## Troubleshooting flow

1. Check service liveness: `GET /health` (expect `{"status": "ok"}`).
2. Check service readiness: `GET /health/ready` (expect `healthy` or
   `degraded`, with a `checks` breakdown).
3. Identify the `alert_id` for the alert in question (from the API
   response, the demo UI, or a client-side report).
4. Search structured logs for that `alert_id`
   (e.g. `grep '"alert_id": "ALT-00123"' <log output>`).
5. Follow the `workflow_stage` values in order (`received` -> `normalized`
   -> `enriched` -> `triaged` -> `ai_requested` -> `ai_validated`/
   `ai_rejected`/`ai_unavailable` -> `analyst_review`/`completed`).
6. Identify the failing `provider` (`enrichment` or the AI assistant class
   name) and stage from the first `provider_degraded`/`*_rejected`/`*_failed`
   event.
7. Check `error_type` and `result` on that event against the "Common
   failures" table above.
8. Determine whether the system is degraded (deterministic triage still
   returned, `review_required=true`) or genuinely failed (HTTP `5xx`,
   `event=unhandled_exception`).
9. Remediate the underlying dependency/configuration issue (e.g. fix
   `ANTHROPIC_API_KEY`, restore provider connectivity) per
   [docs/configuration.md](configuration.md) and the failure-handling ADR.
10. Re-run or reprocess only where appropriate - this system is stateless
    per request, so simply resubmitting the same alert payload is
    sufficient once the underlying issue is fixed; nothing needs to be
    "unstuck".

## Sensitive information

Structured logging deliberately never includes: credentials, API keys,
authorization headers, full request/response bodies, raw alert content
(hostname/username/command line/detection description), or raw provider
exception text that might carry request/response detail. Provider failures
are logged as a short, fixed message plus `error_type` (the exception class
name) - never the exception's own string representation. See
[docs/configuration.md](configuration.md) ("Secrets handling") for how
`ANTHROPIC_API_KEY` itself is protected (`pydantic.SecretStr`, never
logged, never included in any response).
