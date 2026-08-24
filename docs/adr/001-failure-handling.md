# 001. Failure Handling and External Dependency Resilience

## Status

Accepted (2026-08-24)

## Problem

This application's core purpose is security automation: taking an inbound
alert through deterministic triage and (optionally) an AI-assisted
investigation. It depends on external and semi-external systems that can
fail or return invalid data:

- The live AI provider (Anthropic), a real network service, when
  `AI_PROVIDER` is configured for anything other than `mock`.
- The enrichment provider seam (`app/enrichment/providers.py`), currently
  satisfied only by an in-memory synthetic lookup table, but designed as an
  extension point for a real threat-intel/reputation service.
- The inbound HTTP boundary itself (malformed or oversized client
  payloads).

If a failure in any of these is allowed to propagate unpredictably, the
worst outcomes for a SOC automation platform are: an alert silently
disappearing, a degraded result being presented as if it were complete, or
an unhandled exception preventing the deterministic security decision from
being returned at all. None of these are acceptable - "the provider
failed" must never be treated as equivalent to "there is no result", and
correctness (a real, present alert) always trumps availability of the
optional AI layer.

## Decision

The system uses, and this ADR documents, the following already-established
plus newly-added controls:

- **Explicit failure states**, not ambiguous `None`/empty results.
  `AIStatus` (`available` / `unavailable` / `rejected`) and
  `enrichment_available` are first-class, inspectable fields on every
  response, never inferred after the fact.
- **Meaningful application-level exceptions**, kept small and reused across
  layers rather than growing without bound: `EnrichmentUnavailableError`,
  `InvestigationUnavailableError`, `InvestigationValidationError` (carrying
  a specific `InvestigationRejectionReason`), and `UnsupportedSourceError`.
  These map directly onto the concepts this phase asked about
  (`ProviderUnavailable` -> `*UnavailableError`, `InvalidProviderResponse`
  -> `InvestigationValidationError`/JSON-decode handling in `live.py`,
  `ProviderTimeout` -> the built-in `TimeoutError`, raised consistently by
  both `asyncio.wait_for` call sites). No new exception types were added
  for concepts the existing hierarchy already covers correctly.
- **Explicit network timeouts.** Every AI provider call is bounded by
  `asyncio.wait_for` at the call site in
  [app/services/workflow.py](../../app/services/workflow.py)
  (`AI_PROVIDER_TIMEOUT_SECONDS`, default 8s), which is the outer bound on
  total latency regardless of what happens inside the provider call
  (including any retries - see below).
- **Bounded retries with backoff for the live AI provider.** Rather than
  hand-rolling a retry loop, [app/investigation/live.py](../../app/investigation/live.py)
  makes the Anthropic SDK's own built-in retry policy explicit and
  configurable via `AI_LIVE_MAX_RETRIES` (`Settings.ai_live_max_retries`,
  default 2), passed as `max_retries=` to `AsyncAnthropic(...)`. The SDK
  retries connection errors, timeouts, and HTTP 408/409/429/5xx with
  exponential backoff and jitter, honoring a `Retry-After` header when the
  server sends one; it never retries 401/403/400/404/422. This was a
  deliberate choice over re-implementing retry/backoff in application code
  for a concern already implemented in the vetted client library. The
  outer call-site timeout above still caps total latency even if internal
  SDK retries are in progress when it expires.
- **Response validation before trusting external data.**
  `app/investigation/validation.py` schema- and policy-validates every AI
  response (mock or live) before it can affect `ai_assisted_analysis`; a
  live-provider response that isn't even valid JSON is treated the same as
  provider unavailability (`InvestigationUnavailableError`), never as a
  usable result.
- **Deterministic security results are structurally immutable.**
  `app/triage/engine.py` computes `TriageResult` before the AI is ever
  invoked; `AIAssistedAnalysis.decision_authority` is a fixed
  `"DETERMINISTIC"` literal. No failure path - AI or enrichment - can
  overwrite it.
- **Explicit AI/deterministic conflict surfacing.**
  `ai_conflicts_with_triage()` in `app/services/workflow.py` detects (but
  never resolves) disagreement between the AI's risk assessment and the
  deterministic decision, forcing `analyst_review_required=true` rather
  than silently picking a side.
- **Degraded operation, never a dropped alert.** `run_alert_workflow()`
  always returns a complete `ProcessingResponse` - enrichment fallback,
  triage's own catch-all rule, and every AI failure branch all preserve
  and return the alert; nothing in the pipeline can cause an alert to
  vanish because an external dependency failed.

## Retry Strategy

| Failure | Retry? | Where enforced |
|---|---|---|
| AI: connection failure | Yes, bounded | Anthropic SDK (`max_retries`), backoff + jitter |
| AI: timeout (server-side) | Yes, bounded | Anthropic SDK (`max_retries`) |
| AI: HTTP 429 (rate limit) | Yes, bounded | Anthropic SDK, honors `Retry-After` |
| AI: HTTP 5xx | Yes, bounded | Anthropic SDK (`max_retries`) |
| AI: HTTP 401 (auth) | No | Never retried - a credential problem, not transient |
| AI: HTTP 403 (permission) | No | Never retried - an authorization problem, not transient |
| AI: invalid/malformed request or response (4xx other than 429, non-JSON output) | No | Never retried - retrying the same request will not fix it |
| AI: call-site timeout budget exhausted (`AI_PROVIDER_TIMEOUT_SECONDS`) | No | `asyncio.wait_for` cancels regardless of internal retry state; the workflow immediately marks AI `unavailable` |
| Enrichment: `EnrichmentUnavailableError` / unexpected exception | No | No real external call currently exists (synthetic in-memory table); triage already fails closed to `ANALYST_REVIEW` instead of guessing. If a real network-based enrichment provider is added later, it should follow this same policy (bounded retry for transient failures only). |
| Inbound HTTP validation failure (422/413) | No (client's responsibility) | Retrying the same malformed/oversized client payload will not fix it |
| Unexpected/unclassified exception (any layer) | No, not blindly | Caught, logged (`logger.exception`), and degrades the affected stage explicitly rather than being retried without understanding the cause |

## Consequences

**Benefits:**

- An external provider outage degrades one advisory layer
  (`ai_assisted_analysis`) while the deterministic security decision is
  always still returned - the property this whole project is built around.
- Retry behavior for the live AI provider is bounded, explicit, and
  configurable (`AI_LIVE_MAX_RETRIES`) instead of implicit/undocumented
  SDK defaults, and is safe to reason about in a code review: only
  categories that are actually transient are ever retried.
- Failures are classified and logged distinctly (auth/permission vs.
  rate-limit vs. connection/status vs. unexpected) without leaking
  provider-specific exception types into `app/services/workflow.py` or
  beyond - the rest of the application only ever sees
  `InvestigationUnavailableError`.

**Trade-offs:**

- Delegating retry/backoff to the Anthropic SDK means this application
  does not control the exact backoff timing or jitter - only the retry
  count ceiling (`max_retries`). This was accepted because re-implementing
  a correct, tested backoff/jitter/`Retry-After` policy would duplicate
  well-tested library behavior for no functional benefit.
- A live provider experiencing sustained transient failures can add up to
  `AI_LIVE_MAX_RETRIES` retries worth of latency to a single call, though
  this is still capped by the outer `AI_PROVIDER_TIMEOUT_SECONDS` budget.
- The enrichment provider seam currently has no real network failure modes
  to retry (it's synthetic); this is recorded so a future real integration
  doesn't silently skip the same due diligence.
