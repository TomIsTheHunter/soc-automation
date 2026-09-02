# 004. Inbound Webhook Ingestion Security Model

## Status

Accepted (2026-09-02)

## Context

Every provider category built so far (enrichment, vulnerability/asset
context, case management) is **outbound**: this platform calls a vendor
and trusts the response only after it passes schema validation. A
case-management vendor realistically also needs to push updates back
*in* - e.g. "an analyst closed this case in the vendor's UI" - which this
platform cannot poll for continuously. That requires an inbound HTTP
endpoint, which is a fundamentally different trust boundary: anyone on
the network can attempt to `POST` to it, not just this application
calling out on its own schedule.

Naively accepting any well-formed JSON `POST` at a public endpoint and
treating it as authoritative case-status data would let an unauthenticated
attacker inject fake events. This ADR documents the security model chosen
for `app/api/webhooks.py`'s one endpoint (`POST /api/v1/webhooks/incident-desk`).

## Decision

- **HMAC-SHA256 signature verification, fail closed.** Every request must
  carry an `X-Incident-Desk-Signature: sha256=<hexdigest>` header (the
  GitHub/Stripe-style convention), computed over the **raw request body
  bytes** with a shared secret (`INCIDENT_DESK_WEBHOOK_SECRET`). The route
  reads `await request.body()` and verifies the signature *before* any
  JSON parsing or schema validation - a request with a missing, malformed,
  or non-matching signature is rejected (401) without ever being parsed as
  a case update, regardless of how well-formed its JSON is.
- **Constant-time comparison.** `verify_webhook_signature()` uses
  `hmac.compare_digest`, never `==`, so comparing the computed and
  provided digests cannot leak timing information about how many leading
  bytes matched.
- **Signature verified over raw bytes, not the parsed/re-serialized
  model.** Re-serializing a payload after parsing (e.g. via
  `model_dump_json()`) is not guaranteed to produce byte-identical output
  to what the vendor actually signed (field order, whitespace, float
  formatting can all differ) - verifying against the exact bytes received
  avoids that entire class of bug.
- **Strict schema validation after signature verification.**
  `IncidentDeskWebhookPayload` (`extra="forbid"`, UTC-aware `occurred_at`,
  `event`/`status` restricted to controlled vocabularies) mirrors
  `CrowdStrikeStyleAlert`'s existing validation conventions. A
  signature-valid but schema-invalid payload is rejected (422) - a valid
  signature proves *authenticity* (it came from someone holding the
  secret), not *validity* of the content.
- **Bounded in-memory duplicate-delivery detection.** Most webhook
  providers use at-least-once delivery, so `delivery_id` can legitimately
  repeat. `_is_duplicate_delivery()` tracks up to `MAX_SEEN_DELIVERIES`
  (1000) delivery IDs per running process (an `OrderedDict` used as an
  LRU, evicting the oldest entry once full) - bounded so an attacker
  sending many unique IDs can never grow this without limit, the same
  bounded philosophy as [002-provider-resilience.md](002-provider-resilience.md)'s
  retry/backoff caps. A duplicate is acknowledged (200,
  `{"status": "duplicate_ignored"}`) rather than rejected, since the
  vendor should not be encouraged to keep retrying a delivery that already
  succeeded.
- **Request body size limit before the body is read.** The existing
  `RequestBodySizeLimitMiddleware` (generalized in this phase from the
  alerts-only `AlertBodySizeLimitMiddleware` to accept a
  path-to-byte-limit map) rejects an oversized webhook body (413) at the
  ASGI-scope level, based on `Content-Length`, before any handler code -
  including signature verification - ever buffers it into memory.
- **No persistence, by design.** This application has no database (see
  [architecture.md](../architecture.md)) and this phase does not add one.
  A verified, non-duplicate webhook is logged as a structured
  `webhook_received` event and acknowledged - it does not update any case
  record, because none exists to update. This is an honest reflection of
  the current architecture, not a shortcut hiding a gap.

## Retryable / non-retryable failures

Not applicable in the retry sense used elsewhere - this endpoint does not
call out anywhere, so there is nothing for *this platform* to retry. The
**vendor's** retry behavior on delivery failure is exactly what
duplicate-delivery detection above is designed to tolerate safely.

## Bounded behavior

- Body size: bounded by `MAX_WEBHOOK_BODY_BYTES` (default 16 KiB - a case
  webhook payload is small; this is deliberately far below
  `MAX_ALERT_BODY_BYTES`).
- Duplicate-delivery memory: bounded by `MAX_SEEN_DELIVERIES` (1000
  entries, LRU-evicted).

## Failure philosophy

Fail closed on anything about *authenticity* (missing/invalid/tampered
signature -> 401, never processed). Fail informatively on anything about
*validity* (bad schema -> 422, distinct from an auth failure so an
integrator can tell which problem they have). Never silently accept
unsigned or unverifiable input, and never let acknowledging a duplicate
look like an error to the vendor (a duplicate is still a 200).

## Consequences

**Benefits:**

- The endpoint cannot be driven by an attacker who does not hold
  `INCIDENT_DESK_WEBHOOK_SECRET`, verified with a real cryptographic
  primitive (HMAC-SHA256) rather than a plain shared-token string
  comparison.
- Reuses the existing size-limit middleware (generalized, not duplicated)
  and the existing `ErrorResponse`/`ErrorDetail` error shape, structured
  logging conventions, and `extra="forbid"`/UTC-timestamp validation
  conventions already established elsewhere in this codebase - no new
  parallel conventions were introduced.
- Demonstrates the full realistic lifecycle of a webhook: authenticate,
  validate, deduplicate, acknowledge - not just "parse JSON and return
  200."

**Trade-offs / limitations:**

- `INCIDENT_DESK_WEBHOOK_SECRET` has a safe, non-secret **default** value
  (`mock-incident-desk-webhook-secret`), matching every other credential
  in this codebase (`THREAT_INTEL_API_KEY`, `ASSET_INTEL_API_KEY`) so the
  application works out of the box for the demo/test suite. Because this
  value is public (it is committed in this repository), a real deployment
  **must** override it with a real, secret value - this mirrors the
  project's existing, already-disclosed limitation that no endpoint in
  this application has real production-grade authentication (see
  README's "What Production Deployment Would Require").
- Duplicate-delivery detection is in-memory and per-process; it does not
  survive a restart and is not shared across multiple replicas of this
  service. A production deployment would need a shared store (e.g. Redis)
  for this to work correctly behind more than one instance.
- The `X-Incident-Desk-Signature` header name and `sha256=<hex>` format
  are this project's own convention (there being no real "IncidentDesk"
  vendor) - a real integration would need to match whatever format the
  actual vendor uses, though the verification *technique* (HMAC,
  constant-time compare, raw-body signing) generalizes directly.
