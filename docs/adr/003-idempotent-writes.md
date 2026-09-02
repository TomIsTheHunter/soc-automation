# 003. Idempotent Writes for Case-Management Integrations

## Status

Accepted (2026-09-02)

## Context

The enrichment and vulnerability/asset-context provider categories
(`docs/integration-architecture.md`, [002-provider-resilience.md](002-provider-resilience.md))
are both read-only: every request is a `GET`, and retrying a `GET` is
always safe - fetching the same indicator or hostname twice has no side
effect. `BaseIntegrationClient.get()`'s bounded retry policy could
therefore retry freely without any extra precaution.

Case management is different: `create_case()` is a **write**. Retrying a
`POST /cases` request the same way `get()` retries a `GET` - the exact
same bounded backoff already built for transient 429/502/503/504/timeout
failures - would, without more care, risk creating a **second incident**
for the same underlying alert every time a transient failure happened to
occur after the vendor had already processed the first attempt. A
resilience feature (retries) would silently become a data-integrity bug
(duplicate cases) the moment it was applied to a write.

## Decision

- **`BaseIntegrationClient.post()`** was added as a sibling to `get()`,
  sharing the exact same retry/timeout/error-classification loop
  (`_send_with_retries()` - extracted from `get()` in this phase, not a
  second implementation) so write requests get identical resilience
  behavior, not a separate, divergent code path.
- Every `post()` call generates **one** `Idempotency-Key` header value
  (a random UUID, unless the caller supplies one) **before** entering the
  retry loop, and reuses that identical value on every retry attempt of
  that call. A conformant vendor that has already processed a given key
  returns its cached result instead of creating a second resource -
  exactly what `build_mock_incident_desk_transport()` does in
  `app/integrations/case_management/incident_desk.py`.
- The key is generated **once per logical call**, not once per HTTP
  attempt - the entire point is that every attempt of the *same* call
  looks identical to the vendor. Verified directly:
  `tests/test_integrations_base.py::test_post_reuses_the_same_idempotency_key_across_retries`.
- Callers may supply an explicit `idempotency_key` (e.g.
  `IncidentDeskCaseManagementProvider.create_case(..., idempotency_key=...)`)
  when they need safety across **separate** calls too - e.g. a workflow
  that might invoke `create_case()` a second time because it couldn't
  tell whether the first attempt actually succeeded. `MockCaseManagementProvider`
  defaults this key to the alert ID itself, since this platform's model is
  "one alert produces at most one case."
- The mock vendor's idempotency-key store is **per-client-instance**, built
  by a factory (`build_mock_incident_desk_transport()`), never shared
  module-level state - unlike the enrichment/vulnerability mocks' fixed,
  shared, read-only lookup tables, this mock is genuinely stateful
  (it must remember what it already created), so sharing that state across
  unrelated `IncidentDeskClient` instances or test cases would leak
  results between them. This mirrors a real vendor's per-tenant
  idempotency store, just in-memory.

## Retryable failures

Unchanged from [002-provider-resilience.md](002-provider-resilience.md):
429/502/503/504 and timeout/connection failures. Idempotency is what makes
retrying these **safe for a write**, not a reason to retry more failure
classes than `get()` already does.

## Non-retryable failures

Also unchanged: 400/401/403/404, a bare 500, and schema/JSON validation
failures are never retried, for the same reasons as the read-only
categories - none of them are fixed by resending an unchanged request.

## Bounded behavior

No new bound was introduced here - `post()` reuses `get()`'s existing
`RetryPolicy` (bounded attempts, bounded backoff, bounded `Retry-After`)
unchanged. The only new bounded resource is implicit: the mock vendor's
idempotency-key store lives only as long as its owning `IncidentDeskClient`
- there is no persistent, cross-process idempotency store, matching this
project's existing "no persistence" characteristic (see
[architecture.md](../architecture.md)).

## Scale implications

None beyond what [002-provider-resilience.md](002-provider-resilience.md)
already covers for retries in general. Idempotency keys do not change how
many requests a burst of alerts generates - they only guarantee that
*retries* of the same request are safe, not that concurrent, distinct
case-creation calls are deduplicated or rate-limited across a burst; that
remains the same disclosed, not-yet-addressed limitation already recorded
in the prior ADR.

## Failure philosophy

Consistent with the rest of this project: a case-management failure
degrades to `CaseManagementUnavailableError` (mirroring
`EnrichmentUnavailableError`) rather than silently losing the alert or
guessing that a case was created when it wasn't. Idempotency exists so
that *retrying* is one of the safe responses to a transient failure, not
so retries can be applied indiscriminately.

## Consequences

**Benefits:**

- Case creation gets the exact same bounded resilience as read operations,
  without the risk of duplicate incidents that naively applying the same
  retry loop to a write would have created.
- The idempotency mechanism lives in exactly one place
  (`BaseIntegrationClient.post()`) - any future write-based provider
  (e.g. updating a case, closing a ticket) gets it for free by calling
  `post()`, with no per-provider reimplementation.
- `_send_with_retries()` being shared between `get()` and `post()` means
  a future change to retry/backoff/logging behavior only needs to happen
  once.

**Trade-offs / limitations:**

- The mock vendor's idempotency-key store is in-memory and
  per-client-instance only; a real vendor integration would need to trust
  *its* server-side idempotency-key handling (most enterprise
  case-management/ticketing APIs document one), not reimplement dedup
  logic on the client.
- Cross-call idempotency (two separate, unrelated calls to `create_case()`
  for the same alert) is only as good as the caller-supplied key - nothing
  currently calls `create_case()` from the SOC workflow, so this is a
  foundation property, not yet an end-to-end guarantee for a real alert
  path (see docs/integration-architecture.md's "What was deliberately not
  wired").
