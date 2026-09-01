# 002. Provider Resilience: Timeouts, Retries, Backoff, and Rate Limiting

## Status

Accepted (2026-09-01)

## Context

`docs/integration-architecture.md` established the integration layer's
boundaries (`BaseIntegrationClient`, the `IntegrationError` hierarchy, the
first mock-backed provider, `ThreatIntelEnrichmentProvider`) but that phase
deliberately deferred resilience behavior: every request used a single
5-second timeout, no failure was ever retried, and there was no protection
against a provider's `Retry-After` value causing an unbounded wait.

External security providers are unreliable dependencies by nature: they
can be slow, transiently unavailable, rate-limited, or outright broken.
This ADR documents the resilience policy added on top of the existing
foundation - it extends `app/integrations/base.py` in place; it does not
introduce a second HTTP or retry framework.

## Failure Matrix and Reasoning

The generic table in the task brief is a starting point, not a policy -
each row below is an explicit decision for *this* SOC workflow, not a
default copied from a general API-client checklist.

| Failure | Retry? | Why |
|---|---|---|
| Request takes too long (connect or read) | Yes, bounded | A slow provider is usually transient load, not a permanent defect; bounded retry + a hard timeout ceiling avoids either hanging forever or giving up on a merely-slow response. |
| 400 Bad Request | No | The request itself is malformed; retrying an unchanged request gets an unchanged result. |
| 401 / 403 | No | A credential/authorization problem is never fixed by retrying the same request. Surfaced immediately so an operator can rotate the key rather than watching silent retries burn time. |
| 404 Not Found | No, and not a failure | The provider answered; it just has no data for this indicator. `ThreatIntelEnrichmentProvider` already maps this to `Reputation.UNKNOWN`, not an error - unchanged by this phase. |
| 429 Too Many Requests | Yes, bounded, honoring `Retry-After` | The provider is explicitly asking to be backed off, not reporting a defect. Retrying immediately would make rate-limiting worse, so this is the one case where the provider's own signal (`Retry-After`) takes priority over computed backoff - within a hard cap (see "Bounded Behavior"). |
| 500 Internal Server Error | **No** (deliberately, see below) | A bare 500 is ambiguous - it can mean "the provider had a transient blip" or "this request triggers a server-side bug." Unlike 502/503/504, which are gateway/availability signals from infrastructure sitting in front of the provider, a 500 comes from the provider's own application code. Retrying a request that reliably triggers a server bug just repeats load for no benefit. This project treats 500 conservatively: log it clearly and fail fast, rather than assume it is transient. |
| 502 / 503 / 504 | Yes, bounded | These are classic gateway/availability signals (proxy can't reach upstream, service overloaded, gateway timeout) - the textbook transient-infrastructure case bounded retry exists for. |
| Connection failure (refused, reset, DNS) | Yes, bounded | Same reasoning as timeouts: usually transient network/infra state, not a defect in the request. |
| Malformed/invalid JSON | No | A parsing failure on this exact response will not change on retry; it likely means a provider schema change or a non-JSON error page, which needs a human to look, not a retry loop. |
| Schema validation failure (valid JSON, wrong shape) | No | Same reasoning as malformed JSON - the data itself is the problem, not the timing of the request. |

**What happens to the SOC workflow when enrichment fails, retried or not:**
every `IntegrationError` subclass is still translated to the existing
`EnrichmentUnavailableError` at the `ThreatIntelEnrichmentProvider` adapter
boundary (unchanged from the prior phase), which `app/services/workflow.py`
already handles by marking enrichment unavailable and letting deterministic
triage's Rule B route to `ANALYST_REVIEW`. **No workflow or triage code
changed to support resilience** - retries only change *how many attempts*
happen before that same, already-tested degradation path is reached.

## Decision

- **Timeout policy**: every request uses `httpx.Timeout` with a separate
  **connect timeout** (2.0s, fixed) and **read timeout** (5.0s, configurable
  via `THREAT_INTEL_TIMEOUT_SECONDS`). Connect timeout is not exposed as a
  setting - it is an infrastructure-level concern (how long to wait for a
  TCP/TLS handshake), not something an operator tuning provider latency
  needs to adjust; read timeout is, since it reflects the provider's actual
  response-time budget. Both are applied via one `httpx.Client(timeout=...)`
  passed at construction, never scattered per-call.
- **Retry policy** (`RetryPolicy` dataclass in `app/integrations/base.py`):
  `max_attempts` (default 3 = 1 try + 2 retries, configurable via
  `THREAT_INTEL_MAX_RETRIES`), applied only to the failure classes marked
  "Yes" in the table above (`RETRYABLE_STATUS_CODES = {429, 502, 503, 504}`,
  plus `httpx.TimeoutException`/`httpx.TransportError`).
- **Backoff**: exponential (`backoff_base_seconds=0.5`, doubling per
  attempt), capped at `backoff_max_seconds=8.0`. Jitter is added within the
  remaining headroom under that cap (`random.uniform(0, cap - base)`) so the
  total delay can never exceed the cap, avoiding the classic thundering-herd
  problem of many clients retrying in lockstep without adding unbounded
  variance.
- **`Retry-After`**: honored for 429 responses when present and parseable
  as a plain delay-seconds number, but always capped at
  `max_retry_after_seconds` (30.0s). An HTTP-date value, non-numeric value,
  or negative value is treated as absent and falls back to computed
  backoff - a malformed or adversarial `Retry-After` can never cause an
  unbounded wait.
- **Failure classification**: a new `IntegrationRateLimitedError` was added
  to the existing `IntegrationError` hierarchy so a rate-limited failure
  (even after exhausting retries) is distinguishable from a generic 4xx or
  a 5xx - this is one additional, well-justified subclass of the existing
  model, not a new error framework.
- **Observability**: `app/observability.py`'s fixed `STRUCTURED_FIELDS` set
  gained four fields (`operation`, `attempt`, `retry`, `status_code`) used
  by every request/retry/failure log line, alongside the existing
  `provider`/`duration_ms`/`error_type`. Three event names are used
  consistently: `provider_retry` (about to retry), `provider_degraded`
  (final failure, retried or not), `provider_recovered` (succeeded after at
  least one retry). A clean first-attempt success is deliberately not
  logged, matching the existing "don't log the uninteresting path" pattern
  already used for `/health/ready` (see docs/operations.md).

## Retryable Failures

429, 502, 503, 504, connect/read timeouts, and connection failures - all
represent the provider (or something in front of it) being transiently
unavailable or overloaded, where the *same* request is likely to succeed
moments later once conditions change.

## Non-Retryable Failures

400, 401, 403, 404, a bare 500, and any schema/JSON validation failure -
all represent a problem with the request, the credential, or the response
shape itself, none of which are fixed by sending the identical request
again. Retrying these would only add latency and load without any chance
of success.

## Bounded Behavior

Every dimension of retry behavior has a hard ceiling, not just a "usually
small" default:

- Attempts are capped by `max_attempts` (no infinite/unbounded retry loop).
- Backoff is capped by `backoff_max_seconds`, and jitter is computed to
  never push the delay past that same cap.
- A provider-supplied `Retry-After` is capped by `max_retry_after_seconds`
  regardless of what value the provider (or an attacker able to influence
  it) sends.

This mirrors the same philosophy already established for the live AI
provider in [001-failure-handling.md](001-failure-handling.md): bound the
*ceiling* explicitly rather than trusting an external system's stated
delay or an unbounded loop.

## Scale Implications

A single provider outage during a burst of alerts (e.g. thousands arriving
at once, each triggering an enrichment lookup) could, with a naive
"retry everything, immediately, forever" policy, turn one outage into a
self-inflicted request storm: every failed request retried in parallel,
repeatedly, each retry itself likely failing and retrying again - the
classic thundering-herd failure mode that makes a struggling provider's
situation worse instead of better, and can itself trigger the provider's
own rate limiting.

This phase's bounded max-attempts + capped exponential backoff + jitter
directly limits the *per-request* amplification (at most 2 retries per
failed lookup, with delay growing rather than constant hammering). It does
**not** solve cross-request concurrency - if 5,000 alerts each trigger an
enrichment call, this client has no shared concurrency limiter or token
bucket across those 5,000 in-flight requests. That is a deliberate,
disclosed limitation, not an oversight: building a distributed rate limiter
or a request-queueing platform was explicitly out of scope for this phase
(see hard constraints) and would be premature without first observing
real concurrency behavior. If/when the platform needs to bound
*concurrent* outbound calls across many alerts, the natural extension point
is a shared semaphore or connection-pool limit at the point where
`run_alert_workflow()` is invoked per alert - not inside this client.

## Failure Philosophy

The platform should fail safely rather than aggressively retry everything:
a provider outage degrades one enrichment lookup to
`EnrichmentUnavailableError` (already fail-closed to `ANALYST_REVIEW` per
the existing triage Rule B), never an unbounded hang, never a silent
infinite retry loop, and never a request storm that makes a struggling
provider's outage worse. Bounded, observable failure is the goal - not
making failures invisible by retrying until something eventually works.

## Consequences

**Benefits:**

- A transient provider blip (a single 503, a brief network hiccup) now
  self-heals within a few hundred milliseconds to a few seconds, instead of
  immediately degrading enrichment for that alert.
- Every retry/failure is structurally logged with enough context
  (`provider`, `operation`, `attempt`, `status_code`, `duration_ms`,
  `retry`, `error_type`) to answer "did this alert's enrichment retry, how
  many times, and why did it eventually fail?" from logs alone.
- No new HTTP client, retry library, or abstraction layer was introduced -
  `BaseIntegrationClient` remains the single place request/response
  plumbing lives, now with resilience built in rather than bolted on
  per-provider.
- Credentials remain absent from every log line and exception message,
  verified explicitly (see the engineering-quality evidence in the
  associated PR/issue) rather than assumed.

**Trade-offs / limitations:**

- No cross-request concurrency control (see "Scale Implications" above) -
  a large simultaneous alert burst can still generate a large number of
  concurrent outbound requests; this client only bounds *retries per
  request*, not total concurrency.
- `Retry-After`'s HTTP-date form is not parsed (only the delay-seconds
  form) - real-world APIs overwhelmingly use delay-seconds for 429
  responses, so this was judged not worth the added parsing complexity
  for this phase; an HTTP-date value simply falls back to computed backoff
  rather than being rejected outright.
- The bare-500-is-not-retried decision is a judgment call, not a universal
  law - some real providers do return 500 for genuinely transient
  conditions. If evidence from a real provider integration later
  contradicts this, it is a one-line change to `RETRYABLE_STATUS_CODES`
  with a documented reason, not an architecture change.
