# Integration Architecture

This document describes the Sprint 2 integration layer: how the SOC
Automation Platform connects to external enterprise security systems
(threat intelligence, vulnerability/asset context, case management)
without letting any single vendor's API shape leak into the rest of the
application. It is kept accurate to the implementation in
[app/integrations/](../app/integrations/) - if this file and the code
disagree, the code is correct and this file has drifted.

Monday established the foundation plus **one** mock-backed enrichment
provider. Tuesday (see
[adr/002-provider-resilience.md](adr/002-provider-resilience.md)) added
timeouts, bounded retry/backoff, and rate-limit (429/`Retry-After`)
handling on top of that same foundation. Follow-up passes added a runtime
enrichment-provider selector (`ENRICHMENT_PROVIDER`, see
[configuration.md](configuration.md#enrichment-provider-selection-appmainpy-select_enrichment_provider)),
bounded cursor pagination (`BaseIntegrationClient.get_paginated`), the
vulnerability/asset-context provider category, and the case-management
provider category with idempotent writes (see
[adr/003-idempotent-writes.md](adr/003-idempotent-writes.md)). A final
follow-up added inbound webhook ingestion with signature verification
(see [adr/004-webhook-ingestion.md](adr/004-webhook-ingestion.md)),
completing every area named in Issue #4 except pagination-adjacent
extras (concurrency limiting) and the vulnerability/case-management
categories' workflow wiring, both explicitly disclosed as deferred below.

## Why an integration layer exists

Before this phase, the only "provider" abstraction in the codebase was
`app.enrichment.providers.EnrichmentProvider`, satisfied exclusively by an
in-memory synthetic lookup table (`app/enrichment/table.py`) - there was no
real external-API boundary anywhere in the application, and therefore no
established convention for HTTP clients, authentication, or provider error
handling.

Calling an external API directly from `app/services/workflow.py` (or from
inside a provider implementation) would tie the platform's business logic
to one vendor's URL structure, auth scheme, and JSON shape. An integration
layer exists to keep that vendor-specific detail contained to one small,
swappable adapter per provider, so the workflow and triage engine never
need to know or care which vendor answered a lookup.

## Provider categories

```
SOC Automation Platform
          |
          v
   Integration Layer
     /      |      \
    /       |       \
Enrichment Vulnerability Case Management
    |          |          |
 Provider A  Provider A  Provider A
 Provider B  (this doc)  (this doc)
 (this doc)
```

- **Enrichment provider** - enrich security indicators (IPs, domains, URLs,
  hashes). Interface: `app.enrichment.providers.EnrichmentProvider`
  (pre-existing, reused as-is). Implementations today: `MockEnrichmentProvider`
  (in-memory, pre-existing) and `ThreatIntelEnrichmentProvider` (new,
  mock-backed HTTP integration, this phase).
- **Vulnerability/context provider** - retrieve vulnerability or asset
  context for a hostname. Interface: `app.vulnerability.providers.VulnerabilityProvider`
  (new, mirroring `EnrichmentProvider`). Implementations: `MockVulnerabilityProvider`
  (in-memory) and `AssetIntelVulnerabilityProvider` (mock-backed HTTP
  integration). Foundation only - not yet consumed by `app/services/workflow.py`
  or exposed via any API/runtime selector; see "What was deliberately not
  wired" below.
- **Case-management provider** - create SOC cases/incidents/tickets.
  Interface: `app.case_management.providers.CaseManagementProvider` (new).
  Implementations: `MockCaseManagementProvider` (in-memory, idempotent per
  alert ID by default) and `IncidentDeskCaseManagementProvider`
  (mock-backed HTTP integration). The only category whose operation is a
  **write** rather than a lookup - see
  [adr/003-idempotent-writes.md](adr/003-idempotent-writes.md) for why
  that required a new `BaseIntegrationClient.post()` with idempotency-key
  support. Foundation only - not yet consumed by the SOC workflow.

## Internal normalized models: reused, not reinvented

The task brief's example enrichment shape is `indicator, indicator_type,
reputation, confidence, source, first_seen, last_seen, tags`. This
application **already has** a normalized enrichment model that the
deterministic triage engine depends on:
[`app.models.workflow.EnrichmentResult`](../app/models/workflow.py)
(`indicator`, `reputation`, `confidence`, `source`, `category`,
`available`).

Per the "reuse over invention" constraint, `ThreatIntelEnrichmentProvider`
adapts the vendor's raw response into this **existing** model rather than
introducing a second, parallel "normalized enrichment result" type.
Concretely, the vendor's mock response includes `first_seen`/`last_seen`/
`tags` fields that are **deliberately not propagated** into
`EnrichmentResult` - nothing in `app/triage/engine.py` or elsewhere
branches on those concepts today, so adding unused fields would be
speculative, over-engineered plumbing (the same judgment call already
documented for settings in [configuration.md](configuration.md)). The
`tags[0]` value is mapped onto the existing `category` field, which
already exists for exactly this kind of extra evidence context. If a
future provider or workflow rule needs first/last-seen timestamps or a
full tag list, extend `EnrichmentResult` then, with a concrete consumer in
hand - not speculatively now.

```
Provider API response -> Provider adapter -> EnrichmentResult -> SOC workflow / triage engine
```

The vulnerability/asset-context category has no pre-existing model to
reuse (the workflow never handled this concept before), so a new,
deliberately minimal model was created instead:
[`app.models.vulnerability.VulnerabilityContext`](../app/models/vulnerability.py)
(`hostname`, `criticality`, `critical_vulnerability_count`, `source`,
`available`). No CVE lists, patch status, or OS metadata - nothing
consumes those concepts yet, so they were not spec'd in ahead of a real
consumer, following the exact same discipline as `EnrichmentResult` above.

Case management is the same story: [`app.models.case.CaseResult`](../app/models/case.py)
(`case_id`, `status`, `source`) is the entire model - no ticket priority,
assignee, comments, or timestamps, since nothing consumes those yet
either.

## Provider adapter responsibilities

Each adapter (e.g. `ThreatIntelEnrichmentProvider`) is responsible for:

1. Calling its own client (which owns the vendor's endpoint paths).
2. Validating the raw response against a **provider-specific** Pydantic
   schema (`ThreatIntelVendorResponse`, `extra="forbid"`, never exported
   outside its module) before trusting any field.
3. Mapping that raw schema onto the platform's existing normalized model
   (`EnrichmentResult`), including any vendor-specific business rules
   (e.g. verdict -> `Reputation`, score -> `Confidence`).
4. Translating integration-layer exceptions (`IntegrationError` and
   subclasses) into the concept the rest of the application already
   understands - `EnrichmentUnavailableError` - so `app/services/workflow.py`
   never needs a provider-specific except clause. A `404` ("indicator not
   found") is treated as a legitimate `Reputation.UNKNOWN` result, not a
   failure - the provider *did* answer, it just has no data.

## Base client responsibilities (`app/integrations/base.py`)

`BaseIntegrationClient` centralizes everything a provider adapter would
otherwise duplicate:

- Base URL, separate connect/read timeouts (`httpx.Timeout`).
- Auth header construction via a pluggable `AuthStrategy` (see below).
- Standard headers (`Accept: application/json`).
- Bounded retry with exponential backoff and `Retry-After` handling for
  transient failures (429/502/503/504, timeouts, connection errors) - see
  [adr/002-provider-resilience.md](adr/002-provider-resilience.md) for the
  full policy and reasoning.
- Request execution and classification of every failure mode - timeout,
  network error, HTTP status, invalid/unexpected JSON - into a specific
  `IntegrationError` subclass (see the error model below).
- Structured logging of every retry and failure via the existing
  `app.observability.log_event` helper (`event="provider_retry"` /
  `"provider_degraded"` / `"provider_recovered"`, `provider`, `operation`,
  `attempt`, `status_code`, `duration_ms`, `retry`, `error_type` - never
  raw request/response bodies or credentials).
- Bounded cursor pagination (`get_paginated()`): a loop over `get()` that
  follows a `next_cursor` field across pages, capped at `max_pages` so a
  broken or malicious provider returning a cursor loop can never cause an
  unbounded number of requests - the same bounded philosophy as retries.
  Demonstrated by `ThreatIntelClient.list_indicators()` against a
  synthetic multi-page endpoint (not wired into the SOC workflow - nothing
  there needs a bulk indicator listing today).
- Idempotency-safe writes (`post()`): shares the identical retry/timeout/
  classification loop as `get()` (`_send_with_retries()`, extracted from
  `get()` when `post()` was added, not a second implementation), plus a
  stable `Idempotency-Key` header generated once per call and reused
  across that call's retries - see
  [adr/003-idempotent-writes.md](adr/003-idempotent-writes.md) for why a
  write needed this and a read never did. Demonstrated by
  `IncidentDeskClient.create_case()`.

It deliberately does **not** implement cross-request concurrency limiting
or a generic request-building DSL - those remain named as explicit,
deferred areas of work (Issue #4), not silently skipped. It has exactly
one level of abstraction (one client class, one `RetryPolicy` dataclass,
plus two small auth strategy classes) - resilience and pagination were
both added by extending this same class, not by introducing a second HTTP
or retry framework.

## Authentication

```
environment/configuration (Settings) -> client initialization (ThreatIntelClient)
    -> AuthStrategy.headers() -> attached to every outbound request
```

Two strategies are implemented in `app/integrations/base.py`:

- `ApiKeyAuth(api_key, header_name="X-API-Key")` - used by
  `ThreatIntelClient` (a common enterprise threat-intel convention).
- `BearerTokenAuth(token)` - applies `Authorization: Bearer <token>`; not
  wired to a provider yet this phase (no provider needs it), but covered
  directly by `tests/test_integrations_base.py` so the strategy itself is
  proven correct ahead of the provider that will need it (likely
  case-management, per common enterprise API conventions).

Configuration flows through the existing `Settings` model
(`app/config.py`), matching the pattern already established for
`ANTHROPIC_API_KEY` - no new configuration mechanism was introduced:

- `THREAT_INTEL_BASE_URL` (default `https://mock-threat-intel.example/v1` -
  an IANA reserved-for-documentation domain, deliberately never a real one).
- `THREAT_INTEL_API_KEY` (default `mock-threat-intel-api-key`) - safe to
  default because it only ever authenticates against the in-process mocked
  HTTP transport below, never a live vendor; see "Credential handling" below.

## The mock vendor boundary

`ThreatIntelClient` is a real `httpx`-based HTTP client - it builds
requests, attaches auth headers, and parses responses exactly as it would
against a live vendor. The only thing swapped is the *transport*:
`httpx.MockTransport(mock_threat_intel_transport)` stands in for the
vendor, the same technique `tests/conftest.py` already uses
(`httpx.ASGITransport`) to exercise the FastAPI app itself without a real
socket. `mock_threat_intel_transport` validates the API-key header and
returns vendor-shaped JSON (or 401/404), so the authentication and error
paths are genuinely exercised, not assumed.

```
SOC workflow -> ThreatIntelEnrichmentProvider.enrich()
  -> ThreatIntelClient.lookup_indicator()
  -> BaseIntegrationClient.get() (auth headers, timeout, status handling)
  -> httpx.MockTransport (simulated vendor)
  -> ThreatIntelVendorResponse (raw provider schema, validated)
  -> EnrichmentResult (normalized internal model)
```

This is a real, load-bearing HTTP client; only the socket is mocked.
Nothing in the workflow, triage engine, or provider adapter changes if the
transport is later pointed at a real vendor endpoint (`transport=None`
uses a real `httpx.Client` connection to `base_url`).

## Error model (`app/integrations/errors.py`)

| Exception | Condition | Retried? | Adapter translation |
|---|---|---|---|
| `IntegrationAuthError` | HTTP 401/403 | No | `EnrichmentUnavailableError` |
| `IntegrationNotFoundError` | HTTP 404 | No | `Reputation.UNKNOWN` result (not a failure) |
| `IntegrationRateLimitedError` | HTTP 429, even after bounded retries | Yes, bounded, honors `Retry-After` | `EnrichmentUnavailableError` |
| `IntegrationValidationError` | Invalid JSON, or JSON that fails `ThreatIntelVendorResponse` schema validation | No | `EnrichmentUnavailableError` |
| `IntegrationServerError` | HTTP 5xx | Only 502/503/504; a bare 500 is not retried (see the ADR) | `EnrichmentUnavailableError` |
| `IntegrationTimeoutError` | Request timeout or connection failure | Yes, bounded | `EnrichmentUnavailableError` |
| `IntegrationUnexpectedError` | Any other non-2xx status or unclassified `httpx` error | No | `EnrichmentUnavailableError` |

The full retry/backoff/rate-limit policy and the reasoning behind each
"retried?" column above is documented in
[adr/002-provider-resilience.md](adr/002-provider-resilience.md) - this
table is a summary, not the source of truth.

Every subclass carries only `provider` (a name) and `status_code` (an int)
as structured attributes - never headers, query strings, or the response
body, so a caller cannot accidentally log a credential by logging the
exception. This mirrors the existing small, reused exception style already
established in this codebase (`EnrichmentUnavailableError`,
`InvestigationUnavailableError`, `UnsupportedSourceError`).

Collapsing every `IntegrationError` subclass to `EnrichmentUnavailableError`
at the adapter boundary is deliberate: `app/services/workflow.py` already
has a well-tested, fail-closed handling path for that one exception
(enrichment marked unavailable, Rule B routes to `ANALYST_REVIEW`) - see
[adr/001-failure-handling.md](adr/001-failure-handling.md). No workflow
code changed to support this new provider.

## Credential handling rules

- Credentials are read once, from `Settings` (`app/config.py`), and passed
  explicitly into `ThreatIntelClient(api_key=...)` - no integration code
  reads `os.environ` directly, matching the existing
  `ANTHROPIC_API_KEY` -> `AnthropicInvestigationAssistant(api_key=...)`
  pattern in `app/main.py`.
- `IntegrationError` messages only ever include the provider name and HTTP
  status code (see table above) - never headers or bodies.
- `mock_threat_intel_transport` never echoes the API key back into a
  response body, even on 401.
- Verified explicitly for this phase (not just assumed - see the repo's
  final summary for the exact commands run):
  - `grep`/text search across the new `app/integrations/` tree and its
    tests for header-like or credential-like literals in log/exception
    strings - none found.
  - Every new test that triggers an auth failure
    (`test_401_403_raise_auth_error_without_retry`,
    `test_401_is_classified_and_raises_enrichment_unavailable`) asserts the
    configured key/secret string does **not** appear anywhere in the
    raised exception's `str()`; retry-path tests
    (`test_retry_and_failure_logs_never_leak_the_api_key`) additionally
    assert it across every captured log record, including all structured
    fields, not just the message string.
  - `THREAT_INTEL_API_KEY`'s default value is a clearly-labeled placeholder
    (`mock-threat-intel-api-key`) that only ever authenticates against the
    in-process mock transport above - it is not a value that needs to stay
    secret, and is treated the same as the existing synthetic hash/IP
    constants in `app/enrichment/table.py` and `fixtures/alerts.py`.

## Webhook ingestion (inbound)

Every provider category above is outbound: this platform calls a vendor.
`app/api/webhooks.py`'s `POST /api/v1/webhooks/incident-desk` is the one
**inbound** boundary - a vendor calling this platform, e.g. to push a
case-status update this platform cannot poll for. That is a materially
different trust boundary (anyone on the network can attempt to call it,
not just this application on its own schedule), so it needed its own
security model rather than reusing the outbound `BaseIntegrationClient`
machinery. See [adr/004-webhook-ingestion.md](adr/004-webhook-ingestion.md)
for the full design; summarized here:

- **HMAC-SHA256 signature verification** (`X-Incident-Desk-Signature:
  sha256=<hexdigest>`, computed over the raw request body, checked with
  `hmac.compare_digest` before any JSON parsing) - fail closed on
  missing/malformed/non-matching signatures (401).
- **Strict schema validation** (`IncidentDeskWebhookPayload`,
  `extra="forbid"`, UTC-aware timestamp, controlled `event`/`status`
  vocabularies) after signature verification - a valid signature proves
  authenticity, not content validity (422 on schema failure).
- **Bounded in-memory duplicate-delivery detection** (`delivery_id`,
  capped at 1000 tracked deliveries via an LRU) - most webhook providers
  retry, so the same delivery can legitimately arrive twice; a duplicate
  is acknowledged (200), not rejected.
- **Request body size limit before the body is read**: the existing
  `AlertBodySizeLimitMiddleware` was generalized into
  `RequestBodySizeLimitMiddleware` (a path -> byte-limit map) rather than
  writing a second, parallel size-limiting middleware for this one new
  path.
- **No persistence**: a verified webhook is logged
  (`event="webhook_received"`) and acknowledged - it does not update any
  case record, because this application has no database (see
  [architecture.md](architecture.md)) and this phase does not add one.

New settings: `INCIDENT_DESK_WEBHOOK_SECRET` (safe mock default, mirroring
`THREAT_INTEL_API_KEY`) and `MAX_WEBHOOK_BODY_BYTES` (fail-fast, mirroring
`MAX_ALERT_BODY_BYTES`).

## Provider interchangeability - demonstrated, not just asserted

`tests/test_threat_intel_provider.py::test_provider_interchangeability_with_deterministic_triage`
and `::test_provider_interchangeability_on_benign_alert` run the real
indicator-extraction and triage pipeline against both `MockEnrichmentProvider`
and `ThreatIntelEnrichmentProvider` for the same alert fixtures, and assert
on an identical `TriageResult` (`decision` and `rules_triggered`) from
both. Neither `app/services/workflow.py` nor `app/triage/engine.py` needed
any change to support the new provider - only a new adapter
(`app/integrations/enrichment/threat_intel.py`) was added, and the provider
instance passed to `create_app(enrichment_provider=...)` or constructed
directly in a test is the only thing that differs.

## Adding a future provider

1. Pick the right category interface (`EnrichmentProvider` today; a
   `VulnerabilityProvider`/`CaseManagementProvider` interface would be
   added the same way when that category is built).
2. Add a `<provider>/` package under `app/integrations/<category>/` with:
   a provider-specific Pydantic schema (`extra="forbid"`), a client
   subclassing `BaseIntegrationClient`, and an adapter class implementing
   the category interface, mapping the raw schema onto the **existing**
   normalized model for that category (do not invent a new one unless the
   existing model genuinely cannot represent the data the workflow needs).
3. Add `Settings` fields for its base URL/credentials, following the
   `THREAT_INTEL_*` pattern (explicit, no new configuration mechanism).
4. Add contract tests covering 200/401/404/500/invalid-JSON/invalid-schema
   using an `httpx.MockTransport` handler, plus one interchangeability
   test alongside the existing provider for that category.
5. Wire the new provider into `app/main.py`'s provider-selection point
   (mirroring `select_enrichment_provider`/`ENRICHMENT_PROVIDER`, see
   [configuration.md](configuration.md#enrichment-provider-selection-appmainpy-select_enrichment_provider))
   once the runtime actually needs to choose between providers for that
   category.

No SOC workflow code changes are required by these steps - that is the
property this architecture exists to guarantee.

## Missing/inconsistent conventions found, and what was chosen instead

Per the sprint's constraints, these are called out explicitly rather than
silently resolved:

- **No existing HTTP client convention.** The codebase had no outbound
  HTTP client anywhere (the AI provider uses the `anthropic` SDK directly,
  not raw HTTP). `httpx` was chosen because it was already a dependency
  (previously dev-only, used by `tests/conftest.py` for `ASGITransport`)
  and already supports the exact mock-transport testing technique this
  phase needed - promoted from `dev` to core `dependencies` in
  `pyproject.toml` rather than adding a second HTTP library.
- **No existing integration-specific exception hierarchy.** A small,
  dedicated `IntegrationError` hierarchy was added
  (`app/integrations/errors.py`), mirroring the existing style (small,
  purpose-built `RuntimeError` subclasses) rather than reusing
  `EnrichmentUnavailableError` directly inside the client - the client
  layer needs finer-grained classification (auth vs. not-found vs. server
  vs. timeout) than the workflow layer does, and the adapter is the
  translation point between the two.
- **No existing HTTP-mocking convention.** No `responses`/`respx` package
  was present. `httpx.MockTransport` was chosen as the lightest option that
  still exercises the real client code path, following the precedent
  already set by `tests/conftest.py`'s `httpx.ASGITransport` for the
  FastAPI app itself - no new test dependency was added.

## What was deliberately not wired (this phase)

- `app/main.py: select_enrichment_provider` (new, mirroring
  `select_investigation_assistant`) is wired into `create_app()` via the
  new `ENRICHMENT_PROVIDER` setting - `ENRICHMENT_PROVIDER=mock` (default)
  selects `MockEnrichmentProvider`; any other value attempts
  `ThreatIntelEnrichmentProvider`, degrading to `FailingEnrichmentProvider`
  (never a silently substituted mock) if construction fails. See
  [configuration.md](configuration.md#enrichment-provider-selection-appmainpy-select_enrichment_provider).
- Retries and rate limiting were implemented in a prior phase - see
  [adr/002-provider-resilience.md](adr/002-provider-resilience.md).
  Bounded cursor pagination (`get_paginated()`) was also added, demonstrated
  by `ThreatIntelClient.list_indicators()`. Idempotent writes
  (`post()`, `IncidentDeskClient.create_case()`) were added in a later
  phase - see [adr/003-idempotent-writes.md](adr/003-idempotent-writes.md).
  Webhook ingestion (`POST /api/v1/webhooks/incident-desk`) was added
  this phase - see [adr/004-webhook-ingestion.md](adr/004-webhook-ingestion.md).
  Every area originally named in Issue #4 has now been addressed at the
  foundation level.
- Cross-request concurrency control (e.g. bounding how many enrichment
  calls run in parallel across a large burst of alerts) is a disclosed
  limitation of the resilience work, not an oversight - see the ADR's
  "Scale Implications" section.
- The vulnerability/asset-context provider category
  (`app.vulnerability.providers.VulnerabilityProvider`,
  `MockVulnerabilityProvider`, `AssetIntelVulnerabilityProvider`) exists
  as a foundation, mirroring the enrichment category's shape exactly, but
  is **not** wired into `app/services/workflow.py`, `create_app()`, or any
  API response - nothing in the current workflow/triage logic consumes
  asset criticality or vulnerability counts yet, so there is no runtime
  selector (no `VULNERABILITY_PROVIDER` setting) and no
  `application.state.vulnerability_provider`. `ASSET_INTEL_*` settings
  exist in `Settings` (mirroring `THREAT_INTEL_*`) so wiring is a small,
  low-risk follow-up once a concrete consumer exists - deciding *how*
  asset criticality should influence triage (a new rule? advisory
  evidence only?) is a design decision deliberately left for when that's
  actually needed, not speculated on now.
- Case-management provider category
  (`app.case_management.providers.CaseManagementProvider`,
  `MockCaseManagementProvider`, `IncidentDeskCaseManagementProvider`) is
  built as a foundation, same as vulnerability/asset-context - not wired
  into `app/services/workflow.py`, `create_app()`, or any API response.
  Deciding *when* the workflow should open a case (every `ESCALATE`? only
  after analyst confirmation?) is a product/design decision deliberately
  left for when that's actually needed, not speculated on now.
- The webhook endpoint (`app/api/webhooks.py`) verifies and acknowledges
  inbound case-status updates but does not persist or act on them - this
  application has no database (see [architecture.md](architecture.md)),
  so there is nothing to update. It is also not called by anything in
  this application; it exists purely to receive vendor-initiated
  requests. Duplicate-delivery tracking
  (`application.state.webhook_delivery_ids_seen`) is in-memory and
  per-process - it does not survive a restart and would need a shared
  store (e.g. Redis) behind more than one running instance.
