# 005. Pagination, Schema Validation, and Data Contracts for the Vulnerability Provider

## Status

Accepted (2026-09-03)

## Context

`app/integrations/base.py: get_paginated()` (added when enrichment
indicator listing was built) already followed a cursor across pages, but
its return type was a bare `list[dict]` - a caller had no way to tell
"the provider genuinely has no more data" from "we stopped early for
safety reasons" from "something went wrong partway through." That
distinction did not matter yet because the only consumer
(`ThreatIntelClient.list_indicators()`) paginated a small, fixed,
well-behaved fixture set.

Vulnerability data is different: a real vulnerability-management API
realistically returns large, changing collections of findings, using
provider-specific field names, with its own evolving schema. Silently
returning a partial collection as if it were complete is actively
dangerous here - "no vulnerabilities found" and "the provider failed
after retrieving some results" must never look the same to a security
decision. This ADR documents the pagination-completion contract, the
provider-schema-evolution handling, and the normalized
`VulnerabilityFinding` model built to support that safely.

## Decision

### Pagination completion is now an explicit, typed result

`get_paginated()` returns `PaginatedResult(items, complete, pages_fetched,
truncated_reason)` instead of a bare list:

- `complete=True`: the provider signaled no more data (no next cursor, or
  `has_more` false) - every page was followed.
- `complete=False` with a specific `truncated_reason` (`"max_pages_reached"`,
  `"max_items_reached"`, `"duplicate_cursor_detected"`): a **safety limit**
  was hit. The requests themselves succeeded - this is a deliberate stop,
  not a failure, and is a valid, inspectable return value.
- **A genuine page-fetch failure is never represented in `PaginatedResult`
  at all.** If `get()` exhausts its own retries on some page (e.g. a
  persistent 503), the resulting `IntegrationError` propagates out of
  `get_paginated()` unchanged - there is no partial-success return value
  to accidentally treat as "good enough." This was the simplest of the
  three options the brief allowed ("an integration exception, a result
  object with completion metadata, or an explicit partial-result state")
  for the failure case specifically, while the result object handles the
  two *deliberate-stop* cases. Mixing "safety limit reached" and "provider
  failed" into the same bucket would have made a genuine outage
  indistinguishable from an intentional bound - keeping them separate
  (return value vs. exception) makes that distinction impossible to miss.
- `ThreatIntelClient.list_indicators()` (the pre-existing pagination
  consumer) was updated to check `result.complete` and raise if not,
  since its contract promises "every known indicator" - it never changed
  behavior for its own fixed fixture data (always completes), but the
  contract is now enforced, not assumed.

### Pagination edge cases handled explicitly

- **Missing next-page token despite `has_more=true`**: `get_paginated()`
  accepts an optional `has_more_key`; if the provider says there is more
  data but supplies no cursor, that is raised as
  `IntegrationValidationError` immediately - never silently treated as
  "done" (which `next_cursor` being falsy would otherwise imply).
- **Duplicate/looping cursor**: every cursor seen is tracked in a `set`;
  if a page's `next_cursor` repeats one already used, pagination stops
  with `truncated_reason="duplicate_cursor_detected"` rather than looping
  until `max_pages` (or forever, if `max_pages` were ever misconfigured).
- **Empty page**: not treated as an error or an automatic "done" signal -
  the *only* thing that ends pagination is the absence of a next
  cursor/`has_more=false`, checked independently of whether the page's
  `items` list happened to be empty. A provider legitimately returning a
  filtered empty page mid-collection is tolerated; the loop simply
  contributes zero items from that page and continues.
- **Unexpectedly large result set**: bounded two ways - `max_pages`
  (request count, pre-existing) and the new `max_items` (collected item
  count). `AssetIntelClient.list_vulnerability_findings()` sets
  `max_items=500` as an explicit, documented collection limit for this
  provider; hitting it truncates (`"max_items_reached"`) rather than
  silently dropping data past the cap with no signal.
- **Provider failure halfway through pagination**: see above - propagates
  as an `IntegrationError`, translated by the adapter into the existing
  `VulnerabilityContextUnavailableError`, exactly like a single-lookup
  failure. Pages already fetched are simply discarded rather than
  half-returned, because a caller cannot safely assume "the first N pages
  represent N/Total of the truth" without the provider's own total count,
  which this contract does not assume exists.

### No separate pagination HTTP path

`get_paginated()` calls `self.get()` for every page - the same
timeout/retry/rate-limit/backoff/structured-logging behavior applies to
page 1, page 2, and page 37 identically. `list_vulnerability_findings()`
does not open its own connection or implement its own retry loop; it is
a thin cursor-following wrapper, same as `list_indicators()`.

### Provider-specific schema vs. internal data contract

```
Provider API response -> Provider schema validation -> Provider adapter -> Internal model validation -> SOC workflow
```

- **`AssetIntelFindingVendorResponse`** (raw, provider-specific: `id`,
  `host_identifier`, `risk`, `cvss_score`, `exploit_probability`,
  `fix_state`, `vendor`, `timestamp`) is validated first, independently of
  the internal contract.
- **`VulnerabilityFinding`** (internal: `vulnerability_id`, `asset_id`,
  `severity`, `cvss`, `exploitability`, `remediation_status`, `source`,
  `observed_at`) is what the rest of the platform would ever see. No
  workflow code understands `risk`, `fix_state`, or `cvss_score` - only
  `app/integrations/vulnerability/asset_intel.py`'s `_normalize_finding()`
  does. If Provider A were replaced by Provider B, only a new adapter and
  raw schema would need to change.
- **Deliberate schema-strictness divergence, called out explicitly**: the
  pre-existing `AssetIntelVendorResponse` (single-asset lookup) is
  `extra="forbid"` - the tightest possible setting. The new
  `AssetIntelFindingVendorResponse` is `extra="ignore"` - a vendor may add
  a harmless new field to an individual finding without breaking this
  client. This project had no prior convention for "how tolerant should a
  provider schema be to unknown fields" (the enrichment/single-asset
  schemas never needed to answer this), so this ADR establishes it: **use
  `extra="ignore"` for any schema representing one item in a
  vendor-controlled, evolving collection; keep `extra="forbid"` for
  schemas representing a single, narrowly-scoped lookup response.** This
  is a pragmatic distinction, not a claim that one is universally more
  correct.
- **Deliberate type strictness for security-relevant fields**: `cvss_score`
  and `exploit_probability` use `Field(strict=True)`. Pydantic's default
  "lax" mode silently coerces a numeric string (`"8.2"`) into a float,
  which would hide a real provider schema change behind an
  auto-repaired value. Strict mode rejects the type change instead - the
  whole finding validation fails, and the caller finds out.
- **Null handling**: `risk`/`fix_state` are required, non-`Optional`
  fields - a JSON `null` for either is rejected the same way a missing
  field is, by construction, not through extra code.
- **Unknown severity/remediation-status values**: mapped to
  `VulnerabilitySeverity.UNKNOWN`/`RemediationStatus.UNKNOWN` - never
  silently defaulted to `LOW`/`OPEN` (a "probably fine" guess that could
  hide a genuinely dangerous, newly-introduced provider classification).
  This mirrors the pre-existing convention already used for
  `Reputation`/`AssetCriticality` unknown values elsewhere in this
  codebase - not a new pattern invented for this task.
- **Semantically-impossible-but-syntactically-valid values**: `cvss_score:
  9001` is a valid JSON number and passes the raw schema (no upper bound
  there, since a real vendor's own numeric range isn't this platform's to
  assume). `VulnerabilityFinding.cvss` (`ge=0.0, le=10.0`) is where this
  gets rejected - the internal model is the platform's own security
  contract and enforces it independently of whatever the raw schema
  allowed.
- **A finding failing validation fails the whole collection call**, rather
  than being silently dropped from an otherwise-"successful" result -
  consistent with the pre-existing single-object providers, which already
  reject the entire response on any schema mismatch rather than
  attempting per-field salvage.
- **Why `VulnerabilitySeverity` is a new enum, not a reuse of
  `AssetCriticality`**: their value vocabularies happen to overlap
  (critical/high/medium/low/unknown), but they answer different
  questions - how important is this *asset*, vs. how severe is this one
  *finding*. Reusing one type for both would read as if a finding's
  severity and an asset's business importance were the same concept; they
  are not, and conflating them was judged a worse outcome than the minor
  duplication of two small enums.

## Observability

Two new structured-log fields were added to the existing
`app.observability` convention (never a new logging mechanism):
`page` (the 1-indexed page number just fetched) and `cumulative_items`
(running total across the pages fetched so far). Three new event names,
following the existing `provider_retry`/`provider_degraded`/
`provider_recovered` naming style: `pagination_page_fetched` (INFO, one
per page), `pagination_completed` (INFO, once, on a full collection),
`pagination_truncated` (WARNING, once, on any bounded/error stop). Only
counts are ever logged - never the fetched items themselves, which could
be a large and/or sensitive payload.

## Retryable / non-retryable failures

Unchanged from [002-provider-resilience.md](002-provider-resilience.md) -
pagination does not introduce new retry semantics; each page is just
another `get()` call subject to the existing policy.

## Bounded behavior

- `max_pages` (request count) and `max_items` (collected item count) both
  bound a single `get_paginated()` call.
- Duplicate-cursor detection bounds the *set* of cursors that can ever be
  followed to the number of genuinely distinct cursors a well-behaved
  provider would produce.

## Scale implications

`max_items=500` for `list_vulnerability_findings()` is a documented,
explicit collection limit appropriate for this synthetic fixture set;
sized to a real fleet's finding volume, this number would need tuning -
the point is that the limit is visible and adjustable, not baked in
silently. This inherits, and does not change, the existing disclosed
limitation from 002/003/004: no cross-request concurrency control across
a burst of many alerts/hosts each triggering their own paginated fetch.

## Failure philosophy

A partial vulnerability collection must never be indistinguishable from a
complete one - `PaginatedResult.complete`/`VulnerabilityCollectionResult.complete`
exist for exactly that reason. A partial collection due to a genuine
provider failure is not even allowed to reach that far; it fails loudly as
an exception instead, exactly like every other integration failure in
this codebase.

## Consequences

**Benefits:**

- Answers this ADR's own test: if a vulnerability provider changed its
  schema, returned many pages, failed mid-collection, or introduced an
  unexpected severity value, the platform now has a specific, tested,
  documented behavior for each - not an assumption.
- No second pagination/HTTP implementation was introduced -
  `get_paginated()` remains the one path, now richer, not duplicated.
- The provider-specific/internal-contract boundary is enforced by code
  (two independent pydantic validation layers), not just documentation.

**Trade-offs / limitations:**

- `get_paginated()`'s return-type change is a small breaking change to its
  one existing caller (`list_indicators()`), updated in the same change;
  any future caller must use `.items`/`.complete` instead of treating the
  return value as a bare list.
- The `max_items` cap can truncate mid-page (the last page's items are cut
  at the exact boundary) - documented as an accepted trade-off for a
  predictable, exact limit rather than always including a whole "extra"
  page past the cap.
- `list_vulnerability_findings()`/`list_findings()` remain unwired into
  `app/services/workflow.py`, matching the rest of the vulnerability
  category's foundation-only status (see
  docs/integration-architecture.md's "What was deliberately not wired").
