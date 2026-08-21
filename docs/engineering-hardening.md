# Engineering Hardening

## Status

- **Phase 1 — Baseline & Architecture: COMPLETE** (2026-08-20)
- **Phase 2 — Engineering Debt Audit: COMPLETE** (2026-08-20) — 3 issues filed
- **Phase 3 — Quality Tooling Baseline: COMPLETE** (2026-08-20) — all checks clean, no fixes needed
- **Phase 4 — CI Quality Gates: COMPLETE** (2026-08-20) — added `docker-build` job; pushed to `master` and verified green on GitHub Actions (run [32407729571](https://github.com/TomIsTheHunter/soc-automation/actions/runs/32407729571): `docker-build`, `quality`, `secret-scan` all passed)
- **Phase 5 — Wrap-Up: COMPLETE** (2026-08-20) — see final report delivered in chat; this file's Status/Verification Gaps updated fully
- **Post-audit remediation: COMPLETE** (2026-08-20/21) — all 3 filed issues
  (#1, #2, #3) fixed, tested, and closed; see Findings Log for commit
  references and CI run [32435854241](https://github.com/TomIsTheHunter/soc-automation/actions/runs/32435854241)
- **Phase 6 — Configuration, Secrets & Secure Boundaries: COMPLETE** (2026-08-21)
  — centralized typed `Settings` (`pydantic-settings`) replacing scattered
  `os.environ` reads; repository + full-history secrets audit found nothing
  (no new findings); `.env.example` kept placeholder-only; input-boundary
  and AI-output-boundary test coverage extended. See Findings Log entry
  below for full detail.

Secret Handling Protocol: `secret_leaks.md` created at repo root and added to
`.gitignore` (committed alone, commit `f33ab2b`). No secrets found in the
repository during Phase 1 inspection (see Verification Gaps — this was a
read-through, not a dedicated scan; Phase 2/3 includes `gitleaks`/`pip-audit`
already wired into CI). Phase 6 repeated this as a dedicated, explicit
audit (tracked repo + full `git log --all -p` history scan for common
secret patterns) and again found nothing.

## Architecture Map

### Repository shape

This is a small, single-service FastAPI application (`app/`) with **no
database, no message queue, no persistent storage, and no real external
integrations**. Everything is in-memory and stateless per HTTP request:

- Entry point: `app/main.py` (`create_app()` factory, module-level `app`).
- Two routers mounted on the same FastAPI app: `app/api/routes.py` (JSON API,
  `POST /api/v1/alerts`) and `app/web/routes.py` (server-rendered Jinja2 demo
  view, `GET /`, `GET /demo/{scenario_name}`). Both call the same
  `run_alert_workflow()` — there is exactly one pipeline implementation.
- `app/services/workflow.py` is the single source of truth for the pipeline:
  validate → adapt → normalize → extract indicators → enrich → triage →
  build AI context → invoke AI → validate AI output → detect conflicts →
  respond.
- Dependency injection (FastAPI `Depends`) is the seam used both for
  production providers (`MockEnrichmentProvider`, `MockInvestigationAssistant`
  by default) and for test/demo doubles (`FailingEnrichmentProvider`,
  `FailingInvestigationAssistant`, `MalformedInvestigationAssistant`, etc.),
  via `?scenario=` query param (API) or named demo routes (web).
- Dependency management: `uv` + committed `uv.lock`, `pyproject.toml` with
  pinned-range deps, optional extras (`dev`, `live-ai`, `screenshots`) kept
  isolated so CI/base install never needs the live AI SDK or Playwright.
- Config: `app/config.py` reads two env vars (`AI_PROVIDER`,
  `AI_PROVIDER_TIMEOUT_SECONDS`) with safe defaults (`mock`, `8.0s`); no other
  runtime configuration exists. `.env.example` documents this; no secrets are
  required for the default (`mock`) path.
- Only one real secret surface in the whole app: `ANTHROPIC_API_KEY`,
  read directly from `os.environ` in `app/investigation/live.py`, only when
  `AI_PROVIDER != "mock"`. Never logged, never defaulted, never falls back to
  a hardcoded value.

### Alert pipeline trace (one alert, end to end)

| # | Component | Input | Output | Failure Mode(s) | Handling | Observability | Recovery |
|---|---|---|---|---|---|---|---|
| 1 | HTTP ingestion (`app/api/routes.py`, `AlertBodySizeLimitMiddleware` in `app/main.py`) | Raw HTTP JSON body | `CrowdStrikeStyleAlert` or HTTP error | Body > 256 KiB; malformed JSON; unhandled exception | 413 (size), 422 (`RequestValidationError` handler), 500 (generic `Exception` handler) | Generic 500 handler does `logger.exception`; **no per-request correlation ID**; rejected payloads are not logged server-side, only returned to the client | Stateless — client resubmits; no side effects to undo |
| 2 | Pydantic validation (`app/models/alert.py: CrowdStrikeStyleAlert`) | Parsed JSON | Validated model | Missing/invalid fields, bad enum, non-UTC timestamp, bad IP, non-SHA-256 hash, `extra="forbid"` | 422 with field-level `details` | Not logged server-side (client-visible only) | Client corrects and resubmits |
| 3 | Source adapter (`app/adapters/crowdstrike.py`) | Validated `CrowdStrikeStyleAlert` | `NormalizedAlert` (vendor-neutral) | Unsupported `source` value | Raises `UnsupportedSourceError` → 422 (API) / error page (web) | Not logged | Client corrects `source` field |
| 4 | Indicator extraction (`app/services/indicators.py`) | `NormalizedAlert` | `list[Indicator]` (IP/hash only) | None (pure function) | N/A | Count recorded in `processing_history` | N/A |
| 5 | Enrichment (`app/enrichment/providers.py`, fallback logic in `app/services/workflow.py`) | `Indicator` | `EnrichmentResult` per indicator | `EnrichmentUnavailableError` (declared); bare `Exception` (defensive catch-all, documented) | Falls back to `UNKNOWN`/`LOW`/`available=False` for **all** indicators, never a partial/mixed result | `logger.warning` (known-unavailable) / `logger.exception` (unexpected) with alert id; `enriched` history stage records `available` bool | Fails closed: Rule B routes to `ANALYST_REVIEW` rather than assuming safety |
| 6 | Deterministic triage (`app/triage/engine.py`) | `NormalizedAlert`, `EnrichmentResult[]`, `enrichment_available` | `TriageResult` (decision, rules, reason, evidence) | None — 4 ordered rules, last is a total catch-all (`RULE_D`), always produces a decision | N/A (pure function, no I/O) | Decision + evidence recorded in `TriageResult` and `processing_history` | N/A — this is the authoritative decision, nothing downstream can change it |
| 7 | Investigation context build (`app/investigation/context.py`) | Normalized alert, indicators, enrichment, triage | `InvestigationContext` (explicit field allowlist, excludes `source_metadata`) | None (pure function) | N/A | N/A | N/A — data-minimization boundary |
| 8 | AI investigation (`app/investigation/assistant.py` interface; `mock.py` default; `live.py` optional Anthropic) | `InvestigationContext` + timeout | Raw untrusted `dict` | `TimeoutError` (double-enforced: `asyncio.wait_for` at call site + implementation); `InvestigationUnavailableError` (missing key/SDK, live provider error); bare `Exception` (unexpected, caught) | All three degrade to `ai_status=UNAVAILABLE`; `triage` untouched | `processing_history` `ai_requested`/`ai_unavailable` with `reason`; `logger.warning`/`logger.exception` with alert id | Deterministic-only response still returned; response is never blocked by AI failure |
| 9 | AI output validation (`app/investigation/validation.py`) | Raw `dict` + `InvestigationContext` | Validated `InvestigationResult` | `SCHEMA_INVALID`, `POLICY_KEYWORD_MATCH`, `UNGROUNDED_EVIDENCE` | `ai_status=REJECTED`, specific `rejection_reason` recorded | `processing_history` `ai_rejected` with reason; `logger.warning` | Deterministic triage unaffected; `analyst_review_required` forced `True` |
| 10 | Conflict detection (`app/services/workflow.py: ai_conflicts_with_triage`) | `TriageDecision`, `AIRiskAssessment`, `ai_status`, confidence | `conflicts_with_triage` / `analyst_review_required` booleans | None (pure logic) | Surfaces disagreement, never resolves it | `processing_history` `analyst_review` entry | N/A — informational only |
| 11 | Response delivery (`app/api/routes.py` / `app/web/routes.py`) | Full pipeline result | `ProcessingResponse` (JSON) or rendered HTML | Only the generic 500 handler beyond this point | JSON error envelope / error.html | **No persistent audit trail** — `processing_history` exists only in that single HTTP response; nothing is written to disk/DB for later cross-alert correlation | N/A |

### Trust boundaries crossed

1. **HTTP/API boundary** (external, untrusted caller) — step 1–2.
2. **Source-adapter boundary** (vendor-shape trust) — step 3.
3. **Enrichment-provider boundary** (external-service-style, untrusted/fallible) — step 5.
4. **AI boundary** (untrusted model, real external service if `live-ai` is
   used; primary prompt-injection surface) — steps 7–9. Mitigated by: fixed
   system instruction never built from alert content, alert data delimited
   as `<untrusted_alert_data>`, structured-output-only contract
   (`extra="forbid"`, `schema_version`), vocabulary-constrained
   `recommended_actions` enum, keyword denylist, and evidence-grounding
   check. Documented in [docs/ai-security-design.md](ai-security-design.md).
5. **Deterministic-decision authority boundary** — `triage.decision` is
   computed before the AI is ever invoked and is structurally immutable
   after that point (`AIAssistedAnalysis.decision_authority: Literal["DETERMINISTIC"]`).

### Notable architectural facts (not yet judged as findings — that's Phase 2)

- No persistence layer anywhere: every alert's `processing_history` is
  returned once in the HTTP response and then gone. There is no way to look
  up a past decision later, no audit log file/DB, no metrics store.
- No structured/correlated logging: `logging` is used with plain
  `%s`-formatted messages and no request/alert correlation ID threaded
  through log lines (the alert's own `source_alert_id` is passed as a
  format arg in most calls, but there's no consistent structured logging
  approach, e.g. no JSON logs, no request-scoped logger).
- Broad `except Exception` appears in exactly 3 production call sites
  (`app/main.py` generic handler, `app/services/workflow.py` enrichment
  fallback, `app/services/workflow.py` AI fallback) plus one in the optional
  live provider (`app/investigation/live.py`, marked `# noqa: BLE001`). All
  four are documented, intentional fail-safe boundaries with logging — this
  is a candidate for "reviewed and found reasonable" rather than "needs
  fixing" in Phase 2, but will be re-examined there with fresh judgment.
- Rejected/invalid inbound payloads (422s) and unsupported-source rejections
  are not logged server-side at all — only returned to the client. This
  means there's no server-side signal to detect e.g. scanning/fuzzing
  traffic hitting `/api/v1/alerts`.
- CI (`.github/workflows/ci.yml`) already runs: `ruff check`, `ruff format
  --check`, `mypy` (strict), `pytest` (with `pytest-socket` `--disable-socket`
  enforced globally), `pip-audit`, and a separate `gitleaks` full-history
  secret-scan job. This is materially more mature than a typical baseline —
  Phase 3/4 will need to verify these actually pass rather than assume so,
  and look for gaps rather than duplicate what's already there.
- Docs are unusually thorough for the codebase size: `docs/architecture.md`,
  `docs/ai-security-design.md`, and `docs/assumptions.md` already describe
  most of what a Phase 1 audit would normally have to reverse-engineer, and
  `docs/assumptions.md` already flags its own `[UNVERIFIED]` items (e.g. CI
  green-run not locally confirmed, live provider never exercised against a
  real API key).

## Findings Log

Existing issues checked first: the repository's GitHub Issues page
(`TomIsTheHunter/soc-automation`) has **zero open or closed issues**, so
nothing below duplicates prior work.

This codebase is materially more mature than a typical baseline (see Phase 1
notes), so the audit surfaced few genuine, evidenced defects rather than a
long tail of cleanup items. Categories reviewed with **no issue filed**
because the existing behavior was judged reasonable:

- **Exception handling**: exactly 4 broad `except Exception` sites in the
  whole codebase (`app/main.py` generic 500 handler,
  [app/services/workflow.py](../app/services/workflow.py) enrichment and AI
  fallbacks, [app/investigation/live.py](../app/investigation/live.py)
  optional live-provider call). All four are documented, intentional
  fail-safe boundaries with logging (`logger.exception`/`logger.warning`)
  and a narrower, already-caught exception type ahead of them where one
  exists. No narrowing recommended.
- **Type safety**: `Any` usage (11 occurrences) is confined to genuinely
  dynamic data — raw pre-validation AI provider output
  (`dict[str, Any]`), `source_metadata`/`evidence`/history `context` dicts,
  and demo-scenario payload dicts. `mypy --strict` is already configured;
  Phase 3 will confirm it actually passes clean.
- **Logging content**: no stray `print()`, no alert content
  (`command_line`/`detection_description`) or credentials logged anywhere;
  every warning/exception log call is scoped to `source_alert_id` only.
- **Dependencies**: all pinned with upper bounds, `uv.lock` committed,
  dev/live-ai/screenshots extras correctly isolated from the base install
  and from CI. `pip-audit` already runs in CI. No changes recommended.
- **No persistent audit trail** (`processing_history` only exists inside a
  single HTTP response — flagged in Phase 1): considered, but **not filed**
  as a new issue. This is already explicitly acknowledged in
  [README.md](../README.md) ("Roadmap": *"richer audit/evidence
  export"*) and is reasonable for a stateless synthetic-data portfolio
  project. Recorded here so it isn't silently dropped, not as new debt.
- **No authentication/authorization** on `POST /api/v1/alerts`: **not
  filed**. Already explicitly documented as a known limitation in
  [README.md](../README.md) ("Limitations": *"No authentication or
  authorization"*) — a deliberate, disclosed scope boundary, not a hidden
  gap.
- **`AI_PROVIDER` non-`mock` values always attempt the live provider**
  (no plugin registry/typo protection): **not filed** — already documented
  as a deliberate simple design in
  [docs/assumptions.md](assumptions.md).

### Filed findings (pending confirmation)

| ID | Priority | Component | Evidence | Risk | Recommendation |
|---|---|---|---|---|---|
| F1 | **P0 — Security/Reliability** | `app/triage/engine.py` (Rule C) | Rule C's condition (`reputations <= {BENIGN, UNKNOWN}` and `all(...)` over `enrichment`) is **vacuously true when `enrichment == []`**. Any `NormalizedAlert` with severity `LOW`/`MEDIUM` and **no extractable indicators** (no `source_ip`, `destination_ip`, or `file_hash` — all three are `Optional` on the model) matches Rule C and returns `LOW_RISK` with the reason string *"Low or medium severity has only benign or low-confidence unknown enrichment"* — which is false; no enrichment evidence was reviewed at all, because there was nothing to enrich. Confirmed untested: no fixture in `fixtures/alerts.py` and no test in `tests/test_services.py`/`tests/test_integration_workflow.py` exercises a LOW/MEDIUM-severity alert with zero indicators. By contrast, `app/investigation/table.py: reputation_bucket()` already treats an empty `enrichment` list as `"unavailable"`, not `"benign"` — showing the codebase's own precedent for how this case should be handled, which Rule C does not follow. | A LOW/MEDIUM-severity alert whose detection type doesn't naturally carry an IP or file hash (e.g. behavioral, registry, credential-access, or logon-anomaly detections) would auto-resolve to `LOW_RISK` with a misleading analyst-facing justification implying benign evidence was found, when in fact zero enrichment occurred. This is the one component in the system explicitly documented as "authoritative" and "never guesses" (Rule B already fails closed for *unavailable* enrichment) — this is an inconsistent, untested exception to that stated invariant. | Treat "zero indicators extracted" the same as "enrichment unavailable" for Rule C's purposes (e.g. require `enrichment` to be non-empty before Rule C can fire, falling through to the Rule D catch-all/`ANALYST_REVIEW` otherwise). Add regression tests for LOW/MEDIUM severity with zero indicators. |
| F2 | **P1 — Engineering Quality** | `app/main.py` (`validation_exception_handler`, `http_exception_handler`) | Grep-confirmed: neither handler calls `logger` anywhere — only the generic `Exception` handler logs. Malformed payloads (422), oversized bodies (413), and unsupported-source rejections (422, via `UnsupportedSourceError` in `app/adapters/crowdstrike.py`) are returned to the client but leave **zero server-side trace**. | An engineer operating this tomorrow has no way to answer "are clients sending malformed data?", "is something probing `/api/v1/alerts`?", or "why did an integration's alerts silently vanish?" — the only signal is on the client side. This is a genuine, evidenced observability gap at the one boundary that accepts untrusted input. | Add a `logger.info`/`logger.warning` call in both handlers recording the rejection code/reason and `alert_id` if present (never the raw request body, to avoid logging attacker-controlled or oversized content). |
| F3 | **P2 — Polish** | `app/config.py: get_ai_timeout_seconds()` | Only catches `ValueError` from `float(raw)`; never validates sign. A non-positive `AI_PROVIDER_TIMEOUT_SECONDS` (e.g. `"0"` or `"-1"`, a plausible misconfiguration) is accepted as-is, and `asyncio.wait_for(..., timeout<=0)` times out immediately per Python's documented behavior — the AI assistant would silently and permanently appear `"unavailable"` rather than the misconfiguration being caught at startup. | Low severity — this fails closed (deterministic triage is unaffected either way) rather than unsafely, but it is a silent, hard-to-diagnose misconfiguration. | Reject/clamp non-positive values back to `DEFAULT_AI_TIMEOUT_SECONDS` with a startup warning log, mirroring the existing `ValueError` fallback. |

**Filed** (confirmed by user 2026-08-20):

- F1 (P0) → [issues/1](https://github.com/TomIsTheHunter/soc-automation/issues/1) — **RESOLVED** (commit `54d2e3a`, closed 2026-08-20/21): Rule C now requires non-empty `enrichment`; zero-indicator LOW/MEDIUM alerts fall through to `RULE_D_AMBIGUOUS_CATCH_ALL`/`ANALYST_REVIEW`. Regression test added (`tests/test_services.py`) plus a new `ZERO_INDICATOR_ALERT` fixture.
- F2 (P1) → [issues/2](https://github.com/TomIsTheHunter/soc-automation/issues/2) — **RESOLVED** (commit `8e61275`): `app/main.py`'s validation handler, HTTP exception handler, and the oversized-body middleware branch now all log a `logger.warning` (method/path/reason only, never raw body content). Regression test added (`tests/test_api.py`) using `caplog`.
- F3 (P2) → [issues/3](https://github.com/TomIsTheHunter/soc-automation/issues/3) — **RESOLVED** (commit `f5cc61a`): `get_ai_timeout_seconds()` now rejects non-positive values, falling back to the default with a warning log. New `tests/test_config.py` covers missing/valid/non-positive/non-numeric cases.

All three fixes verified locally (ruff/mypy/pytest clean, 51 tests) and on a
real GitHub Actions run
([32435854241](https://github.com/TomIsTheHunter/soc-automation/actions/runs/32435854241),
`quality`/`secret-scan`/`docker-build` all passed) after pushing to
`master`. All three issues auto-closed via `Fixes #N` commit-message
keywords.

### Phase 6 — Configuration, Secrets & Secure Boundaries (2026-08-21)

**Secrets audit (repository-wide, dedicated pass)**: grepped the tracked
working tree for credential-shaped patterns (`sk-...`, `AKIA...`,
`-----BEGIN`, `password=`/`api_key=` literals, credential-bearing URLs) and
separately ran `git log --all -p` over the same patterns to cover full
history, not just the current tree. **No findings** — nothing added to
`secret_leaks.md`, no P0 filed. This is in addition to (not a replacement
for) CI's `gitleaks` full-history job, which continues to run on every
push.

**Configuration centralized**: `app/config.py` now exposes a single typed
`Settings(BaseSettings)` (via `pydantic-settings`, added as a new pinned
dependency) instead of two standalone `os.environ`-reading functions.
`ANTHROPIC_API_KEY` — previously read directly from `os.environ` inside
`app/investigation/live.py` — is now a `SecretStr` field on `Settings`,
passed in explicitly by `app/main.py`; `live.py` no longer touches
`os.environ` at all. Added one new setting, `MAX_ALERT_BODY_BYTES`
(previously a hardcoded `256 * 1024` constant in `app/main.py`), with a
deliberately different missing-value strategy than the two pre-existing
settings: it **fails fast** (`pydantic.ValidationError` at startup) on an
invalid value, whereas `AI_PROVIDER`/`AI_PROVIDER_TIMEOUT_SECONDS`
**degrade gracefully** to their defaults with a warning log (preserving the
exact behavior from issue #3). Full rationale in
[docs/configuration.md](configuration.md).

**Considered and deliberately not added** (to avoid inventing
unsupported requirements): an `ENVIRONMENT`/`LOG_LEVEL` setting. Audited
the codebase for any existing environment-differentiated behavior or
logging-level configuration — there is none (the app has no dev/staging/
prod branching logic anywhere, and no logging level is ever configured
beyond Python's defaults). Adding an unused setting would be
over-engineering; recorded here rather than silently skipped. Also
audited for numeric-configurable "confidence thresholds" — none exist
(`triage/engine.py` and the AI confidence/risk fields are categorical
enums, not numeric thresholds), so there was nothing to centralize there.

**Input boundary strengthening**: the existing `CrowdStrikeStyleAlert`/
`InvestigationResult` models already enforced strict boundaries
(`extra="forbid"`, explicit lengths/patterns, controlled enums) prior to
this phase — deliberately did **not** weaken or duplicate that logic.
Added `tests/test_input_validation.py` (20 tests) proving the full
malformed-input matrix requested for this phase (missing/empty alert ID,
invalid/naive/non-numeric timestamps, unknown severity, wrong-typed
severity, invalid IP/hash IOC values, oversized fields, unexpected nested
data, wrong-typed fields, missing required fields) is rejected at the
Pydantic model boundary, not deeper in the pipeline. Extended the existing
`test_malformed_ai_output_rejected` parametrization in
`tests/test_ai_investigation.py` with oversized-summary,
oversized-key-evidence-list, and unexpected-nested-data cases for the AI
output boundary.

**Observation, not a new finding**: confirmed (via direct model
inspection) that Pydantic's default datetime parsing accepts integer/float
Unix-epoch values as valid, unambiguous UTC timestamps for the `timestamp`
field — this is standard Pydantic v2 behavior, not a defect, and was not
changed. Noted here for future reference since the phase's own test list
specifically calls out "invalid timestamp" handling.

**Verification**: `ruff check`/`ruff format --check`/`mypy --strict`
clean; full suite 81 passed (was 51 before this phase — added 20 in
`tests/test_input_validation.py`, 3 in the AI-output parametrization, and
rewrote `tests/test_config.py` for the new `Settings` model); `pip-audit`
(scoped via `uv export --extra dev`, matching `make audit`) clean with the
new `pydantic-settings`/`python-dotenv` dependencies included.

## Tooling Baseline

All commands run locally (Python 3.12, `.venv`, `uv sync --extra dev` already
installed), matching exactly what `.github/workflows/ci.yml` and the
`Makefile` already run — no new tooling introduced, no existing config
replaced.

| Check | Command | Result |
|---|---|---|
| Lint | `ruff check .` | **Clean** — "All checks passed!" |
| Format | `ruff format --check .` | **Clean** — "40 files already formatted" |
| Type check | `mypy app tests` (strict mode, per `pyproject.toml`) | **Clean** — "Success: no issues found in 37 source files" |
| Tests | `python -m pytest -q` | **Clean** — 43 passed in 1.88s (offline, `--disable-socket` enforced) |
| Dependency audit | `uv export --extra dev --no-hashes` + `pip-audit` | **Clean** — "No known vulnerabilities found" across 69 resolved packages |

**Suppressions reviewed** (none newly found in Phase 3; carried over from
Phase 2 for completeness): exactly one `# noqa: BLE001`
([app/investigation/live.py](../app/investigation/live.py), broad except on
the optional live-provider SDK call, already judged reasonable) and one
`# type: ignore[import-not-found]` (same file, lazy `import anthropic` for
an optional extra never installed by CI — the ignore is correct because the
SDK's types are genuinely unavailable in the base environment). No
globally-disabled rules exist in `pyproject.toml` (`ruff` `select` list has
no matching `ignore`, mypy has no per-module overrides). Nothing was
weakened and no fixes were required to reach a clean baseline.

**Observation (not a finding)**: there is no coverage-measurement tool
(e.g. `pytest-cov`) wired in. Phase 3's scope is lint/format/type-check/test
execution, not coverage measurement, and the existing test suite already
demonstrates thorough manual attention to failure-path coverage (see Phase
2 notes) — introducing a coverage tool now would be adding new tooling
rather than establishing a baseline of what exists, so it is only recorded
here for future reference, not filed as an issue.

## CI Changes

**Existing pipeline reviewed first** ([.github/workflows/ci.yml](../.github/workflows/ci.yml)):
the `quality` job already implements `Dependency install → Lint → Format
check → Type check → Unit tests → Dependency vulnerability audit`
(`uv sync` → `ruff check` → `ruff format --check` → `mypy` → `pytest` →
`pip-audit`), and a separate `secret-scan` job runs full-history `gitleaks`.
This already exceeds the Phase 4 minimum bar
(`Dependency install → Lint → Type check → Unit tests`) — no duplicate or
replacement tooling was introduced.

**Gap found**: the repository ships a `Dockerfile` (used for local
reproducibility per the README), but nothing in CI ever builds it — a
broken `Dockerfile` could go unnoticed indefinitely.

**Change applied** (confirmed via diff review before applying, commit
follows): added a `docker-build` job that runs `docker build -t
soc-automation:ci .` — the same command usable locally, no registry
push, no new secrets, runs as its own parallel job so it doesn't slow down
`quality`/`secret-scan`. No `continue-on-error` — it is a required gate
like every other job.

```diff
   secret-scan:
     runs-on: ubuntu-latest
     steps:
       - uses: actions/checkout@v4
         with:
           fetch-depth: 0
       - name: Gitleaks (full history)
         uses: gitleaks/gitleaks-action@v2
         env:
           GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
+
+  docker-build:
+    runs-on: ubuntu-latest
+    steps:
+      - uses: actions/checkout@v4
+      - name: Build container image
+        run: docker build -t soc-automation:ci .
```

**Not changed**: triggers (`push`/`pull_request` on `master`), the existing
`quality`/`secret-scan` jobs, and no registry push/publish step was added
(out of scope — no deployment target exists for this portfolio project).

## Verification Gaps

- CI green-run status for `.github/workflows/ci.yml`: **resolved**. Phase 3
  confirmed lint/format/type-check/test/dependency-audit all pass locally;
  Phase 4's push triggered a real GitHub Actions run
  ([32407729571](https://github.com/TomIsTheHunter/soc-automation/actions/runs/32407729571))
  which confirmed all three CI jobs (`docker-build`, `quality`,
  `secret-scan`) pass on the actual remote pipeline, not just locally. This
  also resolves the long-standing `[UNVERIFIED]` note in
  `docs/assumptions.md` about CI status never having been confirmed live.
- Secret scanning: **resolved for this audit's scope**. `gitleaks` (full
  history) and `pip-audit` both ran clean as part of the same verified CI
  run above. This is CI-level scanning of the repository as it exists
  today; it does not retroactively guarantee no secret was ever transiently
  present in history before this audit began (no evidence of one was found,
  but this is a scan, not an exhaustive proof).
- Test suite: **resolved**. 43 tests pass locally (Phase 3) and in CI
  (Phase 4 run above).
- The `live-ai` (Anthropic) provider path in `app/investigation/live.py`
  remains **unverified** — flagged as such in `docs/assumptions.md` before
  this audit began, and still true now. It has never been exercised against
  a real API key/account, in this audit or previously. It is optional and
  never required for the base application or CI, so this is a disclosed,
  accepted gap rather than a blocking one.
- The Docker image was never built or run locally in this environment
  (Docker Desktop's engine was not running); its only verification is the
  successful `docker build` in the CI run linked above. The image was never
  smoke-tested (e.g. actually starting the container and hitting `/health`)
  — only that the build itself succeeds. This is a narrower guarantee than
  "the container works," worth knowing if the Dockerfile is relied on for
  more than local reproducibility.
- `secret_leaks.md`: created and gitignored per protocol; no entries were
  ever added to it because no secrets were found during this audit. It
  still exists locally and untracked — see the reminder in the final report
  below.

