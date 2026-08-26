# Configuration

This document describes how the application is configured: what can be
set, safe defaults, validation rules, and what happens when something is
missing or invalid. It is kept accurate to the implementation in
[app/config.py](../app/config.py) - if this file and the code disagree, the
code is correct and this file has drifted.

## Architecture

All environment-driven configuration lives in exactly one place:
[app/config.py](../app/config.py)'s `Settings` class, a typed
[`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/)
`BaseSettings` model. No other module reads `os.environ` directly:

- `app/main.py: create_app()` calls `get_settings()` once per application
  instance and stores the result on `application.state.settings`, alongside
  the derived `ai_timeout_seconds` and the selected `investigation_assistant`
  / `enrichment_provider`.
- `app/investigation/live.py: AnthropicInvestigationAssistant` receives its
  API key as an explicit constructor argument (sourced from `Settings` in
  `app/main.py: select_investigation_assistant`) instead of reading
  `ANTHROPIC_API_KEY` itself.
- Tests construct a fresh app (and therefore a fresh `Settings`) per test via
  the `client` fixture (`tests/conftest.py`), so `monkeypatch.setenv`/
  `monkeypatch.delenv` in one test never leaks into another.

`get_settings()` is **not** memoized (no `functools.lru_cache`). This app is
small, stateless, and reads only a handful of environment variables - the
cost of re-reading them is negligible, and skipping the cache keeps
environment-variable-based tests simple and correct with nothing to
invalidate.

`Settings` uses `extra="forbid"`, matching every other model in this
codebase (`app/models/alert.py`, `app/models/investigation.py`, ...):
unrecognized fields passed to `Settings` directly are rejected. This does
not affect normal environment-variable loading - `pydantic-settings` only
pulls in environment variables that match a known field name/alias, so
unrelated OS environment variables (`PATH`, `HOME`, etc.) are never
considered "extra".

## Available configuration

| Variable | Field | Default | Required? | Missing/invalid behavior |
|---|---|---|---|---|
| `AI_PROVIDER` | `ai_provider` | `"mock"` | No | Empty/whitespace-only value **degrades** to the default with a `logger.warning` (see below). Any other non-empty value is used as-is - see "AI provider selection" below for what happens if it can't be constructed. |
| `AI_PROVIDER_TIMEOUT_SECONDS` | `ai_provider_timeout_seconds` | `8.0` | No | Non-numeric or non-positive values **degrade** to the default with a `logger.warning`. Never fails startup. |
| `MAX_ALERT_BODY_BYTES` | `max_alert_body_bytes` | `262144` (256 KiB) | No | Non-numeric or non-positive values **fail fast**: `Settings()` raises `pydantic.ValidationError` at startup. |
| `AI_LIVE_MAX_RETRIES` | `ai_live_max_retries` | `2` | No | Only used by the live Anthropic provider; bounds its built-in retry policy for transient failures (connection errors, timeouts, HTTP 429/5xx). Non-numeric or negative values **degrade** to the default with a `logger.warning`. See [adr/001-failure-handling.md](adr/001-failure-handling.md). |
| `ANTHROPIC_API_KEY` | `anthropic_api_key` | `None` | No (conditionally required) | Only read/needed when `AI_PROVIDER` selects a non-`mock` provider. If unset in that case, the AI assistant degrades to `unavailable` (see below) - the application still starts and serves requests; deterministic triage is unaffected either way. |
| `LOG_LEVEL` | `log_level` | `"INFO"` | No | Controls structured JSON log verbosity (see [operations.md](operations.md)). An unrecognized value **degrades** to the default with a `logger.warning`. Never fails startup. |

All five are read once at application-construction time
(`create_app()` -> `get_settings()`); there is no runtime reconfiguration.

### Why two different missing-value strategies?

This phase made an explicit, intentional choice for each setting rather
than applying one blanket policy:

- **`AI_PROVIDER` / `AI_PROVIDER_TIMEOUT_SECONDS` / `AI_LIVE_MAX_RETRIES`
  degrade gracefully.** All three only affect the advisory,
  non-authoritative AI investigation layer. Deterministic triage
  (`app/triage/engine.py`) is computed independently and is never affected
  by AI configuration, so failing the whole application over a
  misconfigured AI setting would reduce availability for no safety
  benefit. A misconfiguration is still visible (a `logger.warning`), just
  not fatal.
- **`MAX_ALERT_BODY_BYTES` fails fast.** This is a safety limit that bounds
  how much untrusted request data the process will buffer, not an
  operational tuning knob with a forgiving fallback. A malformed value here
  (e.g. a typo'd negative number) should be loud and immediate at startup,
  not silently ignored.
- **`ANTHROPIC_API_KEY` has no default and is never required at startup.**
  The default provider (`mock`) never reads it. It is only consulted if
  `AI_PROVIDER` explicitly selects a live provider, and its absence there is
  itself the documented degraded path (see next section) rather than a
  configuration error.
- **`LOG_LEVEL` degrades gracefully**, matching the AI settings above - a
  typo'd log level should never prevent the application from starting.

## AI provider selection (`app/main.py: select_investigation_assistant`)

- `AI_PROVIDER=mock` (default): always available, fully offline,
  deterministic. Requires no other configuration.
- Any other value: the application attempts to construct the live Anthropic
  provider (`app/investigation/live.py`), which requires both the optional
  `live-ai` extra (`uv sync --extra live-ai`) to be installed **and**
  `ANTHROPIC_API_KEY` to be set. If either is missing, construction fails
  and the app substitutes an explicitly-unavailable assistant
  (`UnavailableInvestigationAssistant`) rather than silently falling back to
  the mock provider - the deterministic triage result is still returned,
  but `ai_assisted_analysis.status` is `"unavailable"` and
  `analyst_review_required` is `true`, honestly reflecting that no AI
  investigation actually happened. This behavior is unchanged from before
  this phase; only the configuration plumbing was centralized.

## Secrets handling

- The only real secret in this application is `ANTHROPIC_API_KEY`. It is
  modeled as `pydantic.SecretStr`, so it is masked in `repr()`/`str()`
  (including in stack traces and debuggers) and is only ever unwrapped via
  `.get_secret_value()` at the single call site that constructs the
  Anthropic client.
- No secret is ever logged. Every `logger.warning`/`logger.exception` call
  in `app/config.py` and `app/investigation/live.py` logs field
  names/error types only, never values.
- `.env` is gitignored (`.gitignore`); only `.env.example` (placeholders
  only, no real-looking values) is committed.
- Repository-wide secrets audit (this phase): no hardcoded API keys,
  tokens, passwords, or credential-bearing URLs were found anywhere in the
  tracked repository or in full git history. See
  [engineering-hardening.md](engineering-hardening.md) for the audit
  record.

## Local configuration

A fresh clone works with zero configuration (`AI_PROVIDER` defaults to
`mock`). To customize locally:

1. Copy the template: `cp .env.example .env` (never commit `.env`).
2. Edit values as needed. For the default offline/demo experience, no edits
   are required.
3. To exercise the live AI provider: install the extra
   (`uv sync --extra live-ai`), set `AI_PROVIDER=live` (or any non-`mock`
   value) and a real `ANTHROPIC_API_KEY` in `.env`.

## Input validation boundaries

Configuration is one boundary; the other is untrusted external data. See
[ai-security-design.md](ai-security-design.md) and
[architecture.md](architecture.md) for the full pipeline trace. In summary:

- Inbound HTTP alert payloads are validated once, at the edge, by
  `app/models/alert.py: CrowdStrikeStyleAlert` (`extra="forbid"`, explicit
  field types/lengths/patterns, a custom validator requiring
  timezone-aware timestamps). Invalid payloads never reach business logic;
  they are rejected with `422` before the adapter/triage/enrichment layers
  are ever invoked. See `tests/test_input_validation.py` for the boundary
  test matrix (missing/empty required fields, invalid timestamps, unknown
  severities, incorrect IOC types/formats, oversized fields, unexpected
  nested/extra data, wrong field types).
- AI-generated output is never trusted automatically. It passes through two
  independent layers in `app/investigation/validation.py` before becoming
  part of the response: schema validation (`InvestigationResult`,
  `extra="forbid"`, constrained enums/lengths) and policy validation
  (keyword denylist + evidence-grounding). Any failure at either layer sets
  `ai_assisted_analysis.status="rejected"` with a specific
  `rejection_reason` and forces `analyst_review_required=true`; the
  deterministic `triage` result is completely unaffected. See
  `tests/test_ai_investigation.py`'s `test_malformed_ai_output_rejected`
  for the malformed-AI-output test matrix.
