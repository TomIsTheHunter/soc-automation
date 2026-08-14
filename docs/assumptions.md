# Assumptions

Assumptions made during implementation, kept here for future reference
rather than scattered across commit messages and chat history.

## Environment / tooling

- `uv` was unavailable in the authoring environment at the start of Stage 1;
  dependencies were installed and verified with `pip` as a fallback. `uv`
  was later available and used to generate `uv.lock`, which is committed.
  A fresh clone should prefer `uv sync --extra dev`.
- Python 3.12.10 (system interpreter) was the only interpreter available;
  no version matrix was tested.
- CI (`.github/workflows/ci.yml`) is written for `uv` and has not been run
  on actual GitHub Actions infrastructure - only validated locally via the
  equivalent `ruff` / `mypy` / `pytest` commands.
- No real GitHub repository exists yet; the README CI badge URL
  (`github.com/example/soc-automation`) is a placeholder and must be
  updated once the repository is pushed.

## Stage 1

- "CrowdStrike-style synthetic alert" fields (process name, command line,
  file hash, source/destination IP, severity) were chosen based on common
  EDR alert shapes but are not derived from any real CrowdStrike schema or
  documentation.
- File hashes are treated as SHA-256 (64 hex chars) throughout; no other
  hash algorithm is supported.
- The 256 KiB request body limit is an arbitrary but reasonable bound for
  a single alert payload; it is not derived from a specific requirement.
- `EnrichmentResult.source` defaults to `"mock-threat-intelligence"`;
  unavailable results use the literal string `"unavailable"` rather than a
  dedicated enum, since only Stage 1's `available: bool` flag is treated
  as authoritative for availability.

## Stage 2

- The mock AI lookup table's severity/reputation "bucket" functions
  (`severity_bucket`, `reputation_bucket` in `app/investigation/table.py`)
  are original design choices, not given verbatim in the request. In
  particular, `reputation_bucket` treats "unknown reputation with low
  confidence" as equivalent to "benign" for table-matching purposes,
  mirroring the deterministic Rule C definition of safe-looking evidence -
  this was necessary to make the Stage 1 fixtures produce non-`UNCERTAIN`
  mock AI results.
- `AIAssistedAnalysis.analyst_review_required` is set to `True` whenever
  the AI status is not `available`, the AI conflicts with triage, or the
  AI confidence is `LOW`. This combination is a reasonable interpretation
  of the spec, not an explicit table given in the request.
- The optional live provider (`app/investigation/live.py`) targets the
  Anthropic Messages API shape and expects the model to return raw JSON
  text matching the `InvestigationResult` schema. It has not been
  exercised against a real Anthropic account/API key - it is implemented
  behind the `live-ai` extra but unverified end-to-end.
- `AI_PROVIDER` values other than `"mock"` are assumed to mean "try the
  live provider"; there is no explicit provider registry/plugin system.
- No fixture was added specifically for "prompt injection" alerts;
  injection-style text is constructed inline in
  `tests/test_ai_investigation.py` rather than added to
  `fixtures/alerts.py`, since it is only needed for two trust-boundary
  tests and not for demonstrating a triage outcome.
