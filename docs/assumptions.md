# Assumptions

Assumptions made during implementation, kept here for future reference
rather than scattered across commit messages and chat history.

## Environment / tooling

- [VERIFIED] `uv` is available and the project prefers `uv sync --extra dev`.
  `uv.lock` is committed and used as the reproducible dependency source.
- [VERIFIED] Python 3.12.10 was the interpreter used for local verification;
  no wider version matrix was tested.
- [VERIFIED] The repository has been pushed to the real GitHub remote at
  `https://github.com/TomIsTheHunter/soc-automation` and the workflow is
  configured to trigger on the repository's current default branch (`master`).
- [UNVERIFIED] CI (`.github/workflows/ci.yml`) has not successfully run on
  actual GitHub Actions infrastructure; it has only been validated locally via
  equivalent `ruff` / `mypy` / `pytest` commands.

## Stage 1

- [DESIGN] "CrowdStrike-style synthetic alert" fields (process name, command
  line, file hash, source/destination IP, severity) were chosen based on
  common EDR alert shapes but are not derived from any real CrowdStrike schema
  or documentation.
- [VERIFIED] File hashes are treated as SHA-256 (64 hex chars) throughout; no
  other hash algorithm is supported.
- [DESIGN] The 256 KiB request body limit is an arbitrary but reasonable bound
  for a single alert payload; it is not derived from a specific requirement.
- [VERIFIED] `EnrichmentResult.source` defaults to `"mock-threat-intelligence"`;
  unavailable results use the literal string `"unavailable"` rather than a
  dedicated enum, since only Stage 1's `available: bool` flag is treated as
  authoritative for availability.

## Stage 2

- [DESIGN] The mock AI lookup table's severity/reputation "bucket" functions
  (`severity_bucket`, `reputation_bucket` in `app/investigation/table.py`)
  are original design choices, not given verbatim in the request. In
  particular, `reputation_bucket` treats "unknown reputation with low
  confidence" as equivalent to "benign" for table-matching purposes,
  mirroring the deterministic Rule C definition of safe-looking evidence -
  this was necessary to make the Stage 1 fixtures produce non-`UNCERTAIN`
  mock AI results.
- [VERIFIED] `AIAssistedAnalysis.analyst_review_required` is set to `True`
  whenever the AI status is not `available`, the AI conflicts with triage,
  or the AI confidence is `LOW`. This combination is a documented behavior
  and is exercised by tests.
- [UNVERIFIED] The optional live provider (`app/investigation/live.py`)
  targets the Anthropic Messages API shape and expects the model to return
  raw JSON text matching the `InvestigationResult` schema. It has not been
  exercised against a real Anthropic account/API key and remains behind the
  `live-ai` extra as an optional, unverified path.
- [VERIFIED] `AI_PROVIDER` values other than `"mock"` currently cause the app
  to attempt the live provider path, with a safe fallback to the mock assistant
  if construction fails; there is no plugin registry, and this remains a
  simple configuration-driven design.
- [VERIFIED] No fixture was added specifically for "prompt injection" alerts;
  injection-style text is constructed inline in `tests/test_ai_investigation.py`
  rather than added to `fixtures/alerts.py`, since it is only needed for the
  trust-boundary tests and not for demonstrating a triage outcome.
