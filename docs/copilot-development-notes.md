# Copilot Development Notes

GitHub Copilot (agent mode) was used throughout this project's development. Generated code was not accepted as-is; it was run, tested, and corrected where wrong. Three concrete examples from this project's actual history:

## 1. Offline test enforcement vs. Windows event-loop internals

Early API tests used FastAPI's `TestClient` directly under `pytest-socket`'s global `--disable-socket` guard. Running the suite failed with `SocketBlockedError` &mdash; not because of a real network call, but because Windows' `ProactorEventLoop` creates a local `socket.socketpair()` internally just to start an event loop. The generated fix was reviewed, tested, and corrected: rather than weakening the offline guarantee, the tests were switched to an in-process `httpx.ASGITransport` client with `enable_socket()`/`disable_socket()` toggled precisely around loop creation, so real network calls remain blocked everywhere else.

## 2. Mock AI lookup table logic didn't match deterministic triage semantics

The first implementation of `reputation_bucket()` (`app/investigation/table.py`) required *all* enrichment reputations to be exactly `BENIGN` to match the documented "low-risk" table row. A test (`test_low_risk_fixture_maps_to_low_confidence_high`) failed because the benign fixture's own enrichment legitimately includes one `UNKNOWN`/low-confidence result. Tracing the failure back to Stage 1's own Rule C definition of "safe-looking evidence" (benign, or unknown with low confidence) revealed the mismatch; the fix corrected the bucket logic to mirror that existing rule instead of loosening the test to match the bug.

## 3. Dependency audit scope

Running `pip-audit` directly against the working interpreter initially reported 29 "vulnerabilities" in packages such as `aiohttp`, `gitpython`, and even unrelated projects that happened to share the same global Python environment. That result was not reported at face value; it was recognized as scanning the wrong thing, re-run scoped to this project's own resolved dependency set via `uv export`, which correctly reduced the finding to a single real issue (a `pytest` tmpdir CVE) that was verified against its public advisory before deciding to fix it.
