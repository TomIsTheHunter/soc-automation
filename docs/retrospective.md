# Engineering Retrospective

Written at the end of an eight-phase engineering hardening effort
(baseline audit &rarr; debt audit &rarr; tooling &rarr; CI &rarr; configuration &rarr;
error handling &rarr; structured logging/observability &rarr; this release), on
top of the original three-stage vertical slice. Full phase-by-phase detail
is in [engineering-hardening.md](engineering-hardening.md); this is the
honest summary version.

## What improved

- **A real, evidenced defect was found and fixed, not just theorized.**
  Deterministic triage's Rule C (`app/triage/engine.py`) was vacuously true
  for any LOW/MEDIUM-severity alert with zero extractable indicators,
  auto-resolving it to `LOW_RISK` with a reason string implying benign
  evidence had been reviewed when none existed. This is exactly the kind
  of subtle logic bug that "looks reasonable in review" and only surfaces
  under a specific input shape nobody had written a fixture for. Finding
  it required deliberately auditing invariants ("is empty enrichment ever
  treated as benign?") rather than just reading the code top to bottom.
- **Silent server-side blind spots were closed.** Before this work, 422/413
  rejections and unsupported-source errors left zero server-side trace -
  only the client saw them. An operator had no way to distinguish "no
  traffic" from "traffic being silently rejected." This is now logged
  (with structured fields, not just prose) at the one boundary that
  accepts untrusted input.
- **Configuration went from two scattered `os.environ` reads to one typed,
  centrally validated `Settings` model**, with a genuinely different
  policy per setting (fail-fast for a safety limit like
  `MAX_ALERT_BODY_BYTES`, graceful-degrade-with-warning for everything
  that only affects the advisory AI layer) - and that distinction was a
  deliberate design decision, not an accident of implementation order.
- **Failure handling stopped being implicit.** Every external/fallible
  dependency (enrichment, the live AI provider, the HTTP boundary itself)
  now has a written failure matrix and an explicit retry policy
  ([adr/001-failure-handling.md](adr/001-failure-handling.md)), instead of
  "whatever the try/except happened to do."
- **The system became observable, not just correct.** Structured JSON
  logs with one consistent `alert_id` correlation field mean an alert's
  entire lifecycle - including *why* it degraded, not just *that* it did -
  can be reconstructed from logs alone, and a `/health/ready` endpoint
  distinguishes "unhealthy" from "healthy but degraded" instead of
  collapsing both into a single boolean.
- **Every change was verified, not assumed.** ruff/mypy --strict/pytest/
  pip-audit were run after every phase, not just at the end, and several
  README/documentation claims (endpoints, commands, response shapes) were
  validated against a live running instance for this release rather than
  trusted from memory.

## What remains weak

- **No persistence anywhere.** Every alert's `processing_history` lives
  and dies inside one HTTP response. There is no way to answer "what did
  we decide about this alert last week?" without external log
  aggregation - this project's logs are the closest thing to an audit
  trail, and they are stdout-only today.
- **No authentication or authorization on any endpoint.** This was
  correctly scoped out from the start, but it means the entire safety
  story assumes a trusted caller - a real deployment cannot make that
  assumption.
- **The live AI provider has never been exercised against a real API
  key.** The failure classification logic (`app/investigation/live.py`) is
  unit-tested against a hand-built fake `anthropic` module that mirrors
  the documented exception hierarchy - it has not been proven against the
  real SDK's actual runtime behavior, error message shapes, or edge cases
  the fake doesn't anticipate.
- **Policy validation for AI output is heuristic, not a formal guarantee.**
  The keyword denylist and evidence-grounding check are a reasonable
  defense-in-depth layer, but a sufficiently adversarial or unusual model
  response could still find a gap neither anticipates. This should be
  read as "raises the bar," not "closes the risk."
- **No load, chaos, or volume testing.** Every test proves correctness on
  one alert at a time; nothing here says what happens at realistic SOC
  alert volume, under concurrent load, or when a dependency is slow
  rather than cleanly failed.
- **Observability has no downstream consumer.** Structured logs exist, but
  there is no metrics backend, dashboard, or alerting rule watching for
  `provider_degraded` events - today a human has to already be looking at
  stdout to notice.
- **Environment assumptions were more fragile than expected.** The README
  originally assumed `make` was universally available; validating it
  literally on this project's own Windows development machine found it
  was not installed by default, and command output/log-parsing behavior
  differs between PowerShell and POSIX shells in ways that are easy to
  miss if you only test on one platform (see "What I learned" below).

## What I learned

- **"It looks logged" and "it is safely logged" are different claims.**
  The live AI provider's failure handlers were already logging *something*
  useful before this phase, but they were interpolating the raw SDK
  exception's string representation directly into the message - which,
  for a real provider, can carry request/response detail that shouldn't
  be in a log line. The fix (log the exception's class name as a
  structured field, drop the raw text) only became obvious once I asked
  "what if this exception's `str()` isn't as clean as the fakes I'm
  testing against?" rather than "does a log line get written?"
- **Testing a structured logging schema requires asserting on structure,
  not message text.** Early in this work it would have been easy to keep
  writing `assert "some substring" in message` tests, which is exactly the
  brittleness the observability phase was trying to move away from.
  Switching to asserting on `record.event`/`record.alert_id`/etc. (stored
  via `extra=`) makes the tests describe *what* is guaranteed, not *how it
  happens to be phrased today*.
- **A "clean environment walkthrough" has to be literal, not remembered.**
  I had been running `ruff check .`/`mypy app tests`/`pytest -q` directly
  in this session for months without incident, which meant the README's
  `make lint`/`make test` instructions went unvalidated on the very
  machine that was supposedly the reference environment - `make` was
  never actually installed here. Validating documentation means running
  the documented command, not the command you personally use, even if
  they're "equivalent."
- **mypy strict on a dynamic logging schema needs `getattr`, not attribute
  access.** Tests that read custom fields off a stdlib `LogRecord` (added
  via `extra=`) fail strict type checking with direct attribute access
  (`record.alert_id`) because `LogRecord` doesn't declare those attributes
  - `getattr(record, "alert_id", None)` is the correct, type-safe way to
  read them back in tests, and I only caught this by actually running
  `mypy` after writing the tests, not by inspecting the code.
- **A single fixed field vocabulary is worth enforcing structurally, not
  just by convention.** Deciding once that the correlation field is always
  `alert_id` (never `alert`, `alertId`, or `id`) and routing every log call
  through one `log_event()` helper made that decision durable across every
  module that logs, instead of relying on every future contributor to
  remember a naming convention from documentation.

## What would I do differently if this were processing real customer security alerts?

- **Authentication/authorization would be non-negotiable from day one**,
  not a documented limitation - likely mTLS or signed-request
  authentication for machine-to-machine ingestion (SIEM/EDR &rarr; this
  service), plus RBAC for any analyst-facing surface, before a single real
  alert touched the system.
- **Data sensitivity changes everything about logging.** This project's
  logs deliberately never include hostname/username/command-line content
  because the *synthetic* data has no real sensitivity - with real
  endpoint telemetry, I would need a formal data-classification pass over
  every field before deciding what's loggable at all, likely with
  field-level redaction/tokenization rather than a blanket "don't log
  alert content" rule, and a retention policy with an actual deletion
  mechanism, not just "logs are ephemeral by omission."
- **Auditability would need to be a real store, not a log convention.**
  Every triage decision on a real alert needs to be independently
  reconstructable months later for a compliance or incident-response
  review - that means a persistent, tamper-evident audit trail (append-only
  store, not just structured stdout logs an operator has to have been
  watching), with retention aligned to whatever regulatory/contractual
  obligation applies.
- **Provider dependency risk gets real financial and reliability stakes.**
  A synthetic in-memory enrichment table has no rate limits, no outages,
  and no bill. A real threat-intel API has all three - I'd need circuit
  breakers (not just bounded retries), cost/quota monitoring, and a
  fallback enrichment source, not just a documented "fails closed to
  analyst review" story.
- **AI governance would need an explicit, reviewed policy, not just code
  controls.** The keyword denylist/evidence-grounding checks here are
  reasonable engineering controls, but a real deployment needs a written
  AI usage policy (what the model is and isn't allowed to influence, how
  its outputs are audited, what happens when it's demonstrably wrong,
  how/whether its outputs are used to retrain or tune anything), reviewed
  by whoever owns security policy for the organization - not just decided
  by the engineer who wrote the code.
- **False positives and alert volume would drive the actual design, not
  correctness alone.** At real SOC volume, the deterministic triage rules
  would need tuning against real analyst feedback (a false-positive/
  false-negative tracking loop this project has no concept of), and
  `ANALYST_REVIEW` can't be an unbounded catch-all queue - it needs
  prioritization, SLAs, and a plan for what happens when review volume
  exceeds analyst capacity.
- **Monitoring/alerting and incident response would need to exist before
  launch, not be a "remaining gap."** This release adds structured logs
  and health/readiness endpoints, but nothing consumes them yet. A real
  deployment needs alerting on `provider_degraded`/`unhandled_exception`
  events, an on-call rotation, and a written incident-response runbook
  specifically for "the security triage system itself is degraded" -
  which is a different, higher-stakes incident class than a typical
  internal tool going down.
- **Disaster recovery and high availability would need explicit answers.**
  This is a single stateless process today; a real deployment needs a
  documented RTO/RPO, redundancy across at least one failure domain, and
  a tested failover path - "restart the container" is not a DR plan for a
  security-critical control.
- **Privacy review would need to happen before any real endpoint/user data
  is ingested at all** - not just secrets, but hostnames, usernames, and
  process/command-line data are frequently personally identifiable or
  sensitive in their own right, and would need a formal privacy review
  (and likely a legal/compliance sign-off) that a synthetic-data portfolio
  project never had to obtain.
