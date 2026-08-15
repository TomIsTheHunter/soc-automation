# CV / Project Summary

Use in a CV "Projects" section or a LinkedIn project entry.

- **SOC Automation Vertical Slice** &mdash; Built a Python/FastAPI security-automation prototype that ingests synthetic endpoint alerts, normalizes them behind a vendor-independent adapter, and applies a deterministic, precedence-ordered triage engine with full audit history.
- Designed a **bounded AI-assisted investigation layer** (Pydantic-validated structured output, controlled action vocabulary, keyword-denylist and evidence-grounding policy checks) that can summarize and advise but can never override the deterministic security decision or execute any action.
- Implemented **safe-failure engineering**: enrichment and AI provider failures always fail closed to analyst review (never to escalation or false safety), backed by 40+ automated tests enforced fully offline via `pytest-socket`, plus CI-integrated dependency-vulnerability and full-history secret scanning.

This is hands-on engineering/portfolio evidence, not commercial employment or a claim of production deployment.
