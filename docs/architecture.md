# Architecture

## Components

- `app/api`: FastAPI routing, request-size control, and safe error responses.
- `app/adapters`: source-specific translation from the CrowdStrike-style synthetic payload.
- `app/models`: typed Pydantic contracts for source, normalized, enrichment, triage, and audit data.
- `app/services`: focused workflow services such as indicator extraction.
- `app/enrichment`: provider interface, fixed synthetic lookup table, mock provider, and failure test double.
- `app/triage`: precedence-ordered deterministic decision engine.

## Data Flow

`POST /api/v1/alerts` validates the source payload, adapts it to `NormalizedAlert`, extracts IP and hash indicators, enriches each indicator, and applies the triage rules. The response preserves normalized evidence and ordered UTC processing history.

## Trust Boundaries

1. **API boundary:** the HTTP body is untrusted. Pydantic validates required fields, enum severity, timestamp awareness, IP syntax, and bounded strings. Middleware rejects bodies above 256 KiB before parsing.
2. **Source-adapter boundary:** vendor-shaped fields are untrusted and are mapped explicitly. The rest of the application only consumes the vendor-neutral normalized model.
3. **Enrichment-provider boundary:** enrichment is external-style evidence and is untrusted and fallible. Stage 1 uses only a deterministic in-memory provider, but the interface models future external providers without coupling triage to them.

## Failure Behaviour

Unavailable enrichment is not evidence of safety. The workflow preserves the alert and indicators, marks enrichment unavailable, and selects `ANALYST_REVIEW` through Rule B. This is fail-closed for decision-making: it never fabricates malicious evidence, and it never fails open to `ESCALATE` or `LOW_RISK`.

## Deterministic Triage

The triage engine is authoritative for Stage 1 because its ordered rules are inspectable, reproducible, and independently testable. Rule B (unavailable enrichment) runs first, Rule A escalates high-risk malicious alerts, Rule C accepts only low/medium benign or low-confidence unknown evidence, and Rule D is an explicit analyst-review catch-all.

## Provider Abstraction

`EnrichmentProvider` keeps the workflow independent from any vendor or transport. The fixed `SYNTHETIC_LOOKUP_TABLE` is deliberately centralized and documented so a reviewer can trace fixture evidence to enrichment and triage without guessing. A future provider can replace the mock through dependency injection.

## Future AI Assistance

A later stage can add an investigation service after deterministic triage, return a typed AI investigation proposal, validate it, and fall back to this authoritative triage result. No Stage 2 capability is required to change the current adapter, provider, or response boundaries.
