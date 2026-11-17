# Architecture Decision Records (ADRs)

Decisions that shape the public API and contracts of `turul-jwt-validator`.
Format follows the turul-mcp-framework ADR convention.

## ADR Format

- **Status**: one of
  - **Proposed** — decided in principle; not yet implemented, or an alternative path still ships. Stays Proposed until the gate in the ADR is met.
  - **Accepted** — decided and implemented.
  - **Superseded by [NNN]** — replaced; the row names its replacement.
- **Context**: problem and constraints
- **Decision**: what was decided, and why
- **Consequences**: positive and negative outcomes
- **Revision log**: dated entries for every change to a governed contract

## Current ADRs

| Number | Title | Status | Date | Description |
|--------|-------|--------|------|-------------|
| [001](./001-detached-jws-api.md) | Detached JWS Sign and Verify API | Accepted | 2026-11-17 | Additive detached-JWS sign/verify and public P-256 JWK check beside `JwtValidator` |
