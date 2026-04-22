# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-23

### Added
- Initial release. Generic JWT validator with JWKS caching and
  `kid`-miss refresh, extracted from the `turul-a2a` workspace as a
  standalone crate.
- Signature verification via `jsonwebtoken` with the `aws_lc_rs` backend.
  Default allowlist is `RS256` + `ES256`; `RS384` / `RS512` / `ES384`
  are opt-in via `JwtValidator::with_algorithms(...)`.
- Audience, issuer, and expiration (`exp`) enforcement.
- Extra-claims capture via `serde_json::Value`.
- Algorithm cross-check between token header `alg` and JWKS-advertised
  `alg` for the matching `kid`, defending against algorithm-confusion.
- End-to-end integration tests using `wiremock`, covering:
  - RS256 happy path, expired / wrong-audience / wrong-issuer rejection,
    `kid`-miss refetch, scope extraction, extra claims (via `rsa`).
  - ES256 happy path, exercising the JWKS EC (P-256) branch (via `p256`).
  - `UnsupportedAlgorithm` rejection for HS256 tokens under the default
    allowlist.
- Runnable example `examples/validate-token.rs` that reads a JWKS URL,
  audience, and token from environment variables and prints the parsed
  claims.

[0.1.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.1.0
