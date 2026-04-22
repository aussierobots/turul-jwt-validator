# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-04-23

### Added
- Initial release. Generic JWT validator with JWKS caching and `kid`-miss
  refresh, extracted from the `turul-a2a` workspace as a standalone crate.
- RS256/RS384/RS512 and ES256/ES384 verification via `jsonwebtoken` with
  the `aws_lc_rs` crypto backend.
- Audience, issuer, and expiration enforcement; extra-claims capture.
- End-to-end test suite using `wiremock` to serve JWKS and
  `jsonwebtoken` + `rsa` to sign test tokens.

[0.1.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.1.0
