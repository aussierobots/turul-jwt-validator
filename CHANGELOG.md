# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] — 2026-08-02

### Changed
- Updated `jsonwebtoken` to `11`, `p256` (dev-dependency) to `0.14`, and
  `base64` (dev-dependency) to `0.23`. No API changes; adopters do not
  need to change any code.
- `rsa` (dev-dependency) stays on `0.9` — `0.10` has no stable release
  on crates.io yet (only release candidates), so the bump is deferred
  until a stable `0.10` lands.

### Fixed
- Updated the ES256 test's P-256 keypair generation for `p256` 0.14's
  API changes: `SecretKey::random` is deprecated in favour of the
  `Generate` trait's `generate()`, and `ToEncodedPoint` was renamed to
  `ToSec1Point`.

## [0.2.0] — 2026-04-23

### Changed
- Version bumped to **0.2.0** to establish this standalone repository as
  the canonical publish origin. The `0.1.x` line on crates.io
  (`0.1.3`–`0.1.9`) was published from the `turul-a2a` workspace's
  embedded copy prior to this extraction; `0.1.0` was an
  incorrectly-ordered publish from the fresh standalone repo and has
  been yanked. `0.2.0` is the first release where the crate name on
  crates.io tracks the standalone repository exclusively.

No API changes between `0.1.9` (the content of the last embedded
publish) and `0.2.0` (this release) beyond the polish items below —
adopters moving the dep from `"0.1"` to `"0.2"` get identical runtime
behaviour.

### Added
- Generic JWT validator with JWKS caching and `kid`-miss refresh.
- Signature verification via `jsonwebtoken` with the `aws_lc_rs` backend.
  Default allowlist is `RS256` + `ES256`; `RS384` / `RS512` / `ES384`
  are opt-in via `JwtValidator::with_algorithms(...)`.
- Audience, issuer, and expiration (`exp`) enforcement.
- Extra-claims capture via `serde_json::Value`.
- Algorithm cross-check between token header `alg` and JWKS-advertised
  `alg` for the matching `kid`, defending against algorithm-confusion.
- End-to-end integration tests using `wiremock`, covering RS256 happy
  path, expired / wrong-audience / wrong-issuer rejection, `kid`-miss
  refetch, scope extraction, extra claims (via `rsa`); ES256 happy path
  exercising the JWKS EC (P-256) branch (via `p256`); and
  `UnsupportedAlgorithm` rejection for HS256 tokens under the default
  allowlist.
- Runnable example `examples/validate-token.rs` that reads a JWKS URL,
  audience, and token from environment variables and prints the parsed
  claims.

## [0.1.0] — 2026-04-23 — YANKED

Incorrectly published as `0.1.0` from the standalone repository when the
`turul-jwt-validator` crate name already had `0.1.3`–`0.1.9` on
crates.io from the embedded copy in `turul-a2a`. Yanked in favour of
`0.2.0`.

[0.2.1]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.2.1
[0.2.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.2.0
[0.1.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.1.0
