# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] — 2026-08-02

### Added
- `.with_max_age(Duration)` — revocation safety-net. On a `kid`-hit, if
  the cached key is older than `max_age` (measured from the last
  successful fetch), it's treated the same as a cache miss: a refresh
  is attempted before the key is returned, instead of trusting a
  cached key with a matching `kid` indefinitely. Independent of
  `refresh_interval` (which rate-limits how often a refetch attempt
  may fire, not how long a key may be trusted) and unaffected by
  `stale_window` (which only governs what happens when a refresh
  attempt fails). A max-age-triggered refresh that gets skipped by the
  `refresh_interval` cooldown still serves the cached key rather than
  erroring — the same outcome a kid-miss-triggered refresh already
  produces when rate-limited — and, if `.with_retry(...)` is
  configured, goes through the same retry/backoff/timeout path as any
  other refresh. Defaults to unset — cached keys are trusted
  indefinitely on a `kid`-hit, matching pre-existing behavior — so
  existing consumers see no change unless they opt in.

## [0.3.0] — 2026-08-02

### Added
- `.with_stale_window(Duration)` — stale-while-revalidate. If a JWKS
  refresh fails and a cached JWKS exists within this window (measured
  from the last successful fetch), the stale cache is served instead of
  propagating the error (a `tracing::warn!` event is emitted so it's
  observable). Defaults to `Duration::ZERO` — no stale-serve — so
  existing consumers see no change unless they opt in.
- `.with_retry(attempts, base_delay)` — bounded retry with exponential
  backoff for JWKS fetches. The whole retry loop is wrapped in an
  overall timeout ceiling derived from `attempts`/`base_delay`, so a
  slow or hung JWKS endpoint can't block a fetch indefinitely. Defaults
  to `None` (a single attempt, no backoff, no ceiling), matching
  pre-existing behavior.
- `JwksFetchErrorKind` — a `#[non_exhaustive]` categorized-cause enum
  (`Timeout` / `Transport` / `HttpStatus(u16)` / `InvalidJson` /
  `NoSigningKeys`) so consumers can build log/alert filters without
  string-matching `JwtValidationError`'s `Display` output.
- Integration test proving a JWKS response containing both an RSA and
  an EC key in the same `keys` array deserializes and validates
  correctly — guards against a JWK schema regression where `n`/`e` (or
  `x`/`y`/`crv`) become required `String` fields instead of
  `Option<String>`, which would break deserialization of the *entire*
  response the moment a non-matching key type appears anywhere in the
  array.

### Changed
- **Breaking:** `JwtValidationError::JwksFetchError` changed from a
  tuple variant (`JwksFetchError(String)`) to a struct variant
  (`JwksFetchError { kind: JwksFetchErrorKind, message: String }`).
  The `Display` text (`"JWKS fetch error: {message}"`) is unchanged for
  the pre-existing transport-failure and invalid-JSON-body paths, so
  `err.to_string()` output is stable for those cases; code that
  destructures the old tuple shape needs updating.
- JWKS fetch failures are now categorized more precisely on *all* fetch
  paths (not just when `.with_retry` is configured): a non-2xx HTTP
  response is now `HttpStatus(code)` instead of being misreported as
  `InvalidJson` (its body previously failed JSON parsing), and a JWKS
  response with an empty/all-unusable `keys` array is now
  `NoSigningKeys` instead of silently caching zero keys (which
  previously surfaced as `KeyNotFound` on the next lookup instead of a
  fetch error). Both were already failure paths before this change —
  this only fixes which error variant and message they produce.

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

[0.3.1]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.3.1
[0.3.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.3.0
[0.2.1]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.2.1
[0.2.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.2.0
[0.1.0]: https://github.com/aussierobots/turul-jwt-validator/releases/tag/v0.1.0
