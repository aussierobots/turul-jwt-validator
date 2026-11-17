# ADR-001: Detached JWS Sign and Verify API

**Status**: Accepted
**Date**: 2026-11-17
**Requested by**: turul-agent-card, handoff `docs/plan/handoff-turul-jwt-validator.md` in that repo (decision M10 there)
**Related**: turul-mcp-framework ADR-032 (adopts this crate; its `rust_crypto` consumer must not break)

## Context

`JwtValidator` verifies bearer JWTs against a remote JWKS. AI Catalog trust
manifests (AI Catalog spec rev 2026-11-10, "Signed Payload and JWS Construction",
"JWS Algorithm and Key Requirements") are signed as **detached compact JWS**
(`<header>..<sig>`) over caller-supplied payload bytes, checked against one
caller-supplied public JWK. There are no JWT claims, no JWKS URL and no network
access involved. `JwtValidator` cannot express this.

Verified against `jsonwebtoken` 11.1.0:

- `jsonwebtoken::crypto::sign(message, key, alg)` and
  `crypto::verify(signature_b64, message, key, alg)` are public and take raw
  signing-input bytes, so detached input is supported.
- `jsonwebtoken::jws::decode` also runs claim validation (`exp`, `aud`). It is
  not used, because the policy forbids reading claims.
- `DecodingKey::from_ec_components` does not check that the point lies on P-256.
  The crate checks it with `p256`.
- `jsonwebtoken` panics at runtime if both of its crypto backends are enabled
  (`crypto/mod.rs:124`). See Open decision 1.

Constraints:

1. No change in behaviour, signatures or tests of `JwtValidator` or any existing
   public item. Existing consumers, including `default-features = false,
   features = ["rust_crypto"]`, must keep compiling without edits.
2. The detached API must build without `reqwest` or `tokio`.

## Decision

### Feature layout (resolves gate 4; option C, owner-approved)

- `jwks` (new, in `default`): `JwtValidator`, with `reqwest`, `tokio` and `tracing`.
- `aws_lc_rs` and `rust_crypto` (existing): each implies `jwks` and selects the
  jsonwebtoken backend. Existing builds and the API are unchanged.
- `detached_aws_lc_rs` and `detached_rust_crypto` (new): the `detached` module
  with the matching backend and no `reqwest` or `tokio`. Agent-card depends on
  `detached_rust_crypto`.

Gate 4 is re-pointed to
`cargo tree -e normal --no-default-features --features detached_rust_crypto`
(and `detached_aws_lc_rs`), which must show no `reqwest` or `tokio`.

### Public API (`detached` module, owning symbols)

- `check_public_jwk(jwk_json: &[u8]) -> Result<Es256PublicKey, DetachedJwsError>`
  — the only constructor of `Es256PublicKey`. Checks: `kty` EC; `crv` P-256;
  `x` and `y` each base64url-no-pad and exactly 32 bytes; the point lies on
  P-256; no `d` member; if `alg` is present it is `ES256`; if `use` is present
  it is `sig`; if `key_ops` is present it includes `verify`. `kid` is ignored.
- `inspect_detached(detached: &str, policy: &DetachedJwsPolicy) -> Result<serde_json::Map<String, serde_json::Value>, DetachedJwsError>`
  — key-less. Runs policy steps 1–7 below, in the same order and with the same
  errors as `verify_detached`, and stops before the signature. `Ok` does not mean
  the signature is valid or well-formed. Added for turul-agent-card, which must
  report header violations before any DID document or key is fetched, and which
  keeps this crate as its single JWS decoder.
- `verify_detached(detached: &str, payload: &[u8], key: &Es256PublicKey, policy: &DetachedJwsPolicy) -> Result<serde_json::Map<String, serde_json::Value>, DetachedJwsError>`
  — calls the same private check path as `inspect_detached`, then verifies the
  signature (step 8). Returns the decoded protected header.
- `sign_detached_es256(pkcs8_der: &[u8], typ: &str, kid: &str, payload: &[u8]) -> Result<String, DetachedJwsError>`
  — PKCS#8 DER only. Header `{"alg":"ES256","typ":…,"kid":…}` in that order.
- `DetachedJwsPolicy { expected_typ, allowed_algs, forbidden_params }`.
- `DetachedJwsError` — one variant per rule: `Malformed`, `InvalidHeader`,
  `TypMismatch`, `AlgNone`, `AlgNotAllowed`, `B64Present`, `CritPresent`,
  `ForbiddenParam(String)`, `InvalidJwk(String)`, `InvalidSigningKey`,
  `SignatureInvalid`.

Only `inspect_detached`, `verify_detached` and `sign_detached_es256` parse a
detached JWS; only `verify_detached` and `sign_detached_es256` build or check a
detached signing input. The signing input is exactly `header_b64 + "." + b64url(payload)`.

### Policy, checked in `verify_detached`, in this order

1. Input is three dot-separated segments and the middle (payload) segment is
   empty, otherwise `Malformed`. Every segment is strict base64url-no-pad.
2. The header is a JSON object with unique top-level members and an `alg` that is
   a string, otherwise `InvalidHeader`.
3. `alg` is `none` → `AlgNone`.
4. `alg` is not in `allowed_algs` → `AlgNotAllowed`.
5. Any `b64` member → `B64Present`. Any `crit` member → `CritPresent`. No
   parameter is understood by this crate, so any `crit` is rejected. This is
   stricter than RFC 7515 §4.1.11 requires and is intentional.
6. A `forbidden_params` name present → `ForbiddenParam(name)`.
7. `typ` missing or not equal to `expected_typ` → `TypMismatch`.
8. The signature (ES256, raw r‖s, 64 bytes) over the signing input is checked.
   Failure → `SignatureInvalid`.

`aud`, `exp`, `nbf`, `iat` and all other claims are never read.

## Resolved behaviour decisions (owner)

1. **Mixed backends.** jsonwebtoken panics at runtime when both of its backends
   are on. A `compile_error!` in `src/lib.rs` fires when a `detached_*` feature
   is combined with the other backend (for example `detached_rust_crypto` with
   the default `aws_lc_rs`). A detached feature with its own backend feature
   (`detached_rust_crypto,rust_crypto`) compiles. `JwtValidator` builds are not
   guarded, so existing behaviour is unchanged.
2. **High-S signatures are accepted and documented.** A payload can have two
   valid signature strings; the signature bytes must not be used as an
   identifier. The spec is silent on low-S.
3. **Duplicate top-level header members are rejected** as `InvalidHeader`, so a
   verifier that keeps the first member cannot disagree with this one. Nested
   duplicates are not checked.

## Consequences

- Positive: AI Catalog signatures can be verified and produced without network
  access or claim semantics.
- Positive: the policy lives in one module and has one negative test per rule.
- Negative: adds one module, two features and two optional direct dependencies
  (`p256`, `base64`).

## Gates

Each gate must pass with one backend enabled at a time.

- `cargo test --no-default-features --features detached_rust_crypto` and
  `--features detached_aws_lc_rs`: pass. The A.3 signature test verifies the
  RFC 7515 Appendix A.3 signature over the RFC payload. The RFC has no separate
  Appendix F vector; the detached form is that same A.3 signature with its
  payload supplied separately.
- `cargo test --no-default-features --features rust_crypto` and `aws_lc_rs`: pass,
  and `tests/backend_exports.rs` compiles, so the `rust_crypto → jwks` implication
  is covered (mutation-checked).
- One negative test per policy rule (steps 1–8 above) and one per JWK rule.
- `cargo tree -e normal --no-default-features --features detached_rust_crypto`
  and `detached_aws_lc_rs`: no `reqwest` and no `tokio`.
- `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt --check`.
- Existing `JwtValidator` tests are unchanged.

## Revision log

- 2026-11-17 — Proposed. Gate 4 resolved (option C, feature split); agent-card
  agreed to the re-pointed gate. On-curve check resolved (`p256` optional
  dependency). Names, policy order and feature list brought in line with the
  implementation. Behaviour decisions 1–3 resolved and implemented (compile
  guard, high-S accepted, duplicate members rejected). Version 0.3.4. Stays
  Proposed until released.
- 2026-11-17 — Added `inspect_detached` (owner-approved, requested by
  turul-agent-card, decision M12 there). Test asserts identical errors from
  inspect and verify for every header rule.
- 2026-11-17 — Accepted. All gates pass on both backends; Opus pre-release
  re-review found no defects. Released as 0.3.4.
