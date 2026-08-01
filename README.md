# turul-jwt-validator

Generic JWT validator with JWKS caching and `kid`-miss refresh. No
protocol-specific dependencies — use it from any async Rust project that
needs to verify bearer tokens against a JWKS endpoint.

## Features

- Signature verification via [`jsonwebtoken`] with the `aws_lc_rs`
  backend.
  - **Default allowlist:** `RS256`, `ES256`. Both exercised by the
    integration suite.
  - **Opt-in via `.with_algorithms(...)`:** `RS384`, `RS512`, `ES384`.
    Code paths exist and the JWKS parser accepts them, but integration
    coverage is RS256 + ES256 only. Adopters that enable the extras
    should extend the test matrix in their own project.
- JWKS fetched over HTTPS with an in-memory cache, a configurable
  refresh interval, and automatic refetch on `kid` cache miss.
- Audience and issuer claim enforcement.
- Expiration (`exp`) validation.
- Extra-claims extraction via `serde_json::Value`.
- Cross-check: the token's `alg` header must match the
  JWKS-advertised `alg` for the matching `kid`. This blocks
  algorithm-confusion attacks where a caller submits an HS256
  token using a public key as the HMAC secret.

### Resilience (opt-in)

These are off by default — existing behavior is unchanged unless you
call the corresponding builder method:

- **`.with_stale_window(Duration)`** — if a JWKS refresh fails, keep
  serving the existing cached keys for up to this long (measured from
  the last successful fetch) instead of propagating the error. Defaults
  to `Duration::ZERO` (never stale-serve).
- **`.with_retry(attempts, base_delay)`** — retry a failed JWKS fetch up
  to `attempts` times, with exponential backoff starting at
  `base_delay`. The whole retry loop is bounded by an overall timeout
  ceiling derived from `attempts`/`base_delay`, so a hung endpoint can't
  block indefinitely. Defaults to a single attempt with no backoff or
  ceiling.
- **`JwksFetchErrorKind`** — `JwtValidationError::JwksFetchError` now
  carries a `#[non_exhaustive]` `kind` (`Timeout` / `Transport` /
  `HttpStatus(u16)` / `InvalidJson` / `NoSigningKeys`) alongside the
  `message`, so callers can build log/alert filters without
  string-matching.

## Usage

```rust
use std::time::Duration;
use turul_jwt_validator::JwtValidator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let validator = JwtValidator::new(
        "https://auth.example.com/.well-known/jwks.json",
        "my-audience",
    )
    .with_issuer("https://auth.example.com")
    .with_refresh_interval(Duration::from_secs(60));

    let claims = validator.validate("eyJhbGc...").await?;
    println!("subject: {}", claims.sub);
    Ok(())
}
```

A runnable version lives at
[`examples/validate-token.rs`](./examples/validate-token.rs) and reads
the JWKS URL, audience, and token from environment variables:

```sh
TURUL_JWKS=https://auth.example.com/.well-known/jwks.json \
TURUL_AUDIENCE=my-audience \
TURUL_TOKEN='eyJhbGc...' \
cargo run --example validate-token
```

## AWS Lambda builds — Zig version pin

This crate enables `jsonwebtoken`'s `aws_lc_rs` backend, which links
`aws-lc-sys` (C code built via `cc-rs`). `cargo lambda build` delegates
to `cargo-zigbuild`, whose `ar` shim currently **requires Zig 0.15.x** —
Zig 0.16 broke it, and every `cc-rs`-built crate (`aws-lc-sys`, `ring`,
…) fails to archive. This is a Zig-version issue, not a platform issue:
macOS and Linux are both affected if Zig 0.16+ is first on `PATH`.

Until `cargo-zigbuild` ships Zig 0.16 support, put Zig 0.15 ahead of any
newer Zig on your build host's `PATH`:

```sh
# macOS (Homebrew):
brew install zig@0.15
export PATH="/opt/homebrew/opt/zig@0.15/bin:$PATH"

# Linux: install Zig 0.15.x from a distro package, an upstream
# tarball, or asdf, and ensure it resolves first on PATH.

cargo lambda build --release -p your-lambda-crate
```

If Zig 0.15.x is the only Zig on your host, no action needed. Remove
the pin once `cargo-zigbuild` announces 0.16 compatibility.

## Compatibility

- **MSRV**: Rust 1.85 (`rust-version` in `Cargo.toml`).
- **Edition**: 2024.
- **Semver policy**: this is a `0.x` crate. Minor bumps (`0.1.x` →
  `0.2.0`) may introduce breaking changes; patch bumps are additive or
  bug-fix only.

## See also

- [`turul-a2a-auth`](https://crates.io/crates/turul-a2a-auth) — A2A
  bearer/JWT middleware built on this validator.
- [`turul-a2a`](https://github.com/aussierobots/turul-a2a) — A2A
  (Agent-to-Agent) Protocol framework, first adopter of this crate.

## License

Dual-licensed under [MIT](./LICENSE-MIT) OR [Apache
2.0](./LICENSE-APACHE) at your option.
