# turul-jwt-validator

Generic JWT validator with JWKS caching and `kid`-miss refresh. No
protocol-specific dependencies — use it from any async Rust project that
needs to verify bearer tokens against a JWKS endpoint.

## Features

- RS256 / RS384 / RS512 and ES256 / ES384 signature verification via
  [`jsonwebtoken`].
- JWKS fetched over HTTPS with an in-memory cache, configurable refresh
  interval, and automatic refetch on `kid` cache miss.
- Audience and issuer claim enforcement.
- Expiration (`exp`) validation.
- Extra-claims extraction via `serde_json::Value`.
- Cross-check: the token's algorithm header must match the JWKS-advertised
  algorithm for the matching `kid`.

## Usage

```rust
use std::time::Duration;
use turul_jwt_validator::JwtValidator;

# async fn demo() -> Result<(), turul_jwt_validator::JwtValidationError> {
let validator = JwtValidator::new(
    "https://auth.example.com/.well-known/jwks.json",
    "my-audience",
)
.with_issuer("https://auth.example.com")
.with_refresh_interval(Duration::from_secs(60));

let claims = validator.validate("eyJhbGc...").await?;
println!("subject: {}", claims.sub);
# Ok(())
# }
```

## AWS Lambda builds — required Zig pin

This crate enables `jsonwebtoken`'s `aws_lc_rs` backend, which links
`aws-lc-sys`. `cargo lambda build` (via `cargo-zigbuild`) currently
requires **Zig 0.15.x**: Zig 0.16 broke the `ar` shim that archives
cc-rs-built libraries such as `aws-lc-sys` and `ring`. Until
`cargo-zigbuild` adds 0.16 support, prepend Zig 0.15 to your `PATH`
before any Lambda build that depends on this crate:

```sh
# macOS (Homebrew):
brew install zig@0.15
export PATH="/opt/homebrew/opt/zig@0.15/bin:$PATH"

cargo lambda build --release -p your-lambda-crate
```

On Linux CI the workaround is typically unnecessary — install whatever
Zig release your distro ships that pre-dates 0.16.

## License

Dual-licensed under [MIT](./LICENSE-MIT) OR
[Apache 2.0](./LICENSE-APACHE) at your option.
