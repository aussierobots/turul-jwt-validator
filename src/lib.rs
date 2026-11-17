//! Verifies bearer JWTs against a remote JWKS endpoint, with key caching and
//! refresh on an unknown `kid`.
//!
//! Use this crate when an async Rust service must authenticate tokens issued
//! by an external identity provider. [`JwtValidator`] fetches the provider's
//! JWKS, caches the keys in memory, refetches when a token names an unknown
//! `kid` (rate-limited by [`JwtValidator::with_refresh_interval`]), and checks
//! signature, `exp`, audience and, if configured, issuer. It has no
//! dependency on any protocol framework.
//!
//! The token's `alg` header must be on the allowlist and must match the
//! algorithm of the JWKS key for that `kid`, which blocks algorithm-confusion
//! attacks. The default allowlist is `RS256` and `ES256`; widen it with
//! [`JwtValidator::with_algorithms`] to `RS384`, `RS512` or `ES384`.
//!
//! # Example
//!
//! ```toml
//! [dependencies]
//! turul-jwt-validator = "0.3"
//! tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
//! ```
//!
//! ```rust,no_run
//! # #[cfg(feature = "jwks")]
//! use turul_jwt_validator::JwtValidator;
//!
//! # #[cfg(not(feature = "jwks"))]
//! # fn main() {}
//! # #[cfg(feature = "jwks")]
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let validator = JwtValidator::new(
//!     "https://auth.example.com/.well-known/jwks.json",
//!     "my-audience",
//! )
//! .with_issuer("https://auth.example.com");
//!
//! let token = std::env::var("TOKEN")?;
//! let claims = validator.validate(&token).await?;
//! println!("subject: {}", claims.sub);
//! # Ok(())
//! # }
//! ```
//!
//! Failures are reported as [`JwtValidationError`]; JWKS fetch failures carry
//! a [`JwksFetchErrorKind`].
//!
//! # Features
//!
//! | Feature | Default | Enables |
//! |---|---|---|
//! | `aws_lc_rs` | yes | AWS-LC crypto backend for `jsonwebtoken` |
//! | `rust_crypto` | no | Pure-Rust crypto backend instead; use `default-features = false` |
//! | `jwks` | via backends | [`JwtValidator`] (reqwest, tokio); implied by both backends |
//! | `detached_aws_lc_rs`, `detached_rust_crypto` | no | `detached` module with that backend, without reqwest or tokio |
//!
//! # Where next
//!
//! - Resilience options, all off by default: [`JwtValidator::with_stale_window`],
//!   [`JwtValidator::with_retry`], [`JwtValidator::with_max_age`].
//! - [Runnable example](https://github.com/aussierobots/turul-jwt-validator/blob/main/examples/validate-token.rs)
//!   reading the JWKS URL, audience and token from the environment.
//! - [Project page](https://aussierobots.com.au/turul-jwt.html) and the
//!   [Turul family](https://aussierobots.com.au/turul.html).

#[cfg(feature = "jwks")]
mod validator;
#[cfg(feature = "jwks")]
pub use validator::*;

// jsonwebtoken panics at runtime when both of its crypto backends are on. This
// guard turns that into a build error for the detached API only, so existing
// `JwtValidator` builds are unaffected. Use `default-features = false` and one
// backend feature.
#[cfg(all(
    any(feature = "detached_rust_crypto", feature = "detached_aws_lc_rs"),
    any(feature = "aws_lc_rs", feature = "detached_aws_lc_rs"),
    any(feature = "rust_crypto", feature = "detached_rust_crypto"),
))]
compile_error!(
    "turul-jwt-validator: a detached_* feature cannot be combined with the other crypto backend \
     (jsonwebtoken panics at runtime). Use default-features = false with one backend feature."
);

#[cfg(any(feature = "detached_rust_crypto", feature = "detached_aws_lc_rs"))]
pub mod detached;
