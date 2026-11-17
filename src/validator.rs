//! JWT validation against a cached, rate-limited JWKS.
//!
//! Provides [`JwtValidator`], its [`TokenClaims`] output, and the
//! [`JwtValidationError`] and [`JwksFetchErrorKind`] error types.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// Errors from JWT validation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JwtValidationError {
    /// The token failed validation for a reason with no dedicated variant, such as a bad signature.
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    /// The token's `exp` claim is more than 60 seconds in the past (jsonwebtoken's
    /// default leeway).
    #[error("Token expired")]
    TokenExpired,
    /// The token's `aud` claim is missing or does not contain the configured audience.
    #[error("Invalid audience")]
    InvalidAudience,
    /// The token's `iss` claim is missing or does not match the configured issuer.
    #[error("Invalid issuer")]
    InvalidIssuer,
    /// The token's algorithm is not allowed, or differs from the algorithm the JWKS key advertises.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    /// Fetching the JWKS failed.
    #[error("JWKS fetch error: {message}")]
    JwksFetchError {
        /// Categorized cause of the failure.
        kind: JwksFetchErrorKind,
        /// Human-readable description of the failure.
        message: String,
    },
    /// No key with the token's `kid` exists in the JWKS after a refresh attempt,
    /// which the refresh-interval rate limit may have skipped.
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    /// The token header could not be decoded.
    #[error("Decoding error: {0}")]
    DecodingError(String),
}

/// Categorized cause of a JWKS fetch failure.
///
/// Lets consumers build log/alert filters (e.g. distinguish an
/// auth-server outage from a key-rotation/config problem) without
/// string-matching on [`JwtValidationError`]'s `Display` output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwksFetchErrorKind {
    /// Overall fetch (including retries) exceeded its timeout ceiling.
    Timeout,
    /// The HTTP request itself failed (DNS, TLS, connection reset, etc).
    Transport,
    /// The JWKS endpoint responded with a non-2xx HTTP status.
    HttpStatus(u16),
    /// The response body did not parse as JWKS JSON.
    InvalidJson,
    /// The JWKS parsed but contained no usable signing keys.
    NoSigningKeys,
}

/// Validated token claims extracted from a JWT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (`sub`) claim; empty if absent.
    #[serde(default)]
    pub sub: String,
    /// Issuer (`iss`) claim; empty if absent.
    #[serde(default)]
    pub iss: String,
    /// Audience (`aud`) claim, which a JWT may encode as a string or an array.
    #[serde(default)]
    pub aud: serde_json::Value,
    /// Expiration time (`exp`) as seconds since the Unix epoch; `0` if absent.
    #[serde(default)]
    pub exp: u64,
    /// Issued-at time (`iat`) as seconds since the Unix epoch; `0` if absent.
    #[serde(default)]
    pub iat: u64,
    /// Scopes (`scope`) as a space-separated string.
    #[serde(default)]
    pub scope: Option<String>,
    /// All other claims.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkKey {
    kty: String,
    kid: Option<String>,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
}

struct CachedJwks {
    keys: HashMap<String, (DecodingKey, Algorithm)>,
    last_refresh_at: Instant,
}

/// Bounded-retry configuration for JWKS fetches.
#[derive(Debug, Clone, Copy)]
struct RetryConfig {
    attempts: usize,
    base_delay: Duration,
}

impl RetryConfig {
    /// Returns the overall timeout ceiling for the whole retry loop: the sum of
    /// exponential backoff delays between attempts (base_delay, then
    /// doubling), plus one base_delay of request-time headroom per
    /// attempt. Derived purely from the caller's own configuration — no
    /// fixed protocol-specific constants — so it stays proportional to
    /// what was actually asked for.
    fn ceiling(&self) -> Duration {
        let mut ceiling = Duration::ZERO;
        let mut delay = self.base_delay;
        for attempt in 0..self.attempts {
            if attempt > 0 {
                ceiling += delay;
                delay = delay.saturating_mul(2);
            }
            ceiling += self.base_delay;
        }
        ceiling
    }
}

/// JWT validator with JWKS caching and kid-miss refresh.
///
/// Supports RS256 and ES256 by default. Rate-limits JWKS fetches.
pub struct JwtValidator {
    jwks_uri: String,
    cached_jwks: RwLock<Option<CachedJwks>>,
    allowed_algorithms: Vec<Algorithm>,
    issuer: Option<String>,
    audience: Option<String>,
    refresh_interval: Duration,
    stale_window: Duration,
    retry: Option<RetryConfig>,
    max_age: Option<Duration>,
    http_client: reqwest::Client,
}

impl JwtValidator {
    /// Creates a validator for the JWKS at `jwks_uri` that requires the token's
    /// `aud` claim to be present and contain `audience`.
    ///
    /// Defaults to RS256 and ES256, no issuer check, a 60-second refresh
    /// interval, no stale-serve, no retry and no key max age.
    ///
    /// # Panics
    ///
    /// Panics if `reqwest` cannot initialize its TLS backend or load the system
    /// resolver configuration, as `reqwest::Client::new` does.
    pub fn new(jwks_uri: impl Into<String>, audience: impl Into<String>) -> Self {
        Self {
            jwks_uri: jwks_uri.into(),
            cached_jwks: RwLock::new(None),
            allowed_algorithms: vec![Algorithm::RS256, Algorithm::ES256],
            issuer: None,
            audience: Some(audience.into()),
            refresh_interval: Duration::from_secs(60),
            stale_window: Duration::ZERO,
            retry: None,
            max_age: None,
            http_client: reqwest::Client::new(),
        }
    }

    /// Requires the token's `iss` claim to be present and equal `issuer`.
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Replaces the set of algorithms a token may use.
    pub fn with_algorithms(mut self, algorithms: Vec<Algorithm>) -> Self {
        self.allowed_algorithms = algorithms;
        self
    }

    /// Sets the minimum time between JWKS fetch attempts.
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Sets how long a cached JWKS may keep being served after a failed refresh,
    /// measured from the last successful fetch. Defaults to
    /// [`Duration::ZERO`]: no stale-serve, so a refresh failure always
    /// propagates.
    pub fn with_stale_window(mut self, window: Duration) -> Self {
        self.stale_window = window;
        self
    }

    /// Retries a failed JWKS fetch up to `attempts` times (>=1), with
    /// exponential backoff starting at `base_delay` between attempts. The
    /// whole retry loop is wrapped in an overall timeout ceiling derived
    /// from `attempts` and `base_delay`, so a slow/hanging endpoint can't
    /// block indefinitely. Without this call, a fetch is a single attempt
    /// with no backoff or ceiling.
    pub fn with_retry(mut self, attempts: usize, base_delay: Duration) -> Self {
        self.retry = Some(RetryConfig {
            attempts: attempts.max(1),
            base_delay,
        });
        self
    }

    /// Sets the maximum age a cached key may be trusted on a `kid`-hit before a
    /// refresh is attempted, measured from the last successful fetch. A
    /// cache hit past this age is treated the same as a cache miss: a JWKS
    /// refresh runs (subject to the `refresh_interval` rate limit) before
    /// the key is returned, so a revoked key gets a chance to be dropped
    /// instead of being trusted indefinitely. Without this call, cached keys
    /// are trusted indefinitely on a `kid`-hit.
    ///
    /// Independent of `refresh_interval`: this governs how long a key may
    /// be trusted; `refresh_interval` governs how often a refetch attempt
    /// is allowed to actually fire. If a max-age-triggered refresh gets
    /// skipped by the `refresh_interval` cooldown, the still-cached key is
    /// served rather than erroring — the same outcome a kid-miss-triggered
    /// refresh already produces when rate-limited.
    pub fn with_max_age(mut self, max_age: Duration) -> Self {
        self.max_age = Some(max_age);
        self
    }

    /// Validates a JWT and returns its claims.
    ///
    /// # Errors
    ///
    /// Returns [`JwtValidationError`]:
    ///
    /// - [`DecodingError`](JwtValidationError::DecodingError) if the token header cannot be decoded.
    /// - [`UnsupportedAlgorithm`](JwtValidationError::UnsupportedAlgorithm) if the header
    ///   algorithm is not in the allowed set.
    /// - [`JwksFetchError`](JwtValidationError::JwksFetchError) if the key is not cached (or
    ///   is past `max_age`) and the JWKS refresh fails outside the stale window.
    /// - [`KeyNotFound`](JwtValidationError::KeyNotFound) if no key matches the token's
    ///   `kid` (`"default"` when absent) after the refresh.
    /// - [`UnsupportedAlgorithm`](JwtValidationError::UnsupportedAlgorithm) if the header
    ///   algorithm differs from the algorithm the JWKS key advertises.
    /// - [`InvalidToken`](JwtValidationError::InvalidToken) if the signature is invalid or
    ///   the token is malformed.
    /// - A required claim is missing. All required claims are checked together, in no fixed
    ///   order: [`InvalidToken`](JwtValidationError::InvalidToken) for `exp`,
    ///   [`InvalidAudience`](JwtValidationError::InvalidAudience) for `aud`, and
    ///   [`InvalidIssuer`](JwtValidationError::InvalidIssuer) for `iss` when an issuer is
    ///   configured.
    /// - [`TokenExpired`](JwtValidationError::TokenExpired) if `exp` is more than 60 seconds
    ///   in the past (jsonwebtoken's default leeway).
    /// - [`InvalidIssuer`](JwtValidationError::InvalidIssuer) if an issuer is configured
    ///   and `iss` does not match it.
    /// - [`InvalidAudience`](JwtValidationError::InvalidAudience) if `aud` does not contain
    ///   the configured audience.
    pub async fn validate(&self, token: &str) -> Result<TokenClaims, JwtValidationError> {
        let header = decode_header(token)
            .map_err(|e| JwtValidationError::DecodingError(format!("Invalid JWT header: {e}")))?;

        if !self.allowed_algorithms.contains(&header.alg) {
            return Err(JwtValidationError::UnsupportedAlgorithm(format!(
                "{:?}",
                header.alg
            )));
        }

        let kid = header.kid.as_deref().unwrap_or("default").to_string();
        let (key, jwks_alg) = self.get_decoding_key(&kid).await?;

        // The header's alg must match the key's own alg, so a token cannot pick
        // the algorithm a key is verified under (algorithm confusion).
        if header.alg != jwks_alg {
            return Err(JwtValidationError::UnsupportedAlgorithm(format!(
                "Token uses {:?} but JWKS key '{kid}' advertises {:?}",
                header.alg, jwks_alg
            )));
        }

        let mut validation = Validation::new(header.alg);
        validation.validate_exp = true;

        // jsonwebtoken checks `aud` and `iss` only when the claim is present, so
        // a missing claim must be required explicitly or it bypasses the check.
        if let Some(ref iss) = self.issuer {
            validation.set_issuer(&[iss]);
            validation.required_spec_claims.insert("iss".to_string());
        }

        if let Some(ref aud) = self.audience {
            validation.set_audience(&[aud]);
            validation.required_spec_claims.insert("aud".to_string());
        } else {
            validation.validate_aud = false;
        }

        let token_data =
            decode::<TokenClaims>(token, &key, &validation).map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    JwtValidationError::TokenExpired
                }
                jsonwebtoken::errors::ErrorKind::InvalidAudience => {
                    JwtValidationError::InvalidAudience
                }
                jsonwebtoken::errors::ErrorKind::InvalidIssuer => JwtValidationError::InvalidIssuer,
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) if claim == "aud" => {
                    JwtValidationError::InvalidAudience
                }
                jsonwebtoken::errors::ErrorKind::MissingRequiredClaim(claim) if claim == "iss" => {
                    JwtValidationError::InvalidIssuer
                }
                _ => JwtValidationError::InvalidToken(e.to_string()),
            })?;

        Ok(token_data.claims)
    }

    async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> Result<(DecodingKey, Algorithm), JwtValidationError> {
        // Try cache first — a hit past `max_age` (if configured) is treated
        // as a miss below, so the key gets a chance to be refreshed/revoked
        // instead of being trusted indefinitely.
        {
            let cache = self.cached_jwks.read().await;
            if let Some(ref cached) = *cache {
                if let Some((key, alg)) = cached.keys.get(kid) {
                    let past_max_age = self
                        .max_age
                        .is_some_and(|max_age| cached.last_refresh_at.elapsed() >= max_age);
                    if !past_max_age {
                        return Ok((key.clone(), *alg));
                    }
                }
            }
        }

        // A miss may mean the issuer rotated keys, and a hit past max_age may be
        // a revoked key; either way, refresh before trusting the cache.
        self.refresh_jwks().await?;

        // Re-check without the max_age test: a refresh skipped by the rate limit must still serve the cached key.
        let cache = self.cached_jwks.read().await;
        if let Some(ref cached) = *cache {
            if let Some((key, alg)) = cached.keys.get(kid) {
                return Ok((key.clone(), *alg));
            }
        }

        Err(JwtValidationError::KeyNotFound(kid.to_string()))
    }

    async fn refresh_jwks(&self) -> Result<(), JwtValidationError> {
        // Skip the fetch inside refresh_interval so unknown-kid tokens cannot force unbounded refetches.
        {
            let cache = self.cached_jwks.read().await;
            if let Some(ref cached) = *cache {
                if cached.last_refresh_at.elapsed() < self.refresh_interval {
                    debug!("JWKS refresh rate-limited, skipping");
                    return Ok(());
                }
            }
        }

        debug!("Fetching JWKS from {}", self.jwks_uri);

        match self.fetch_jwks_with_retry().await {
            Ok(keys) => {
                let now = Instant::now();
                *self.cached_jwks.write().await = Some(CachedJwks {
                    keys,
                    last_refresh_at: now,
                });
                Ok(())
            }
            Err(err) => {
                let cache = self.cached_jwks.read().await;
                if let Some(ref cached) = *cache {
                    if cached.last_refresh_at.elapsed() <= self.stale_window {
                        warn!(
                            "JWKS refresh failed ({err}); serving stale cache (age {:?}, within stale window)",
                            cached.last_refresh_at.elapsed()
                        );
                        return Ok(());
                    }
                }
                Err(err)
            }
        }
    }

    /// Fetches JWKS, retrying per `self.retry` if configured. With no retry
    /// configured, makes exactly one attempt and propagates its error
    /// directly, with no timeout.
    async fn fetch_jwks_with_retry(
        &self,
    ) -> Result<HashMap<String, (DecodingKey, Algorithm)>, JwtValidationError> {
        let Some(retry) = self.retry else {
            return self.fetch_jwks_once().await;
        };

        let ceiling = retry.ceiling();
        if ceiling.is_zero() {
            return self.fetch_jwks_with_retry_inner(retry).await;
        }

        match tokio::time::timeout(ceiling, self.fetch_jwks_with_retry_inner(retry)).await {
            Ok(result) => result,
            Err(_) => Err(JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::Timeout,
                message: format!("JWKS fetch timed out after {ceiling:?}"),
            }),
        }
    }

    /// Runs the retry loop: up to `retry.attempts` calls to `fetch_jwks_once`,
    /// sleeping an exponentially-doubling backoff (starting at
    /// `retry.base_delay`) between attempts.
    async fn fetch_jwks_with_retry_inner(
        &self,
        retry: RetryConfig,
    ) -> Result<HashMap<String, (DecodingKey, Algorithm)>, JwtValidationError> {
        let mut delay = retry.base_delay;
        let mut last_err = None;

        for attempt in 0..retry.attempts {
            if attempt > 0 {
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2);
            }
            match self.fetch_jwks_once().await {
                Ok(keys) => return Ok(keys),
                Err(e) => {
                    warn!("JWKS fetch attempt {} failed: {e}", attempt + 1);
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.expect("retry loop ran without recording an error"))
    }

    /// Performs a single JWKS fetch attempt: request, status check, JSON parse, and
    /// key parsing. No retry or rate-limiting — callers own that.
    async fn fetch_jwks_once(
        &self,
    ) -> Result<HashMap<String, (DecodingKey, Algorithm)>, JwtValidationError> {
        let response = self
            .http_client
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::Transport,
                message: e.to_string(),
            })?;

        let status = response.status();
        if !status.is_success() {
            return Err(JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::HttpStatus(status.as_u16()),
                message: format!("JWKS endpoint returned HTTP {}", status.as_u16()),
            });
        }

        let jwks: JwksResponse =
            response
                .json()
                .await
                .map_err(|e| JwtValidationError::JwksFetchError {
                    kind: JwksFetchErrorKind::InvalidJson,
                    message: format!("Invalid JWKS JSON: {e}"),
                })?;

        let mut keys = HashMap::new();

        for key in &jwks.keys {
            let kid = key.kid.clone().unwrap_or_else(|| "default".to_string());

            match key.kty.as_str() {
                "RSA" => {
                    if let (Some(n), Some(e)) = (&key.n, &key.e) {
                        match DecodingKey::from_rsa_components(n, e) {
                            Ok(decoding_key) => {
                                let alg = key
                                    .alg
                                    .as_deref()
                                    .and_then(|a| match a {
                                        "RS256" => Some(Algorithm::RS256),
                                        "RS384" => Some(Algorithm::RS384),
                                        "RS512" => Some(Algorithm::RS512),
                                        _ => None,
                                    })
                                    .unwrap_or(Algorithm::RS256);
                                keys.insert(kid, (decoding_key, alg));
                            }
                            Err(e) => warn!("Failed to parse RSA key: {e}"),
                        }
                    }
                }
                "EC" => {
                    if let (Some(x), Some(y), Some(crv)) = (&key.x, &key.y, &key.crv) {
                        match DecodingKey::from_ec_components(x, y) {
                            Ok(decoding_key) => {
                                let alg = match crv.as_str() {
                                    "P-256" => Algorithm::ES256,
                                    "P-384" => Algorithm::ES384,
                                    _ => {
                                        warn!("Unsupported EC curve: {crv}");
                                        continue;
                                    }
                                };
                                keys.insert(kid, (decoding_key, alg));
                            }
                            Err(e) => warn!("Failed to parse EC key: {e}"),
                        }
                    }
                }
                other => debug!("Skipping unsupported key type: {other}"),
            }
        }

        if keys.is_empty() {
            return Err(JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::NoSigningKeys,
                message: "JWKS response contained no usable signing keys".to_string(),
            });
        }

        debug!("JWKS loaded: {} keys", keys.len());

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_claims_deserializes_with_defaults() {
        let json = r#"{"sub":"user-1","iss":"https://auth.example.com","exp":999999999}"#;
        let claims: TokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-1");
        assert_eq!(claims.iss, "https://auth.example.com");
        assert_eq!(claims.exp, 999999999);
        assert!(claims.scope.is_none());
    }

    #[test]
    fn token_claims_handles_array_audience() {
        let json = r#"{"sub":"u","aud":["a","b"],"exp":1}"#;
        let claims: TokenClaims = serde_json::from_str(json).unwrap();
        assert!(claims.aud.is_array());
    }

    #[test]
    fn token_claims_handles_string_audience() {
        let json = r#"{"sub":"u","aud":"single","exp":1}"#;
        let claims: TokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.aud, "single");
    }

    #[test]
    fn token_claims_captures_extra_fields() {
        let json = r#"{"sub":"u","exp":1,"custom_field":"custom_value"}"#;
        let claims: TokenClaims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.extra.get("custom_field").unwrap(), "custom_value");
    }

    #[test]
    fn error_types_are_distinct() {
        let errors: Vec<JwtValidationError> = vec![
            JwtValidationError::InvalidToken("bad".into()),
            JwtValidationError::TokenExpired,
            JwtValidationError::InvalidAudience,
            JwtValidationError::InvalidIssuer,
            JwtValidationError::UnsupportedAlgorithm("HS256".into()),
            JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::Transport,
                message: "network".into(),
            },
            JwtValidationError::KeyNotFound("kid-1".into()),
            JwtValidationError::DecodingError("corrupt".into()),
        ];
        // All should have non-empty display
        for err in &errors {
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn jwks_fetch_error_display_preserves_message_text() {
        let err = JwtValidationError::JwksFetchError {
            kind: JwksFetchErrorKind::Transport,
            message: "connection refused".to_string(),
        };
        assert_eq!(err.to_string(), "JWKS fetch error: connection refused");
    }

    #[test]
    fn jwks_fetch_error_kind_is_matchable() {
        let err = JwtValidationError::JwksFetchError {
            kind: JwksFetchErrorKind::HttpStatus(503),
            message: "JWKS endpoint returned HTTP 503".to_string(),
        };
        match err {
            JwtValidationError::JwksFetchError {
                kind: JwksFetchErrorKind::HttpStatus(code),
                ..
            } => assert_eq!(code, 503),
            other => panic!("expected HttpStatus(503), got {other:?}"),
        }
    }

    #[test]
    fn validator_builder_api() {
        let _validator =
            JwtValidator::new("https://example.com/.well-known/jwks.json", "my-audience")
                .with_issuer("https://example.com")
                .with_algorithms(vec![Algorithm::RS256])
                .with_refresh_interval(Duration::from_secs(120));
    }
}
