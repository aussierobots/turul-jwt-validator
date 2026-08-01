//! Resilience-behavior tests for `JwtValidator`'s JWKS fetch/cache engine:
//! stale-while-revalidate, bounded retry with backoff, structured
//! fetch-error categorization, and the max_age revocation safety-net.
//!
//! Uses a hand-rolled axum + `tokio::net::TcpListener` mock server (rather
//! than wiremock) so handlers can carry shared atomic state — request
//! counters, first-call/second-call behavior switches — needed to assert
//! retry counts and backoff timing precisely.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs1::EncodeRsaPrivateKey;
use serde_json::json;

use turul_jwt_validator::{JwksFetchErrorKind, JwtValidationError, JwtValidator};

/// Generate an RSA keypair and return (private_key_pem, jwks_json with kid).
fn generate_rsa_keypair(kid: &str) -> (String, serde_json::Value) {
    use rsa::RsaPrivateKey;

    let mut rng = rsa::rand_core::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let private_pem = private_key
        .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
        .unwrap();

    let public_key = private_key.to_public_key();
    let n = rsa::traits::PublicKeyParts::n(&public_key);
    let e = rsa::traits::PublicKeyParts::e(&public_key);

    use base64::Engine;
    let n_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n.to_bytes_be());
    let e_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(e.to_bytes_be());

    let jwks = json!({
        "keys": [{
            "kty": "RSA",
            "kid": kid,
            "alg": "RS256",
            "n": n_b64,
            "e": e_b64,
        }]
    });

    (private_pem.to_string(), jwks)
}

fn sign_token(private_pem: &str, kid: &str, claims: &serde_json::Value) -> String {
    let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes()).unwrap();
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    jsonwebtoken::encode(&header, claims, &encoding_key).unwrap()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Spawn a mock JWKS server backed by an arbitrary handler closure, returning
/// its `/.well-known/jwks.json` URL.
async fn spawn_mock_jwks_server<F>(handler: F) -> String
where
    F: Fn() -> Response + Send + Sync + 'static + Clone,
{
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || {
            let h = handler.clone();
            async move { h() }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock JWKS server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://127.0.0.1:{}/.well-known/jwks.json", addr.port())
}

// =========================================================
// Structured fetch-error categorization
// =========================================================

#[tokio::test]
async fn fetch_error_categorizes_http_status() {
    let jwks_url = spawn_mock_jwks_server(|| {
        (StatusCode::SERVICE_UNAVAILABLE, "down for maintenance").into_response()
    })
    .await;

    let validator = JwtValidator::new(jwks_url, "test-audience");
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(
        &generate_rsa_keypair("any-kid").0,
        "any-kid",
        &claims,
    );

    let err = validator.validate(&token).await.unwrap_err();
    let JwtValidationError::JwksFetchError { kind, .. } = err else {
        panic!("expected JwksFetchError, got {err:?}");
    };
    assert_eq!(kind, JwksFetchErrorKind::HttpStatus(503));
}

#[tokio::test]
async fn fetch_error_categorizes_invalid_json() {
    let jwks_url = spawn_mock_jwks_server(|| {
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            "not json at all {{{",
        )
            .into_response()
    })
    .await;

    let validator = JwtValidator::new(jwks_url, "test-audience");
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let err = validator.validate(&token).await.unwrap_err();
    let JwtValidationError::JwksFetchError { kind, .. } = err else {
        panic!("expected JwksFetchError, got {err:?}");
    };
    assert_eq!(kind, JwksFetchErrorKind::InvalidJson);
}

#[tokio::test]
async fn fetch_error_categorizes_no_signing_keys() {
    let jwks_url = spawn_mock_jwks_server(|| {
        (
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            r#"{"keys":[]}"#,
        )
            .into_response()
    })
    .await;

    let validator = JwtValidator::new(jwks_url, "test-audience");
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let err = validator.validate(&token).await.unwrap_err();
    let JwtValidationError::JwksFetchError { kind, .. } = err else {
        panic!("expected JwksFetchError, got {err:?}");
    };
    assert_eq!(kind, JwksFetchErrorKind::NoSigningKeys);
}

#[tokio::test]
async fn fetch_error_categorizes_transport_failure() {
    // Bind a listener just to claim a free local port, then drop it —
    // connecting to a closed local port fails fast with "connection
    // refused" instead of depending on external-network unroutability
    // (e.g. a reserved TEST-NET IP), which can hang for a long time on
    // networks that black-hole rather than reject unroutable traffic.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind throwaway listener");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let validator = JwtValidator::new(
        format!("http://{addr}/.well-known/jwks.json"),
        "test-audience",
    );
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let err = validator.validate(&token).await.unwrap_err();
    let JwtValidationError::JwksFetchError { kind, .. } = err else {
        panic!("expected JwksFetchError, got {err:?}");
    };
    assert_eq!(kind, JwksFetchErrorKind::Transport);
}

// =========================================================
// Stale-while-revalidate
// =========================================================

/// Spawn a mock JWKS server that serves `good_body` while the returned flag
/// is `true`, and a 503 once flipped to `false`.
async fn spawn_switchable_jwks_server(
    good_body: serde_json::Value,
) -> (String, Arc<std::sync::atomic::AtomicBool>) {
    let serve_good = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flag = serve_good.clone();
    let jwks_url = spawn_mock_jwks_server(move || {
        if flag.load(Ordering::SeqCst) {
            axum::Json(good_body.clone()).into_response()
        } else {
            (StatusCode::SERVICE_UNAVAILABLE, "down").into_response()
        }
    })
    .await;
    (jwks_url, serve_good)
}

#[tokio::test]
async fn stale_while_revalidate_swallows_fetch_error_within_window() {
    let (pem, jwks) = generate_rsa_keypair("cached-key");
    let (jwks_url, serve_good) = spawn_switchable_jwks_server(jwks).await;

    let validator = JwtValidator::new(jwks_url, "test-audience")
        .with_refresh_interval(Duration::from_millis(10))
        .with_stale_window(Duration::from_secs(60));

    // Warm the cache with a successful fetch.
    let claims = json!({"sub": "u1", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&pem, "cached-key", &claims);
    validator
        .validate(&token)
        .await
        .expect("initial fetch should succeed");

    // Flip the server to failing, then request an unknown kid — this
    // forces a refetch that fails; with a generous stale window the
    // failure should be swallowed rather than surfaced as JwksFetchError.
    // Cross the refresh-interval rate-limit boundary so the next lookup
    // actually attempts a fetch instead of short-circuiting on the
    // pre-existing rate limiter.
    tokio::time::sleep(Duration::from_millis(20)).await;
    serve_good.store(false, Ordering::SeqCst);
    let unknown_claims = json!({"sub": "u2", "aud": "test-audience", "exp": now_epoch() + 3600});
    let unknown_token = sign_token(&pem, "unknown-key", &unknown_claims);
    let err = validator.validate(&unknown_token).await.unwrap_err();

    assert!(
        matches!(err, JwtValidationError::KeyNotFound(_)),
        "expected fetch failure to be swallowed by stale window, got {err:?}"
    );
}

#[tokio::test]
async fn stale_window_default_zero_does_not_swallow_fetch_errors() {
    let (pem, jwks) = generate_rsa_keypair("cached-key");
    let (jwks_url, serve_good) = spawn_switchable_jwks_server(jwks).await;

    // No .with_stale_window(...) call — must reproduce today's behavior.
    let validator =
        JwtValidator::new(jwks_url, "test-audience").with_refresh_interval(Duration::from_millis(10));

    let claims = json!({"sub": "u1", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&pem, "cached-key", &claims);
    validator
        .validate(&token)
        .await
        .expect("initial fetch should succeed");

    // Cross the refresh-interval rate-limit boundary so the next lookup
    // actually attempts a fetch instead of short-circuiting on the
    // pre-existing rate limiter.
    tokio::time::sleep(Duration::from_millis(20)).await;
    serve_good.store(false, Ordering::SeqCst);
    let unknown_claims = json!({"sub": "u2", "aud": "test-audience", "exp": now_epoch() + 3600});
    let unknown_token = sign_token(&pem, "unknown-key", &unknown_claims);
    let err = validator.validate(&unknown_token).await.unwrap_err();

    assert!(
        matches!(err, JwtValidationError::JwksFetchError { .. }),
        "expected raw fetch error to propagate by default (no with_stale_window call), got {err:?}"
    );
}

// =========================================================
// Bounded retry with backoff
// =========================================================

#[tokio::test]
async fn retry_disabled_by_default_makes_one_attempt() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let jwks_url = spawn_mock_jwks_server(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        (StatusCode::SERVICE_UNAVAILABLE, "down").into_response()
    })
    .await;

    // No .with_retry(...) call — must reproduce today's behavior.
    let validator = JwtValidator::new(jwks_url, "test-audience");
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let err = validator.validate(&token).await.unwrap_err();
    assert!(matches!(err, JwtValidationError::JwksFetchError { .. }));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        1,
        "expected exactly 1 attempt without with_retry configured"
    );
}

#[tokio::test]
async fn retry_retries_configured_attempts_with_backoff() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let counter = attempts.clone();
    let jwks_url = spawn_mock_jwks_server(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        (StatusCode::SERVICE_UNAVAILABLE, "down").into_response()
    })
    .await;

    let base_delay = Duration::from_millis(20);
    let validator = JwtValidator::new(jwks_url, "test-audience").with_retry(3, base_delay);
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let start = Instant::now();
    let err = validator.validate(&token).await.unwrap_err();
    let elapsed = start.elapsed();

    assert!(matches!(err, JwtValidationError::JwksFetchError { .. }));
    assert_eq!(
        attempts.load(Ordering::SeqCst),
        3,
        "expected exactly 3 attempts (initial + 2 retries)"
    );
    // Backoff schedule before attempts 2 and 3: base_delay, base_delay*2.
    let expected_min_backoff = base_delay + base_delay * 2;
    assert!(
        elapsed >= expected_min_backoff,
        "expected backoff delays (>= {expected_min_backoff:?}) between attempts, elapsed {elapsed:?}"
    );
}

#[tokio::test]
async fn retry_bounds_hanging_endpoint_by_ceiling() {
    let jwks_url = spawn_slow_jwks_server(Duration::from_secs(5)).await;

    let base_delay = Duration::from_millis(10);
    let validator = JwtValidator::new(jwks_url, "test-audience").with_retry(1, base_delay);
    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&generate_rsa_keypair("any-kid").0, "any-kid", &claims);

    let start = Instant::now();
    let err = validator.validate(&token).await.unwrap_err();
    let elapsed = start.elapsed();

    let JwtValidationError::JwksFetchError { kind, .. } = err else {
        panic!("expected JwksFetchError, got {err:?}");
    };
    assert_eq!(kind, JwksFetchErrorKind::Timeout);
    assert!(
        elapsed < Duration::from_secs(5),
        "expected the ceiling to cut the hung request short, elapsed {elapsed:?}"
    );
}

/// Spawn a mock JWKS server whose single handler sleeps for `delay` before
/// responding, to simulate a hung/very slow endpoint.
async fn spawn_slow_jwks_server(delay: Duration) -> String {
    use axum::{Router, routing::get};
    let app = Router::new().route(
        "/.well-known/jwks.json",
        get(move || async move {
            tokio::time::sleep(delay).await;
            StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock JWKS server");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://127.0.0.1:{}/.well-known/jwks.json", addr.port())
}

// =========================================================
// max_age revocation safety-net — cache hits past max_age
// are treated like a cache miss and trigger a refresh.
// =========================================================

/// Spawn a mock JWKS server that always serves `body` and counts requests.
async fn spawn_counting_jwks_server(body: serde_json::Value) -> (String, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    let jwks_url = spawn_mock_jwks_server(move || {
        counter.fetch_add(1, Ordering::SeqCst);
        axum::Json(body.clone()).into_response()
    })
    .await;
    (jwks_url, count)
}

#[tokio::test]
async fn max_age_fresh_cache_hit_makes_zero_fetch_calls() {
    let (pem, jwks) = generate_rsa_keypair("cached-key");
    let (jwks_url, count) = spawn_counting_jwks_server(jwks).await;

    let validator = JwtValidator::new(jwks_url, "test-audience")
        .with_refresh_interval(Duration::from_millis(10))
        .with_max_age(Duration::from_secs(60));

    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&pem, "cached-key", &claims);

    validator
        .validate(&token)
        .await
        .expect("initial fetch should succeed");
    let after_warm_up = count.load(Ordering::SeqCst);

    validator
        .validate(&token)
        .await
        .expect("second validate within max_age should still succeed");

    assert_eq!(
        count.load(Ordering::SeqCst),
        after_warm_up,
        "expected zero additional fetch calls for a cache hit within max_age"
    );
}

#[tokio::test]
async fn max_age_expired_cache_hit_triggers_exactly_one_refresh() {
    let (pem, jwks) = generate_rsa_keypair("cached-key");
    let (jwks_url, count) = spawn_counting_jwks_server(jwks).await;

    let validator = JwtValidator::new(jwks_url, "test-audience")
        .with_refresh_interval(Duration::from_millis(1))
        .with_max_age(Duration::from_millis(20));

    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&pem, "cached-key", &claims);

    validator
        .validate(&token)
        .await
        .expect("initial fetch should succeed");
    let after_warm_up = count.load(Ordering::SeqCst);

    tokio::time::sleep(Duration::from_millis(30)).await;
    validator
        .validate(&token)
        .await
        .expect("validate past max_age should still succeed");

    assert_eq!(
        count.load(Ordering::SeqCst),
        after_warm_up + 1,
        "expected exactly one refresh call once max_age elapsed"
    );
}

#[tokio::test]
async fn max_age_expired_cache_hit_rate_limited_by_refresh_interval_serves_stale_key() {
    let (pem, jwks) = generate_rsa_keypair("cached-key");
    let (jwks_url, count) = spawn_counting_jwks_server(jwks).await;

    let validator = JwtValidator::new(jwks_url, "test-audience")
        .with_refresh_interval(Duration::from_secs(60))
        .with_max_age(Duration::from_millis(20));

    let claims = json!({"sub": "u", "aud": "test-audience", "exp": now_epoch() + 3600});
    let token = sign_token(&pem, "cached-key", &claims);

    validator
        .validate(&token)
        .await
        .expect("initial fetch should succeed");
    let after_warm_up = count.load(Ordering::SeqCst);

    // Past max_age, but well within the 60s refresh_interval cooldown.
    tokio::time::sleep(Duration::from_millis(30)).await;
    let claims = validator
        .validate(&token)
        .await
        .expect("rate-limited max_age refresh should still serve the stale cached key");
    assert_eq!(claims.sub, "u");

    assert_eq!(
        count.load(Ordering::SeqCst),
        after_warm_up,
        "expected zero additional fetch calls — refresh_interval cooldown should block the refetch attempt"
    );
}
