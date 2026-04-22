//! Validate a JWT against a live JWKS endpoint.
//!
//! Reads configuration from environment variables:
//!   TURUL_JWKS      — JWKS endpoint URL (required)
//!   TURUL_AUDIENCE  — expected `aud` claim (required)
//!   TURUL_TOKEN     — the JWT string to validate (required)
//!   TURUL_ISSUER    — expected `iss` claim (optional)
//!
//! Run:
//!   cargo run --example validate-token

use std::env;
use std::process::ExitCode;

use turul_jwt_validator::JwtValidator;

fn require(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("error: environment variable {name} not set");
        eprintln!("usage: set TURUL_JWKS, TURUL_AUDIENCE, TURUL_TOKEN (and optional TURUL_ISSUER)");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() -> ExitCode {
    let jwks_uri = require("TURUL_JWKS");
    let audience = require("TURUL_AUDIENCE");
    let token = require("TURUL_TOKEN");

    let mut validator = JwtValidator::new(jwks_uri, audience);
    if let Ok(iss) = env::var("TURUL_ISSUER") {
        validator = validator.with_issuer(iss);
    }

    match validator.validate(&token).await {
        Ok(claims) => {
            println!("token valid:");
            println!("  sub:   {}", claims.sub);
            println!("  iss:   {}", claims.iss);
            println!("  aud:   {}", claims.aud);
            println!("  exp:   {}", claims.exp);
            if let Some(scope) = &claims.scope {
                println!("  scope: {scope}");
            }
            if !claims.extra.is_empty() {
                match serde_json::to_string_pretty(&claims.extra) {
                    Ok(pretty) => println!("  extra: {pretty}"),
                    Err(_) => println!("  extra: <failed to render>"),
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("token invalid: {err}");
            ExitCode::FAILURE
        }
    }
}
