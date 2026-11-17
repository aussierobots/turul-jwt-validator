//! Backend features imply `jwks`: `JwtValidator` must stay exported.
#![cfg(any(feature = "rust_crypto", feature = "aws_lc_rs"))]

#[test]
fn backend_features_export_jwt_validator() {
    let _ = turul_jwt_validator::JwtValidator::new("https://example.com/jwks.json", "aud");
}
