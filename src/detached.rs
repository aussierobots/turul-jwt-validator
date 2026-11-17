//! Signs and verifies detached compact JWS (`header..signature`), ES256 only.
//! Performs no network access and no claims validation.
//!
//! Available with the `detached_aws_lc_rs` feature, or with
//! `detached_rust_crypto` and `default-features = false`. A detached feature
//! cannot be combined with the other crypto backend.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, crypto};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// A JSON object whose top-level member names must be unique. serde_json
/// keeps the last duplicate, so a verifier that keeps the first would read a
/// different `alg` or `typ`; a duplicate is rejected instead.
struct StrictObject(Map<String, Value>);

impl<'de> Deserialize<'de> for StrictObject {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ObjectVisitor;
        impl<'de> serde::de::Visitor<'de> for ObjectVisitor {
            type Value = Map<String, Value>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let value: Value = map.next_value()?;
                    if out.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(ObjectVisitor).map(StrictObject)
    }
}

/// Lists the supported JWS algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwsAlg {
    /// ECDSA over P-256 with SHA-256.
    Es256,
}

/// Header rules enforced by [`inspect_detached`] and [`verify_detached`].
#[derive(Debug, Clone, Copy)]
pub struct DetachedJwsPolicy<'a> {
    /// Required `typ` header value, compared byte for byte.
    pub expected_typ: &'a str,
    /// Algorithms accepted in the `alg` header.
    pub allowed_algs: &'a [JwsAlg],
    /// Header parameter names whose presence is rejected.
    pub forbidden_params: &'a [&'a str],
}

/// Describes detached JWS failures, one variant per rule.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DetachedJwsError {
    /// The input is not `header..signature`, or the header or signature segment is not base64url.
    #[error("malformed detached JWS")]
    Malformed,
    /// The protected header is not a JSON object, repeats a member, or lacks a string `alg`; also returned if signing cannot serialize the header.
    #[error("invalid protected header")]
    InvalidHeader,
    /// The `typ` header is missing or differs from the policy value.
    #[error("typ missing or not the expected value")]
    TypMismatch,
    /// The `alg` header is `none`.
    #[error("alg is none")]
    AlgNone,
    /// The `alg` header is not ES256 or is not in the policy allowlist.
    #[error("alg not allowed")]
    AlgNotAllowed,
    /// The `b64` header parameter is present.
    #[error("b64 header parameter present")]
    B64Present,
    /// The `crit` header parameter is present.
    #[error("crit header parameter present")]
    CritPresent,
    /// A header parameter listed in the policy is present; holds its name.
    #[error("forbidden header parameter: {0}")]
    ForbiddenParam(String),
    /// The public JWK failed validation; holds the rule that failed.
    #[error("invalid public JWK: {0}")]
    InvalidJwk(String),
    /// The signing key could not produce an ES256 signature.
    #[error("invalid signing key")]
    InvalidSigningKey,
    /// The signature is not 64 bytes or does not verify.
    #[error("signature invalid")]
    SignatureInvalid,
}

/// Holds a validated P-256 public key, constructible only via [`check_public_jwk`].
pub struct Es256PublicKey(DecodingKey);

fn jwk_err(m: &str) -> DetachedJwsError {
    DetachedJwsError::InvalidJwk(m.into())
}

fn coord(jwk: &Map<String, Value>, name: &str) -> Result<Vec<u8>, DetachedJwsError> {
    let s = jwk
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| jwk_err(&format!("{name} missing")))?;
    let b = B64
        .decode(s)
        .map_err(|_| jwk_err(&format!("{name} not base64url")))?;
    if b.len() != 32 {
        return Err(jwk_err(&format!("{name} not 32 bytes")));
    }
    Ok(b)
}

/// Validates a public P-256 JWK (raw JSON) and returns the key.
///
/// # Errors
///
/// Returns [`DetachedJwsError::InvalidJwk`] when, checked in this order:
/// the input is not JSON or not an object; the private member `d` is present;
/// `kty` is not `EC`; `crv` is not `P-256`; `alg` is present and not `ES256`;
/// `use` is present and not `sig`; `key_ops` is present and lacks `verify`;
/// `x` or `y` is missing, not base64url, or not 32 bytes; the point is not on
/// P-256; or the key is unusable.
pub fn check_public_jwk(jwk_json: &[u8]) -> Result<Es256PublicKey, DetachedJwsError> {
    let v: Value = serde_json::from_slice(jwk_json).map_err(|_| jwk_err("not JSON"))?;
    let jwk = v.as_object().ok_or_else(|| jwk_err("not an object"))?;
    if jwk.contains_key("d") {
        return Err(jwk_err("private member d present"));
    }
    if jwk.get("kty").and_then(Value::as_str) != Some("EC") {
        return Err(jwk_err("kty must be EC"));
    }
    if jwk.get("crv").and_then(Value::as_str) != Some("P-256") {
        return Err(jwk_err("crv must be P-256"));
    }
    if jwk.get("alg").is_some_and(|a| a.as_str() != Some("ES256")) {
        return Err(jwk_err("alg must be ES256"));
    }
    if jwk.get("use").is_some_and(|u| u.as_str() != Some("sig")) {
        return Err(jwk_err("use must be sig"));
    }
    if let Some(ops) = jwk.get("key_ops")
        && !ops
            .as_array()
            .is_some_and(|a| a.iter().any(|o| o.as_str() == Some("verify")))
    {
        return Err(jwk_err("key_ops must include verify"));
    }
    let (x, y) = (coord(jwk, "x")?, coord(jwk, "y")?);
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    p256::PublicKey::from_sec1_bytes(&sec1).map_err(|_| jwk_err("point not on P-256"))?;
    let key = DecodingKey::from_ec_components(&B64.encode(&x), &B64.encode(&y))
        .map_err(|_| jwk_err("unusable key"))?;
    Ok(Es256PublicKey(key))
}

/// The one ES256 verifier. Uses jsonwebtoken's crypto so the backend follows
/// the crate feature, with no per-backend copy.
fn verify_raw(
    signing_input: &[u8],
    sig_b64: &str,
    key: &Es256PublicKey,
) -> Result<(), DetachedJwsError> {
    let sig = B64
        .decode(sig_b64)
        .map_err(|_| DetachedJwsError::Malformed)?;
    if sig.len() != 64 {
        return Err(DetachedJwsError::SignatureInvalid);
    }
    match crypto::verify(sig_b64, signing_input, &key.0, Algorithm::ES256) {
        Ok(true) => Ok(()),
        _ => Err(DetachedJwsError::SignatureInvalid),
    }
}

/// The one structure and header check path, shared by [`inspect_detached`]
/// and [`verify_detached`]. Returns the header and the header and signature
/// segments. The signature segment is not decoded here.
fn check_header<'a>(
    detached: &'a str,
    policy: &DetachedJwsPolicy<'_>,
) -> Result<(Map<String, Value>, &'a str, &'a str), DetachedJwsError> {
    let parts: Vec<&str> = detached.split('.').collect();
    let [h, p, s] = parts[..] else {
        return Err(DetachedJwsError::Malformed);
    };
    if !p.is_empty() {
        return Err(DetachedJwsError::Malformed);
    }
    let raw = B64.decode(h).map_err(|_| DetachedJwsError::Malformed)?;
    let header = serde_json::from_slice::<StrictObject>(&raw)
        .map_err(|_| DetachedJwsError::InvalidHeader)?
        .0;
    let alg = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(DetachedJwsError::InvalidHeader)?;
    if alg == "none" {
        return Err(DetachedJwsError::AlgNone);
    }
    let alg_ok = alg == "ES256" && policy.allowed_algs.contains(&JwsAlg::Es256);
    if !alg_ok {
        return Err(DetachedJwsError::AlgNotAllowed);
    }
    if header.contains_key("b64") {
        return Err(DetachedJwsError::B64Present);
    }
    if header.contains_key("crit") {
        return Err(DetachedJwsError::CritPresent);
    }
    if let Some(f) = policy
        .forbidden_params
        .iter()
        .find(|f| header.contains_key(**f))
    {
        return Err(DetachedJwsError::ForbiddenParam((*f).to_string()));
    }
    if header.get("typ").and_then(Value::as_str) != Some(policy.expected_typ) {
        return Err(DetachedJwsError::TypMismatch);
    }
    Ok((header, h, s))
}

/// Runs every [`verify_detached`] check except the signature, with no key:
/// structure, header, `none`, allowlist, `b64`, `crit`, forbidden parameters
/// and `typ`, in the same order and with the same errors. Returns the
/// protected header.
///
/// `Ok` does not mean the signature is valid, or even well-formed: use it to
/// report header violations before a key is available, then call
/// [`verify_detached`].
///
/// # Errors
///
/// Returns, in the order checked: [`DetachedJwsError::Malformed`] if the input
/// is not `header..signature` or the header is not base64url;
/// [`DetachedJwsError::InvalidHeader`] if the header is not a JSON object,
/// repeats a member, or lacks a string `alg`; [`DetachedJwsError::AlgNone`];
/// [`DetachedJwsError::AlgNotAllowed`]; [`DetachedJwsError::B64Present`];
/// [`DetachedJwsError::CritPresent`]; [`DetachedJwsError::ForbiddenParam`];
/// and [`DetachedJwsError::TypMismatch`].
pub fn inspect_detached(
    detached: &str,
    policy: &DetachedJwsPolicy<'_>,
) -> Result<Map<String, Value>, DetachedJwsError> {
    check_header(detached, policy).map(|(header, _, _)| header)
}

/// Verifies a detached compact JWS over `payload`. Policy checks run before
/// the signature check (see [`inspect_detached`]). Returns the protected header.
///
/// Duplicate top-level header members are rejected as `InvalidHeader`. High-S
/// ECDSA signatures are accepted: a payload can therefore have two valid
/// signature strings, so do not use the signature bytes as an identifier.
///
/// # Errors
///
/// Returns every error of [`inspect_detached`], in the same order, then
/// [`DetachedJwsError::Malformed`] if the signature segment is not base64url,
/// then [`DetachedJwsError::SignatureInvalid`] if the signature is not 64 bytes
/// or does not verify over the header and `payload`.
pub fn verify_detached(
    detached: &str,
    payload: &[u8],
    key: &Es256PublicKey,
    policy: &DetachedJwsPolicy<'_>,
) -> Result<Map<String, Value>, DetachedJwsError> {
    let (header, h, s) = check_header(detached, policy)?;
    let input = format!("{h}.{}", B64.encode(payload));
    verify_raw(input.as_bytes(), s, key)?;
    Ok(header)
}

#[derive(Serialize)]
struct SignHeader<'a> {
    alg: &'a str,
    typ: &'a str,
    kid: &'a str,
}

/// Signs `payload` with an ES256 PKCS#8 DER key; returns `header..signature`.
///
/// # Errors
///
/// Returns [`DetachedJwsError::InvalidHeader`] if the header cannot be
/// serialized, then [`DetachedJwsError::InvalidSigningKey`] if `pkcs8_der`
/// cannot produce an ES256 signature.
pub fn sign_detached_es256(
    pkcs8_der: &[u8],
    typ: &str,
    kid: &str,
    payload: &[u8],
) -> Result<String, DetachedJwsError> {
    let header = SignHeader {
        alg: "ES256",
        typ,
        kid,
    };
    let h = B64.encode(serde_json::to_vec(&header).map_err(|_| DetachedJwsError::InvalidHeader)?);
    let input = format!("{h}.{}", B64.encode(payload));
    let sig = crypto::sign(
        input.as_bytes(),
        &EncodingKey::from_ec_der(pkcs8_der),
        Algorithm::ES256,
    )
    .map_err(|_| DetachedJwsError::InvalidSigningKey)?;
    Ok(format!("{h}..{sig}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;

    const A3_JWK: &str = r#"{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#;
    const A3_D: &str = "jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI";
    const A3_H: &str = "eyJhbGciOiJFUzI1NiJ9";
    const A3_P: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const A3_S: &str =
        "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    const TYP: &str = "ai-catalog+jws";
    const POLICY: DetachedJwsPolicy<'static> = DetachedJwsPolicy {
        expected_typ: TYP,
        allowed_algs: &[JwsAlg::Es256],
        forbidden_params: &["jku", "jwk", "x5u", "x5c"],
    };

    fn a3_key() -> Es256PublicKey {
        check_public_jwk(A3_JWK.as_bytes()).unwrap()
    }
    fn sk() -> SigningKey {
        SigningKey::from_slice(&B64.decode(A3_D).unwrap()).unwrap()
    }
    fn der() -> Vec<u8> {
        sk().to_pkcs8_der().unwrap().as_bytes().to_vec()
    }
    fn b64j(v: Value) -> String {
        B64.encode(serde_json::to_vec(&v).unwrap())
    }
    /// Signs `header` JSON with the A.3 key over `payload`, detached.
    fn sign_with_header(header: Value, payload: &[u8]) -> String {
        use p256::ecdsa::signature::Signer;
        let h = b64j(header);
        let input = format!("{h}.{}", B64.encode(payload));
        let sig: p256::ecdsa::Signature = sk().sign(input.as_bytes());
        format!("{h}..{}", B64.encode(sig.to_bytes()))
    }
    fn good_header() -> Value {
        serde_json::json!({"alg":"ES256","typ":TYP,"kid":"k"})
    }
    fn verify(d: &str, p: &[u8]) -> Result<Map<String, Value>, DetachedJwsError> {
        verify_detached(d, p, &a3_key(), &POLICY)
    }

    #[test]
    fn rfc7515_a3_vector() {
        let payload = B64.decode(A3_P).unwrap();
        assert_eq!(payload[..8], *b"{\"iss\":\"");
        let input = format!("{A3_H}.{A3_P}");
        assert_eq!(verify_raw(input.as_bytes(), A3_S, &a3_key()), Ok(()));
        // A flipped payload bit must invalidate the signature.
        let mut bad = payload.clone();
        bad[2] ^= 1;
        let input = format!("{A3_H}.{}", B64.encode(&bad));
        assert_eq!(
            verify_raw(input.as_bytes(), A3_S, &a3_key()),
            Err(DetachedJwsError::SignatureInvalid)
        );
    }

    #[test]
    fn rfc7515_a3_detached_form_rejected_by_policy_only_for_typ() {
        let d = format!("{A3_H}..{A3_S}");
        let payload = B64.decode(A3_P).unwrap();
        assert_eq!(verify(&d, &payload), Err(DetachedJwsError::TypMismatch));
    }

    #[test]
    fn round_trip() {
        let d = sign_detached_es256(&der(), TYP, "kid-1", b"hello").unwrap();
        assert!(d.contains(".."));
        let h = verify(&d, b"hello").unwrap();
        assert_eq!(h["kid"], "kid-1");
        assert_eq!(h["typ"], TYP);
        let raw = B64.decode(d.split('.').next().unwrap()).unwrap();
        assert_eq!(
            raw,
            format!(r#"{{"alg":"ES256","typ":"{TYP}","kid":"kid-1"}}"#).into_bytes()
        );
    }

    /// Signs a raw header JSON string (not produced by serde) over `payload`.
    fn sign_raw_header(raw_json: &str, payload: &[u8]) -> String {
        use p256::ecdsa::signature::Signer;
        let h = B64.encode(raw_json.as_bytes());
        let input = format!("{h}.{}", B64.encode(payload));
        let sig: p256::ecdsa::Signature = sk().sign(input.as_bytes());
        format!("{h}..{}", B64.encode(sig.to_bytes()))
    }

    #[test]
    fn typ_is_byte_exact_and_case_sensitive() {
        // No RFC 7515 4.1.9 `application/` prefix equivalence, no case folding.
        for bad in [
            "application/ai-catalog+jws",
            "AI-CATALOG+JWS",
            "Ai-Catalog+Jws",
            "ai-catalog+jws ",
            " ai-catalog+jws",
        ] {
            let d = sign_with_header(serde_json::json!({"alg":"ES256","typ":bad}), b"p");
            assert_eq!(
                verify(&d, b"p"),
                Err(DetachedJwsError::TypMismatch),
                "typ {bad:?}"
            );
        }
    }

    #[test]
    fn input_must_have_exactly_two_dots_and_empty_payload() {
        let good = sign_with_header(good_header(), b"p");
        let (h, s) = good.split_once("..").unwrap();
        let embedded = format!("{h}.{}.{s}", B64.encode(b"p"));
        for bad in [
            embedded.as_str(),
            &format!("{h}..{s}."),
            &format!("{h}...{s}"),
            &format!("{h}.{s}"),
            h,
            "",
            "...",
        ] {
            assert_eq!(
                verify(bad, b"p"),
                Err(DetachedJwsError::Malformed),
                "input {bad:?}"
            );
        }
    }

    #[test]
    fn inspect_matches_verify_errors_and_needs_no_key() {
        let good = sign_with_header(good_header(), b"p");
        // Same header outcome as verify, and no key is needed.
        assert_eq!(
            inspect_detached(&good, &POLICY).unwrap(),
            verify(&good, b"p").unwrap()
        );
        // Header-only: a garbage signature segment still inspects Ok, verify rejects it.
        let (h, _) = good.split_once("..").unwrap();
        let bad_sig = format!("{h}..AAAA");
        assert!(inspect_detached(&bad_sig, &POLICY).is_ok());
        assert_eq!(
            verify(&bad_sig, b"p"),
            Err(DetachedJwsError::SignatureInvalid)
        );
        // Every header rule gives the identical error from both.
        let mut no_typ = good_header();
        no_typ.as_object_mut().unwrap().remove("typ");
        let cases = [
            sign_with_header(no_typ, b"p"),
            hdr_with("typ", "x".into()),
            hdr_with("alg", "none".into()),
            hdr_with("alg", "ES384".into()),
            hdr_with("alg", serde_json::json!(5)),
            hdr_with("b64", false.into()),
            hdr_with("crit", serde_json::json!(["x"])),
            hdr_with("jku", "u".into()),
            hdr_with("x5c", serde_json::json!([])),
            sign_raw_header(
                r#"{"alg":"ES256","alg":"none","typ":"ai-catalog+jws"}"#,
                b"p",
            ),
            format!("{h}.{}.AAAA", B64.encode(b"p")),
            "h".to_string(),
        ];
        for d in &cases {
            assert_eq!(
                inspect_detached(d, &POLICY).unwrap_err(),
                verify(d, b"p").unwrap_err(),
                "input {d}"
            );
        }
    }

    #[test]
    fn duplicate_header_member_rejected() {
        // Last-wins would read alg ES256; first-wins would read alg none.
        let raw = r#"{"alg":"none","alg":"ES256","typ":"ai-catalog+jws","kid":"k"}"#;
        let d = sign_raw_header(raw, b"p");
        assert_eq!(verify(&d, b"p"), Err(DetachedJwsError::InvalidHeader));
    }

    #[test]
    fn non_string_alg_rejected_as_invalid_header() {
        let d = sign_with_header(serde_json::json!({"alg":5,"typ":TYP}), b"p");
        assert_eq!(verify(&d, b"p"), Err(DetachedJwsError::InvalidHeader));
    }

    #[test]
    fn bad_pkcs8_rejected() {
        assert_eq!(
            sign_detached_es256(b"junk", TYP, "k", b"x"),
            Err(DetachedJwsError::InvalidSigningKey)
        );
    }

    fn hdr_with(k: &str, v: Value) -> String {
        let mut h = good_header();
        h[k] = v;
        sign_with_header(h, b"p")
    }

    #[test]
    fn policy_negatives() {
        let e = |d: String| verify(&d, b"p").unwrap_err();
        let mut h = good_header();
        h.as_object_mut().unwrap().remove("typ");
        assert_eq!(e(sign_with_header(h, b"p")), DetachedJwsError::TypMismatch);
        assert_eq!(
            e(hdr_with("typ", "x".into())),
            DetachedJwsError::TypMismatch
        );
        assert_eq!(e(hdr_with("alg", "none".into())), DetachedJwsError::AlgNone);
        assert_eq!(
            e(hdr_with("alg", "ES384".into())),
            DetachedJwsError::AlgNotAllowed
        );
        assert_eq!(
            e(hdr_with("alg", 5.into())),
            DetachedJwsError::InvalidHeader
        );
        assert_eq!(
            e(hdr_with("b64", true.into())),
            DetachedJwsError::B64Present
        );
        assert_eq!(
            e(hdr_with("b64", false.into())),
            DetachedJwsError::B64Present
        );
        assert_eq!(
            e(hdr_with("crit", serde_json::json!(["x"]))),
            DetachedJwsError::CritPresent
        );
        for p in ["jku", "jwk", "x5u", "x5c"] {
            assert_eq!(
                e(hdr_with(p, "v".into())),
                DetachedJwsError::ForbiddenParam(p.into())
            );
        }
    }

    #[test]
    fn signature_and_shape_negatives() {
        let d = sign_detached_es256(&der(), TYP, "k", b"hello").unwrap();
        assert_eq!(
            verify(&d, b"hellp"),
            Err(DetachedJwsError::SignatureInvalid)
        );
        let (h, s) = d.split_once("..").unwrap();
        let mut sig = B64.decode(s).unwrap();
        sig[0] ^= 1;
        let t = format!("{h}..{}", B64.encode(&sig));
        assert_eq!(
            verify(&t, b"hello"),
            Err(DetachedJwsError::SignatureInvalid)
        );
        let t = format!("{h}..{}", B64.encode(&sig[..63]));
        assert_eq!(
            verify(&t, b"hello"),
            Err(DetachedJwsError::SignatureInvalid)
        );
        let t = format!("{h}.{}.{s}", B64.encode(b"hello"));
        assert_eq!(verify(&t, b"hello"), Err(DetachedJwsError::Malformed));
        assert_eq!(
            verify(&format!("{h}.{s}"), b"hello"),
            Err(DetachedJwsError::Malformed)
        );
        let padded = format!("{h}=..{s}");
        assert_eq!(verify(&padded, b"hello"), Err(DetachedJwsError::Malformed));
        let t = format!("{}..{s}", B64.encode(b"[1]"));
        assert_eq!(verify(&t, b"hello"), Err(DetachedJwsError::InvalidHeader));
    }

    /// Asserts `j` is rejected as `InvalidJwk` whose message contains `reason`,
    /// so each case fails for the rule it names.
    fn jwk_rejected(j: &str, reason: &str) {
        match check_public_jwk(j.as_bytes()) {
            Err(DetachedJwsError::InvalidJwk(m)) => {
                assert!(m.contains(reason), "{m:?} lacks {reason:?} for {j}")
            }
            other => panic!(
                "expected InvalidJwk({reason}) for {j}, got {:?}",
                other.err()
            ),
        }
    }
    const X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
    const Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

    #[test]
    fn jwk_negatives() {
        let with =
            |extra: &str| format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"{extra}}}"#);
        jwk_rejected(&with(&format!(r#","d":"{A3_D}""#)), "private member d");
        jwk_rejected(&with(r#","alg":"ES384""#), "alg must be ES256");
        jwk_rejected(&with(r#","use":"enc""#), "use must be sig");
        jwk_rejected(
            &with(r#","key_ops":["sign"]"#),
            "key_ops must include verify",
        );
        jwk_rejected(
            &format!(r#"{{"kty":"RSA","crv":"P-256","x":"{X}","y":"{Y}"}}"#),
            "kty must be EC",
        );
        jwk_rejected(
            &format!(r#"{{"kty":"EC","crv":"P-384","x":"{X}","y":"{Y}"}}"#),
            "crv must be P-256",
        );
        let x31 = B64.encode([1u8; 31]);
        jwk_rejected(
            &format!(r#"{{"kty":"EC","crv":"P-256","x":"{x31}","y":"{Y}"}}"#),
            "x not 32 bytes",
        );
        // Valid x with y off by one bit: not on curve.
        let mut y = B64.decode(Y).unwrap();
        y[31] ^= 1;
        let yb = B64.encode(&y);
        jwk_rejected(
            &format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{yb}"}}"#),
            "point not on P-256",
        );
        jwk_rejected(
            &format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}"}}"#),
            "y missing",
        );
        jwk_rejected("not json", "not JSON");
    }

    #[test]
    fn jwk_positives() {
        assert!(check_public_jwk(A3_JWK.as_bytes()).is_ok());
        let j = format!(
            r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}","kid":"ignored","alg":"ES256","use":"sig","key_ops":["verify"]}}"#
        );
        assert!(check_public_jwk(j.as_bytes()).is_ok());
    }
}
