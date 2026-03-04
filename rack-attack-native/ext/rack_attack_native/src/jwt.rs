use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use std::cell::RefCell;
use std::collections::HashMap;

/// Configuration for JWT key(s), parsed from the `jwt_keys` config field.
#[derive(Debug, Clone)]
pub struct JwtConfig {
    pub keys: Vec<JwtKeyEntry>,
}

#[derive(Clone)]
pub struct JwtKeyEntry {
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
    /// Pre-computed validation settings (sig + exp check, no aud check).
    pub validation: Validation,
}

impl std::fmt::Debug for JwtKeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtKeyEntry")
            .field("algorithm", &self.algorithm)
            .field("decoding_key", &"<key>")
            .finish()
    }
}

/// Raw JWT key entry deserialized from JSON config.
#[derive(Debug, Deserialize)]
pub struct RawJwtKey {
    pub algorithm: String,
    pub key: String,
}

impl JwtConfig {
    pub fn from_raw(raw_keys: &[RawJwtKey]) -> Result<Self, String> {
        let mut keys = Vec::with_capacity(raw_keys.len());
        for raw in raw_keys {
            let algorithm = parse_algorithm(&raw.algorithm)?;
            let decoding_key = make_decoding_key(algorithm, &raw.key)?;
            let mut validation = Validation::new(algorithm);
            validation.validate_exp = true;
            validation.validate_aud = false;
            validation.required_spec_claims = std::collections::HashSet::new();
            validation.required_spec_claims.insert("exp".to_string());
            keys.push(JwtKeyEntry {
                algorithm,
                decoding_key,
                validation,
            });
        }
        Ok(JwtConfig { keys })
    }
}

fn parse_algorithm(s: &str) -> Result<Algorithm, String> {
    match s {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "PS256" => Ok(Algorithm::PS256),
        "PS384" => Ok(Algorithm::PS384),
        "PS512" => Ok(Algorithm::PS512),
        _ => Err(format!("Unsupported JWT algorithm: {}", s)),
    }
}

fn make_decoding_key(alg: Algorithm, key_str: &str) -> Result<DecodingKey, String> {
    match alg {
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Ok(DecodingKey::from_secret(key_str.as_bytes()))
        }
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => {
            if key_str.contains("BEGIN RSA PUBLIC KEY") || key_str.contains("BEGIN PUBLIC KEY") {
                DecodingKey::from_rsa_pem(key_str.as_bytes())
                    .map_err(|e| format!("Invalid RSA PEM key: {}", e))
            } else {
                Ok(DecodingKey::from_rsa_der(
                    &URL_SAFE_NO_PAD
                        .decode(key_str)
                        .map_err(|e| format!("Invalid base64 RSA key: {}", e))?,
                ))
            }
        }
        Algorithm::ES256 | Algorithm::ES384 => {
            if key_str.contains("BEGIN PUBLIC KEY") {
                DecodingKey::from_ec_pem(key_str.as_bytes())
                    .map_err(|e| format!("Invalid EC PEM key: {}", e))
            } else {
                Ok(DecodingKey::from_ec_der(
                    &URL_SAFE_NO_PAD
                        .decode(key_str)
                        .map_err(|e| format!("Invalid base64 EC key: {}", e))?,
                ))
            }
        }
        _ => Err(format!(
            "Unsupported algorithm for key construction: {:?}",
            alg
        )),
    }
}

/// Cached JWT decode results for a single request.
/// Borrows `JwtConfig` from the `RuleSet` to avoid cloning crypto keys.
pub struct JwtData<'a> {
    /// Raw token extracted from Authorization: Bearer header.
    token: Option<&'a str>,
    /// Lazily decoded unverified header + payload (base64 only, no sig check).
    unverified: RefCell<Option<Option<UnverifiedJwt>>>,
    /// Lazily decoded verified payload (sig checked). Also sets `validated`.
    verified: RefCell<Option<Option<HashMap<String, serde_json::Value>>>>,
    /// Lazily computed: is the JWT signature valid?
    validated: RefCell<Option<bool>>,
    /// Reference to the RuleSet's key config (no clone).
    config: Option<&'a JwtConfig>,
}

#[derive(Debug, Clone)]
struct UnverifiedJwt {
    header: HashMap<String, serde_json::Value>,
    payload: HashMap<String, serde_json::Value>,
}

impl<'a> JwtData<'a> {
    pub fn new(authorization: Option<&'a str>, config: Option<&'a JwtConfig>) -> Self {
        // Case-insensitive "Bearer" prefix with flexible whitespace (matches Ruby regex /\ABearer\s+(.+)\z/i)
        let token = authorization.and_then(|auth| {
            let trimmed = auth.trim();
            // Match Ruby regex /\ABearer\s+(.+)\z/i: case-insensitive "bearer"
            // followed by one or more ASCII whitespace characters (space, tab, etc.)
            if trimmed.len() > 6
                && trimmed[..6].eq_ignore_ascii_case("bearer")
            {
                let after_bearer = &trimmed[6..];
                // Require at least one whitespace char after "bearer"
                if after_bearer.is_empty()
                    || !after_bearer.as_bytes()[0].is_ascii_whitespace()
                {
                    return None;
                }
                let token = after_bearer.trim_start();
                if token.is_empty() {
                    None
                } else {
                    Some(token)
                }
            } else {
                None
            }
        });
        JwtData {
            token,
            unverified: RefCell::new(None),
            verified: RefCell::new(None),
            validated: RefCell::new(None),
            config,
        }
    }

    /// Get an unverified payload claim value as a string.
    /// If the verified cache is already populated (from a prior verified_payload access),
    /// reuses it to avoid a redundant base64 decode.
    pub fn payload_claim(&self, claim: &str) -> Option<String> {
        // Check verified cache first — avoids separate base64 decode when
        // verified_payload was already accessed for this request.
        if let Some(Some(payload)) = self.verified.borrow().as_ref() {
            return payload.get(claim).map(json_value_to_string);
        }
        self.ensure_unverified();
        let cache = self.unverified.borrow();
        cache
            .as_ref()
            .unwrap()
            .as_ref()
            .and_then(|jwt| jwt.payload.get(claim))
            .map(json_value_to_string)
    }

    /// Get an unverified header field value as a string.
    pub fn header_field(&self, field: &str) -> Option<String> {
        self.ensure_unverified();
        let cache = self.unverified.borrow();
        cache
            .as_ref()
            .unwrap()
            .as_ref()
            .and_then(|jwt| jwt.header.get(field))
            .map(json_value_to_string)
    }

    /// Get a verified payload claim value as a string.
    /// Signature is checked on first access; result is cached.
    pub fn verified_payload_claim(&self, claim: &str) -> Option<String> {
        self.ensure_verified();
        let cache = self.verified.borrow();
        cache
            .as_ref()
            .unwrap()
            .as_ref()
            .and_then(|payload| payload.get(claim))
            .map(json_value_to_string)
    }

    /// Check if JWT signature is valid. Uses cached result from
    /// `ensure_verified` if available, otherwise verifies now.
    pub fn is_valid(&self) -> bool {
        // If we already verified (e.g. from a verified_payload access), reuse.
        if self.validated.borrow().is_some() {
            return *self.validated.borrow().as_ref().unwrap();
        }
        // Otherwise, run verification (which caches both validated + verified).
        self.ensure_verified();
        *self.validated.borrow().as_ref().unwrap()
    }

    fn ensure_unverified(&self) {
        if self.unverified.borrow().is_some() {
            return;
        }
        let result = self.token.and_then(decode_unverified);
        *self.unverified.borrow_mut() = Some(result);
    }

    /// Verify the token signature, caching both the payload and the
    /// validity boolean in one pass.
    fn ensure_verified(&self) {
        if self.verified.borrow().is_some() {
            return;
        }
        let payload = match (self.token, self.config) {
            (Some(token), Some(config)) => decode_verified(token, config),
            _ => None,
        };
        let valid = payload.is_some();
        *self.verified.borrow_mut() = Some(payload);
        // Also populate the validated cache so is_valid() won't re-verify.
        if self.validated.borrow().is_none() {
            *self.validated.borrow_mut() = Some(valid);
        }
    }
}

/// Decode a JWT without verifying the signature (base64 decode only).
fn decode_unverified(token: &str) -> Option<UnverifiedJwt> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    let header_json = URL_SAFE_NO_PAD.decode(parts[0]).ok()?;
    let payload_json = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;

    let header: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&header_json).ok()?;
    let payload: HashMap<String, serde_json::Value> =
        serde_json::from_slice(&payload_json).ok()?;

    Some(UnverifiedJwt { header, payload })
}

/// Decode a JWT with signature verification, returning the payload if valid.
/// Tries each configured key in order; first successful decode wins.
fn decode_verified(
    token: &str,
    config: &JwtConfig,
) -> Option<HashMap<String, serde_json::Value>> {
    for key_entry in &config.keys {
        if let Ok(data) = decode::<HashMap<String, serde_json::Value>>(
            token,
            &key_entry.decoding_key,
            &key_entry.validation,
        ) {
            return Some(data.claims);
        }
    }
    None
}

/// Convert a serde_json::Value to a string representation.
fn json_value_to_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
        // Arrays and objects serialize as JSON strings
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Future expiration timestamp (year ~2286).
    const FUTURE_EXP: u64 = 9_999_999_999;

    /// Past expiration timestamp (1 hour ago from a fixed epoch).
    fn past_exp() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600
    }

    fn make_hs256_token(payload: &serde_json::Value) -> String {
        use jsonwebtoken::{encode, EncodingKey, Header};
        let claims: HashMap<String, serde_json::Value> =
            serde_json::from_value(payload.clone()).unwrap();
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"test-secret"),
        )
        .unwrap()
    }

    fn hs256_config(secret: &str) -> JwtConfig {
        JwtConfig::from_raw(&[RawJwtKey {
            algorithm: "HS256".to_string(),
            key: secret.to_string(),
        }])
        .unwrap()
    }

    #[test]
    fn test_decode_unverified() {
        let payload = serde_json::json!({
            "sub": "user_123",
            "exp": FUTURE_EXP,
            "roles": ["admin", "user"]
        });
        let token = make_hs256_token(&payload);
        let result = decode_unverified(&token).unwrap();
        assert_eq!(
            result.payload.get("sub").unwrap(),
            &serde_json::Value::String("user_123".to_string())
        );
        assert_eq!(
            result.header.get("alg").unwrap(),
            &serde_json::Value::String("HS256".to_string())
        );
    }

    #[test]
    fn test_decode_unverified_array_claim() {
        let payload = serde_json::json!({
            "sub": "user_123",
            "exp": FUTURE_EXP,
            "roles": ["admin", "user"]
        });
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let jwt_data = JwtData::new(Some(&auth), None);
        // Array claims serialize as JSON
        let roles = jwt_data.payload_claim("roles").unwrap();
        assert_eq!(roles, r#"["admin","user"]"#);
    }

    #[test]
    fn test_validate_token_correct_key() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let config = hs256_config("test-secret");
        assert!(decode_verified(&token, &config).is_some());
    }

    #[test]
    fn test_validate_token_wrong_key() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let config = hs256_config("wrong-secret");
        assert!(decode_verified(&token, &config).is_none());
    }

    #[test]
    fn test_validate_token_expired() {
        let payload = serde_json::json!({"sub": "user_123", "exp": past_exp()});
        let token = make_hs256_token(&payload);
        let config = hs256_config("test-secret");
        // Signature is valid but token is expired — should fail verification
        assert!(decode_verified(&token, &config).is_none());
    }

    #[test]
    fn test_expired_token_unverified_still_works() {
        // Unverified decode should still return claims for expired tokens
        let payload = serde_json::json!({"sub": "user_99", "exp": past_exp()});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("test-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        // Unverified payload access works
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_99".to_string()));
        // But verified access fails (expired)
        assert!(!jwt_data.is_valid());
        assert_eq!(jwt_data.verified_payload_claim("sub"), None);
    }

    #[test]
    fn test_multi_key_fallback() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload); // signed with "test-secret"
        let config = JwtConfig::from_raw(&[
            RawJwtKey {
                algorithm: "HS256".to_string(),
                key: "wrong-key-1".to_string(),
            },
            RawJwtKey {
                algorithm: "HS256".to_string(),
                key: "test-secret".to_string(),
            },
        ])
        .unwrap();
        // First key fails, second succeeds
        assert!(decode_verified(&token, &config).is_some());
    }

    #[test]
    fn test_jwt_data_lazy() {
        let payload =
            serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP, "count": 42, "active": true});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("test-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
        assert_eq!(jwt_data.payload_claim("count"), Some("42".to_string()));
        assert_eq!(jwt_data.payload_claim("active"), Some("true".to_string()));
        assert_eq!(jwt_data.header_field("alg"), Some("HS256".to_string()));
        assert!(jwt_data.is_valid());
        assert_eq!(
            jwt_data.verified_payload_claim("sub"),
            Some("user_123".to_string())
        );
    }

    #[test]
    fn test_verified_sets_validated_cache() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("test-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        // Access verified_payload first — this should also cache validated
        assert_eq!(
            jwt_data.verified_payload_claim("sub"),
            Some("user_123".to_string())
        );
        // validated should already be cached (no re-verification)
        assert!(jwt_data.validated.borrow().is_some());
        assert!(jwt_data.is_valid());
    }

    #[test]
    fn test_no_token() {
        let jwt_data = JwtData::new(None, None);
        assert_eq!(jwt_data.payload_claim("sub"), None);
        assert!(!jwt_data.is_valid());
    }

    #[test]
    fn test_invalid_token_format() {
        // Not 3 dot-separated parts
        let jwt_data = JwtData::new(Some("Bearer not-a-jwt"), None);
        assert_eq!(jwt_data.payload_claim("sub"), None);
        assert!(!jwt_data.is_valid());
    }

    #[test]
    fn test_malformed_token_bad_base64() {
        let jwt_data = JwtData::new(Some("Bearer aaa.bbb.ccc"), None);
        assert_eq!(jwt_data.payload_claim("sub"), None);
    }

    #[test]
    fn test_non_bearer_auth_header() {
        let jwt_data = JwtData::new(Some("Basic dXNlcjpwYXNz"), None);
        assert_eq!(jwt_data.payload_claim("sub"), None);
        assert!(!jwt_data.is_valid());
    }

    #[test]
    fn test_case_insensitive_bearer() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("bearer {}", token); // lowercase "bearer"
        let jwt_data = JwtData::new(Some(&auth), None);
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
    }

    #[test]
    fn test_bearer_multiple_spaces() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer   {}", token); // multiple spaces
        let jwt_data = JwtData::new(Some(&auth), None);
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
    }

    #[test]
    fn test_bearer_mixed_case() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("BEARER {}", token);
        let jwt_data = JwtData::new(Some(&auth), None);
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
    }

    #[test]
    fn test_jwt_two_parts_only() {
        // JWT with only 2 parts (no signature) should fail unverified decode
        let jwt_data = JwtData::new(Some("Bearer part1.part2"), None);
        assert_eq!(jwt_data.payload_claim("sub"), None);
    }

    #[test]
    fn test_json_value_to_string_null() {
        assert_eq!(json_value_to_string(&serde_json::Value::Null), "null");
    }

    #[test]
    fn test_json_value_to_string_bool() {
        assert_eq!(
            json_value_to_string(&serde_json::Value::Bool(true)),
            "true"
        );
        assert_eq!(
            json_value_to_string(&serde_json::Value::Bool(false)),
            "false"
        );
    }

    #[test]
    fn test_verified_then_unverified_reuses_cache() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("test-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        // Access verified first
        assert_eq!(
            jwt_data.verified_payload_claim("sub"),
            Some("user_123".to_string())
        );
        // Now access unverified — should reuse verified cache, unverified should stay None
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
        assert!(jwt_data.unverified.borrow().is_none());
    }

    #[test]
    fn test_unverified_then_verified_both_work() {
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("test-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        // Access unverified first
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
        // Then verified
        assert_eq!(
            jwt_data.verified_payload_claim("sub"),
            Some("user_123".to_string())
        );
    }

    #[test]
    fn test_failed_verified_unverified_still_works() {
        let payload = serde_json::json!({"sub": "user_99", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer {}", token);
        let config = hs256_config("wrong-secret");
        let jwt_data = JwtData::new(Some(&auth), Some(&config));

        // Verified fails (wrong key)
        assert_eq!(jwt_data.verified_payload_claim("sub"), None);
        // Unverified still works via base64 decode (verified cache has None payload)
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_99".to_string()));
    }

    #[test]
    fn test_bearer_tab_separator() {
        // Ruby regex /\ABearer\s+(.+)\z/i matches tab as whitespace
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer\t{}", token); // tab instead of space
        let jwt_data = JwtData::new(Some(&auth), None);
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
    }

    #[test]
    fn test_bearer_newline_separator() {
        // \s also matches newlines in Ruby
        let payload = serde_json::json!({"sub": "user_123", "exp": FUTURE_EXP});
        let token = make_hs256_token(&payload);
        let auth = format!("Bearer\n{}", token);
        // Note: trim() at the start removes outer whitespace, but newline between
        // bearer and token is inside the string. After trim, "Bearer\n<token>"
        // still has the newline. The check should pass since \n is ASCII whitespace.
        let jwt_data = JwtData::new(Some(&auth), None);
        assert_eq!(jwt_data.payload_claim("sub"), Some("user_123".to_string()));
    }

    #[test]
    fn test_json_value_to_string_array() {
        let arr = serde_json::json!([1, 2, 3]);
        assert_eq!(json_value_to_string(&arr), "[1,2,3]");
    }

    #[test]
    fn test_json_value_to_string_object() {
        let obj = serde_json::json!({"key": "value"});
        assert_eq!(json_value_to_string(&obj), r#"{"key":"value"}"#);
    }
}
