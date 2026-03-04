use crate::body::BodyData;
use crate::jwt::JwtData;
use crate::query::QueryData;
use crate::request_data::RequestData;
use percent_encoding::percent_decode_str;
use std::borrow::Cow;

/// Transform functions applied to field values before operator comparison.
#[derive(Debug, Clone)]
pub enum Transform {
    Lower,
    Upper,
    UrlDecode,
    Length,
}

impl Transform {
    pub fn parse(s: &str) -> Result<Transform, String> {
        match s {
            "lower" => Ok(Transform::Lower),
            "upper" => Ok(Transform::Upper),
            "url_decode" => Ok(Transform::UrlDecode),
            "length" => Ok(Transform::Length),
            _ => Err(format!("Unknown transform: {}", s)),
        }
    }
}

/// Represents a field reference in a rule condition.
#[derive(Debug, Clone)]
pub enum Field {
    Path,
    Method,
    IpSrc,
    UserAgent,
    Host,
    QueryString,
    ContentLength,
    Header(String),
    Cookie(String),
    /// Full URI: path + "?" + query (or just path if no query)
    Uri,
    /// Lowercase file extension from path (no dot), e.g. "js", "png"
    PathExtension,
    /// Query parameter value: `http.request.uri.args["param"]`
    QueryParam(String),
    /// Raw request body
    BodyRaw,
    /// JSON body field: `http.request.body.json["key"]`
    BodyJsonField(String),
    /// Unverified JWT payload claim: `jwt.payload["claim"]`
    JwtPayload(String),
    /// Unverified JWT header field: `jwt.header["field"]`
    JwtHeader(String),
    /// Verified JWT payload claim: `jwt.verified_payload["claim"]`
    JwtVerifiedPayload(String),
    /// JWT validity check: `jwt.valid`
    JwtValid,
}

/// The extracted value of a field from a request.
/// Uses `Cow` so non-JWT fields borrow from `RequestData` (zero-copy)
/// while JWT fields return owned strings.
pub enum FieldValue<'a> {
    /// Always-present string (borrows from request data or owns JWT output).
    Str(Cow<'a, str>),
    /// Optional string (e.g. user_agent, host, headers, cookies, JWT claims).
    OptStr(Option<Cow<'a, str>>),
    /// Numeric value (e.g. content_length).
    Number(u64),
}

/// Bundles all per-request lazy caches for field extraction.
pub struct RequestContext<'a> {
    pub jwt: Option<JwtData<'a>>,
    pub query: QueryData<'a>,
    pub body: BodyData<'a>,
}

impl Field {
    /// Parse a Cloudflare-style field name string into a Field enum.
    pub fn parse(s: &str) -> Result<Field, String> {
        match s {
            "http.request.uri.path" => Ok(Field::Path),
            "http.request.method" => Ok(Field::Method),
            "ip.src" => Ok(Field::IpSrc),
            "http.user_agent" => Ok(Field::UserAgent),
            "http.host" => Ok(Field::Host),
            "http.request.uri.query" => Ok(Field::QueryString),
            "http.request.body.size" => Ok(Field::ContentLength),
            "http.request.uri" => Ok(Field::Uri),
            "http.request.uri.path.extension" => Ok(Field::PathExtension),
            "http.request.body.raw" => Ok(Field::BodyRaw),
            "jwt.valid" => Ok(Field::JwtValid),
            _ => {
                if let Some(rest) = s.strip_prefix("http.request.headers[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::Header(name.to_lowercase()));
                    }
                }
                if let Some(rest) = s.strip_prefix("http.request.cookies[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::Cookie(name.to_string()));
                    }
                }
                if let Some(rest) = s.strip_prefix("http.request.uri.args[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::QueryParam(name.to_string()));
                    }
                }
                if let Some(rest) = s.strip_prefix("http.request.body.json[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::BodyJsonField(name.to_string()));
                    }
                }
                if let Some(rest) = s.strip_prefix("jwt.payload[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::JwtPayload(name.to_string()));
                    }
                }
                if let Some(rest) = s.strip_prefix("jwt.header[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::JwtHeader(name.to_string()));
                    }
                }
                if let Some(rest) = s.strip_prefix("jwt.verified_payload[\"") {
                    if let Some(name) = rest.strip_suffix("\"]") {
                        return Ok(Field::JwtVerifiedPayload(name.to_string()));
                    }
                }
                Err(format!("Unknown field: {}", s))
            }
        }
    }

    /// Returns true if this field requires JWT data for extraction.
    #[cfg(test)]
    fn needs_jwt(&self) -> bool {
        matches!(
            self,
            Field::JwtPayload(_)
                | Field::JwtHeader(_)
                | Field::JwtVerifiedPayload(_)
                | Field::JwtValid
        )
    }

    /// Extract field value from request data and request context.
    pub fn extract<'a>(
        &self,
        data: &'a RequestData,
        ctx: &RequestContext<'a>,
    ) -> FieldValue<'a> {
        match self {
            // Non-JWT fields — all zero-copy borrows from RequestData
            Field::Path => FieldValue::Str(Cow::Borrowed(&data.path)),
            Field::Method => FieldValue::Str(Cow::Borrowed(&data.method)),
            Field::IpSrc => FieldValue::Str(Cow::Borrowed(&data.ip)),
            Field::UserAgent => {
                FieldValue::OptStr(data.user_agent.as_deref().map(Cow::Borrowed))
            }
            Field::Host => FieldValue::OptStr(data.host.as_deref().map(Cow::Borrowed)),
            Field::QueryString => FieldValue::Str(Cow::Borrowed(&data.query_string)),
            Field::ContentLength => FieldValue::Number(data.content_length),
            Field::Header(name) => {
                FieldValue::OptStr(data.headers.get(name).map(|s| Cow::Borrowed(s.as_str())))
            }
            Field::Cookie(name) => {
                FieldValue::OptStr(data.cookies.get(name).map(|s| Cow::Borrowed(s.as_str())))
            }

            // URI = path + "?" + query (or just path if query is empty)
            Field::Uri => {
                if data.query_string.is_empty() {
                    FieldValue::Str(Cow::Borrowed(&data.path))
                } else {
                    FieldValue::Str(Cow::Owned(format!(
                        "{}?{}",
                        data.path, data.query_string
                    )))
                }
            }

            // PathExtension: extension after last '.' in filename portion (as-is, no lowercasing)
            // Users can apply `lower` transform explicitly if needed.
            Field::PathExtension => {
                let path = &data.path;
                // Find the filename portion (after last '/')
                let filename = path.rsplit('/').next().unwrap_or(path);
                if let Some(dot_pos) = filename.rfind('.') {
                    let ext = &filename[dot_pos + 1..];
                    if ext.is_empty() {
                        FieldValue::OptStr(None)
                    } else {
                        FieldValue::Str(Cow::Borrowed(ext))
                    }
                } else {
                    FieldValue::OptStr(None)
                }
            }

            // Query parameter from parsed query string
            Field::QueryParam(name) => {
                FieldValue::OptStr(ctx.query.get(name).map(Cow::Owned))
            }

            // Raw request body
            Field::BodyRaw => {
                FieldValue::OptStr(ctx.body.raw().map(Cow::Borrowed))
            }

            // JSON body field
            Field::BodyJsonField(key) => {
                FieldValue::OptStr(ctx.body.json_field(key).map(Cow::Owned))
            }

            // JWT fields — return owned strings from JWT decode
            Field::JwtPayload(claim) => {
                let val = ctx.jwt.as_ref().and_then(|jwt| jwt.payload_claim(claim));
                FieldValue::OptStr(val.map(Cow::Owned))
            }
            Field::JwtHeader(field) => {
                let val = ctx.jwt.as_ref().and_then(|jwt| jwt.header_field(field));
                FieldValue::OptStr(val.map(Cow::Owned))
            }
            Field::JwtVerifiedPayload(claim) => {
                let val = ctx
                    .jwt
                    .as_ref()
                    .and_then(|jwt| jwt.verified_payload_claim(claim));
                FieldValue::OptStr(val.map(Cow::Owned))
            }
            Field::JwtValid => {
                // exists = valid, not_exists = invalid/no token
                let valid = ctx.jwt.as_ref().is_some_and(|jwt| jwt.is_valid());
                if valid {
                    FieldValue::Str(Cow::Borrowed("true"))
                } else {
                    FieldValue::OptStr(None)
                }
            }
        }
    }
}

/// Apply a sequence of transforms to a field value.
/// Returns a new FieldValue with the transforms applied.
pub fn apply_transforms<'a>(val: FieldValue<'a>, transforms: &[Transform]) -> FieldValue<'a> {
    let mut current = val;
    for transform in transforms {
        current = apply_one_transform(current, transform);
    }
    current
}

fn apply_one_transform<'a>(val: FieldValue<'a>, transform: &Transform) -> FieldValue<'a> {
    match transform {
        Transform::Length => {
            match &val {
                FieldValue::Str(cow) => FieldValue::Number(cow.len() as u64),
                FieldValue::OptStr(Some(cow)) => FieldValue::Number(cow.len() as u64),
                FieldValue::OptStr(None) => FieldValue::Number(0),
                FieldValue::Number(_) => val, // length of a number is itself
            }
        }
        Transform::Lower => match val {
            FieldValue::Str(cow) => FieldValue::Str(Cow::Owned(cow.to_lowercase())),
            FieldValue::OptStr(Some(cow)) => {
                FieldValue::OptStr(Some(Cow::Owned(cow.to_lowercase())))
            }
            other => other,
        },
        Transform::Upper => match val {
            FieldValue::Str(cow) => FieldValue::Str(Cow::Owned(cow.to_uppercase())),
            FieldValue::OptStr(Some(cow)) => {
                FieldValue::OptStr(Some(Cow::Owned(cow.to_uppercase())))
            }
            other => other,
        },
        Transform::UrlDecode => match val {
            FieldValue::Str(cow) => {
                let decoded = percent_decode_str(&cow).decode_utf8_lossy().into_owned();
                FieldValue::Str(Cow::Owned(decoded))
            }
            FieldValue::OptStr(Some(cow)) => {
                let decoded = percent_decode_str(&cow).decode_utf8_lossy().into_owned();
                FieldValue::OptStr(Some(Cow::Owned(decoded)))
            }
            other => other,
        },
    }
}

impl<'a> FieldValue<'a> {
    /// Get the string value if present.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::Str(cow) => Some(cow),
            FieldValue::OptStr(Some(cow)) => Some(cow),
            FieldValue::OptStr(None) => None,
            FieldValue::Number(_) => None,
        }
    }

    /// Check if the field exists (has a non-empty value).
    pub fn exists(&self) -> bool {
        match self {
            FieldValue::Str(cow) => !cow.is_empty(),
            FieldValue::OptStr(Some(cow)) => !cow.is_empty(),
            FieldValue::OptStr(None) => false,
            FieldValue::Number(_) => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_jwt_payload() {
        match Field::parse("jwt.payload[\"sub\"]").unwrap() {
            Field::JwtPayload(name) => assert_eq!(name, "sub"),
            other => panic!("Expected JwtPayload, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_jwt_header() {
        match Field::parse("jwt.header[\"alg\"]").unwrap() {
            Field::JwtHeader(name) => assert_eq!(name, "alg"),
            other => panic!("Expected JwtHeader, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_jwt_verified_payload() {
        match Field::parse("jwt.verified_payload[\"sub\"]").unwrap() {
            Field::JwtVerifiedPayload(name) => assert_eq!(name, "sub"),
            other => panic!("Expected JwtVerifiedPayload, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_jwt_valid() {
        assert!(matches!(Field::parse("jwt.valid").unwrap(), Field::JwtValid));
    }

    #[test]
    fn test_parse_jwt_invalid() {
        assert!(Field::parse("jwt.unknown").is_err());
        assert!(Field::parse("jwt.payload").is_err()); // missing ["claim"]
    }

    #[test]
    fn test_needs_jwt() {
        assert!(Field::JwtPayload("sub".into()).needs_jwt());
        assert!(Field::JwtHeader("alg".into()).needs_jwt());
        assert!(Field::JwtVerifiedPayload("sub".into()).needs_jwt());
        assert!(Field::JwtValid.needs_jwt());
        assert!(!Field::Path.needs_jwt());
        assert!(!Field::Header("x-api-key".into()).needs_jwt());
    }

    #[test]
    fn test_parse_uri() {
        assert!(matches!(
            Field::parse("http.request.uri").unwrap(),
            Field::Uri
        ));
    }

    #[test]
    fn test_parse_path_extension() {
        assert!(matches!(
            Field::parse("http.request.uri.path.extension").unwrap(),
            Field::PathExtension
        ));
    }

    #[test]
    fn test_parse_query_param() {
        match Field::parse("http.request.uri.args[\"q\"]").unwrap() {
            Field::QueryParam(name) => assert_eq!(name, "q"),
            other => panic!("Expected QueryParam, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_body_raw() {
        assert!(matches!(
            Field::parse("http.request.body.raw").unwrap(),
            Field::BodyRaw
        ));
    }

    #[test]
    fn test_parse_body_json_field() {
        match Field::parse("http.request.body.json[\"user_id\"]").unwrap() {
            Field::BodyJsonField(name) => assert_eq!(name, "user_id"),
            other => panic!("Expected BodyJsonField, got {:?}", other),
        }
    }

    #[test]
    fn test_transform_lower() {
        let val = FieldValue::Str(Cow::Borrowed("AhrefsBot"));
        let result = apply_transforms(val, &[Transform::Lower]);
        assert_eq!(result.as_str(), Some("ahrefsbot"));
    }

    #[test]
    fn test_transform_upper() {
        let val = FieldValue::Str(Cow::Borrowed("hello"));
        let result = apply_transforms(val, &[Transform::Upper]);
        assert_eq!(result.as_str(), Some("HELLO"));
    }

    #[test]
    fn test_transform_url_decode() {
        let val = FieldValue::Str(Cow::Borrowed("%2e%2e"));
        let result = apply_transforms(val, &[Transform::UrlDecode]);
        assert_eq!(result.as_str(), Some(".."));
    }

    #[test]
    fn test_transform_length() {
        let val = FieldValue::Str(Cow::Borrowed("/api/v2/users"));
        let result = apply_transforms(val, &[Transform::Length]);
        match result {
            FieldValue::Number(n) => assert_eq!(n, 13),
            _ => panic!("Expected Number"),
        }
    }

    #[test]
    fn test_chained_transforms() {
        let val = FieldValue::Str(Cow::Borrowed("UNION%20SELECT"));
        let result = apply_transforms(val, &[Transform::UrlDecode, Transform::Lower]);
        assert_eq!(result.as_str(), Some("union select"));
    }

    #[test]
    fn test_transform_opt_str_none() {
        let val = FieldValue::OptStr(None);
        let result = apply_transforms(val, &[Transform::Lower]);
        assert_eq!(result.as_str(), None);
    }

    // --- Field parsing tests ---

    #[test]
    fn test_parse_basic_fields() {
        assert!(matches!(Field::parse("http.request.uri.path").unwrap(), Field::Path));
        assert!(matches!(Field::parse("http.request.method").unwrap(), Field::Method));
        assert!(matches!(Field::parse("ip.src").unwrap(), Field::IpSrc));
        assert!(matches!(Field::parse("http.user_agent").unwrap(), Field::UserAgent));
        assert!(matches!(Field::parse("http.host").unwrap(), Field::Host));
        assert!(matches!(Field::parse("http.request.uri.query").unwrap(), Field::QueryString));
        assert!(matches!(Field::parse("http.request.body.size").unwrap(), Field::ContentLength));
    }

    #[test]
    fn test_parse_cookie() {
        match Field::parse("http.request.cookies[\"session_id\"]").unwrap() {
            Field::Cookie(name) => assert_eq!(name, "session_id"),
            other => panic!("Expected Cookie, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_header() {
        match Field::parse("http.request.headers[\"X-API-Key\"]").unwrap() {
            Field::Header(name) => assert_eq!(name, "x-api-key"), // lowercased
            other => panic!("Expected Header, got {:?}", other),
        }
    }

    #[test]
    fn test_unknown_field_string() {
        assert!(Field::parse("nonexistent.field").is_err());
    }

    #[test]
    fn test_unknown_transform_string() {
        assert!(Transform::parse("nonexistent_transform").is_err());
    }

    // --- FieldValue tests ---

    #[test]
    fn test_field_value_exists() {
        assert!(FieldValue::Str(Cow::Borrowed("hello")).exists());
        assert!(!FieldValue::Str(Cow::Borrowed("")).exists());
        assert!(FieldValue::OptStr(Some(Cow::Borrowed("x"))).exists());
        assert!(!FieldValue::OptStr(Some(Cow::Borrowed(""))).exists());
        assert!(!FieldValue::OptStr(None).exists());
        assert!(FieldValue::Number(0).exists()); // numbers always exist
    }

    #[test]
    fn test_field_value_as_str() {
        assert_eq!(FieldValue::Str(Cow::Borrowed("x")).as_str(), Some("x"));
        assert_eq!(FieldValue::OptStr(Some(Cow::Borrowed("y"))).as_str(), Some("y"));
        assert_eq!(FieldValue::OptStr(None).as_str(), None);
        assert_eq!(FieldValue::Number(42).as_str(), None);
    }

    // --- PathExtension dotfile ---

    #[test]
    fn test_dotfile_has_no_extension() {
        // .env is a dotfile, not a file with extension "env" (per Ruby File.extname)
        // In Rust, rsplit('.') on ".env" filename gives "env" after the dot
        // This differs from Ruby where File.extname(".env") returns ""
        // Note: Rust implementation treats the dot-separated part as extension
        // regardless of whether it's a dotfile
        let val = ".env";
        let filename = val.rsplit('/').next().unwrap_or(val);
        let ext = filename.rfind('.').map(|pos| &filename[pos + 1..]);
        // The Rust impl will find "env" after the dot — this is by design
        assert_eq!(ext, Some("env"));
    }
}
