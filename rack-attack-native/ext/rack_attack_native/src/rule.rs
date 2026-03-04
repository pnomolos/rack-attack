use crate::field::{apply_transforms, Field, FieldValue, RequestContext, Transform};
use crate::ip_matcher::{ip_in_ranges, parse_cidrs};
use crate::jwt::RawJwtKey;
use crate::request_data::RequestData;
use ipnet::IpNet;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashSet;

// ── Raw JSON types (deserialized from user input) ──────────────────────────

#[derive(Debug, Deserialize)]
pub struct RawRuleSet {
    pub rules: Vec<RawRule>,
    #[serde(default)]
    pub jwt_keys: Option<Vec<RawJwtKey>>,
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub name: String,
    #[serde(rename = "type")]
    pub rule_type: String,
    pub condition: Option<RawCondition>,
    pub limit: Option<u64>,
    pub period: Option<u64>,
    pub key: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawCondition {
    Leaf(LeafCondition),
    Logical(LogicalCondition),
}

#[derive(Debug, Deserialize)]
pub struct LogicalCondition {
    #[serde(default)]
    pub and: Option<Vec<RawCondition>>,
    #[serde(default)]
    pub or: Option<Vec<RawCondition>>,
    #[serde(default)]
    pub not: Option<Box<RawCondition>>,
}

#[derive(Debug, Deserialize)]
pub struct LeafCondition {
    pub field: String,
    pub operator: String,
    pub value: Option<serde_json::Value>,
    #[serde(default)]
    pub transform: Option<serde_json::Value>,
}

// ── Compiled types (optimized for evaluation) ──────────────────────────────

/// A compiled condition tree, ready for fast evaluation.
#[derive(Debug)]
pub enum Condition {
    Leaf {
        field: Field,
        operator: Operator,
        compiled: CompiledValue,
        transforms: Vec<Transform>,
    },
    And(Vec<Condition>),
    Or(Vec<Condition>),
    Not(Box<Condition>),
    /// Always true (used when a rule has no condition)
    Always,
}

#[derive(Debug, Clone, Copy)]
pub enum Operator {
    Eq,
    Ne,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    In,
    NotIn,
    InIpRange,
    NotInIpRange,
    Gt,
    Lt,
    Gte,
    Lte,
    Exists,
    NotExists,
    Wildcard,
}

#[derive(Debug)]
pub enum CompiledValue {
    Str(String),
    StringSet(HashSet<String>),
    Regex(Regex),
    IpNets(Vec<IpNet>),
    Number(f64),
    GlobPattern(String),
    None,
}

/// A fully compiled rule ready for evaluation.
#[derive(Debug)]
pub struct Rule {
    pub name: String,
    pub rule_type: RuleType,
    pub condition: Condition,
    pub limit: Option<u64>,
    pub period: Option<u64>,
    pub key_fields: Vec<Field>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RuleType {
    Safelist,
    Blocklist,
    Throttle,
    Track,
}

// ── Compilation ────────────────────────────────────────────────────────────

impl Operator {
    fn parse(s: &str) -> Result<Operator, String> {
        match s {
            "eq" => Ok(Operator::Eq),
            "ne" => Ok(Operator::Ne),
            "contains" => Ok(Operator::Contains),
            "starts_with" => Ok(Operator::StartsWith),
            "ends_with" => Ok(Operator::EndsWith),
            "matches" => Ok(Operator::Matches),
            "in" => Ok(Operator::In),
            "not_in" => Ok(Operator::NotIn),
            "in_ip_range" => Ok(Operator::InIpRange),
            "not_in_ip_range" => Ok(Operator::NotInIpRange),
            "gt" => Ok(Operator::Gt),
            "lt" => Ok(Operator::Lt),
            "gte" => Ok(Operator::Gte),
            "lte" => Ok(Operator::Lte),
            "exists" => Ok(Operator::Exists),
            "not_exists" => Ok(Operator::NotExists),
            "wildcard" => Ok(Operator::Wildcard),
            _ => Err(format!("Unknown operator: {}", s)),
        }
    }
}

impl RuleType {
    fn parse(s: &str) -> Result<RuleType, String> {
        match s {
            "safelist" => Ok(RuleType::Safelist),
            "blocklist" => Ok(RuleType::Blocklist),
            "throttle" => Ok(RuleType::Throttle),
            "track" => Ok(RuleType::Track),
            _ => Err(format!("Unknown rule type: {}", s)),
        }
    }
}

fn compile_value(
    op: &Operator,
    value: &Option<serde_json::Value>,
) -> Result<CompiledValue, String> {
    match op {
        Operator::Exists | Operator::NotExists => Ok(CompiledValue::None),
        Operator::Matches => {
            let s = value
                .as_ref()
                .and_then(|v| v.as_str())
                .ok_or("matches operator requires a string value")?;
            let re = Regex::new(s).map_err(|e| format!("Invalid regex '{}': {}", s, e))?;
            Ok(CompiledValue::Regex(re))
        }
        Operator::Wildcard => {
            let s = value
                .as_ref()
                .and_then(|v| v.as_str())
                .ok_or("wildcard operator requires a string value")?;
            // Store pattern as-is for case-sensitive matching (matches Ruby File.fnmatch)
            Ok(CompiledValue::GlobPattern(s.to_string()))
        }
        Operator::InIpRange | Operator::NotInIpRange => {
            let cidrs: Vec<String> = match value.as_ref() {
                Some(serde_json::Value::Array(arr)) => arr
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(|s| s.to_string())
                            .ok_or("CIDR values must be strings".to_string())
                    })
                    .collect::<Result<Vec<_>, _>>()?,
                Some(serde_json::Value::String(s)) => vec![s.clone()],
                _ => {
                    return Err(
                        "IP range operator requires a string or array of strings".to_string()
                    )
                }
            };
            let nets = parse_cidrs(&cidrs)?;
            Ok(CompiledValue::IpNets(nets))
        }
        Operator::In | Operator::NotIn => {
            let arr = value
                .as_ref()
                .and_then(|v| v.as_array())
                .ok_or("in/not_in operator requires an array value")?;
            let set: HashSet<String> = arr
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .ok_or("in/not_in values must be strings".to_string())
                })
                .collect::<Result<_, _>>()?;
            Ok(CompiledValue::StringSet(set))
        }
        Operator::Gt | Operator::Lt | Operator::Gte | Operator::Lte => {
            let n = value
                .as_ref()
                .and_then(|v| v.as_f64())
                .ok_or("comparison operator requires a numeric value")?;
            Ok(CompiledValue::Number(n))
        }
        Operator::Eq | Operator::Ne => {
            // eq/ne support both string and numeric values
            if let Some(n) = value.as_ref().and_then(|v| v.as_f64()) {
                // Only treat as numeric if the JSON value is actually a number (not a string)
                if value.as_ref().map_or(false, |v| v.is_number()) {
                    return Ok(CompiledValue::Number(n));
                }
            }
            let s = value
                .as_ref()
                .and_then(|v| v.as_str())
                .ok_or("eq/ne operator requires a string or numeric value")?;
            Ok(CompiledValue::Str(s.to_string()))
        }
        Operator::Contains | Operator::StartsWith | Operator::EndsWith => {
            let s = value
                .as_ref()
                .and_then(|v| v.as_str())
                .ok_or("string operator requires a string value")?;
            Ok(CompiledValue::Str(s.to_string()))
        }
    }
}

fn parse_transforms(raw: &Option<serde_json::Value>) -> Result<Vec<Transform>, String> {
    match raw {
        None => Ok(Vec::new()),
        Some(serde_json::Value::String(s)) => Ok(vec![Transform::parse(s)?]),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .map(|v| {
                let s = v
                    .as_str()
                    .ok_or("transform array values must be strings")?;
                Transform::parse(s)
            })
            .collect(),
        _ => Err("transform must be a string or array of strings".to_string()),
    }
}

fn compile_condition(raw: &RawCondition) -> Result<Condition, String> {
    match raw {
        RawCondition::Logical(lc) => {
            if let Some(children) = &lc.and {
                let compiled: Result<Vec<_>, _> =
                    children.iter().map(compile_condition).collect();
                Ok(Condition::And(compiled?))
            } else if let Some(children) = &lc.or {
                let compiled: Result<Vec<_>, _> =
                    children.iter().map(compile_condition).collect();
                Ok(Condition::Or(compiled?))
            } else if let Some(child) = &lc.not {
                Ok(Condition::Not(Box::new(compile_condition(child)?)))
            } else {
                Err("Logical condition must have 'and', 'or', or 'not' key".to_string())
            }
        }
        RawCondition::Leaf(leaf) => {
            let field = Field::parse(&leaf.field)?;
            let operator = Operator::parse(&leaf.operator)?;
            let compiled = compile_value(&operator, &leaf.value)?;
            let transforms = parse_transforms(&leaf.transform)?;
            Ok(Condition::Leaf {
                field,
                operator,
                compiled,
                transforms,
            })
        }
    }
}

pub fn compile_rule(raw: &RawRule) -> Result<Rule, String> {
    let rule_type = RuleType::parse(&raw.rule_type)?;
    let condition = match &raw.condition {
        Some(c) => compile_condition(c)?,
        None => Condition::Always,
    };
    let key_fields: Vec<Field> = match &raw.key {
        Some(keys) => keys
            .iter()
            .map(|k| Field::parse(k))
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
    };

    if rule_type == RuleType::Throttle {
        if raw.limit.is_none() || raw.period.is_none() {
            return Err(format!(
                "Throttle rule '{}' requires limit and period",
                raw.name
            ));
        }
    }

    // Default throttle key to ip.src when not specified (matches Ruby behavior)
    let key_fields = if rule_type == RuleType::Throttle && key_fields.is_empty() {
        vec![Field::IpSrc]
    } else {
        key_fields
    };

    Ok(Rule {
        name: raw.name.clone(),
        rule_type,
        condition,
        limit: raw.limit,
        period: raw.period,
        key_fields,
    })
}

// ── Evaluation ─────────────────────────────────────────────────────────────

impl Condition {
    pub fn matches(&self, data: &RequestData, ctx: &RequestContext) -> bool {
        match self {
            Condition::Always => true,
            Condition::And(children) => children.iter().all(|c| c.matches(data, ctx)),
            Condition::Or(children) => children.iter().any(|c| c.matches(data, ctx)),
            Condition::Not(child) => !child.matches(data, ctx),
            Condition::Leaf {
                field,
                operator,
                compiled,
                transforms,
            } => eval_leaf(field, operator, compiled, transforms, data, ctx),
        }
    }
}

/// Compare a numeric value against a compiled numeric threshold.
fn eval_numeric(value: u64, operator: &Operator, compiled: &CompiledValue) -> bool {
    if let CompiledValue::Number(threshold) = compiled {
        let nf = value as f64;
        match operator {
            Operator::Gt => nf > *threshold,
            Operator::Lt => nf < *threshold,
            Operator::Gte => nf >= *threshold,
            Operator::Lte => nf <= *threshold,
            Operator::Eq => (nf - *threshold).abs() < f64::EPSILON,
            Operator::Ne => (nf - *threshold).abs() >= f64::EPSILON,
            _ => false,
        }
    } else {
        false
    }
}

fn eval_leaf(
    field: &Field,
    operator: &Operator,
    compiled: &CompiledValue,
    transforms: &[Transform],
    data: &RequestData,
    ctx: &RequestContext,
) -> bool {
    let raw_val = field.extract(data, ctx);

    // Check exists/not_exists BEFORE applying transforms (matches Ruby behavior)
    match operator {
        Operator::Exists => return raw_val.exists(),
        Operator::NotExists => return !raw_val.exists(),
        _ => {}
    }

    // Fast path: [lower/upper..., length] on ASCII → skip string transforms
    if let Some(Transform::Length) = transforms.last() {
        if matches!(compiled, CompiledValue::Number(_)) {
            let all_preserve = transforms[..transforms.len() - 1]
                .iter()
                .all(|t| matches!(t, Transform::Lower | Transform::Upper));
            if all_preserve {
                let is_ascii = match &raw_val {
                    FieldValue::Str(cow) => cow.is_ascii(),
                    FieldValue::OptStr(Some(cow)) => cow.is_ascii(),
                    _ => true,
                };
                if is_ascii {
                    let len = match &raw_val {
                        FieldValue::Str(cow) => cow.len() as u64,
                        FieldValue::OptStr(Some(cow)) => cow.len() as u64,
                        FieldValue::OptStr(None) => 0,
                        FieldValue::Number(n) => *n,
                    };
                    return eval_numeric(len, operator, compiled);
                }
            }
        }
    }

    let field_val = if transforms.is_empty() {
        raw_val
    } else {
        apply_transforms(raw_val, transforms)
    };

    // For numeric fields: try numeric comparison first, then fall back to
    // string comparison by stringifying the number (matches Ruby behavior where
    // content_length is a string and "0" == "0" works).
    if let FieldValue::Number(n) = &field_val {
        if matches!(compiled, CompiledValue::Number(_)) {
            return eval_numeric(*n, operator, compiled);
        }
        // Stringify the number and fall through to string comparison
        // so that eq/ne/in/not_in with string values work correctly.
        let stringified = n.to_string();
        return match (operator, compiled) {
            (Operator::Eq, CompiledValue::Str(v)) => stringified == *v,
            (Operator::Ne, CompiledValue::Str(v)) => stringified != *v,
            (Operator::Contains, CompiledValue::Str(v)) => stringified.contains(v.as_str()),
            (Operator::StartsWith, CompiledValue::Str(v)) => stringified.starts_with(v.as_str()),
            (Operator::EndsWith, CompiledValue::Str(v)) => stringified.ends_with(v.as_str()),
            (Operator::Matches, CompiledValue::Regex(re)) => re.is_match(&stringified),
            (Operator::In, CompiledValue::StringSet(set)) => set.contains(&stringified),
            (Operator::NotIn, CompiledValue::StringSet(set)) => !set.contains(&stringified),
            _ => false,
        };
    }

    let s = match field_val.as_str() {
        Some(s) => s,
        None => return false,
    };

    match (operator, compiled) {
        (Operator::Eq, CompiledValue::Str(v)) => s == v,
        (Operator::Ne, CompiledValue::Str(v)) => s != v,
        (Operator::Contains, CompiledValue::Str(v)) => s.contains(v.as_str()),
        (Operator::StartsWith, CompiledValue::Str(v)) => s.starts_with(v.as_str()),
        (Operator::EndsWith, CompiledValue::Str(v)) => s.ends_with(v.as_str()),
        (Operator::Matches, CompiledValue::Regex(re)) => re.is_match(s),
        (Operator::In, CompiledValue::StringSet(set)) => set.contains(s),
        (Operator::NotIn, CompiledValue::StringSet(set)) => !set.contains(s),
        (Operator::InIpRange, CompiledValue::IpNets(nets)) => ip_in_ranges(s, nets),
        (Operator::NotInIpRange, CompiledValue::IpNets(nets)) => !ip_in_ranges(s, nets),
        (Operator::Wildcard, CompiledValue::GlobPattern(pattern)) => {
            // Case-sensitive matching (matches Ruby File.fnmatch with FNM_PATHNAME)
            glob_match::glob_match(pattern, s)
        }
        (Operator::Gt, CompiledValue::Number(n)) => s.parse::<f64>().map_or(false, |v| v > *n),
        (Operator::Lt, CompiledValue::Number(n)) => s.parse::<f64>().map_or(false, |v| v < *n),
        (Operator::Gte, CompiledValue::Number(n)) => s.parse::<f64>().map_or(false, |v| v >= *n),
        (Operator::Eq, CompiledValue::Number(n)) => {
            s.parse::<f64>().map_or(false, |v| (v - *n).abs() < f64::EPSILON)
        }
        (Operator::Ne, CompiledValue::Number(n)) => {
            s.parse::<f64>().map_or(false, |v| (v - *n).abs() >= f64::EPSILON)
        }
        (Operator::Lte, CompiledValue::Number(n)) => {
            s.parse::<f64>().map_or(false, |v| v <= *n)
        }
        _ => false,
    }
}

/// Extract the throttle discriminator key from a request.
pub fn extract_throttle_key(
    key_fields: &[Field],
    data: &RequestData,
    ctx: &RequestContext,
) -> Option<String> {
    let mut parts = Vec::with_capacity(key_fields.len());
    for field in key_fields {
        let val = field.extract(data, ctx);
        match &val {
            FieldValue::Number(n) => parts.push(n.to_string()),
            _ => match val.as_str() {
                Some(s) if !s.is_empty() => parts.push(s.to_string()),
                _ => return None,
            },
        }
    }
    Some(parts.join(":"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::BodyData;
    use crate::query::QueryData;
    use std::collections::HashMap;

    fn test_request() -> RequestData {
        RequestData {
            path: "/api/v2/users".to_string(),
            method: "GET".to_string(),
            ip: "10.0.1.50".to_string(),
            user_agent: Some("Mozilla/5.0".to_string()),
            host: Some("api.example.com".to_string()),
            query_string: "page=1".to_string(),
            content_length: 0,
            authorization: None,
            body: None,
            headers: {
                let mut h = HashMap::new();
                h.insert("x-api-key".to_string(), "key123".to_string());
                h
            },
            cookies: {
                let mut c = HashMap::new();
                c.insert("_session_id".to_string(), "abc123".to_string());
                c
            },
        }
    }

    fn test_ctx<'a>(data: &'a RequestData) -> RequestContext<'a> {
        RequestContext {
            jwt: None,
            query: QueryData::new(&data.query_string),
            body: BodyData::new(data.body.as_deref()),
            uri_cache: std::cell::OnceCell::new(),
        }
    }

    #[test]
    fn test_eq_operator() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Eq,
            compiled: CompiledValue::Str("/api/v2/users".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_starts_with() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::StartsWith,
            compiled: CompiledValue::Str("/api/".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_regex_match() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Matches,
            compiled: CompiledValue::Regex(Regex::new(r"^/api/v[0-9]+/").unwrap()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_ip_range() {
        let cond = Condition::Leaf {
            field: Field::IpSrc,
            operator: Operator::InIpRange,
            compiled: CompiledValue::IpNets(vec!["10.0.0.0/8".parse().unwrap()]),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_and_condition() {
        let cond = Condition::And(vec![
            Condition::Leaf {
                field: Field::Method,
                operator: Operator::Eq,
                compiled: CompiledValue::Str("GET".to_string()),
                transforms: vec![],
            },
            Condition::Leaf {
                field: Field::Path,
                operator: Operator::StartsWith,
                compiled: CompiledValue::Str("/api/".to_string()),
                transforms: vec![],
            },
        ]);
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_not_condition() {
        let cond = Condition::Not(Box::new(Condition::Leaf {
            field: Field::Method,
            operator: Operator::Eq,
            compiled: CompiledValue::Str("POST".to_string()),
            transforms: vec![],
        }));
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_header_extraction() {
        let cond = Condition::Leaf {
            field: Field::Header("x-api-key".to_string()),
            operator: Operator::Eq,
            compiled: CompiledValue::Str("key123".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_wildcard_operator() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Wildcard,
            compiled: CompiledValue::GlobPattern("/api/*/users".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_wildcard_no_match() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Wildcard,
            compiled: CompiledValue::GlobPattern("/admin/*".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(!cond.matches(&data, &ctx));
    }

    #[test]
    fn test_wildcard_case_sensitive() {
        // Wildcard matching is case-sensitive (matches Ruby File.fnmatch behavior)
        let mut data = test_request();
        data.path = "/API/V2/Users".to_string();
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Wildcard,
            compiled: CompiledValue::GlobPattern("/api/*/users".to_string()),
            transforms: vec![],
        };
        // Case mismatch should NOT match
        assert!(!cond.matches(&data, &ctx));

        // With lower transform, it should match
        let cond_lower = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Wildcard,
            compiled: CompiledValue::GlobPattern("/api/*/users".to_string()),
            transforms: vec![Transform::Lower],
        };
        assert!(cond_lower.matches(&data, &ctx));
    }

    #[test]
    fn test_transform_in_condition() {
        let cond = Condition::Leaf {
            field: Field::UserAgent,
            operator: Operator::Contains,
            compiled: CompiledValue::Str("bot".to_string()),
            transforms: vec![Transform::Lower],
        };
        let mut data = test_request();
        data.user_agent = Some("AhrefsBot/7.0".to_string());
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_url_decode_transform() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Contains,
            compiled: CompiledValue::Str("..".to_string()),
            transforms: vec![Transform::UrlDecode],
        };
        let mut data = test_request();
        data.path = "/foo/%2e%2e/bar".to_string();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_transform() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Gt,
            compiled: CompiledValue::Number(10.0),
            transforms: vec![Transform::Length],
        };
        let data = test_request(); // path = "/api/v2/users" (13 chars)
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_uri_field_with_query() {
        let data = test_request(); // path="/api/v2/users", query="page=1"
        let ctx = test_ctx(&data);
        let val = Field::Uri.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("/api/v2/users?page=1"));
    }

    #[test]
    fn test_uri_field_without_query() {
        let mut data = test_request();
        data.query_string = String::new();
        let ctx = test_ctx(&data);
        let val = Field::Uri.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("/api/v2/users"));
    }

    #[test]
    fn test_path_extension_js() {
        let mut data = test_request();
        data.path = "/assets/app.js".to_string();
        let ctx = test_ctx(&data);
        let val = Field::PathExtension.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("js"));
    }

    #[test]
    fn test_path_extension_tar_gz() {
        let mut data = test_request();
        data.path = "/files/archive.tar.gz".to_string();
        let ctx = test_ctx(&data);
        let val = Field::PathExtension.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("gz"));
    }

    #[test]
    fn test_path_extension_none() {
        let mut data = test_request();
        data.path = "/api/v2/users".to_string();
        let ctx = test_ctx(&data);
        let val = Field::PathExtension.extract(&data, &ctx);
        assert!(!val.exists());
    }

    #[test]
    fn test_path_extension_trailing_slash() {
        let mut data = test_request();
        data.path = "/api/v2/users/".to_string();
        let ctx = test_ctx(&data);
        let val = Field::PathExtension.extract(&data, &ctx);
        assert!(!val.exists());
    }

    #[test]
    fn test_path_extension_preserves_case() {
        // Extension is returned as-is (matches Ruby behavior); use `lower` transform for case-insensitive matching
        let mut data = test_request();
        data.path = "/assets/image.PNG".to_string();
        let ctx = test_ctx(&data);
        let val = Field::PathExtension.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("PNG"));
    }

    #[test]
    fn test_query_param_field() {
        let mut data = test_request();
        data.query_string = "q=hello&page=2".to_string();
        let ctx = test_ctx(&data);
        let val = Field::QueryParam("q".to_string()).extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("hello"));
    }

    #[test]
    fn test_query_param_missing() {
        let data = test_request();
        let ctx = test_ctx(&data);
        let val = Field::QueryParam("missing".to_string()).extract(&data, &ctx);
        assert!(!val.exists());
    }

    #[test]
    fn test_body_raw_present() {
        let mut data = test_request();
        data.body = Some("raw body content".to_string());
        let ctx = test_ctx(&data);
        let val = Field::BodyRaw.extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("raw body content"));
    }

    #[test]
    fn test_body_raw_absent() {
        let data = test_request();
        let ctx = test_ctx(&data);
        let val = Field::BodyRaw.extract(&data, &ctx);
        assert!(!val.exists());
    }

    #[test]
    fn test_body_json_field() {
        let mut data = test_request();
        data.body = Some(r#"{"user_id": "123", "name": "Alice"}"#.to_string());
        let ctx = test_ctx(&data);
        let val = Field::BodyJsonField("user_id".to_string()).extract(&data, &ctx);
        assert_eq!(val.as_str(), Some("123"));
    }

    #[test]
    fn test_body_json_field_missing_key() {
        let mut data = test_request();
        data.body = Some(r#"{"a": "b"}"#.to_string());
        let ctx = test_ctx(&data);
        let val = Field::BodyJsonField("missing".to_string()).extract(&data, &ctx);
        assert!(!val.exists());
    }

    #[test]
    fn test_compile_wildcard() {
        let json = r#"{"field": "http.request.uri.path", "operator": "wildcard", "value": "/api/*/users"}"#;
        let leaf: LeafCondition = serde_json::from_str(json).unwrap();
        let raw = RawCondition::Leaf(leaf);
        let cond = compile_condition(&raw).unwrap();
        match cond {
            Condition::Leaf { operator, compiled, .. } => {
                assert!(matches!(operator, Operator::Wildcard));
                match compiled {
                    CompiledValue::GlobPattern(p) => assert_eq!(p, "/api/*/users"),
                    _ => panic!("Expected GlobPattern"),
                }
            }
            _ => panic!("Expected Leaf"),
        }
    }

    #[test]
    fn test_compile_transform_string() {
        let json = r#"{"field": "http.user_agent", "operator": "contains", "value": "bot", "transform": "lower"}"#;
        let leaf: LeafCondition = serde_json::from_str(json).unwrap();
        let raw = RawCondition::Leaf(leaf);
        let cond = compile_condition(&raw).unwrap();
        match cond {
            Condition::Leaf { transforms, .. } => {
                assert_eq!(transforms.len(), 1);
                assert!(matches!(transforms[0], Transform::Lower));
            }
            _ => panic!("Expected Leaf"),
        }
    }

    #[test]
    fn test_compile_transform_array() {
        let json = r#"{"field": "http.request.uri.query", "operator": "contains", "value": "select", "transform": ["url_decode", "lower"]}"#;
        let leaf: LeafCondition = serde_json::from_str(json).unwrap();
        let raw = RawCondition::Leaf(leaf);
        let cond = compile_condition(&raw).unwrap();
        match cond {
            Condition::Leaf { transforms, .. } => {
                assert_eq!(transforms.len(), 2);
                assert!(matches!(transforms[0], Transform::UrlDecode));
                assert!(matches!(transforms[1], Transform::Lower));
            }
            _ => panic!("Expected Leaf"),
        }
    }

    // --- Compilation error tests ---

    #[test]
    fn test_throttle_without_limit() {
        let raw = RawRule {
            name: "test".into(),
            rule_type: "throttle".into(),
            condition: None,
            limit: None,
            period: Some(60),
            key: Some(vec!["ip.src".into()]),
        };
        assert!(compile_rule(&raw).is_err());
    }

    #[test]
    fn test_throttle_without_period() {
        let raw = RawRule {
            name: "test".into(),
            rule_type: "throttle".into(),
            condition: None,
            limit: Some(100),
            period: None,
            key: Some(vec!["ip.src".into()]),
        };
        assert!(compile_rule(&raw).is_err());
    }

    #[test]
    fn test_throttle_defaults_key_to_ip_src() {
        let raw = RawRule {
            name: "test".into(),
            rule_type: "throttle".into(),
            condition: None,
            limit: Some(100),
            period: Some(60),
            key: None,
        };
        let rule = compile_rule(&raw).unwrap();
        assert_eq!(rule.key_fields.len(), 1);
        assert!(matches!(rule.key_fields[0], Field::IpSrc));
    }

    #[test]
    fn test_unknown_operator_string() {
        assert!(Operator::parse("fake_op").is_err());
    }

    #[test]
    fn test_unknown_rule_type_string() {
        assert!(RuleType::parse("unknown").is_err());
    }

    #[test]
    fn test_invalid_regex_compile_error() {
        let result = compile_value(
            &Operator::Matches,
            &Some(serde_json::Value::String("[invalid".into())),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr_compile_error() {
        let result = compile_value(
            &Operator::InIpRange,
            &Some(serde_json::Value::String("not-cidr".into())),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_eq_with_numeric_value() {
        let result = compile_value(
            &Operator::Eq,
            &Some(serde_json::json!(1024)),
        )
        .unwrap();
        assert!(matches!(result, CompiledValue::Number(n) if (n - 1024.0).abs() < f64::EPSILON));
    }

    #[test]
    fn test_ne_with_numeric_value() {
        let result = compile_value(
            &Operator::Ne,
            &Some(serde_json::json!(42.5)),
        )
        .unwrap();
        assert!(matches!(result, CompiledValue::Number(n) if (n - 42.5).abs() < f64::EPSILON));
    }

    #[test]
    fn test_eq_with_string_value() {
        let result = compile_value(
            &Operator::Eq,
            &Some(serde_json::json!("hello")),
        )
        .unwrap();
        assert!(matches!(result, CompiledValue::Str(ref s) if s == "hello"));
    }

    // --- Evaluation tests for missing operators ---

    #[test]
    fn test_ne_operator() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Ne,
            compiled: CompiledValue::Str("/other".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_contains_operator() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Contains,
            compiled: CompiledValue::Str("v2".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_ends_with_operator() {
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::EndsWith,
            compiled: CompiledValue::Str("/users".to_string()),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_in_operator() {
        let mut set = HashSet::new();
        set.insert("GET".to_string());
        set.insert("HEAD".to_string());
        let cond = Condition::Leaf {
            field: Field::Method,
            operator: Operator::In,
            compiled: CompiledValue::StringSet(set),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_not_in_operator() {
        let mut set = HashSet::new();
        set.insert("POST".to_string());
        set.insert("PUT".to_string());
        let cond = Condition::Leaf {
            field: Field::Method,
            operator: Operator::NotIn,
            compiled: CompiledValue::StringSet(set),
            transforms: vec![],
        };
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_not_in_ip_range() {
        let cond = Condition::Leaf {
            field: Field::IpSrc,
            operator: Operator::NotInIpRange,
            compiled: CompiledValue::IpNets(vec!["192.168.0.0/16".parse().unwrap()]),
            transforms: vec![],
        };
        let data = test_request(); // ip = 10.0.1.50
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_or_condition() {
        let cond = Condition::Or(vec![
            Condition::Leaf {
                field: Field::Method,
                operator: Operator::Eq,
                compiled: CompiledValue::Str("POST".to_string()),
                transforms: vec![],
            },
            Condition::Leaf {
                field: Field::Method,
                operator: Operator::Eq,
                compiled: CompiledValue::Str("GET".to_string()),
                transforms: vec![],
            },
        ]);
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_always_condition() {
        let data = test_request();
        let ctx = test_ctx(&data);
        assert!(Condition::Always.matches(&data, &ctx));
    }

    #[test]
    fn test_numeric_non_parseable_string_returns_false() {
        let mut data = test_request();
        data.user_agent = Some("hello".to_string());
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::UserAgent,
            operator: Operator::Gt,
            compiled: CompiledValue::Number(5.0),
            transforms: vec![],
        };
        assert!(!cond.matches(&data, &ctx));
    }

    #[test]
    fn test_eq_numeric_string_comparison() {
        // eq with numeric compiled value against a string field value
        let mut data = test_request();
        data.query_string = "count=42".to_string();
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::QueryParam("count".to_string()),
            operator: Operator::Eq,
            compiled: CompiledValue::Number(42.0),
            transforms: vec![],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_exists_before_transforms() {
        // exists should check raw field value, not transformed value
        let mut data = test_request();
        data.user_agent = Some("Bot".to_string());
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::UserAgent,
            operator: Operator::Exists,
            compiled: CompiledValue::None,
            transforms: vec![Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_not_exists_before_transforms() {
        let mut data = test_request();
        data.user_agent = None;
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::UserAgent,
            operator: Operator::NotExists,
            compiled: CompiledValue::None,
            transforms: vec![Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_extract_throttle_key_multiple_fields() {
        let data = test_request(); // ip=10.0.1.50, path=/api/v2/users
        let ctx = test_ctx(&data);
        let key = extract_throttle_key(
            &[Field::IpSrc, Field::Path],
            &data,
            &ctx,
        );
        assert_eq!(key, Some("10.0.1.50:/api/v2/users".to_string()));
    }

    #[test]
    fn test_extract_throttle_key_with_number_field() {
        let data = test_request(); // content_length=0
        let ctx = test_ctx(&data);
        let key = extract_throttle_key(
            &[Field::IpSrc, Field::ContentLength],
            &data,
            &ctx,
        );
        assert_eq!(key, Some("10.0.1.50:0".to_string()));
    }

    #[test]
    fn test_extract_throttle_key_missing_field() {
        let mut data = test_request();
        data.user_agent = None;
        let ctx = test_ctx(&data);
        let key = extract_throttle_key(
            &[Field::IpSrc, Field::UserAgent],
            &data,
            &ctx,
        );
        assert_eq!(key, None);
    }

    // --- Number-to-string comparison tests ---

    #[test]
    fn test_content_length_eq_string_zero() {
        // Ruby returns content_length as string; "0" == "0" should be true
        let data = test_request(); // content_length = 0
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::ContentLength,
            operator: Operator::Eq,
            compiled: CompiledValue::Str("0".to_string()),
            transforms: vec![],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_content_length_ne_string() {
        let data = test_request(); // content_length = 0
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::ContentLength,
            operator: Operator::Ne,
            compiled: CompiledValue::Str("100".to_string()),
            transforms: vec![],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_content_length_in_string_set() {
        let mut data = test_request();
        data.content_length = 42;
        let ctx = test_ctx(&data);
        let mut set = HashSet::new();
        set.insert("42".to_string());
        set.insert("100".to_string());
        let cond = Condition::Leaf {
            field: Field::ContentLength,
            operator: Operator::In,
            compiled: CompiledValue::StringSet(set),
            transforms: vec![],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_transform_eq_string_value() {
        // length transform produces Number; comparing against string "13" should work
        let data = test_request(); // path = "/api/v2/users" (13 chars)
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Eq,
            compiled: CompiledValue::Str("13".to_string()),
            transforms: vec![Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_transform_ne_string_value() {
        let data = test_request(); // path = "/api/v2/users" (13 chars)
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Ne,
            compiled: CompiledValue::Str("5".to_string()),
            transforms: vec![Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    // --- Length transform fast-path tests ---

    #[test]
    fn test_length_fast_path_ascii() {
        // [lower, length] on ASCII path should use fast path
        let data = test_request(); // path = "/api/v2/users" (13 chars)
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Gt,
            compiled: CompiledValue::Number(10.0),
            transforms: vec![Transform::Lower, Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_only_fast_path() {
        // [length] alone uses fast path (no preceding transforms)
        let data = test_request(); // path = "/api/v2/users" (13 chars)
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Eq,
            compiled: CompiledValue::Number(13.0),
            transforms: vec![Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_no_fast_path_url_decode() {
        // [url_decode, length] should NOT use fast path (url_decode changes length)
        let mut data = test_request();
        data.path = "/foo%20bar".to_string(); // url_decode → "/foo bar" (8 chars)
        let ctx = test_ctx(&data);
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Eq,
            compiled: CompiledValue::Number(8.0),
            transforms: vec![Transform::UrlDecode, Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }

    #[test]
    fn test_length_no_fast_path_non_ascii() {
        // Non-ASCII: lower/upper may change byte length, so fast path is skipped
        let mut data = test_request();
        data.path = "/café".to_string(); // non-ASCII
        let ctx = test_ctx(&data);
        // [lower, length] on non-ASCII falls back to full pipeline
        let cond = Condition::Leaf {
            field: Field::Path,
            operator: Operator::Gt,
            compiled: CompiledValue::Number(3.0),
            transforms: vec![Transform::Lower, Transform::Length],
        };
        assert!(cond.matches(&data, &ctx));
    }
}
