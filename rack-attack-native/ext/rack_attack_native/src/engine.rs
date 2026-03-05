use crate::body::BodyData;
use crate::field::{Field, RequestContext, Transform};
use crate::jwt::{JwtConfig, JwtData};
use crate::query::QueryData;
use crate::request_data::RequestData;
use crate::result::{EvaluationResult, ThrottleMatch};
use crate::rule::{compile_rule, extract_throttle_key, Condition, Operator, RawRuleSet, Rule, RuleType};
use std::collections::HashSet;

/// Categories of request fields that may need to be marshalled from Ruby.
/// Path, Method, and IP are always sent (near-zero cost).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FieldCategory {
    Body,
    Headers,
    Cookies,
    Authorization,
    UserAgent,
    Host,
    ContentLength,
    QueryString,
}

impl FieldCategory {
    pub fn name(&self) -> &'static str {
        match self {
            FieldCategory::Body => "body",
            FieldCategory::Headers => "headers",
            FieldCategory::Cookies => "cookies",
            FieldCategory::Authorization => "authorization",
            FieldCategory::UserAgent => "user_agent",
            FieldCategory::Host => "host",
            FieldCategory::ContentLength => "content_length",
            FieldCategory::QueryString => "query_string",
        }
    }
}

/// Collect which field categories a condition tree references.
fn collect_field_categories(condition: &Condition, categories: &mut HashSet<FieldCategory>) {
    match condition {
        Condition::Always => {}
        Condition::Leaf { field, .. } => {
            collect_field_category(field, categories);
        }
        Condition::And(children) | Condition::Or(children) => {
            for child in children {
                collect_field_categories(child, categories);
            }
        }
        Condition::Not(child) => collect_field_categories(child, categories),
    }
}

fn collect_field_category(field: &Field, categories: &mut HashSet<FieldCategory>) {
    match field {
        // Path, Method, IpSrc are always sent — no category needed
        Field::Path | Field::Method | Field::IpSrc | Field::PathExtension => {}
        Field::UserAgent => { categories.insert(FieldCategory::UserAgent); }
        Field::Host => { categories.insert(FieldCategory::Host); }
        Field::QueryString => { categories.insert(FieldCategory::QueryString); }
        Field::ContentLength => { categories.insert(FieldCategory::ContentLength); }
        Field::Header(_) => { categories.insert(FieldCategory::Headers); }
        Field::Cookie(_) => { categories.insert(FieldCategory::Cookies); }
        Field::Uri | Field::QueryParam(_) => { categories.insert(FieldCategory::QueryString); }
        Field::BodyRaw | Field::BodyJson(_) => { categories.insert(FieldCategory::Body); }
        Field::JwtPayload(_) | Field::JwtHeader(_) | Field::JwtVerifiedPayload(_) | Field::JwtValid => {
            categories.insert(FieldCategory::Authorization);
        }
    }
}

/// Estimate the evaluation cost of a condition for rule ordering.
/// Lower cost = cheaper to evaluate = should be checked first.
fn estimate_rule_cost(condition: &Condition) -> u32 {
    match condition {
        Condition::Always => 0,
        Condition::Leaf { field, operator, transforms, .. } => {
            let field_cost = estimate_field_cost(field);
            let op_cost = estimate_operator_cost(operator);
            let transform_cost: u32 = transforms.iter().map(estimate_transform_cost).sum();
            field_cost + op_cost + transform_cost
        }
        Condition::And(children) => children.iter().map(estimate_rule_cost).sum(),
        Condition::Or(children) => children.iter().map(estimate_rule_cost).min().unwrap_or(0),
        Condition::Not(child) => estimate_rule_cost(child),
    }
}

fn estimate_field_cost(field: &Field) -> u32 {
    match field {
        Field::Path | Field::Method | Field::IpSrc => 1,
        Field::UserAgent | Field::Host | Field::PathExtension => 2,
        Field::QueryString | Field::ContentLength | Field::Uri => 2,
        Field::Header(_) | Field::Cookie(_) => 4,
        Field::QueryParam(_) => 5,
        Field::BodyRaw => 8,
        Field::BodyJson(_) => 10,
        Field::JwtPayload(_) | Field::JwtHeader(_) => 15,
        Field::JwtValid => 20,
        Field::JwtVerifiedPayload(_) => 50,
    }
}

fn estimate_operator_cost(op: &Operator) -> u32 {
    match op {
        Operator::Exists | Operator::NotExists | Operator::Eq | Operator::Ne => 1,
        Operator::In | Operator::NotIn | Operator::StartsWith | Operator::EndsWith => 2,
        Operator::Contains => 3,
        Operator::InIpRange | Operator::NotInIpRange => 5,
        Operator::Wildcard => 6,
        Operator::Gt | Operator::Lt | Operator::Gte | Operator::Lte => 1,
        Operator::Matches => 8,
    }
}

fn estimate_transform_cost(transform: &Transform) -> u32 {
    match transform {
        Transform::Length => 1,
        Transform::Lower | Transform::Upper => 3,
        Transform::UrlDecode => 5,
    }
}

/// A compiled rule set, partitioned by type for efficient evaluation.
pub struct RuleSet {
    pub safelists: Vec<Rule>,
    pub blocklists: Vec<Rule>,
    pub throttles: Vec<Rule>,
    pub tracks: Vec<Rule>,
    pub jwt_config: Option<JwtConfig>,
    /// Which field categories are actually referenced by rules in this set.
    pub required_categories: HashSet<FieldCategory>,
}

impl RuleSet {
    /// Parse a JSON string into a compiled RuleSet.
    pub fn from_json(json: &str) -> Result<RuleSet, String> {
        let raw: RawRuleSet =
            serde_json::from_str(json).map_err(|e| format!("Invalid JSON: {}", e))?;

        let jwt_config = match &raw.jwt_keys {
            Some(keys) if !keys.is_empty() => Some(JwtConfig::from_raw(keys)?),
            _ => None,
        };

        let mut safelists = Vec::new();
        let mut blocklists = Vec::new();
        let mut throttles = Vec::new();
        let mut tracks = Vec::new();

        for raw_rule in &raw.rules {
            // Skip disabled rules entirely
            if !raw_rule.enabled {
                continue;
            }
            let rule = compile_rule(raw_rule)?;
            match rule.rule_type {
                RuleType::Safelist => safelists.push(rule),
                RuleType::Blocklist => blocklists.push(rule),
                RuleType::Throttle => throttles.push(rule),
                RuleType::Track => tracks.push(rule),
            }
        }

        // Validate and apply rule ordering
        let use_cost_order = match raw.rule_order.as_deref() {
            None | Some("cost") => true,
            Some("insertion") => false,
            Some(other) => {
                return Err(format!(
                    "Invalid rule_order \"{}\", must be \"cost\" or \"insertion\"",
                    other
                ));
            }
        };
        if use_cost_order {
            safelists.sort_by_key(|r| estimate_rule_cost(&r.condition));
            blocklists.sort_by_key(|r| estimate_rule_cost(&r.condition));
            throttles.sort_by_key(|r| estimate_rule_cost(&r.condition));
            tracks.sort_by_key(|r| estimate_rule_cost(&r.condition));
        }

        // Collect which field categories are actually needed by all rules
        let mut required_categories = HashSet::new();
        let all_rules = safelists.iter()
            .chain(blocklists.iter())
            .chain(throttles.iter())
            .chain(tracks.iter());
        for rule in all_rules {
            collect_field_categories(&rule.condition, &mut required_categories);
            // Also check throttle key fields
            for key_field in &rule.key_fields {
                collect_field_category(key_field, &mut required_categories);
            }
        }

        Ok(RuleSet {
            safelists,
            blocklists,
            throttles,
            tracks,
            jwt_config,
            required_categories,
        })
    }

    /// Return the list of required field category names for Ruby-side marshalling.
    pub fn required_fields(&self) -> Vec<String> {
        self.required_categories.iter().map(|c| c.name().to_string()).collect()
    }

    /// Evaluate all rules against a request.
    ///
    /// Evaluation order:
    /// 1. Safelists — short-circuit on first match
    /// 2. Blocklists — short-circuit on first match
    /// 3. Throttles — evaluate all, collect matches
    /// 4. Tracks — evaluate all, collect matching names
    pub fn evaluate(&self, data: &RequestData) -> EvaluationResult {
        let mut result = EvaluationResult::default();

        // Create per-request lazy caches bundled into RequestContext
        let jwt_data = JwtData::new(data.authorization.as_deref(), self.jwt_config.as_ref());
        let query_data = QueryData::new(&data.query_string);
        let body_data = BodyData::new(data.body.as_deref());

        let ctx = RequestContext {
            jwt: Some(jwt_data),
            query: query_data,
            body: body_data,
            uri_cache: std::cell::OnceCell::new(),
        };

        // 1. Safelists — first match wins
        for rule in &self.safelists {
            if rule.condition.matches(data, &ctx) {
                result.safelisted = Some(rule.name.clone());
                return result;
            }
        }

        // 2. Blocklists — first match wins
        for rule in &self.blocklists {
            if rule.condition.matches(data, &ctx) {
                result.blocklisted = Some(rule.name.clone());
                return result;
            }
        }

        // 3. Throttles — evaluate all matching rules
        for rule in &self.throttles {
            if rule.condition.matches(data, &ctx) {
                if let Some(discriminator) =
                    extract_throttle_key(&rule.key_fields, data, &ctx)
                {
                    result.throttle_matches.push(ThrottleMatch {
                        name: rule.name.clone(),
                        discriminator,
                        limit: rule.limit.unwrap_or(0),
                        period: rule.period.unwrap_or(0),
                    });
                }
            }
        }

        // 4. Tracks — collect all matching names
        for rule in &self.tracks {
            if rule.condition.matches(data, &ctx) {
                result.tracked.push(rule.name.clone());
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn simple_rules_json() -> &'static str {
        r#"{
            "rules": [
                {
                    "name": "internal-net",
                    "type": "safelist",
                    "condition": {
                        "field": "ip.src", "operator": "in_ip_range",
                        "value": ["10.0.0.0/8", "192.168.0.0/16"]
                    }
                },
                {
                    "name": "bad-bot",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.user_agent", "operator": "matches",
                        "value": "\\b(AhrefsBot|SemrushBot)\\b"
                    }
                },
                {
                    "name": "api-rate",
                    "type": "throttle",
                    "limit": 100, "period": 60,
                    "key": ["ip.src"],
                    "condition": {
                        "field": "http.request.uri.path", "operator": "starts_with",
                        "value": "/api/"
                    }
                },
                {
                    "name": "api-version",
                    "type": "track",
                    "condition": {
                        "field": "http.request.uri.path", "operator": "matches",
                        "value": "^/api/v[0-9]+/"
                    }
                }
            ]
        }"#
    }

    fn make_request(ip: &str, path: &str, ua: Option<&str>) -> RequestData {
        RequestData {
            path: path.to_string(),
            method: "GET".to_string(),
            ip: ip.to_string(),
            user_agent: ua.map(|s| s.to_string()),
            host: None,
            query_string: String::new(),
            content_length: 0,
            authorization: None,
            body: None,
            headers: HashMap::new(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn test_safelist_short_circuit() {
        let rs = RuleSet::from_json(simple_rules_json()).unwrap();
        let data = make_request("10.0.1.50", "/api/v2/users", Some("Mozilla/5.0"));
        let result = rs.evaluate(&data);
        assert_eq!(result.safelisted.as_deref(), Some("internal-net"));
        assert!(result.blocklisted.is_none());
        assert!(result.throttle_matches.is_empty());
        assert!(result.tracked.is_empty());
    }

    #[test]
    fn test_blocklist_match() {
        let rs = RuleSet::from_json(simple_rules_json()).unwrap();
        let data = make_request(
            "203.0.113.1",
            "/",
            Some("Mozilla/5.0 (compatible; AhrefsBot/7.0)"),
        );
        let result = rs.evaluate(&data);
        assert!(result.safelisted.is_none());
        assert_eq!(result.blocklisted.as_deref(), Some("bad-bot"));
    }

    #[test]
    fn test_throttle_and_track() {
        let rs = RuleSet::from_json(simple_rules_json()).unwrap();
        let data = make_request("203.0.113.1", "/api/v2/users", Some("Mozilla/5.0"));
        let result = rs.evaluate(&data);
        assert!(result.safelisted.is_none());
        assert!(result.blocklisted.is_none());
        assert_eq!(result.throttle_matches.len(), 1);
        assert_eq!(result.throttle_matches[0].name, "api-rate");
        assert_eq!(result.throttle_matches[0].discriminator, "203.0.113.1");
        assert_eq!(result.throttle_matches[0].limit, 100);
        assert_eq!(result.tracked, vec!["api-version"]);
    }

    #[test]
    fn test_transform_rules() {
        let json = r#"{
            "rules": [
                {
                    "name": "traversal-detect",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "contains",
                        "value": "..",
                        "transform": "url_decode"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        // Encoded path traversal should be caught
        let data = make_request("1.2.3.4", "/foo/%2e%2e/bar", None);
        let result = rs.evaluate(&data);
        assert_eq!(result.blocklisted.as_deref(), Some("traversal-detect"));

        // Normal path should not match
        let data2 = make_request("1.2.3.4", "/foo/bar", None);
        let result2 = rs.evaluate(&data2);
        assert!(result2.blocklisted.is_none());
    }

    #[test]
    fn test_wildcard_rules() {
        let json = r#"{
            "rules": [
                {
                    "name": "api-wildcard",
                    "type": "track",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "wildcard",
                        "value": "/api/*/users"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        let data = make_request("1.2.3.4", "/api/v2/users", None);
        let result = rs.evaluate(&data);
        assert_eq!(result.tracked, vec!["api-wildcard"]);
    }

    #[test]
    fn test_path_extension_rules() {
        let json = r#"{
            "rules": [
                {
                    "name": "static-assets",
                    "type": "safelist",
                    "condition": {
                        "and": [
                            { "field": "http.request.method", "operator": "eq", "value": "GET" },
                            { "field": "http.request.uri.path.extension", "operator": "in", "value": ["js", "css", "png", "jpg"] }
                        ]
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        let data = make_request("1.2.3.4", "/assets/app.js", None);
        let result = rs.evaluate(&data);
        assert_eq!(result.safelisted.as_deref(), Some("static-assets"));

        let data2 = make_request("1.2.3.4", "/api/users", None);
        let result2 = rs.evaluate(&data2);
        assert!(result2.safelisted.is_none());
    }

    #[test]
    fn test_body_json_rules() {
        let json = r#"{
            "rules": [
                {
                    "name": "admin-action",
                    "type": "track",
                    "condition": {
                        "field": "http.request.body.json[\"action\"]",
                        "operator": "eq",
                        "value": "delete_all"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        let mut data = make_request("1.2.3.4", "/api/v2/admin", None);
        data.body = Some(r#"{"action": "delete_all", "confirm": true}"#.to_string());
        let result = rs.evaluate(&data);
        assert_eq!(result.tracked, vec!["admin-action"]);
    }

    #[test]
    fn test_query_param_rules() {
        let json = r#"{
            "rules": [
                {
                    "name": "search-track",
                    "type": "track",
                    "condition": {
                        "field": "http.request.uri.args[\"q\"]",
                        "operator": "exists"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        let mut data = make_request("1.2.3.4", "/search", None);
        data.query_string = "q=hello&page=1".to_string();
        let result = rs.evaluate(&data);
        assert_eq!(result.tracked, vec!["search-track"]);

        let data2 = make_request("1.2.3.4", "/search", None);
        let result2 = rs.evaluate(&data2);
        assert!(result2.tracked.is_empty());
    }

    // --- Cost-based ordering tests ---

    // --- Required fields tests ---

    #[test]
    fn test_required_fields_path_only() {
        let json = r#"{
            "rules": [
                {
                    "name": "health",
                    "type": "safelist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/health"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        // Path-only rule needs no extra categories
        assert!(rs.required_categories.is_empty());
        assert!(rs.required_fields().is_empty());
    }

    #[test]
    fn test_required_fields_jwt() {
        let json = r#"{
            "rules": [
                {
                    "name": "jwt-check",
                    "type": "blocklist",
                    "condition": {
                        "field": "jwt.verified_payload[\"role\"]",
                        "operator": "ne",
                        "value": "admin"
                    }
                }
            ],
            "jwt_keys": [{"algorithm": "HS256", "key": "test-secret"}]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert!(rs.required_categories.contains(&FieldCategory::Authorization));
        assert_eq!(rs.required_categories.len(), 1);
    }

    #[test]
    fn test_required_fields_body() {
        let json = r#"{
            "rules": [
                {
                    "name": "body-check",
                    "type": "track",
                    "condition": {
                        "field": "http.request.body.json[\"action\"]",
                        "operator": "eq",
                        "value": "delete"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert!(rs.required_categories.contains(&FieldCategory::Body));
        assert_eq!(rs.required_categories.len(), 1);
    }

    #[test]
    fn test_required_fields_headers_cookies() {
        let json = r#"{
            "rules": [
                {
                    "name": "header-check",
                    "type": "blocklist",
                    "condition": {
                        "and": [
                            { "field": "http.request.headers[\"x-api-key\"]", "operator": "exists" },
                            { "field": "http.request.cookies[\"session\"]", "operator": "exists" }
                        ]
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert!(rs.required_categories.contains(&FieldCategory::Headers));
        assert!(rs.required_categories.contains(&FieldCategory::Cookies));
        assert_eq!(rs.required_categories.len(), 2);
    }

    #[test]
    fn test_cost_ordering_safelists() {
        // JWT safelist has higher cost than path eq safelist
        let json = r#"{
            "rules": [
                {
                    "name": "jwt-safelist",
                    "type": "safelist",
                    "condition": {
                        "field": "jwt.verified_payload[\"role\"]",
                        "operator": "eq",
                        "value": "admin"
                    }
                },
                {
                    "name": "path-safelist",
                    "type": "safelist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/health"
                    }
                }
            ],
            "jwt_keys": [{"algorithm": "HS256", "key": "test-secret"}]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        // Path eq (cost=2) should come before JWT verified (cost=51)
        assert_eq!(rs.safelists[0].name, "path-safelist");
        assert_eq!(rs.safelists[1].name, "jwt-safelist");
    }

    #[test]
    fn test_cost_ordering_blocklists() {
        let json = r#"{
            "rules": [
                {
                    "name": "regex-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.user_agent",
                        "operator": "matches",
                        "value": "\\b(AhrefsBot|SemrushBot)\\b"
                    }
                },
                {
                    "name": "ip-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "ip.src",
                        "operator": "in_ip_range",
                        "value": ["10.0.0.0/8"]
                    }
                },
                {
                    "name": "simple-eq-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        // simple eq (1+1=2) < ip range (1+5=6) < regex ua (2+8=10)
        assert_eq!(rs.blocklists[0].name, "simple-eq-blocklist");
        assert_eq!(rs.blocklists[1].name, "ip-blocklist");
        assert_eq!(rs.blocklists[2].name, "regex-blocklist");
    }

    #[test]
    fn test_cost_ordering_preserves_correctness() {
        // Same as simple_rules_json but verify results are identical
        let rs = RuleSet::from_json(simple_rules_json()).unwrap();

        // Safelist still works
        let data = make_request("10.0.1.50", "/api/v2/users", Some("Mozilla/5.0"));
        let result = rs.evaluate(&data);
        assert_eq!(result.safelisted.as_deref(), Some("internal-net"));

        // Blocklist still works
        let data2 = make_request("203.0.113.1", "/", Some("AhrefsBot/7.0"));
        let result2 = rs.evaluate(&data2);
        assert_eq!(result2.blocklisted.as_deref(), Some("bad-bot"));

        // Throttle + track still work
        let data3 = make_request("203.0.113.1", "/api/v2/users", Some("Mozilla/5.0"));
        let result3 = rs.evaluate(&data3);
        assert_eq!(result3.throttle_matches[0].name, "api-rate");
        assert_eq!(result3.tracked, vec!["api-version"]);
    }

    // --- Disabled rules tests ---

    #[test]
    fn test_disabled_rules_skipped() {
        let json = r#"{
            "rules": [
                {
                    "name": "disabled-block",
                    "type": "blocklist",
                    "enabled": false,
                    "description": "This rule is disabled for testing",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                },
                {
                    "name": "enabled-track",
                    "type": "track",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert!(rs.blocklists.is_empty(), "disabled blocklist should be skipped");
        assert_eq!(rs.tracks.len(), 1);

        let data = make_request("1.2.3.4", "/blocked", None);
        let result = rs.evaluate(&data);
        assert!(result.blocklisted.is_none());
        assert_eq!(result.tracked, vec!["enabled-track"]);
    }

    #[test]
    fn test_enabled_default_true() {
        let json = r#"{
            "rules": [
                {
                    "name": "no-enabled-field",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert_eq!(rs.blocklists.len(), 1);
    }

    #[test]
    fn test_description_field_accepted() {
        let json = r#"{
            "rules": [
                {
                    "name": "with-desc",
                    "type": "track",
                    "description": "A helpful description",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        assert_eq!(rs.tracks.len(), 1);
    }

    // --- Insertion order tests ---

    #[test]
    fn test_insertion_order() {
        let json = r#"{
            "rule_order": "insertion",
            "rules": [
                {
                    "name": "regex-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.user_agent",
                        "operator": "matches",
                        "value": "\\b(AhrefsBot|SemrushBot)\\b"
                    }
                },
                {
                    "name": "simple-eq-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        // With insertion order, regex-blocklist should come first (not re-sorted by cost)
        assert_eq!(rs.blocklists[0].name, "regex-blocklist");
        assert_eq!(rs.blocklists[1].name, "simple-eq-blocklist");
    }

    #[test]
    fn test_cost_order_explicit() {
        let json = r#"{
            "rule_order": "cost",
            "rules": [
                {
                    "name": "regex-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.user_agent",
                        "operator": "matches",
                        "value": "\\b(AhrefsBot|SemrushBot)\\b"
                    }
                },
                {
                    "name": "simple-eq-blocklist",
                    "type": "blocklist",
                    "condition": {
                        "field": "http.request.uri.path",
                        "operator": "eq",
                        "value": "/blocked"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();
        // With cost order, simple-eq (cost 2) should come before regex (cost 10)
        assert_eq!(rs.blocklists[0].name, "simple-eq-blocklist");
        assert_eq!(rs.blocklists[1].name, "regex-blocklist");
    }

    // --- Nested body JSON tests ---

    #[test]
    fn test_nested_body_json() {
        let json = r#"{
            "rules": [
                {
                    "name": "nested-check",
                    "type": "track",
                    "condition": {
                        "field": "http.request.body.json[\"user.profile.name\"]",
                        "operator": "eq",
                        "value": "Alice"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        let mut data = make_request("1.2.3.4", "/api", None);
        data.body = Some(r#"{"user": {"profile": {"name": "Alice"}}}"#.to_string());
        let result = rs.evaluate(&data);
        assert_eq!(result.tracked, vec!["nested-check"]);
    }

    #[test]
    fn test_nested_body_json_missing_key() {
        let json = r#"{
            "rules": [
                {
                    "name": "nested-missing",
                    "type": "track",
                    "condition": {
                        "field": "http.request.body.json[\"user.profile.email\"]",
                        "operator": "exists"
                    }
                }
            ]
        }"#;
        let rs = RuleSet::from_json(json).unwrap();

        let mut data = make_request("1.2.3.4", "/api", None);
        data.body = Some(r#"{"user": {"profile": {"name": "Alice"}}}"#.to_string());
        let result = rs.evaluate(&data);
        assert!(result.tracked.is_empty());
    }
}
