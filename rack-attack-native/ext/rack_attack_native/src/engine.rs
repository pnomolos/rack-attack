use crate::body::BodyData;
use crate::field::RequestContext;
use crate::jwt::{JwtConfig, JwtData};
use crate::query::QueryData;
use crate::request_data::RequestData;
use crate::result::{EvaluationResult, ThrottleMatch};
use crate::rule::{compile_rule, extract_throttle_key, RawRuleSet, Rule, RuleType};

/// A compiled rule set, partitioned by type for efficient evaluation.
pub struct RuleSet {
    pub safelists: Vec<Rule>,
    pub blocklists: Vec<Rule>,
    pub throttles: Vec<Rule>,
    pub tracks: Vec<Rule>,
    pub jwt_config: Option<JwtConfig>,
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
            let rule = compile_rule(raw_rule)?;
            match rule.rule_type {
                RuleType::Safelist => safelists.push(rule),
                RuleType::Blocklist => blocklists.push(rule),
                RuleType::Throttle => throttles.push(rule),
                RuleType::Track => tracks.push(rule),
            }
        }

        Ok(RuleSet {
            safelists,
            blocklists,
            throttles,
            tracks,
            jwt_config,
        })
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
}
