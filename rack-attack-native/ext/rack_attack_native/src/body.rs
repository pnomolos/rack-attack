use serde_json::Value;
use std::cell::OnceCell;

/// Lazy JSON body parser. Parses on first access and caches the result.
pub struct BodyData<'a> {
    raw: Option<&'a str>,
    parsed: OnceCell<Option<Value>>,
}

impl<'a> BodyData<'a> {
    pub fn new(raw: Option<&'a str>) -> Self {
        BodyData {
            raw,
            parsed: OnceCell::new(),
        }
    }

    pub fn raw(&self) -> Option<&'a str> {
        self.raw
    }

    /// Navigate a JSON path (one or more keys) and return borrowed &str for string leaf values.
    /// Returns None for non-string values; use json_nested_field_string() for those.
    pub fn json_nested_field_str(&self, keys: &[String]) -> Option<&str> {
        let parsed = self.parsed().as_ref()?;
        let mut current = parsed;
        for key in keys {
            current = current.get(key.as_str())?;
        }
        current.as_str()
    }

    /// Navigate a JSON path (one or more keys) and return owned String for any leaf value.
    /// Non-string JSON values (numbers, bools) are stringified.
    pub fn json_nested_field_string(&self, keys: &[String]) -> Option<String> {
        let parsed = self.parsed().as_ref()?;
        let mut current = parsed;
        for key in keys {
            current = current.get(key.as_str())?;
        }
        Some(match current {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
    }

    fn parsed(&self) -> &Option<Value> {
        self.parsed
            .get_or_init(|| self.raw.and_then(|s| serde_json::from_str(s).ok()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_nested_single_key_string() {
        let bd = BodyData::new(Some(r#"{"user_id": "123", "name": "Alice"}"#));
        let keys = vec!["user_id".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), Some("123"));
        let keys2 = vec!["name".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys2), Some("Alice"));
    }

    #[test]
    fn test_json_nested_single_key_number() {
        let bd = BodyData::new(Some(r#"{"count": 42}"#));
        let keys = vec!["count".to_string()];
        // Non-string values return None from json_nested_field_str
        assert_eq!(bd.json_nested_field_str(&keys), None);
        // But return stringified from json_nested_field_string
        assert_eq!(bd.json_nested_field_string(&keys), Some("42".to_string()));
    }

    #[test]
    fn test_json_nested_single_key_missing() {
        let bd = BodyData::new(Some(r#"{"a": "b"}"#));
        let keys = vec!["missing".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), None);
        assert_eq!(bd.json_nested_field_string(&keys), None);
    }

    #[test]
    fn test_no_body() {
        let bd = BodyData::new(None);
        let keys = vec!["anything".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), None);
        assert_eq!(bd.json_nested_field_string(&keys), None);
    }

    #[test]
    fn test_invalid_json() {
        let bd = BodyData::new(Some("not json"));
        let keys = vec!["anything".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), None);
    }

    #[test]
    fn test_raw_body() {
        let bd = BodyData::new(Some("raw body content"));
        assert_eq!(bd.raw(), Some("raw body content"));
    }

    #[test]
    fn test_raw_body_none() {
        let bd = BodyData::new(None);
        assert_eq!(bd.raw(), None);
    }

    #[test]
    fn test_json_nested_field_str() {
        let bd = BodyData::new(Some(r#"{"user": {"profile": {"name": "Alice"}}}"#));
        let keys = vec!["user".to_string(), "profile".to_string(), "name".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), Some("Alice"));
    }

    #[test]
    fn test_json_nested_field_string_number() {
        let bd = BodyData::new(Some(r#"{"data": {"count": 42}}"#));
        let keys = vec!["data".to_string(), "count".to_string()];
        assert_eq!(bd.json_nested_field_string(&keys), Some("42".to_string()));
    }

    #[test]
    fn test_json_nested_field_missing() {
        let bd = BodyData::new(Some(r#"{"user": {"name": "Alice"}}"#));
        let keys = vec!["user".to_string(), "profile".to_string(), "name".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), None);
    }

    #[test]
    fn test_json_nested_single_key() {
        let bd = BodyData::new(Some(r#"{"action": "delete"}"#));
        let keys = vec!["action".to_string()];
        assert_eq!(bd.json_nested_field_str(&keys), Some("delete"));
    }
}
