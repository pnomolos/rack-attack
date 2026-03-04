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

    /// Get a JSON field value as a borrowed &str (zero-copy for string values).
    /// Returns None for non-string values; use json_field_string() for those.
    pub fn json_field_str(&self, key: &str) -> Option<&str> {
        self.parsed()
            .as_ref()
            .and_then(|val| val.get(key))
            .and_then(|v| v.as_str())
    }

    /// Get a JSON field value as an owned String (for non-string JSON values like numbers, bools).
    pub fn json_field_string(&self, key: &str) -> Option<String> {
        self.parsed()
            .as_ref()
            .and_then(|val| val.get(key))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
    }

    /// Get a JSON field as an owned String (convenience method, tries borrowed first).
    pub fn json_field(&self, key: &str) -> Option<String> {
        self.json_field_string(key)
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
    fn test_json_field_string() {
        let bd = BodyData::new(Some(r#"{"user_id": "123", "name": "Alice"}"#));
        assert_eq!(bd.json_field("user_id"), Some("123".to_string()));
        assert_eq!(bd.json_field("name"), Some("Alice".to_string()));
    }

    #[test]
    fn test_json_field_number() {
        let bd = BodyData::new(Some(r#"{"count": 42}"#));
        assert_eq!(bd.json_field("count"), Some("42".to_string()));
    }

    #[test]
    fn test_json_field_missing() {
        let bd = BodyData::new(Some(r#"{"a": "b"}"#));
        assert_eq!(bd.json_field("missing"), None);
    }

    #[test]
    fn test_no_body() {
        let bd = BodyData::new(None);
        assert_eq!(bd.json_field("anything"), None);
    }

    #[test]
    fn test_invalid_json() {
        let bd = BodyData::new(Some("not json"));
        assert_eq!(bd.json_field("anything"), None);
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
    fn test_json_field_str_borrows() {
        let bd = BodyData::new(Some(r#"{"name": "Alice"}"#));
        // String values should be borrowable
        assert_eq!(bd.json_field_str("name"), Some("Alice"));
    }

    #[test]
    fn test_json_field_str_returns_none_for_number() {
        let bd = BodyData::new(Some(r#"{"count": 42}"#));
        // Non-string values return None from json_field_str
        assert_eq!(bd.json_field_str("count"), None);
    }

    #[test]
    fn test_json_field_string_number() {
        let bd = BodyData::new(Some(r#"{"count": 42}"#));
        // Non-string values return owned string via json_field_string
        assert_eq!(bd.json_field_string("count"), Some("42".to_string()));
    }
}
