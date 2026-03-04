use serde_json::Value;
use std::cell::RefCell;

/// Lazy JSON body parser. Parses on first access and caches the result.
pub struct BodyData<'a> {
    raw: Option<&'a str>,
    parsed: RefCell<Option<Option<Value>>>, // outer Option = cached?, inner = parse result
}

impl<'a> BodyData<'a> {
    pub fn new(raw: Option<&'a str>) -> Self {
        BodyData {
            raw,
            parsed: RefCell::new(None),
        }
    }

    pub fn raw(&self) -> Option<&'a str> {
        self.raw
    }

    pub fn json_field(&self, key: &str) -> Option<String> {
        self.ensure_parsed();
        let cache = self.parsed.borrow();
        cache
            .as_ref()
            .unwrap()
            .as_ref()
            .and_then(|val| val.get(key))
            .map(|v| match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
    }

    fn ensure_parsed(&self) {
        if self.parsed.borrow().is_some() {
            return;
        }
        let result = self.raw.and_then(|s| serde_json::from_str(s).ok());
        *self.parsed.borrow_mut() = Some(result);
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
}
