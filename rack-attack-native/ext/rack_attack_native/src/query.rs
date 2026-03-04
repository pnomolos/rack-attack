use percent_encoding::percent_decode_str;
use std::cell::OnceCell;
use std::collections::HashMap;

/// Lazy query string parser. Parses on first access and caches the result.
/// URL-decodes both keys and values (matches Ruby's URI.decode_www_form).
pub struct QueryData<'a> {
    raw: &'a str,
    parsed: OnceCell<HashMap<String, String>>,
}

impl<'a> QueryData<'a> {
    pub fn new(raw: &'a str) -> Self {
        QueryData {
            raw,
            parsed: OnceCell::new(),
        }
    }

    /// Get a query parameter value by key. Returns a borrowed reference
    /// into the cached HashMap, avoiding clones on every access.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.parsed().get(key).map(|s| s.as_str())
    }

    /// Check if a key exists without necessarily triggering a full parse.
    /// If already parsed, checks the HashMap. Otherwise, does a linear scan
    /// of the raw query string for an exact key match.
    pub fn contains_key(&self, key: &str) -> bool {
        if let Some(map) = self.parsed.get() {
            return map.contains_key(key);
        }
        // Fast linear scan: look for key at start or after '&', followed by '=' or '&' or end
        raw_contains_key(self.raw, key)
    }

    /// Returns true if the OnceCell has been initialized (parsed).
    #[cfg(test)]
    pub fn is_parsed(&self) -> bool {
        self.parsed.get().is_some()
    }

    fn parsed(&self) -> &HashMap<String, String> {
        self.parsed.get_or_init(|| {
            self.raw
                .split('&')
                .filter(|s| !s.is_empty())
                .filter_map(|pair| {
                    let mut parts = pair.splitn(2, '=');
                    let key = parts.next()?;
                    let val = parts.next().unwrap_or("");
                    // URL-decode both key and value (+ → space, %XX → byte)
                    let decoded_key = decode_www_form_component(key);
                    let decoded_val = decode_www_form_component(val);
                    Some((decoded_key, decoded_val))
                })
                .collect()
        })
    }
}

/// Check if a raw query string contains a key without full URL-decode parsing.
/// Works for typical ASCII keys that don't need URL-decoding.
fn raw_contains_key(raw: &str, key: &str) -> bool {
    if raw.is_empty() || key.is_empty() {
        return false;
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let k = match pair.find('=') {
            Some(pos) => &pair[..pos],
            None => pair,
        };
        if k == key {
            return true;
        }
    }
    false
}

/// Decode a www-form-urlencoded component: percent-decode and replace '+' with space.
fn decode_www_form_component(s: &str) -> String {
    let plus_replaced = s.replace('+', " ");
    percent_decode_str(&plus_replaced)
        .decode_utf8_lossy()
        .into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_query_parsing() {
        let qd = QueryData::new("q=hello&page=1&sort=asc");
        assert_eq!(qd.get("q"), Some("hello"));
        assert_eq!(qd.get("page"), Some("1"));
        assert_eq!(qd.get("sort"), Some("asc"));
        assert_eq!(qd.get("missing"), None);
    }

    #[test]
    fn test_empty_query() {
        let qd = QueryData::new("");
        assert_eq!(qd.get("anything"), None);
    }

    #[test]
    fn test_key_without_value() {
        let qd = QueryData::new("flag&key=val");
        assert_eq!(qd.get("flag"), Some(""));
        assert_eq!(qd.get("key"), Some("val"));
    }

    #[test]
    fn test_duplicate_keys_last_wins() {
        let qd = QueryData::new("a=1&a=2");
        // HashMap: last insert wins
        assert_eq!(qd.get("a"), Some("2"));
    }

    #[test]
    fn test_equals_in_value() {
        // key=a=b should give key -> "a=b"
        let qd = QueryData::new("key=a=b");
        assert_eq!(qd.get("key"), Some("a=b"));
    }

    #[test]
    fn test_empty_key() {
        // =value has empty key
        let qd = QueryData::new("=value");
        assert_eq!(qd.get(""), Some("value"));
    }

    #[test]
    fn test_url_encoded_values() {
        let qd = QueryData::new("name=hello%20world&path=%2Ffoo%2Fbar");
        assert_eq!(qd.get("name"), Some("hello world"));
        assert_eq!(qd.get("path"), Some("/foo/bar"));
    }

    #[test]
    fn test_url_encoded_keys() {
        let qd = QueryData::new("my%20key=value");
        assert_eq!(qd.get("my key"), Some("value"));
    }

    #[test]
    fn test_plus_as_space() {
        let qd = QueryData::new("q=hello+world");
        assert_eq!(qd.get("q"), Some("hello world"));
    }

    #[test]
    fn test_get_returns_reference() {
        let qd = QueryData::new("key=value");
        let v1 = qd.get("key");
        let v2 = qd.get("key");
        // Both return borrowed references from the same cached HashMap
        assert_eq!(v1, v2);
        assert_eq!(v1, Some("value"));
    }

    // --- contains_key tests ---

    #[test]
    fn test_contains_key_found() {
        let qd = QueryData::new("q=hello&page=1");
        assert!(qd.contains_key("q"));
        assert!(qd.contains_key("page"));
    }

    #[test]
    fn test_contains_key_not_found() {
        let qd = QueryData::new("q=hello&page=1");
        assert!(!qd.contains_key("missing"));
    }

    #[test]
    fn test_contains_key_no_full_parse() {
        let qd = QueryData::new("q=hello&page=1");
        assert!(qd.contains_key("q"));
        // OnceCell should NOT have been initialized by contains_key
        assert!(!qd.is_parsed());
    }

    #[test]
    fn test_contains_key_after_parse() {
        let qd = QueryData::new("q=hello&page=1");
        // Trigger full parse first
        let _ = qd.get("q");
        assert!(qd.is_parsed());
        // contains_key should still work via HashMap
        assert!(qd.contains_key("q"));
        assert!(!qd.contains_key("missing"));
    }

    #[test]
    fn test_contains_key_empty_query() {
        let qd = QueryData::new("");
        assert!(!qd.contains_key("anything"));
    }
}
