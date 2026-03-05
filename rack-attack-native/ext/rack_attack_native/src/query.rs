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

}
