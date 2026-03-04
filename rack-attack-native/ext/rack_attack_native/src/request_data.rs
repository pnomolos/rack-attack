use serde::Deserialize;
use std::collections::HashMap;

/// Flat request data deserialized from a Ruby Hash via serde_magnus.
#[derive(Debug, Default, Deserialize)]
pub struct RequestData {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub user_agent: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub query_string: String,
    #[serde(default)]
    pub content_length: u64,
    /// Raw Authorization header value (e.g. "Bearer eyJ...")
    #[serde(default)]
    pub authorization: Option<String>,
    /// Raw request body (for body inspection rules)
    #[serde(default)]
    pub body: Option<String>,
    /// Lowercased header keys (e.g. "x-api-key")
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub cookies: HashMap<String, String>,
}
