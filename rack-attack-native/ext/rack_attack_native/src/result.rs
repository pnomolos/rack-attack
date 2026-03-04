use serde::Serialize;

/// Result of evaluating a full RuleSet against a request.
#[derive(Debug, Serialize, Default)]
pub struct EvaluationResult {
    pub safelisted: Option<String>,
    pub blocklisted: Option<String>,
    pub throttle_matches: Vec<ThrottleMatch>,
    pub tracked: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ThrottleMatch {
    pub name: String,
    pub discriminator: String,
    pub limit: u64,
    pub period: u64,
}
