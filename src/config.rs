use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    pub upstream: String,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(default = "default_max_request_body_buffer")]
    pub max_request_body_buffer: usize,

    #[serde(default)]
    pub inspect_response_body: bool,

    #[serde(default = "default_max_response_body_buffer")]
    pub max_response_body_buffer: usize,

    #[serde(default)]
    pub logging: LoggingConfig,

    #[serde(default)]
    pub geoip: Option<GeoIpConfig>,

    #[serde(default)]
    pub metrics: Option<MetricsConfig>,

    #[serde(default)]
    pub scores: Vec<String>,

    #[serde(default)]
    pub lists: Vec<ListConfig>,

    #[serde(default)]
    pub challenge: Option<ChallengeConfig>,

    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// App log level (debug/info/warn/error)
    pub level: String,
    /// Access + audit log format (text/json)
    pub format: String,
    /// Access log output path (/dev/stdout, /dev/stderr, or file)
    pub access_log: PathBuf,
    /// Audit log output path — detailed logs when rules match
    pub audit_log: PathBuf,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "json".into(),
            access_log: PathBuf::from("/dev/stdout"),
            audit_log: PathBuf::from("/dev/stderr"),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeoIpConfig {
    pub city_mmdb: PathBuf,
    pub asn_mmdb: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ListConfig {
    pub name: String,
    #[serde(default = "default_list_kind")]
    pub kind: String,
    #[serde(default)]
    pub items: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(default = "default_phase")]
    pub phase: Phase,
    pub action: Action,
    pub expression: String,
    #[serde(default)]
    pub action_parameters: Option<ActionParameters>,
    #[serde(default)]
    pub ratelimit: Option<RateLimitConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Logging,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Block,
    Log,
    Allow,
    Score,
    Challenge,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionParameters {
    #[serde(default)]
    pub response: Option<BlockResponse>,
    #[serde(default)]
    pub scores: Vec<ScoreAction>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockResponse {
    #[serde(default = "default_status_code")]
    pub status_code: u16,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScoreAction {
    pub name: String,
    #[serde(default = "default_increment")]
    pub increment: i64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChallengeConfig {
    pub turnstile_site_key: String,
    pub turnstile_secret_key: String,
    pub cookie_secret: String,
    #[serde(default = "default_challenge_cookie_ttl")]
    pub cookie_ttl: u64,
    #[serde(default = "default_challenge_cookie_name")]
    pub cookie_name: String,
    #[serde(default = "default_challenge_path")]
    pub challenge_path: String,
    /// Path to custom HTML challenge page. The page must contain
    /// `{{turnstile_site_key}}` placeholder which will be replaced with the
    /// actual site key.
    #[serde(default)]
    pub custom_page: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub characteristics: Vec<String>,
    #[serde(default)]
    pub period: u64,
    #[serde(default)]
    pub requests_per_period: u64,
    #[serde(default)]
    pub mitigation_timeout: u64,
}

// Defaults
fn default_max_request_body_buffer() -> usize {
    1_048_576
}
fn default_max_response_body_buffer() -> usize {
    1_048_576
}
fn default_true() -> bool {
    true
}
fn default_metrics_listen() -> String {
    "127.0.0.1:9090".into()
}
fn default_challenge_cookie_ttl() -> u64 {
    3600
}
fn default_challenge_cookie_name() -> String {
    "oss_challenge".into()
}
fn default_challenge_path() -> String {
    "/__openshield/challenge".into()
}
fn default_list_kind() -> String {
    "ip".into()
}
fn default_phase() -> Phase {
    Phase::RequestHeaders
}
fn default_status_code() -> u16 {
    403
}
fn default_increment() -> i64 {
    1
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.listen.is_empty() {
            return Err("listen address is required".into());
        }
        if self.upstream.is_empty() {
            return Err("upstream address is required".into());
        }
        for rule in &self.rules {
            if rule.id.is_empty() {
                return Err("rule id is required".into());
            }
            if rule.expression.is_empty() {
                return Err(format!("rule '{}' has empty expression", rule.id).into());
            }
            if let Action::Challenge = rule.action {
                if self.challenge.is_none() {
                    return Err(format!(
                        "rule '{}' has action 'challenge' but no challenge config",
                        rule.id
                    )
                    .into());
                }
            }
            if let Action::Score = rule.action {
                let has_scores = rule
                    .action_parameters
                    .as_ref()
                    .is_some_and(|p| !p.scores.is_empty());
                if !has_scores {
                    return Err(format!(
                        "rule '{}' has action 'score' but no score parameters",
                        rule.id
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
}
