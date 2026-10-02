use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub listen: String,
    pub upstream: String,

    #[serde(default)]
    pub tls: Option<TlsConfig>,

    #[serde(default)]
    pub detection_only: bool,

    #[serde(default)]
    pub workers: Option<usize>,

    #[serde(default = "default_pid_file")]
    pub pid_file: String,

    #[serde(default = "default_upgrade_sock")]
    pub upgrade_sock: String,

    #[serde(default)]
    pub upstream_keepalive_pool: Option<usize>,

    #[serde(default = "default_max_request_body_buffer")]
    pub max_request_body_buffer: usize,

    #[serde(default)]
    pub request_body_limit_action: BodyLimitAction,

    #[serde(default)]
    pub inspect_response_body: bool,

    #[serde(default = "default_max_response_body_buffer")]
    pub max_response_body_buffer: usize,

    #[serde(default)]
    pub response_body_limit_action: BodyLimitAction,

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
    pub rulesets: Vec<RulesetConfig>,
}

/// A named container of rules. `root` rulesets run on every request;
/// `custom` and `managed` rulesets run only via a root rule with
/// `action: execute`.
#[derive(Debug, Clone, Deserialize)]
pub struct RulesetConfig {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    #[serde(default)]
    pub kind: RulesetKind,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RulesetKind {
    Root,
    #[default]
    Custom,
    Managed,
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
    /// Log the payload values that triggered each matched rule (audit log).
    pub log_payloads: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: "json".into(),
            access_log: PathBuf::from("/dev/stdout"),
            audit_log: PathBuf::from("/dev/stderr"),
            log_payloads: false,
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
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub r#ref: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub version: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_phase")]
    pub phase: Phase,
    pub action: Action,
    pub expression: String,
    #[serde(default)]
    pub action_parameters: Option<ActionParameters>,
    #[serde(default)]
    pub ratelimit: Option<RateLimitConfig>,
    #[serde(default)]
    pub logging: RuleLoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleLoggingConfig {
    pub enabled: bool,
}

impl Default for RuleLoggingConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
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
    Execute,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum BodyLimitAction {
    #[default]
    ProcessPartial,
    Reject,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ActionParameters {
    #[serde(default)]
    pub response: Option<BlockResponse>,
    #[serde(default)]
    pub scores: Vec<ScoreAction>,
    /// `execute` only: name of the ruleset to run.
    #[serde(default)]
    pub id: Option<String>,
    /// `execute` only: overrides applied to the executed ruleset.
    #[serde(default)]
    pub overrides: Option<Overrides>,
}

/// Overrides for an executed ruleset. Precedence (highest first):
/// `rules` > `categories` > top-level `action` / `enabled`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Overrides {
    /// Action to override all rules with.
    #[serde(default)]
    pub action: Option<Action>,
    /// Whether to enable execution of all rules.
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub categories: Vec<CategoryOverride>,
    #[serde(default)]
    pub rules: Vec<RuleOverride>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CategoryOverride {
    pub category: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RuleOverride {
    pub id: String,
    #[serde(default)]
    pub action: Option<Action>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

impl Overrides {
    /// Resolve the effective (enabled, action) for `rule` under these
    /// overrides. Rule-level wins over category-level, which wins over the
    /// ruleset-wide setting; each layer only replaces what it sets.
    pub fn resolve(&self, rule: &RuleConfig) -> (bool, Action) {
        let mut enabled = self.enabled.unwrap_or(rule.enabled);
        let mut action = self.action.clone().unwrap_or_else(|| rule.action.clone());

        for c in self
            .categories
            .iter()
            .filter(|c| rule.categories.contains(&c.category))
        {
            if let Some(e) = c.enabled {
                enabled = e;
            }
            if let Some(ref a) = c.action {
                action = a.clone();
            }
        }

        if let Some(r) = self.rules.iter().find(|r| r.id == rule.id) {
            if let Some(e) = r.enabled {
                enabled = e;
            }
            if let Some(ref a) = r.action {
                action = a.clone();
            }
        }

        (enabled, action)
    }
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
fn default_pid_file() -> String {
    "/tmp/openshield.pid".into()
}
fn default_upgrade_sock() -> String {
    "/tmp/openshield_upgrade.sock".into()
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
        for rs in &self.rulesets {
            if rs.name.is_empty() {
                return Err("ruleset name is required".into());
            }
            if self.rulesets.iter().filter(|r| r.name == rs.name).count() > 1 {
                return Err(format!("duplicate ruleset name '{}'", rs.name).into());
            }
            for rule in &rs.rules {
                let result = match (&rule.action, rs.kind) {
                    (Action::Execute, RulesetKind::Root) => self.validate_execute(rule),
                    (Action::Execute, _) => Err(format!(
                        "rule '{}': 'execute' is only allowed in a ruleset with 'kind: root'",
                        rule.id
                    )
                    .into()),
                    _ => self.validate_rule(rule, &rule.action),
                };
                result.map_err(|e| format!("ruleset '{}': {}", rs.name, e))?;
            }
        }
        Ok(())
    }

    /// Validate a rule as if it ran with `action` (which may differ from
    /// `rule.action` when an `execute` override is applied).
    fn validate_rule(
        &self,
        rule: &RuleConfig,
        action: &Action,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if rule.id.is_empty() {
            return Err("rule id is required".into());
        }
        if rule.expression.is_empty() {
            return Err(format!("rule '{}' has empty expression", rule.id).into());
        }
        match action {
            Action::Challenge if self.challenge.is_none() => Err(format!(
                "rule '{}' has action 'challenge' but no challenge config",
                rule.id
            )
            .into()),
            Action::Score => {
                let has_scores = rule
                    .action_parameters
                    .as_ref()
                    .is_some_and(|p| !p.scores.is_empty());
                if has_scores {
                    Ok(())
                } else {
                    Err(format!(
                        "rule '{}' has action 'score' but no score parameters",
                        rule.id
                    )
                    .into())
                }
            }
            Action::Execute => Err(format!(
                "rule '{}': 'execute' cannot be used as an override action",
                rule.id
            )
            .into()),
            _ => Ok(()),
        }
    }

    fn validate_execute(&self, rule: &RuleConfig) -> Result<(), Box<dyn std::error::Error>> {
        if rule.id.is_empty() {
            return Err("rule id is required".into());
        }
        if rule.expression.is_empty() {
            return Err(format!("rule '{}' has empty expression", rule.id).into());
        }
        let params = rule.action_parameters.as_ref();
        let Some(id) = params.and_then(|p| p.id.as_deref()) else {
            return Err(format!(
                "rule '{}' has action 'execute' but no action_parameters.id",
                rule.id
            )
            .into());
        };
        let Some(ruleset) = self.rulesets.iter().find(|r| r.name == id) else {
            return Err(format!("rule '{}' executes unknown ruleset '{}'", rule.id, id).into());
        };
        if ruleset.kind == RulesetKind::Root {
            return Err(format!("rule '{}' executes root ruleset '{}'", rule.id, id).into());
        }
        let overrides = params.and_then(|p| p.overrides.clone()).unwrap_or_default();

        for o in &overrides.rules {
            if !ruleset.rules.iter().any(|r| r.id == o.id) {
                return Err(format!(
                    "rule '{}' overrides unknown rule '{}' in ruleset '{}'",
                    rule.id, o.id, id
                )
                .into());
            }
        }
        for o in &overrides.categories {
            if !ruleset
                .rules
                .iter()
                .any(|r| r.categories.contains(&o.category))
            {
                return Err(format!(
                    "rule '{}' overrides unknown category '{}' in ruleset '{}'",
                    rule.id, o.category, id
                )
                .into());
            }
        }

        // Every rule must be valid under the action it will actually run with.
        for rs_rule in &ruleset.rules {
            let (enabled, action) = overrides.resolve(rs_rule);
            if enabled {
                self.validate_rule(rs_rule, &action).map_err(|e| {
                    format!("rule '{}' (via execute '{}'): {}", rs_rule.id, rule.id, e)
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<Config, Box<dyn std::error::Error>> {
        let cfg: Config = serde_yaml::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    const BASE: &str = r#"
listen: "127.0.0.1:8080"
upstream: "http://127.0.0.1:9000"
scores: [sqli]
rulesets:
  - name: crs
    description: OWASP Core Rule Set
    version: "4.0.0"
    rules:
      - id: "942100"
        description: SQLi via libinjection
        ref: https://example.com/942100
        version: "4.0.0"
        categories: [attack-sqli, paranoia-level-1]
        action: block
        expression: 'http.request.uri.path contains "sqli"'
      - id: "941100"
        categories: [attack-xss, paranoia-level-1]
        action: log
        expression: 'http.request.uri.path contains "xss"'
      - id: "920100"
        categories: [protocol]
        enabled: false
        action: block
        expression: 'http.request.uri.path contains "proto"'
"#;

    /// `BASE` plus a root ruleset `main` holding `rules` (a YAML list).
    fn with_root(rules: &str) -> String {
        let rules: String = rules
            .trim_matches('\n')
            .lines()
            .map(|l| format!("      {l}\n"))
            .collect();
        format!("{BASE}  - name: main\n    kind: root\n    rules:\n{rules}")
    }

    /// `BASE` plus a root rule executing `crs` with extra `action_parameters`.
    fn with_execute(params: &str) -> String {
        let params: String = params
            .trim_matches('\n')
            .lines()
            .map(|l| format!("    {l}\n"))
            .collect();
        with_root(&format!(
            "- id: run\n  action: execute\n  expression: \"true\"\n  action_parameters:\n    \
             id: crs\n{params}"
        ))
    }

    #[test]
    fn rule_metadata_fields_parse_with_defaults() {
        let cfg = parse(BASE).unwrap();
        let rs = &cfg.rulesets[0];
        assert_eq!(rs.name, "crs");
        assert_eq!(rs.version.as_deref(), Some("4.0.0"));
        assert_eq!(rs.kind, RulesetKind::Custom, "kind defaults to custom");
        let r = &rs.rules[0];
        assert_eq!(r.r#ref.as_deref(), Some("https://example.com/942100"));
        assert_eq!(r.categories, vec!["attack-sqli", "paranoia-level-1"]);
        assert!(r.enabled, "enabled defaults to true");
        assert!(!rs.rules[2].enabled);
    }

    #[test]
    fn managed_ruleset_is_executable_but_cannot_execute() {
        let managed = BASE.replace("  - name: crs\n", "  - name: crs\n    kind: managed\n");
        let cfg = parse(&format!(
            "{managed}  - name: main\n    kind: root\n    rules:\n      - {{id: run, action: \
             execute, expression: \"true\", action_parameters: {{id: crs}}}}"
        ))
        .unwrap();
        assert_eq!(cfg.rulesets[0].kind, RulesetKind::Managed);

        let err = parse(
            r#"
listen: a
upstream: b
rulesets:
  - name: other
  - name: rs
    kind: managed
    rules:
      - {id: x, action: execute, expression: "true", action_parameters: {id: other}}
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only allowed in a ruleset with 'kind: root'"),
            "{err}"
        );
    }

    #[test]
    fn ruleset_names_must_be_unique() {
        let err = parse(&format!("{BASE}  - name: crs\n    kind: root")).unwrap_err();
        assert!(
            err.to_string().contains("duplicate ruleset name 'crs'"),
            "{err}"
        );
    }

    #[test]
    fn root_ruleset_rules_are_validated() {
        let err = parse(&with_root(
            r#"
- id: c
  action: challenge
  expression: 'http.host == "x"'
"#,
        ))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("ruleset 'main': rule 'c' has action 'challenge'"),
            "{err}"
        );
    }

    #[test]
    fn execute_requires_known_custom_ruleset() {
        let rule = |params: &str| {
            with_root(&format!(
                "- id: run\n  action: execute\n  expression: \"true\"\n{params}"
            ))
        };

        let err = parse(&rule("  action_parameters:\n    id: nope")).unwrap_err();
        assert!(err.to_string().contains("unknown ruleset 'nope'"), "{err}");

        let err = parse(&rule("")).unwrap_err();
        assert!(err.to_string().contains("no action_parameters.id"), "{err}");

        let err = parse(&rule("  action_parameters:\n    id: main")).unwrap_err();
        assert!(
            err.to_string().contains("executes root ruleset 'main'"),
            "{err}"
        );
    }

    #[test]
    fn execute_requires_expression() {
        let err = parse(&with_root(
            "- id: run\n  action: execute\n  action_parameters:\n    id: crs",
        ))
        .unwrap_err();
        assert!(
            err.to_string().contains("missing field `expression`"),
            "{err}"
        );
    }

    #[test]
    fn execute_rejects_unknown_override_targets() {
        let err = parse(&with_execute(
            "overrides:\n  rules: [{id: \"000000\", enabled: false}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown rule '000000'"), "{err}");

        let err = parse(&with_execute(
            "overrides:\n  categories: [{category: nope, action: log}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unknown category 'nope'"), "{err}");
    }

    #[test]
    fn execute_only_allowed_in_root_ruleset_and_not_as_override_action() {
        let err = parse(
            r#"
listen: a
upstream: b
rulesets:
  - name: other
  - name: rs
    rules:
      - {id: x, action: execute, expression: "true", action_parameters: {id: other}}
"#,
        )
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("only allowed in a ruleset with 'kind: root'"),
            "{err}"
        );

        let err = parse(&with_execute("overrides:\n  action: execute")).unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot be used as an override action"),
            "{err}"
        );
    }

    #[test]
    fn override_to_score_validates_score_parameters() {
        // 942100 has no score parameters, so overriding it to `score` is
        // invalid.
        let err = parse(&with_execute(
            "overrides:\n  rules: [{id: \"942100\", action: score}]",
        ))
        .unwrap_err();
        assert!(err.to_string().contains("no score parameters"), "{err}");

        // ...unless that rule is disabled by the same overrides.
        parse(&with_execute(
            "overrides:\n  enabled: false\n  rules: [{id: \"942100\", action: score}]",
        ))
        .unwrap();
    }

    #[test]
    fn override_precedence_rule_over_category_over_global() {
        let cfg = parse(BASE).unwrap();
        let rs = &cfg.rulesets[0];
        let sqli = &rs.rules[0];
        let xss = &rs.rules[1];
        let proto = &rs.rules[2];

        let overrides: Overrides = serde_yaml::from_str(
            r#"
action: log
enabled: false
categories:
  - category: paranoia-level-1
    enabled: true
    action: challenge
  - category: attack-xss
    action: allow
rules:
  - id: "942100"
    action: block
"#,
        )
        .unwrap();

        // rule-level action wins; category-level enabled wins over global.
        let (en, act) = overrides.resolve(sqli);
        assert!(en);
        assert!(matches!(act, Action::Block));

        // both categories match; later category in the list wins for action.
        let (en, act) = overrides.resolve(xss);
        assert!(en);
        assert!(matches!(act, Action::Allow));

        // no category/rule override -> global applies (disabled, log).
        let (en, act) = overrides.resolve(proto);
        assert!(!en);
        assert!(matches!(act, Action::Log));

        // Empty overrides keep the rule's own settings.
        let (en, act) = Overrides::default().resolve(proto);
        assert!(!en);
        assert!(matches!(act, Action::Block));
    }
}
