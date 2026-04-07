use std::collections::HashMap;

use log::{debug, info, warn};
use wirefilter_engine::{ExecutionContext, Filter, LhsValue, Scheme};

use super::ratelimit::{RateLimitKey, RateLimitManager};

#[derive(Debug, Clone)]
pub enum Action {
    Block {
        status_code: u16,
        content_type: Option<String>,
        content: Option<String>,
    },
    Allow,
    Log,
    Score {
        scores: Vec<(String, i64)>,
    },
    Challenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Phase {
    RequestHeaders,
    RequestBody,
    ResponseHeaders,
    ResponseBody,
    Logging,
}

pub struct CompiledRule {
    pub id: String,
    pub phase: Phase,
    pub action: Action,
    pub filter: Filter,
    pub ratelimit_characteristics: Option<Vec<String>>,
}

pub enum RuleAction {
    Block {
        rule_id: String,
        status_code: u16,
        content_type: Option<String>,
        content: Option<String>,
    },
    Allow {
        rule_id: String,
    },
    Challenge {
        rule_id: String,
    },
    NoMatch,
}

pub struct Engine {
    rules: HashMap<Phase, Vec<CompiledRule>>,
    pub ratelimit_mgr: RateLimitManager,
}

impl Engine {
    pub fn new(rules: Vec<CompiledRule>, ratelimit_mgr: RateLimitManager) -> Self {
        let mut grouped: HashMap<Phase, Vec<CompiledRule>> = HashMap::new();
        for rule in rules {
            grouped.entry(rule.phase.clone()).or_default().push(rule);
        }

        let total: usize = grouped.values().map(|v| v.len()).sum();
        info!("Engine loaded {} rules ({} phases)", total, grouped.len());
        for (phase, phase_rules) in &grouped {
            debug!("  {:?}: {} rules", phase, phase_rules.len());
        }

        Self {
            rules: grouped,
            ratelimit_mgr,
        }
    }

    pub fn evaluate(
        &self,
        phase: &Phase,
        ctx: &ExecutionContext<'_>,
        scores: &mut HashMap<String, i64>,
        matched_rules: &mut Vec<(String, String)>, // (rule_id, action)
    ) -> RuleAction {
        let Some(phase_rules) = self.rules.get(phase) else {
            return RuleAction::NoMatch;
        };

        for rule in phase_rules {
            let matched = match rule.filter.execute(ctx) {
                Ok(v) => v,
                Err(e) => {
                    warn!("Rule '{}' execution error: {}", rule.id, e);
                    false
                }
            };

            if !matched {
                continue;
            }

            // Rate limit check
            if rule.ratelimit_characteristics.is_some() {
                let key = build_ratelimit_key(rule, ctx);
                let exceeded = self.ratelimit_mgr.check(&rule.id, &key);
                if !exceeded {
                    debug!("Rule '{}' matched but rate limit not exceeded", rule.id);
                    continue;
                }
                debug!("Rule '{}' rate limit exceeded", rule.id);
            }

            debug!("Rule '{}' matched (action: {:?})", rule.id, rule.action);

            match &rule.action {
                Action::Block {
                    status_code,
                    content_type,
                    content,
                } => {
                    info!("BLOCK by rule '{}' (status {})", rule.id, status_code);
                    return RuleAction::Block {
                        rule_id: rule.id.clone(),
                        status_code: *status_code,
                        content_type: content_type.clone(),
                        content: content.clone(),
                    };
                }
                Action::Allow => {
                    info!("ALLOW by rule '{}'", rule.id);
                    return RuleAction::Allow {
                        rule_id: rule.id.clone(),
                    };
                }
                Action::Log => {
                    info!("LOG by rule '{}'", rule.id);
                    matched_rules.push((rule.id.clone(), "log".into()));
                }
                Action::Score { scores: score_list } => {
                    for (name, increment) in score_list {
                        let counter = scores.entry(name.clone()).or_insert(0);
                        *counter += increment;
                        debug!("SCORE '{}' += {} (now {})", name, increment, counter);
                    }
                    matched_rules.push((rule.id.clone(), "score".into()));
                }
                Action::Challenge => {
                    info!("CHALLENGE by rule '{}'", rule.id);
                    return RuleAction::Challenge {
                        rule_id: rule.id.clone(),
                    };
                }
            }
        }

        RuleAction::NoMatch
    }

    pub fn rule_count(&self) -> usize {
        self.rules.values().map(|v| v.len()).sum()
    }
}

fn build_ratelimit_key(rule: &CompiledRule, ctx: &ExecutionContext<'_>) -> RateLimitKey {
    let mut key = RateLimitKey::new();

    let characteristics = rule
        .ratelimit_characteristics
        .as_deref()
        .unwrap_or_default();

    if characteristics.is_empty() {
        if let Ok(field) = ctx.scheme().get_field("ip.src") {
            if let Some(LhsValue::Ip(ip)) = ctx.get_field_value(field) {
                key.push(ip.to_string());
            }
        }
    } else {
        for char_name in characteristics {
            if let Ok(field) = ctx.scheme().get_field(char_name) {
                if let Some(val) = ctx.get_field_value(field) {
                    match val {
                        LhsValue::Ip(ip) => key.push(ip.to_string()),
                        LhsValue::Bytes(b) => key.push(String::from_utf8_lossy(b).into_owned()),
                        LhsValue::Int(i) => key.push(i.to_string()),
                        LhsValue::Bool(b) => key.push(b.to_string()),
                        _ => key.push(format!("{:?}", val)),
                    }
                }
            }
        }
    }

    key
}

pub fn sync_scores(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    scores: &HashMap<String, i64>,
) {
    let mut field_name = String::with_capacity(32);
    for (name, value) in scores {
        field_name.clear();
        field_name.push_str("oss.waf.score.");
        field_name.push_str(name);
        if let Ok(field) = scheme.get_field(&field_name) {
            let _ = ctx.set_field_value(field, LhsValue::Int(*value));
        }
    }
}
