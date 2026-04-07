use log::debug;
use wirefilter_engine::Scheme;

use crate::config;
use crate::waf::engine::{Action, CompiledRule, Engine, Phase};
use crate::waf::ratelimit::RateLimitManager;

/// Compile rules from config into an Engine.
pub fn compile(
    config: &config::Config,
    scheme: &Scheme,
    existing_mgr: Option<RateLimitManager>,
) -> Result<Engine, Box<dyn std::error::Error>> {
    let mut rules = Vec::new();
    let mut mgr = existing_mgr.unwrap_or_else(RateLimitManager::new);

    for rule_cfg in &config.rules {
        debug!("Compiling rule '{}'", rule_cfg.id);

        let ast = scheme
            .parse(&rule_cfg.expression)
            .map_err(|e| format!("Failed to parse rule '{}': {}", rule_cfg.id, e))?;
        let filter = ast.compile();

        let phase = convert_phase(&rule_cfg.phase);
        let action = convert_action(rule_cfg);

        let ratelimit_characteristics = if let Some(ref rl_cfg) = rule_cfg.ratelimit {
            mgr.add_rule(&rule_cfg.id, rl_cfg);
            debug!(
                "  rate limit: {}/{} per {}s",
                rl_cfg.requests_per_period, rl_cfg.period, rl_cfg.mitigation_timeout
            );
            Some(rl_cfg.characteristics.clone())
        } else {
            None
        };

        rules.push(CompiledRule {
            id: rule_cfg.id.clone(),
            phase,
            action,
            filter,
            ratelimit_characteristics,
        });
    }

    Ok(Engine::new(rules, mgr))
}

fn convert_phase(phase: &config::Phase) -> Phase {
    match phase {
        config::Phase::RequestHeaders => Phase::RequestHeaders,
        config::Phase::RequestBody => Phase::RequestBody,
        config::Phase::ResponseHeaders => Phase::ResponseHeaders,
        config::Phase::ResponseBody => Phase::ResponseBody,
        config::Phase::Logging => Phase::Logging,
    }
}

fn convert_action(rule: &config::RuleConfig) -> Action {
    match &rule.action {
        config::Action::Block => {
            let (status_code, content_type, content) =
                if let Some(ref params) = rule.action_parameters {
                    if let Some(ref resp) = params.response {
                        (
                            resp.status_code,
                            resp.content_type.clone(),
                            resp.content.clone(),
                        )
                    } else {
                        (403, None, None)
                    }
                } else {
                    (403, None, None)
                };
            Action::Block {
                status_code,
                content_type,
                content,
            }
        }
        config::Action::Allow => Action::Allow,
        config::Action::Log => Action::Log,
        config::Action::Score => {
            let scores = rule
                .action_parameters
                .as_ref()
                .map(|p| {
                    p.scores
                        .iter()
                        .map(|s| (s.name.clone(), s.increment))
                        .collect()
                })
                .unwrap_or_default();
            Action::Score { scores }
        }
        config::Action::Challenge => Action::Challenge,
    }
}
