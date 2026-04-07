use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pingora_limits::rate::Rate;

use crate::config::RateLimitConfig;

/// A rate limiter instance for a single rule.
pub struct RuleLimiter {
    rate: Arc<Rate>,
    requests_per_period: u64,
    mitigation_timeout: Duration,
    /// Tracks when each key entered mitigation (blocked state).
    /// Key is serialized to String for HashMap compatibility.
    mitigated: Mutex<HashMap<String, Instant>>,
}

impl RuleLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        let period = Duration::from_secs(config.period.max(1));
        Self {
            rate: Arc::new(Rate::new(period)),
            requests_per_period: config.requests_per_period,
            mitigation_timeout: Duration::from_secs(config.mitigation_timeout),
            mitigated: Mutex::new(HashMap::new()),
        }
    }

    /// Observe a request and return true if it should be blocked.
    pub fn check_and_incr(&self, key: &RateLimitKey) -> bool {
        let key_str = key.to_string();

        // Check if already in mitigation
        if self.mitigation_timeout.as_secs() > 0 {
            let mut mitigated = self.mitigated.lock().unwrap();
            if let Some(since) = mitigated.get(&key_str) {
                if since.elapsed() < self.mitigation_timeout {
                    // Still in mitigation — count the request but stay blocked
                    self.rate.observe(key, 1);
                    return true;
                } else {
                    // Mitigation expired — remove and re-evaluate
                    mitigated.remove(&key_str);
                }
            }
        }

        let count = self.rate.observe(key, 1);
        let exceeded = count as u64 > self.requests_per_period;

        if exceeded && self.mitigation_timeout.as_secs() > 0 {
            let mut mitigated = self.mitigated.lock().unwrap();
            mitigated.entry(key_str).or_insert_with(Instant::now);
        }

        exceeded
    }
}

/// Composite key for rate limiting, built from characteristics.
#[derive(Clone, Debug)]
pub struct RateLimitKey {
    parts: Vec<String>,
}

impl RateLimitKey {
    pub fn new() -> Self {
        Self { parts: Vec::new() }
    }

    pub fn push(&mut self, value: String) {
        self.parts.push(value);
    }
}

impl std::fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.parts.join(":"))
    }
}

impl Hash for RateLimitKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for part in &self.parts {
            part.hash(state);
        }
    }
}

/// Manages rate limiters for all rules that have ratelimit config.
pub struct RateLimitManager {
    limiters: HashMap<String, RuleLimiter>,
}

impl RateLimitManager {
    pub fn new() -> Self {
        Self {
            limiters: HashMap::new(),
        }
    }

    pub fn add_rule(&mut self, rule_id: &str, config: &RateLimitConfig) {
        // Only create new limiter if rule doesn't already exist (preserves state across
        // reloads)
        if !self.limiters.contains_key(rule_id) {
            self.limiters
                .insert(rule_id.to_string(), RuleLimiter::new(config));
        }
    }

    /// Check if the rate limit for a rule is exceeded. Returns true if
    /// exceeded.
    pub fn check(&self, rule_id: &str, key: &RateLimitKey) -> bool {
        self.limiters
            .get(rule_id)
            .map(|limiter| limiter.check_and_incr(key))
            .unwrap_or(false)
    }
}
