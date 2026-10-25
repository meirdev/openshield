use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use pingora_limits::rate::Rate;

use crate::config::RateLimitConfig;

/// The limits a rule applies to each key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub period: Duration,
    pub requests_per_period: u64,
    /// How long a key stays blocked after exceeding the limit; zero means
    /// it is re-evaluated on every request.
    pub mitigation_timeout: Duration,
}

impl From<&RateLimitConfig> for Limits {
    fn from(config: &RateLimitConfig) -> Self {
        Self {
            period: Duration::from_secs(config.period.max(1)),
            requests_per_period: config.requests_per_period,
            mitigation_timeout: Duration::from_secs(config.mitigation_timeout),
        }
    }
}

/// Composite key for rate limiting, built from characteristics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct RateLimitKey {
    parts: Vec<String>,
}

impl RateLimitKey {
    pub fn new() -> Self {
        Self::default()
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

/// Where request counts live. [`MemoryStore`] serves one process; a
/// deployment whose workers are separate processes, such as an nginx module,
/// provides a store backed by memory they share. Counting and deciding are
/// one call so the store can make them atomic.
pub trait RateLimitStore: Send + Sync {
    /// Count one request for `key` under `rule` and report whether the
    /// request should be blocked.
    fn check_and_incr(&self, rule: &str, key: &RateLimitKey, limits: &Limits) -> bool;
}

/// Counters for one process, created per rule on first use.
#[derive(Default)]
pub struct MemoryStore {
    rules: RwLock<HashMap<String, Arc<RuleCounters>>>,
}

struct RuleCounters {
    period: Duration,
    rate: Rate,
    mitigated: Mutex<Mitigated>,
}

/// Keys currently blocked and when their block started. Expired entries
/// are swept out whenever a key is added more than a timeout after the last
/// sweep, which bounds the map to keys seen in the last two timeouts.
struct Mitigated {
    since: HashMap<RateLimitKey, Instant>,
    last_sweep: Instant,
}

impl RuleCounters {
    fn new(period: Duration) -> Self {
        Self {
            period,
            rate: Rate::new(period),
            mitigated: Mutex::new(Mitigated {
                since: HashMap::new(),
                last_sweep: Instant::now(),
            }),
        }
    }

    fn check_and_incr(&self, key: &RateLimitKey, limits: &Limits) -> bool {
        let timeout = limits.mitigation_timeout;
        if !timeout.is_zero() {
            let mut mitigated = self.mitigated.lock().unwrap();
            match mitigated.since.get(key) {
                Some(since) if since.elapsed() < timeout => {
                    // Still blocked: the request counts but is not
                    // re-evaluated.
                    self.rate.observe(key, 1);
                    return true;
                }
                Some(_) => {
                    mitigated.since.remove(key);
                }
                None => {}
            }
        }

        let exceeded = self.rate.observe(key, 1) as u64 > limits.requests_per_period;

        if exceeded && !timeout.is_zero() {
            let mut mitigated = self.mitigated.lock().unwrap();
            if mitigated.last_sweep.elapsed() >= timeout {
                mitigated.since.retain(|_, since| since.elapsed() < timeout);
                mitigated.last_sweep = Instant::now();
            }
            mitigated
                .since
                .entry(key.clone())
                .or_insert_with(Instant::now);
        }
        exceeded
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// The counters for `rule`, created on first use and recreated when its
    /// period changed.
    fn counters(&self, rule: &str, period: Duration) -> Arc<RuleCounters> {
        if let Some(counters) = self.rules.read().unwrap().get(rule)
            && counters.period == period
        {
            return Arc::clone(counters);
        }
        let mut rules = self.rules.write().unwrap();
        let counters = rules
            .entry(rule.to_string())
            .and_modify(|c| {
                if c.period != period {
                    *c = Arc::new(RuleCounters::new(period));
                }
            })
            .or_insert_with(|| Arc::new(RuleCounters::new(period)));
        Arc::clone(counters)
    }
}

impl RateLimitStore for MemoryStore {
    fn check_and_incr(&self, rule: &str, key: &RateLimitKey, limits: &Limits) -> bool {
        self.counters(rule, limits.period)
            .check_and_incr(key, limits)
    }
}

/// The limits of every rate-limited rule and the store that counts for them.
pub struct RateLimitManager {
    limits: HashMap<String, Limits>,
    store: Arc<dyn RateLimitStore>,
}

impl Default for RateLimitManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimitManager {
    /// A manager counting in this process only.
    pub fn new() -> Self {
        Self::with_store(Arc::new(MemoryStore::new()))
    }

    pub fn with_store(store: Arc<dyn RateLimitStore>) -> Self {
        Self {
            limits: HashMap::new(),
            store,
        }
    }

    /// Register (or update) a rule's limits. Counts already in the store are
    /// kept, so a reload does not reset them.
    pub fn add_rule(&mut self, rule_id: &str, config: &RateLimitConfig) {
        self.limits
            .insert(rule_id.to_string(), Limits::from(config));
    }

    /// Count a request for `rule_id` and report whether its limit is
    /// exceeded. Rules without limits are never exceeded.
    pub fn check(&self, rule_id: &str, key: &RateLimitKey) -> bool {
        self.limits
            .get(rule_id)
            .is_some_and(|limits| self.store.check_and_incr(rule_id, key, limits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> RateLimitKey {
        let mut key = RateLimitKey::new();
        key.push(s.to_string());
        key
    }

    fn limits(requests_per_period: u64, mitigation_timeout: Duration) -> Limits {
        Limits {
            period: Duration::from_secs(60),
            requests_per_period,
            mitigation_timeout,
        }
    }

    #[test]
    fn limit_is_per_key_and_per_rule() {
        let store = MemoryStore::new();
        let l = limits(2, Duration::ZERO);
        assert!(!store.check_and_incr("r", &key("a"), &l));
        assert!(!store.check_and_incr("r", &key("a"), &l));
        assert!(
            store.check_and_incr("r", &key("a"), &l),
            "third request exceeds"
        );
        assert!(
            !store.check_and_incr("r", &key("b"), &l),
            "other key counts separately"
        );
        assert!(
            !store.check_and_incr("other", &key("a"), &l),
            "other rule counts separately"
        );
    }

    #[test]
    fn without_mitigation_each_request_is_re_evaluated() {
        let store = MemoryStore::new();
        let l = limits(0, Duration::ZERO);
        assert!(store.check_and_incr("r", &key("a"), &l));
        // Nothing is remembered about the key.
        let counters = store.counters("r", l.period);
        assert!(counters.mitigated.lock().unwrap().since.is_empty());
    }

    #[test]
    fn mitigation_blocks_until_the_timeout_passes() {
        let store = MemoryStore::new();
        let l = limits(1, Duration::from_millis(60));
        assert!(!store.check_and_incr("r", &key("a"), &l));
        assert!(store.check_and_incr("r", &key("a"), &l));
        // Blocked by the mitigation, even though the window has not refilled.
        assert!(store.check_and_incr("r", &key("a"), &l));
        std::thread::sleep(Duration::from_millis(70));
        // Mitigation over: re-evaluated against the (still exceeded) count.
        let counters = store.counters("r", l.period);
        store.check_and_incr("r", &key("a"), &l);
        assert_eq!(counters.mitigated.lock().unwrap().since.len(), 1);
    }

    #[test]
    fn expired_mitigations_are_swept() {
        let store = MemoryStore::new();
        let l = limits(0, Duration::from_millis(20));
        for i in 0..50 {
            store.check_and_incr("r", &key(&i.to_string()), &l);
        }
        let counters = store.counters("r", l.period);
        assert_eq!(counters.mitigated.lock().unwrap().since.len(), 50);
        std::thread::sleep(Duration::from_millis(30));
        // The next block after a timeout sweeps the expired entries.
        store.check_and_incr("r", &key("fresh"), &l);
        assert_eq!(counters.mitigated.lock().unwrap().since.len(), 1);
    }

    #[test]
    fn changing_the_period_resets_the_rule_counters() {
        let store = MemoryStore::new();
        let l = limits(1, Duration::ZERO);
        assert!(!store.check_and_incr("r", &key("a"), &l));
        assert!(store.check_and_incr("r", &key("a"), &l));
        let longer = Limits {
            period: Duration::from_secs(120),
            ..l
        };
        assert!(
            !store.check_and_incr("r", &key("a"), &longer),
            "fresh counters"
        );
    }

    #[test]
    fn manager_keeps_store_across_reconfiguration() {
        let store = Arc::new(MemoryStore::new());
        let config = RateLimitConfig {
            characteristics: vec![],
            period: 60,
            requests_per_period: 1,
            mitigation_timeout: 0,
        };
        let mut mgr = RateLimitManager::with_store(store.clone());
        mgr.add_rule("r", &config);
        assert!(!mgr.check("r", &key("a")));
        assert!(
            !mgr.check("unknown", &key("a")),
            "rules without limits never exceed"
        );

        // A reload builds a new manager over the same store: counts survive.
        let mut reloaded = RateLimitManager::with_store(store);
        reloaded.add_rule("r", &config);
        assert!(reloaded.check("r", &key("a")));
    }

    #[test]
    fn key_display_joins_parts() {
        let mut k = RateLimitKey::new();
        k.push("10.0.0.1".into());
        k.push("/api".into());
        assert_eq!(k.to_string(), "10.0.0.1:/api");
    }
}
