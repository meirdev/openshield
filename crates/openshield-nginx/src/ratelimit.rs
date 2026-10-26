//! Rate-limit counters in nginx shared memory, so every worker process sees
//! the same counts.
//!
//! One zone, `openshield_ratelimit`, holds a tree of per-key counters behind
//! nginx's cross-process rwlock. Each counter is a sliding window like the
//! in-process store's: the previous and current period's counts, weighted by
//! how far into the current period the request falls. nginx reuses a zone of
//! the same name and size across `nginx -s reload`, so counts survive it.

use core::ffi::c_void;

use ngx::allocator::AllocError;
use ngx::collections::RbTreeMap;
use ngx::core::{SlabPool, Status};
use ngx::ffi::{NGX_LOG_WARN, ngx_cycle, ngx_int_t, ngx_shm_zone_t, ngx_timeofday};
use ngx::ngx_log_error;
use ngx::sync::RwLock;
use openshield_core::waf::ratelimit::{Limits, RateLimitKey, RateLimitStore};

/// Two independent 64-bit hashes of `rule` and `key`: fixed-size, so keys
/// need no shared-memory allocation of their own.
type Key = [u64; 2];

#[derive(Clone, Copy)]
struct Counter {
    period_ms: u64,
    window_start_ms: u64,
    prev: u64,
    cur: u64,
    mitigated_until_ms: u64,
    last_seen_ms: u64,
}

struct Shared {
    counters: RbTreeMap<Key, Counter, SlabPool>,
    ops_since_sweep: u32,
}

/// Sweep stale counters this often, besides when the zone is full.
const SWEEP_EVERY: u32 = 256;

/// Counts in the shared zone. Resolves the zone's memory on each use, since
/// the zone is set up after the module's configuration is built.
pub struct SharedStore {
    zone: *mut ngx_shm_zone_t,
}

// The pointer is to nginx's zone descriptor, valid for the cycle's life;
// the data behind it is guarded by the lock inside the zone.
unsafe impl Send for SharedStore {}
unsafe impl Sync for SharedStore {}

impl SharedStore {
    pub fn new(zone: *mut ngx_shm_zone_t) -> Self {
        Self { zone }
    }

    fn shared(&self) -> Option<&RwLock<Shared>> {
        let data = unsafe { (*self.zone).data } as *const RwLock<Shared>;
        unsafe { data.as_ref() }
    }
}

/// The zone's init callback: build the tree in the zone's slab pool, or keep
/// the one from the previous cycle on reload.
pub unsafe extern "C" fn zone_init(zone: *mut ngx_shm_zone_t, data: *mut c_void) -> ngx_int_t {
    if !data.is_null() {
        unsafe { (*zone).data = data };
        return Status::NGX_OK.into();
    }
    let Some(alloc) = (unsafe { SlabPool::from_shm_zone(&*zone) }) else {
        return Status::NGX_ERROR.into();
    };
    let Ok(counters) = RbTreeMap::try_new_in(alloc.clone()) else {
        return Status::NGX_ERROR.into();
    };
    let shared = RwLock::new(Shared {
        counters,
        ops_since_sweep: 0,
    });
    match ngx::allocator::allocate(shared, &alloc) {
        Ok(ptr) => {
            unsafe { (*zone).data = ptr.as_ptr() as *mut c_void };
            Status::NGX_OK.into()
        }
        Err(_) => Status::NGX_ERROR.into(),
    }
}

fn now_ms() -> u64 {
    let t = ngx_timeofday();
    t.sec as u64 * 1000 + t.msec as u64
}

fn hash_key(rule: &str, key: &RateLimitKey, seed: u64) -> u64 {
    // FNV-1a; deterministic across processes, unlike the std hasher.
    let mut h = seed;
    for b in rule
        .as_bytes()
        .iter()
        .chain(b"\0")
        .chain(key.to_string().as_bytes())
    {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

impl Counter {
    fn new(now: u64, period_ms: u64) -> Self {
        Self {
            period_ms,
            window_start_ms: now,
            prev: 0,
            cur: 0,
            mitigated_until_ms: 0,
            last_seen_ms: now,
        }
    }

    /// Count one request at `now` and report whether the limit is exceeded.
    fn observe(&mut self, now: u64, limits: &Limits) -> bool {
        let period = (limits.period.as_millis() as u64).max(1);
        if self.period_ms != period {
            *self = Self::new(now, period);
        }
        // Roll the window forward past elapsed periods.
        let elapsed = now.saturating_sub(self.window_start_ms);
        if elapsed >= period {
            let shifts = elapsed / period;
            self.prev = if shifts == 1 { self.cur } else { 0 };
            self.cur = 0;
            self.window_start_ms += shifts * period;
        }
        self.last_seen_ms = now;

        let timeout = limits.mitigation_timeout.as_millis() as u64;
        if timeout > 0 && now < self.mitigated_until_ms {
            // Still blocked: the request counts but is not re-evaluated.
            self.cur += 1;
            return true;
        }

        self.cur += 1;
        let into_window = now.saturating_sub(self.window_start_ms) as f64 / period as f64;
        let estimate = self.prev as f64 * (1.0 - into_window) + self.cur as f64;
        let exceeded = estimate > limits.requests_per_period as f64;
        if exceeded && timeout > 0 {
            self.mitigated_until_ms = now + timeout;
        }
        exceeded
    }

    /// Nothing in the window and no mitigation left: safe to drop.
    fn stale(&self, now: u64) -> bool {
        now >= self.mitigated_until_ms && now.saturating_sub(self.last_seen_ms) > 2 * self.period_ms
    }
}

impl Shared {
    fn sweep(&mut self, now: u64) {
        let stale: Vec<Key> = self
            .counters
            .iter()
            .filter(|(_, c)| c.stale(now))
            .map(|(k, _)| *k)
            .collect();
        for key in stale {
            self.counters.remove(&key);
        }
        self.ops_since_sweep = 0;
    }

    fn observe(&mut self, key: Key, now: u64, limits: &Limits) -> Result<bool, AllocError> {
        self.ops_since_sweep += 1;
        if self.ops_since_sweep >= SWEEP_EVERY {
            self.sweep(now);
        }
        if let Some(counter) = self.counters.get_mut(&key) {
            return Ok(counter.observe(now, limits));
        }
        let period = (limits.period.as_millis() as u64).max(1);
        let mut counter = Counter::new(now, period);
        let exceeded = counter.observe(now, limits);
        if self.counters.try_insert(key, counter).is_err() {
            // Zone full: make room from counters that no longer matter.
            self.sweep(now);
            self.counters.try_insert(key, counter)?;
        }
        Ok(exceeded)
    }
}

impl RateLimitStore for SharedStore {
    fn check_and_incr(&self, rule: &str, key: &RateLimitKey, limits: &Limits) -> bool {
        let Some(shared) = self.shared() else {
            return false;
        };
        let now = now_ms();
        let hashed = [
            hash_key(rule, key, 0xcbf29ce484222325),
            hash_key(rule, key, 0x84222325cbf29ce4),
        ];
        match shared.write().observe(hashed, now, limits) {
            Ok(exceeded) => exceeded,
            Err(_) => {
                let log = unsafe { (*ngx_cycle).log };
                if !log.is_null() {
                    ngx_log_error!(
                        NGX_LOG_WARN,
                        log,
                        "openshield: rate-limit zone is full; raise openshield_ratelimit_zone (request for rule {rule} not limited)"
                    );
                }
                false
            }
        }
    }
}
