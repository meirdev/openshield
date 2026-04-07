use std::sync::{Arc, RwLock};

use log::{error, info, warn};
use wirefilter_engine::Scheme;

use crate::config::Config;
use crate::geoip::GeoIp;
use crate::waf::engine::Engine;
use crate::waf::lists::{BytesListMatcher, IpListMatcher};
use crate::waf::ratelimit::RateLimitManager;

/// Listen for SIGHUP and reload config, rules, lists, and GeoIP databases.
pub fn start_reload_listener(
    config_path: std::path::PathBuf,
    scheme: Arc<Scheme>,
    engine: Arc<RwLock<Engine>>,
    ip_lists: Arc<RwLock<IpListMatcher>>,
    bytes_lists: Arc<RwLock<BytesListMatcher>>,
    geoip: Arc<RwLock<Option<GeoIp>>>,
) {
    std::thread::spawn(move || {
        use signal_hook::iterator::Signals;
        let mut signals =
            Signals::new([signal_hook::consts::SIGHUP]).expect("Failed to register SIGHUP handler");

        info!("Send SIGHUP to reload config");

        for _ in signals.forever() {
            info!("SIGHUP received, reloading...");
            match Config::load(&config_path) {
                Ok(new_config) => {
                    // Reload rules (preserve rate limit counters)
                    let existing_mgr = {
                        let mut eng = engine.write().unwrap();
                        Some(std::mem::replace(
                            &mut eng.ratelimit_mgr,
                            RateLimitManager::new(),
                        ))
                    };
                    match crate::compiler::compile(&new_config, &scheme, existing_mgr) {
                        Ok(new_engine) => {
                            let mut eng = engine.write().unwrap();
                            *eng = new_engine;
                            info!("Rules reloaded: {} rules", eng.rule_count());
                        }
                        Err(e) => error!("Failed to compile rules: {}", e),
                    }

                    // Reload lists
                    let (new_ip, new_bytes) =
                        crate::waf::lists::build_from_config(&new_config.lists);
                    *ip_lists.write().unwrap() = new_ip;
                    *bytes_lists.write().unwrap() = new_bytes;
                    info!("Lists reloaded");

                    // Reload GeoIP databases
                    if let Some(ref geo_cfg) = new_config.geoip {
                        match GeoIp::open(&geo_cfg.city_mmdb, &geo_cfg.asn_mmdb) {
                            Ok(new_geoip) => {
                                *geoip.write().unwrap() = Some(new_geoip);
                                info!("GeoIP databases reloaded");
                            }
                            Err(e) => warn!("Failed to reload GeoIP databases: {}", e),
                        }
                    } else {
                        *geoip.write().unwrap() = None;
                    }
                }
                Err(e) => error!("Failed to load config: {}", e),
            }
        }
    });
}
