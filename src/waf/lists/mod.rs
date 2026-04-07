mod bytes;
mod ip;

use log::{info, warn};

pub use self::bytes::{BytesListDefinition, BytesListMatcher};
pub use self::ip::{IpListDefinition, IpListMatcher};
use crate::config::ListConfig;

pub fn build_from_config(lists: &[ListConfig]) -> (IpListMatcher, BytesListMatcher) {
    let mut ip_lists = IpListMatcher::new();
    let mut bytes_lists = BytesListMatcher::new();
    for list_cfg in lists {
        let refs: Vec<&str> = list_cfg.items.iter().map(|s| s.as_str()).collect();
        match list_cfg.kind.as_str() {
            "ip" => {
                ip_lists.add_list(&list_cfg.name, &refs);
                info!(
                    "IP list '{}': {} entries",
                    list_cfg.name,
                    list_cfg.items.len()
                );
            }
            "bytes" | "string" => {
                bytes_lists.add_list(&list_cfg.name, &refs);
                info!(
                    "String list '{}': {} entries",
                    list_cfg.name,
                    list_cfg.items.len()
                );
            }
            other => {
                warn!("Unknown list kind '{}' for list '{}'", other, list_cfg.name);
            }
        }
    }
    (ip_lists, bytes_lists)
}
