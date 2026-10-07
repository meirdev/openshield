mod bytes;
mod ip;

use log::{info, warn};

pub use self::bytes::{BytesListDefinition, BytesListMatcher, BytesListMode};
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
                bytes_lists.add_list(&list_cfg.name, BytesListMode::Exact, &refs);
                info!(
                    "String list '{}' (exact): {} entries",
                    list_cfg.name,
                    list_cfg.items.len()
                );
            }
            "substring" => {
                bytes_lists.add_list(&list_cfg.name, BytesListMode::Substring, &refs);
                info!(
                    "String list '{}' (substring): {} entries",
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

#[cfg(test)]
mod tests {
    use wirefilter_engine::Type;

    use super::*;
    use crate::waf::scheme;

    fn list(name: &str, kind: &str, items: &[&str]) -> ListConfig {
        ListConfig {
            name: name.into(),
            kind: kind.into(),
            items: items.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Compiles `expr` against the real scheme, injects the configured lists
    /// the same way the proxy does per request, sets `http.user_agent`, and
    /// returns the filter result.
    fn eval(lists: &[ListConfig], ua: &str, expr: &str) -> bool {
        let (ip_lists, bytes_lists) = build_from_config(lists);
        let sch = scheme::build(&[], &[]);
        let mut ctx = scheme::new_context(&sch);
        if let Some(list_ref) = sch.get_list(&Type::Ip) {
            *ctx.get_list_matcher_mut(list_ref)
                .as_any_mut()
                .downcast_mut::<IpListMatcher>()
                .unwrap() = ip_lists.clone();
        }
        if let Some(list_ref) = sch.get_list(&Type::Bytes) {
            *ctx.get_list_matcher_mut(list_ref)
                .as_any_mut()
                .downcast_mut::<BytesListMatcher>()
                .unwrap() = bytes_lists.clone();
        }
        let field = sch.get_field("http.user_agent").unwrap();
        ctx.set_field_value(field, ua).unwrap();
        sch.parse(expr).unwrap().compile().execute(&ctx).unwrap()
    }

    #[test]
    fn string_kind_is_exact_and_substring_kind_is_contains() {
        let lists = [
            list("exact_ua", "string", &["sqlmap", "nikto"]),
            list("scanner_ua", "substring", &["sqlmap", "nikto"]),
        ];
        assert!(eval(&lists, "sqlmap", "http.user_agent in $exact_ua"));
        assert!(!eval(&lists, "sqlmap/1.7", "http.user_agent in $exact_ua"));
        assert!(eval(&lists, "sqlmap/1.7", "http.user_agent in $scanner_ua"));
        assert!(eval(
            &lists,
            "Mozilla (nikto)",
            "http.user_agent in $scanner_ua"
        ));
        assert!(!eval(&lists, "curl/8.0", "http.user_agent in $scanner_ua"));
        assert!(!eval(&lists, "curl/8.0", "http.user_agent in $exact_ua"));
    }

    #[test]
    fn unknown_kind_is_skipped() {
        let lists = [list("weird", "nope", &["x"])];
        assert!(!eval(&lists, "x", "http.user_agent in $weird"));
    }
}
