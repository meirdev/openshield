mod bytes;
mod ip;

use log::info;
use wirefilter_engine::{ExecutionContext, Scheme, Type};

pub use self::bytes::{BytesListDefinition, BytesListMatcher, BytesListMode};
pub use self::ip::{IpListDefinition, IpListMatcher};
use crate::config::{ListConfig, ListKind};

pub fn build_from_config(
    lists: &[ListConfig],
) -> Result<(IpListMatcher, BytesListMatcher), Box<dyn std::error::Error>> {
    let mut ip_lists = IpListMatcher::new();
    let mut bytes_lists = BytesListMatcher::new();
    for list_cfg in lists {
        let refs: Vec<&str> = list_cfg.items.iter().map(|s| s.as_str()).collect();
        let mode = match list_cfg.kind {
            ListKind::Ip => {
                ip_lists.add_list(&list_cfg.name, &refs);
                info!("IP list '{}': {} entries", list_cfg.name, refs.len());
                continue;
            }
            ListKind::String => BytesListMode::Exact,
            ListKind::Substring => BytesListMode::Substring,
        };
        bytes_lists.add_list(&list_cfg.name, mode, &refs)?;
        info!(
            "String list '{}' ({:?}): {} entries",
            list_cfg.name,
            mode,
            refs.len()
        );
    }
    Ok((ip_lists, bytes_lists))
}

/// Make the configured lists available to `ctx`. Both matchers share their
/// data behind an `Arc`, so this is cheap enough to do per request.
pub fn install(
    ctx: &mut ExecutionContext<'_>,
    scheme: &Scheme,
    ip_lists: &IpListMatcher,
    bytes_lists: &BytesListMatcher,
) {
    if let Some(list_ref) = scheme.get_list(&Type::Ip) {
        *ctx.get_list_matcher_mut(list_ref)
            .as_any_mut()
            .downcast_mut::<IpListMatcher>()
            .unwrap() = ip_lists.clone();
    }
    if let Some(list_ref) = scheme.get_list(&Type::Bytes) {
        *ctx.get_list_matcher_mut(list_ref)
            .as_any_mut()
            .downcast_mut::<BytesListMatcher>()
            .unwrap() = bytes_lists.clone();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::waf::scheme;

    fn list(name: &str, kind: ListKind, items: &[&str]) -> ListConfig {
        ListConfig {
            name: name.into(),
            kind,
            items: items.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Compiles `expr` against the real scheme, installs the configured
    /// lists the way the proxy does per request, sets `http.user_agent`, and
    /// returns the filter result.
    fn eval(lists: &[ListConfig], ua: &str, expr: &str) -> bool {
        let (ip_lists, bytes_lists) = build_from_config(lists).unwrap();
        let sch = scheme::build(&[], &[]);
        let mut ctx = scheme::new_context(&sch);
        install(&mut ctx, &sch, &ip_lists, &bytes_lists);
        let field = sch.get_field("http.user_agent").unwrap();
        ctx.set_field_value(field, ua).unwrap();
        sch.parse(expr).unwrap().compile().execute(&ctx).unwrap()
    }

    #[test]
    fn string_kind_is_exact_and_substring_kind_is_contains() {
        let lists = [
            list("exact_ua", ListKind::String, &["sqlmap", "nikto"]),
            list("scanner_ua", ListKind::Substring, &["sqlmap", "nikto"]),
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
}
