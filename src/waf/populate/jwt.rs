use serde_json::Value;
use wirefilter_engine::{ExecutionContext, Scheme, TypedArray, TypedMap};

use super::{owned_array, set_field};
use crate::waf::functions::{PRESENT_FIELD, VALID_FIELD};
use crate::waf::jwt::TokenOutcome;
use crate::waf::scheme::{JWT_STRING_CLAIMS, JWT_TIME_CLAIMS};

/// A string claim, or the strings of an array claim (`aud` may be either).
fn strings(claim: &Value) -> Vec<String> {
    match claim {
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}

/// A NumericDate claim in whole seconds.
fn seconds(claim: &Value) -> Vec<i64> {
    claim
        .as_i64()
        .or_else(|| claim.as_f64().map(|f| f as i64))
        .into_iter()
        .collect()
}

/// Each valid token's values for `claim`, by token configuration ID.
/// Configurations whose token lacks the claim are left out.
fn collect<'a, T>(
    outcomes: &'a [TokenOutcome<'_>],
    claim: &str,
    values: fn(&Value) -> Vec<T>,
) -> Vec<(&'a str, Vec<T>)> {
    outcomes
        .iter()
        .filter_map(|o| Some((o.id, values(o.claims.as_ref()?.get(claim)?))))
        .filter(|(_, values)| !values.is_empty())
        .collect()
}

fn ids<T>(entries: &[(&str, Vec<T>)]) -> Vec<String> {
    entries.iter().map(|(id, _)| id.to_string()).collect()
}

fn key(id: &str) -> Box<[u8]> {
    id.as_bytes().into()
}

pub fn jwt_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    outcomes: &[TokenOutcome<'_>],
) {
    let ids_where = |keep: fn(&TokenOutcome<'_>) -> bool| {
        outcomes
            .iter()
            .filter(|o| keep(o))
            .map(|o| o.id.to_string())
            .collect::<Vec<_>>()
    };
    set_field!(ctx, scheme, PRESENT_FIELD, Arr, ids_where(|o| o.present));
    set_field!(
        ctx,
        scheme,
        VALID_FIELD,
        Arr,
        ids_where(|o| o.claims.is_some())
    );

    for claim in JWT_STRING_CLAIMS {
        let entries = collect(outcomes, claim, strings);
        if entries.is_empty() {
            continue;
        }
        let name = format!("http.request.jwt.claims.{claim}");
        set_field!(ctx, scheme, &format!("{name}.names"), Arr, ids(&entries));
        set_field!(
            ctx,
            scheme,
            &format!("{name}.values"),
            Arr,
            entries.iter().flat_map(|(_, values)| values.clone())
        );
        let mut map = TypedMap::new();
        for (id, values) in entries {
            map.insert(key(id), owned_array(values));
        }
        set_field!(ctx, scheme, &name, map);
    }

    for claim in JWT_TIME_CLAIMS {
        let entries = collect(outcomes, claim, seconds);
        if entries.is_empty() {
            continue;
        }
        let name = format!("http.request.jwt.claims.{claim}.sec");
        set_field!(ctx, scheme, &format!("{name}.names"), Arr, ids(&entries));
        set_field!(
            ctx,
            scheme,
            &format!("{name}.values"),
            TypedArray::from_iter(
                entries
                    .iter()
                    .flat_map(|(_, values)| values.iter().copied())
            )
        );
        let mut map = TypedMap::new();
        for (id, values) in entries {
            map.insert(key(id), TypedArray::<i64>::from_iter(values));
        }
        set_field!(ctx, scheme, &name, map);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use wirefilter_engine::{ExecutionContext, Scheme};

    use super::jwt_fields;
    use crate::waf::functions::RuleCompiler;
    use crate::waf::jwt::TokenOutcome;

    fn valid<'a>(id: &'a str, claims: Value) -> TokenOutcome<'a> {
        let Value::Object(claims) = claims else {
            panic!("claims must be an object");
        };
        TokenOutcome {
            id,
            present: true,
            claims: Some(claims),
        }
    }

    fn populate(outcomes: &[TokenOutcome<'_>]) -> (Scheme, ExecutionContext<'static>) {
        let ids: Vec<String> = outcomes.iter().map(|o| o.id.to_string()).collect();
        let scheme = crate::waf::scheme::build(&[], &ids);
        let mut ctx = crate::waf::scheme::new_context(&scheme);
        jwt_fields(&mut ctx, &scheme, outcomes);
        (scheme, ctx)
    }

    fn check(scheme: &Scheme, ctx: &ExecutionContext<'static>, expr: &str) -> bool {
        scheme
            .parse(expr)
            .unwrap_or_else(|e| panic!("{expr}: {e}"))
            .compile_with_compiler(&mut RuleCompiler::new(scheme))
            .execute(ctx)
            .expect("filter should execute")
    }

    #[test]
    fn string_claims_are_keyed_by_token_configuration() {
        let (scheme, ctx) = populate(&[
            valid(
                "api",
                json!({"iss": "https://a.example", "sub": "alice", "jti": "1", "aud": "svc"}),
            ),
            valid("partner", json!({"iss": "https://b.example"})),
        ]);

        for expr in [
            r#"http.request.jwt.claims.iss["api"][0] == "https://a.example""#,
            r#"http.request.jwt.claims.iss["partner"][0] == "https://b.example""#,
            r#"http.request.jwt.claims.sub["api"][0] == "alice""#,
            r#"http.request.jwt.claims.jti["api"][0] == "1""#,
            r#"http.request.jwt.claims.aud["api"][0] == "svc""#,
            r#"any(http.request.jwt.claims.iss.names[*] == "partner")"#,
            r#"any(http.request.jwt.claims.iss.values[*] == "https://b.example")"#,
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }

        // `partner`'s token has no `sub`.
        assert!(!check(
            &scheme,
            &ctx,
            r#"any(http.request.jwt.claims.sub.names[*] == "partner")"#
        ));
        assert!(!check(
            &scheme,
            &ctx,
            r#"http.request.jwt.claims.sub["partner"][0] == "alice""#
        ));
    }

    #[test]
    fn audience_may_be_an_array() {
        let (scheme, ctx) = populate(&[valid("api", json!({"aud": ["svc-a", "svc-b", 7]}))]);
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.jwt.claims.aud["api"][*] == "svc-b")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"all(http.request.jwt.claims.aud.values[*] in {"svc-a" "svc-b"})"#
        ));
    }

    #[test]
    fn time_claims_are_integers() {
        let (scheme, ctx) = populate(&[valid(
            "api",
            json!({"iat": 1_700_000_000, "nbf": 1_700_000_060.9}),
        )]);
        for expr in [
            r#"http.request.jwt.claims.iat.sec["api"][0] == 1700000000"#,
            r#"http.request.jwt.claims.nbf.sec["api"][0] == 1700000060"#,
            r#"any(http.request.jwt.claims.iat.sec.values[*] > 1600000000)"#,
            r#"any(http.request.jwt.claims.iat.sec.names[*] == "api")"#,
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }
    }

    #[test]
    fn claims_of_the_wrong_type_are_skipped() {
        let (scheme, ctx) = populate(&[valid("api", json!({"sub": 42, "iat": "now"}))]);
        assert!(!check(
            &scheme,
            &ctx,
            r#"any(http.request.jwt.claims.sub.names[*] == "api")"#
        ));
        assert!(!check(
            &scheme,
            &ctx,
            r#"any(http.request.jwt.claims.iat.sec.names[*] == "api")"#
        ));
    }

    #[test]
    fn only_valid_tokens_expose_claims() {
        let (scheme, ctx) = populate(&[
            TokenOutcome {
                id: "api",
                present: true,
                claims: None,
            },
            TokenOutcome {
                id: "partner",
                present: false,
                claims: None,
            },
        ]);
        assert!(check(&scheme, &ctx, r#"is_jwt_present("api")"#));
        assert!(!check(&scheme, &ctx, r#"is_jwt_valid("api")"#));
        assert!(!check(&scheme, &ctx, r#"is_jwt_present("partner")"#));
        assert!(!check(
            &scheme,
            &ctx,
            r#"any(http.request.jwt.claims.sub.names[*] == "api")"#
        ));
    }
}
