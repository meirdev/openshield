use wirefilter_engine::{ExecutionContext, LhsValue, Scheme};

use super::{dedup, set_field};
use crate::waf::openapi::{Location, Violation};
use crate::waf::schema::SchemaOutcome;

pub const PREFIX: &str = "schema_validation";

/// Request components in field-name form.
pub const LOCATIONS: [(Location, &str); 5] = [
    (Location::Path, "path"),
    (Location::Query, "query"),
    (Location::Header, "headers"),
    (Location::Cookie, "cookies"),
    (Location::Body, "body"),
];

fn segment(location: Location) -> &'static str {
    LOCATIONS
        .iter()
        .find(|(l, _)| *l == location)
        .map(|(_, s)| *s)
        .unwrap()
}

fn violated_parameters(violations: &[Violation], location: Location) -> Vec<String> {
    dedup(
        violations
            .iter()
            .filter(|v| v.location == location)
            .map(|v| v.target.clone())
            .collect(),
    )
}

fn violation_details(ctx: &mut ExecutionContext<'static>, scheme: &Scheme, first: &Violation) {
    let name = |field: &str| format!("{PREFIX}.violation_details.{field}");
    set_field!(ctx, scheme, &name("location"), Str, first.location.as_str());
    set_field!(ctx, scheme, &name("error_class"), Str, first.class.as_str());
    set_field!(ctx, scheme, &name("target"), Str, &first.target);
    if let Some(detail) = &first.detail {
        set_field!(ctx, scheme, &name("error_detail"), Str, detail);
    }
}

/// Fields from the request-headers step: which schema and operation apply,
/// and the parameter violations.
pub fn schema_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    outcome: &SchemaOutcome<'_>,
) {
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.schema"),
        Str,
        outcome.schema
    );
    let Ok(template) = outcome.operation else {
        set_field!(
            ctx,
            scheme,
            &format!("{PREFIX}.operation.matched"),
            Bool,
            false
        );
        set_field!(ctx, scheme, &format!("{PREFIX}.violated"), Bool, false);
        for (_, segment) in LOCATIONS {
            set_field!(
                ctx,
                scheme,
                &format!("{PREFIX}.{segment}.violated_parameters"),
                Arr,
                Vec::new()
            );
        }
        set_field!(
            ctx,
            scheme,
            &format!("{PREFIX}.query.undeclared_parameters"),
            Arr,
            Vec::new()
        );
        return;
    };
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.operation.matched"),
        Bool,
        true
    );
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.operation.template"),
        Str,
        template
    );
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.query.undeclared_parameters"),
        Arr,
        outcome.undeclared_query_parameters.clone()
    );

    let violations = &outcome.violations;
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.violated"),
        Bool,
        !violations.is_empty()
    );
    for (location, segment) in LOCATIONS {
        if location == Location::Body {
            continue;
        }
        set_field!(
            ctx,
            scheme,
            &format!("{PREFIX}.{segment}.violated_parameters"),
            Arr,
            violated_parameters(violations, location)
        );
    }
    if let Some(first) = violations.first() {
        violation_details(ctx, scheme, first);
    }
}

/// Fields from the request-body step. `violated` and the details already
/// reflect the parameters; the body only adds to them.
pub fn schema_body_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    violations: &[Violation],
) {
    set_field!(
        ctx,
        scheme,
        &format!("{PREFIX}.{}.violated_parameters", segment(Location::Body)),
        Arr,
        violated_parameters(violations, Location::Body)
    );
    let Some(first) = violations.first() else {
        return;
    };
    let violated = scheme.get_field(&format!("{PREFIX}.violated")).ok();
    let already = violated
        .as_ref()
        .is_some_and(|f| matches!(ctx.get_field_value(*f), Some(LhsValue::Bool(true))));
    set_field!(ctx, scheme, &format!("{PREFIX}.violated"), Bool, true);
    if !already {
        violation_details(ctx, scheme, first);
    }
}

#[cfg(test)]
mod tests {
    use wirefilter_engine::{ExecutionContext, Scheme};

    use super::{schema_body_fields, schema_fields};
    use crate::waf::populate::test_support::{check, context, empty_request, scheme};
    use crate::waf::schema::SchemaValidator;
    use crate::waf::schema::test_support::petstore;

    fn validator() -> SchemaValidator {
        SchemaValidator::from_specs(vec![("pets", &[], petstore())])
    }

    /// Populate the header-step fields for `method path?query` and, with a
    /// body, the body-step fields too.
    fn populate(
        method: &str,
        path: &str,
        query: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> (Scheme, ExecutionContext<'static>) {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        let v = validator();
        let mut req = empty_request();
        req.host = "api.example.com".into();
        req.method = method.into();
        req.path = path.into();
        req.query = query.into();
        req.headers = headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (request, outcome) = v.check_request(&req).unwrap();
        schema_fields(&mut ctx, &scheme, &outcome);
        if let (Some(request), Some(body)) = (request, body) {
            let violations = v.check_body(&request, Some("application/json"), body, false);
            schema_body_fields(&mut ctx, &scheme, &violations);
        }
        (scheme, ctx)
    }

    #[test]
    fn valid_request_sets_operation_and_no_violations() {
        let (scheme, ctx) = populate("GET", "/v1/pets/7", "", &[], None);
        for expr in [
            r#"schema_validation.schema == "pets""#,
            "schema_validation.operation.matched",
            r#"schema_validation.operation.template == "/pets/{id}""#,
            "not schema_validation.violated",
            "len(schema_validation.query.violated_parameters) == 0",
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }
    }

    #[test]
    fn unmatched_operation_is_not_a_violation() {
        let (scheme, ctx) = populate("GET", "/v1/owners", "", &[], None);
        assert!(check(
            &scheme,
            &ctx,
            "not schema_validation.operation.matched"
        ));
        assert!(check(&scheme, &ctx, "not schema_validation.violated"));
        for expr in [
            "len(schema_validation.query.violated_parameters) == 0",
            "len(schema_validation.body.violated_parameters) == 0",
            "len(schema_validation.query.undeclared_parameters) == 0",
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }
    }

    #[test]
    fn parameter_violations_and_details() {
        let (scheme, ctx) = populate("GET", "/v1/pets", "limit=500&page=1", &[], None);
        for expr in [
            "schema_validation.violated",
            r#"any(schema_validation.query.violated_parameters[*] == "limit")"#,
            r#"any(schema_validation.headers.violated_parameters[*] == "X-Tenant")"#,
            r#"any(schema_validation.query.undeclared_parameters[*] == "page")"#,
            r#"schema_validation.violation_details.location == "query""#,
            r#"schema_validation.violation_details.error_class == "constraint_violation""#,
            r#"schema_validation.violation_details.error_detail == "maximum""#,
            r#"schema_validation.violation_details.target == "limit""#,
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }
    }

    #[test]
    fn body_violations_add_to_the_header_step() {
        let (scheme, ctx) = populate("POST", "/v1/pets", "", &[], Some(br#"{"age": "x"}"#));
        for expr in [
            "schema_validation.violated",
            r#"any(schema_validation.body.violated_parameters[*] == "/name")"#,
            r#"any(schema_validation.body.violated_parameters[*] == "/age")"#,
            r#"schema_validation.violation_details.location == "body""#,
            r#"schema_validation.violation_details.error_class == "missing_required""#,
            r#"schema_validation.violation_details.target == "/name""#,
        ] {
            assert!(check(&scheme, &ctx, expr), "{expr}");
        }

        // Parameter violations come first, and the body does not replace them.
        let (scheme, ctx) = populate("POST", "/v1/pets", "dry_run=maybe", &[], Some(b"{}"));
        assert!(check(
            &scheme,
            &ctx,
            r#"schema_validation.violation_details.location == "query""#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(schema_validation.body.violated_parameters[*] == "/name")"#
        ));
    }
}
