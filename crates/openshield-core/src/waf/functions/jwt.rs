use std::sync::Arc;

use wirefilter_engine::{
    BytesExpr, CompiledValueExpr, Compiler, ExecutionContext, Field, Function, FunctionArgs,
    FunctionCallArgExpr, FunctionCallExpr, FunctionDefinition, FunctionDefinitionContext,
    FunctionParam, FunctionParamError, LhsValue, LiteralValue, ParserSettings, Scheme, Type,
    ValueExpr, Visitor,
};

pub const IS_JWT_VALID: &str = "is_jwt_valid";
pub const IS_JWT_PRESENT: &str = "is_jwt_present";

/// Fields holding the IDs of the token configurations that found a valid
/// token, or any token, on the request. They back [`IS_JWT_VALID`] and
/// [`IS_JWT_PRESENT`].
pub const VALID_FIELD: &str = "http.request.jwt.valid";
pub const PRESENT_FIELD: &str = "http.request.jwt.present";

/// `is_jwt_valid("id")` / `is_jwt_present("id")`: takes a token configuration
/// ID, checked at parse time against the configured ones.
///
/// A wirefilter function only sees its arguments, but the answer lives in the
/// execution context, so the call itself is compiled by [`RuleCompiler`].
#[derive(Debug)]
pub struct JwtFunction {
    token_ids: Arc<[String]>,
}

impl JwtFunction {
    pub fn new(token_ids: Arc<[String]>) -> Self {
        Self { token_ids }
    }
}

impl FunctionDefinition for JwtFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        next_param.expect_const_value::<&BytesExpr, _>(|id| {
            if self.token_ids.iter().any(|known| known.as_bytes() == &**id) {
                Ok(())
            } else {
                Err(format!(
                    "unknown token configuration '{}'",
                    String::from_utf8_lossy(id)
                ))
            }
        })
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bool
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (1, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        unreachable!("JWT functions must be compiled with RuleCompiler")
    }
}

/// Compiles expressions like the default compiler, except for the JWT
/// functions, which it turns into a lookup in [`VALID_FIELD`] or
/// [`PRESENT_FIELD`].
pub struct RuleCompiler {
    valid: Field,
    present: Field,
}

impl RuleCompiler {
    pub fn new(scheme: &Scheme) -> Self {
        let field = |name| scheme.get_field(name).unwrap().to_owned();
        Self {
            valid: field(VALID_FIELD),
            present: field(PRESENT_FIELD),
        }
    }
}

impl Compiler for RuleCompiler {
    type U = ();

    fn compile_function_call_expr(&mut self, node: FunctionCallExpr) -> CompiledValueExpr<()> {
        let mut call = Call::default();
        node.walk(&mut call);

        let field = match call.function {
            Some(IS_JWT_VALID) => self.valid.clone(),
            Some(IS_JWT_PRESENT) => self.present.clone(),
            _ => return self.compile_value_expr(node),
        };
        let Some(LiteralValue::Bytes(id)) = call.literal else {
            unreachable!("validated in check_param");
        };
        let id: Box<[u8]> = id.to_vec().into();

        CompiledValueExpr::new(move |ctx: &ExecutionContext<'_>| {
            let listed = match ctx.get_field_value(field.as_ref()) {
                Some(LhsValue::Array(ids)) => ids
                    .iter()
                    .any(|v| matches!(v, LhsValue::Bytes(b) if **b == *id)),
                _ => false,
            };
            Ok(LhsValue::Bool(listed))
        })
    }
}

/// The name and literal argument of a function call.
#[derive(Default)]
struct Call<'a> {
    function: Option<&'a str>,
    literal: Option<&'a LiteralValue>,
}

impl<'a> Visitor<'a> for Call<'a> {
    // Arguments are not walked into, so `visit_function` only ever sees the
    // outermost call.
    fn visit_function_call_arg_expr(&mut self, arg: &'a FunctionCallArgExpr) {
        if let FunctionCallArgExpr::Literal(literal) = arg {
            self.literal = Some(literal);
        }
    }

    fn visit_function(&mut self, function: &'a Function) {
        self.function = Some(function.name());
    }
}

#[cfg(test)]
mod tests {
    use wirefilter_engine::{ExecutionContext, Scheme};

    use super::{PRESENT_FIELD, RuleCompiler, VALID_FIELD};
    use crate::waf::populate::owned_array;

    fn scheme() -> Scheme {
        crate::waf::scheme::build(&[], &["api".to_string(), "partner".to_string()])
    }

    fn context(scheme: &Scheme, valid: &[&str], present: &[&str]) -> ExecutionContext<'static> {
        let mut ctx = crate::waf::scheme::new_context(scheme);
        for (name, ids) in [(VALID_FIELD, valid), (PRESENT_FIELD, present)] {
            let field = scheme.get_field(name).unwrap();
            ctx.set_field_value(field, owned_array(ids.iter().map(|id| id.to_string())))
                .unwrap();
        }
        ctx
    }

    fn eval(scheme: &Scheme, ctx: &ExecutionContext<'static>, expr: &str) -> bool {
        scheme
            .parse(expr)
            .expect("expression should parse")
            .compile_with_compiler(&mut RuleCompiler::new(scheme))
            .execute(ctx)
            .expect("filter should execute")
    }

    #[test]
    fn functions_report_the_outcome_for_their_configuration() {
        let scheme = scheme();
        let ctx = context(&scheme, &["api"], &["api", "partner"]);

        assert!(eval(&scheme, &ctx, r#"is_jwt_valid("api")"#));
        assert!(eval(&scheme, &ctx, r#"is_jwt_present("api")"#));

        assert!(!eval(&scheme, &ctx, r#"is_jwt_valid("partner")"#));
        assert!(eval(&scheme, &ctx, r#"is_jwt_present("partner")"#));
    }

    #[test]
    fn functions_combine_with_other_expressions() {
        let scheme = scheme();
        let ctx = context(&scheme, &["api"], &["api"]);

        assert!(eval(
            &scheme,
            &ctx,
            r#"is_jwt_valid("api") or is_jwt_valid("partner")"#
        ));
        assert!(eval(
            &scheme,
            &ctx,
            r#"is_jwt_valid("partner") or not is_jwt_present("partner")"#
        ));
        assert!(!eval(&scheme, &ctx, r#"not is_jwt_valid("api")"#));
        assert!(!eval(
            &scheme,
            &ctx,
            r#"not (is_jwt_valid("api") or is_jwt_valid("partner"))"#
        ));
        assert!(!eval(
            &scheme,
            &ctx,
            r#"is_jwt_present("api") and not is_jwt_valid("api")"#
        ));
        // Other functions still compile normally alongside them.
        assert!(eval(
            &scheme,
            &ctx,
            r#"is_jwt_valid("api") and lower("ABC") == "abc""#
        ));
    }

    #[test]
    fn false_when_no_token_was_evaluated() {
        let scheme = scheme();
        let ctx = crate::waf::scheme::new_context(&scheme);
        assert!(!eval(&scheme, &ctx, r#"is_jwt_valid("api")"#));
        assert!(!eval(&scheme, &ctx, r#"is_jwt_present("api")"#));
    }

    #[test]
    fn unknown_token_configuration_is_a_parse_error() {
        let scheme = scheme();
        let err = scheme.parse(r#"is_jwt_valid("nope")"#).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown token configuration 'nope'"),
            "{err}"
        );
        assert!(scheme.parse("is_jwt_valid(http.host)").is_err());
        assert!(scheme.parse("is_jwt_valid()").is_err());
    }
}
