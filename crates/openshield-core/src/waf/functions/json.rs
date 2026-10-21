use std::fmt;

use serde_json::Value;
use wirefilter_engine::{
    BytesExpr, ExpectedType, FunctionArgs, FunctionDefinition, FunctionDefinitionContext,
    FunctionParam, FunctionParamError, LhsValue, LiteralValue, ParserSettings, Type,
};

#[derive(Clone)]
enum JsonKey {
    String(String),
    Index(i64),
}

fn check_lookup_param(
    params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
    next_param: &FunctionParam<'_>,
) -> Result<(), FunctionParamError> {
    match params.len() {
        0 => next_param.expect_val_type([ExpectedType::Type(Type::Bytes)].into_iter()),
        _ => match next_param {
            FunctionParam::Constant(LiteralValue::Bytes(_))
            | FunctionParam::Constant(LiteralValue::Int(_)) => Ok(()),
            // Fall through to produce a meaningful error
            _ => next_param.expect_const_value::<&BytesExpr, _>(|_| Ok(())),
        },
    }
}

fn lookup_keys(params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>) -> Vec<JsonKey> {
    let _source = params.next().unwrap();
    params
        .map(|p| match p {
            FunctionParam::Constant(LiteralValue::Bytes(b)) => {
                JsonKey::String(String::from_utf8_lossy(b).into_owned())
            }
            FunctionParam::Constant(LiteralValue::Int(i)) => JsonKey::Index(*i),
            _ => unreachable!("validated in check_param"),
        })
        .collect()
}

fn lookup(input: &[u8], keys: &[JsonKey]) -> Option<Value> {
    let json: Value = serde_json::from_slice(input).ok()?;
    let mut current = &json;
    for key in keys {
        current = match key {
            JsonKey::String(s) => current.get(s.as_str())?,
            JsonKey::Index(i) => current.get(usize::try_from(*i).ok()?)?,
        };
    }
    Some(current.clone())
}

pub struct LookupJsonStringFunction;

impl fmt::Debug for LookupJsonStringFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LookupJsonStringFunction")
    }
}

impl FunctionDefinition for LookupJsonStringFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        check_lookup_param(params, next_param)
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bytes
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, None) // field + at least 1 key, unlimited additional keys
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let keys = lookup_keys(params);
        Box::new(move |args| {
            let empty = || Some(LhsValue::Bytes(Vec::new().into()));
            let LhsValue::Bytes(input) = args.next()?.ok()? else {
                return empty();
            };
            let Some(value) = lookup(&input, &keys) else {
                return empty();
            };
            let result = match value {
                Value::String(s) => s.into_bytes(),
                Value::Number(n) => n.to_string().into_bytes(),
                Value::Bool(b) => b.to_string().into_bytes(),
                Value::Null => Vec::new(),
                other => other.to_string().into_bytes(),
            };
            Some(LhsValue::Bytes(result.into()))
        })
    }
}

pub struct LookupJsonIntegerFunction;

impl fmt::Debug for LookupJsonIntegerFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LookupJsonIntegerFunction")
    }
}

impl FunctionDefinition for LookupJsonIntegerFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        check_lookup_param(params, next_param)
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Int
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, None)
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let keys = lookup_keys(params);
        Box::new(move |args| {
            let LhsValue::Bytes(input) = args.next()?.ok()? else {
                return None;
            };
            let value = lookup(&input, &keys)?;
            value.as_i64().map(LhsValue::Int)
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::waf::functions::test_support::eval_bytes;

    const SRC: &str = "http.request.body.raw";

    #[test]
    fn top_level_string() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "name") == "alice""#,
            SRC,
            br#"{"name":"alice"}"#,
        ));
    }

    #[test]
    fn nested_object() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "user", "name") == "bob""#,
            SRC,
            br#"{"user":{"name":"bob"}}"#,
        ));
    }

    #[test]
    fn array_index() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "items", 1) == "b""#,
            SRC,
            br#"{"items":["a","b","c"]}"#,
        ));
    }

    #[test]
    fn number_and_bool_coerced_to_string() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "age") == "42""#,
            SRC,
            br#"{"age":42}"#,
        ));
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "ok") == "true""#,
            SRC,
            br#"{"ok":true}"#,
        ));
    }

    #[test]
    fn missing_key_yields_empty() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "missing") == """#,
            SRC,
            br#"{"present":1}"#,
        ));
    }

    #[test]
    fn invalid_json_yields_empty() {
        assert!(eval_bytes(
            r#"lookup_json_string(http.request.body.raw, "any") == """#,
            SRC,
            b"this is not json",
        ));
    }

    #[test]
    fn integer_examples_from_cloudflare_docs() {
        for (body, expr) in [
            (r#"{"record_id":"aed53a","version":2}"#, "\"version\") == 2"),
            (r#"{"product":{"id":356}}"#, "\"product\", \"id\") == 356"),
            (r#"["first_item",-234]"#, "1) == -234"),
            (r#"{"network_ids":[123,456]}"#, "\"network_ids\", 0) == 123"),
            (
                r#"[{"product_id":123},{"product_id":456}]"#,
                "1, \"product_id\") == 456",
            ),
        ] {
            let expr = format!("lookup_json_integer(http.request.body.raw, {expr}");
            assert!(eval_bytes(&expr, SRC, body.as_bytes()), "{expr} on {body}");
        }
    }

    #[test]
    fn integer_comparisons_work_as_integers() {
        assert!(eval_bytes(
            r#"lookup_json_integer(http.request.body.raw, "n") > 9"#,
            SRC,
            br#"{"n":10}"#,
        ));
        assert!(!eval_bytes(
            r#"lookup_json_integer(http.request.body.raw, "n") > 9"#,
            SRC,
            br#"{"n":"10"}"#,
        ));
    }

    #[test]
    fn integer_missing_invalid_or_non_integer_never_matches() {
        for body in [
            br#"{"other":1}"#.as_slice(),
            b"not json",
            br#"{"n":42.0}"#,
            br#"{"n":"42"}"#,
            br#"{"n":true}"#,
            br#"{"n":null}"#,
            br#"{"n":[0]}"#,
        ] {
            // No value: behaves like an absent field, so `==` is false and
            // `!=` is true.
            let eq = r#"lookup_json_integer(http.request.body.raw, "n") == 0"#;
            let ne = r#"lookup_json_integer(http.request.body.raw, "n") != 0"#;
            assert!(!eval_bytes(eq, SRC, body), "{eq} on {body:?}");
            assert!(eval_bytes(ne, SRC, body), "{ne} on {body:?}");
        }
    }

    #[test]
    fn integer_negative_index_never_matches() {
        assert!(!eval_bytes(
            r#"lookup_json_integer(http.request.body.raw, -1) == 5"#,
            SRC,
            br#"[5]"#,
        ));
    }
}
