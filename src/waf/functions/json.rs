use std::fmt;

use serde_json::Value;
use wirefilter_engine::{
    BytesExpr, ExpectedType, FunctionArgs, FunctionDefinition, FunctionDefinitionContext,
    FunctionParam, FunctionParamError, LhsValue, ParserSettings, RhsValue, Type,
};

#[derive(Clone)]
enum JsonKey {
    String(String),
    Index(i64),
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
        match params.len() {
            // First param: the JSON field (Bytes)
            0 => next_param.expect_val_type([ExpectedType::Type(Type::Bytes)].into_iter()),
            // Subsequent params: literal keys (Bytes for object keys, Int for array indices)
            _ => match next_param {
                FunctionParam::Constant(RhsValue::Bytes(_))
                | FunctionParam::Constant(RhsValue::Int(_)) => Ok(()),
                // Fall through to produce a meaningful error
                _ => next_param.expect_const_value::<&BytesExpr, _>(|_| Ok(())),
            },
        }
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
        let _source = params.next().unwrap();
        let keys: Vec<JsonKey> = params
            .map(|p| match p {
                FunctionParam::Constant(RhsValue::Bytes(b)) => {
                    JsonKey::String(String::from_utf8_lossy(&b).into_owned())
                }
                FunctionParam::Constant(RhsValue::Int(i)) => JsonKey::Index(*i),
                _ => unreachable!("validated in check_param"),
            })
            .collect();

        Box::new(move |args| {
            let LhsValue::Bytes(input) = args.next()?.ok()? else {
                return Some(LhsValue::Bytes(Vec::new().into()));
            };

            let json: Value = match serde_json::from_slice(&input) {
                Ok(v) => v,
                Err(_) => return Some(LhsValue::Bytes(Vec::new().into())),
            };

            let mut current = &json;
            for key in &keys {
                match key {
                    JsonKey::String(s) => match current.get(s.as_str()) {
                        Some(v) => current = v,
                        None => return Some(LhsValue::Bytes(Vec::new().into())),
                    },
                    JsonKey::Index(i) => {
                        if *i < 0 {
                            return Some(LhsValue::Bytes(Vec::new().into()));
                        }
                        match current.get(*i as usize) {
                            Some(v) => current = v,
                            None => return Some(LhsValue::Bytes(Vec::new().into())),
                        }
                    }
                }
            }

            let result = match current {
                Value::String(s) => s.as_bytes().to_vec(),
                Value::Number(n) => n.to_string().into_bytes(),
                Value::Bool(b) => b.to_string().into_bytes(),
                Value::Null => Vec::new(),
                other => other.to_string().into_bytes(),
            };
            Some(LhsValue::Bytes(result.into()))
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
}
