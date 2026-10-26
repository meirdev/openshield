use wirefilter_engine::{
    ExpectedType, FunctionArgs, FunctionDefinition, FunctionDefinitionContext, FunctionParam,
    FunctionParamError, GetType, LhsValue, ParserSettings, Type,
};

#[derive(Debug)]
pub struct LenFunction;

impl FunctionDefinition for LenFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        _params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        next_param.expect_val_type(
            [ExpectedType::Type(Type::Bytes), ExpectedType::Array]
                .iter()
                .cloned(),
        )
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Int
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
        Box::new(|args| match args.next()?.ok()? {
            LhsValue::Bytes(b) => Some(LhsValue::Int(b.len() as i64)),
            LhsValue::Array(a) => Some(LhsValue::Int(a.len() as i64)),
            _ => None,
        })
    }
}

/// `has_key(map, key)`: whether `key` is present in the map. The key may be
/// a literal or a string expression.
#[derive(Debug)]
pub struct HasKeyFunction;

impl FunctionDefinition for HasKeyFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => next_param.expect_val_type([ExpectedType::Map].into_iter()),
            _ => next_param.expect_val_type([ExpectedType::Type(Type::Bytes)].into_iter()),
        }
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bool
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(|args| {
            let LhsValue::Map(map) = args.next()?.ok()? else {
                return None;
            };
            let LhsValue::Bytes(key) = args.next()?.ok()? else {
                return None;
            };
            Some(LhsValue::Bool(map.get(&key).is_some()))
        })
    }
}

/// `has_value(collection, value)`: whether `value` occurs in the map or
/// array, looking through nested arrays (a header map holds an array of
/// values per name). `value` must have the collection's element type; it
/// may be a literal or an expression.
#[derive(Debug)]
pub struct HasValueFunction;

/// The innermost element type of a map or array type.
fn element_type(mut ty: Type) -> Type {
    while let Some(inner) = ty.next() {
        ty = inner;
    }
    ty
}

fn contains(value: &LhsValue<'_>, needle: &LhsValue<'_>) -> bool {
    match value {
        LhsValue::Array(array) => array.iter().any(|v| contains(v, needle)),
        LhsValue::Map(map) => map.iter().any(|(_, v)| contains(v, needle)),
        other => other == needle,
    }
}

impl FunctionDefinition for HasValueFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.next() {
            None => {
                next_param.expect_val_type([ExpectedType::Map, ExpectedType::Array].into_iter())
            }
            Some(collection) => next_param.expect_val_type(
                [ExpectedType::Type(element_type(collection.get_type()))].into_iter(),
            ),
        }
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Bool
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, Some(0))
    }

    fn compile(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        Box::new(|args| {
            let collection = args.next()?.ok()?;
            let needle = args.next()?.ok()?;
            Some(LhsValue::Bool(contains(&collection, &needle)))
        })
    }
}

#[cfg(test)]
mod tests {
    mod via_scheme {
        use crate::waf::functions::test_support::{eval_array, eval_bytes};

        #[test]
        fn len_returns_byte_count() {
            assert!(eval_bytes("len(http.host) == 5", "http.host", b"hello"));
        }

        #[test]
        fn len_counts_array_elements() {
            assert!(eval_array(
                "len(http.request.uri.args.values) == 3",
                "http.request.uri.args.values",
                &[b"a", b"b", b"c"]
            ));
        }
    }

    mod collections {
        use crate::waf::data::RequestData;
        use crate::waf::populate::request_fields;
        use crate::waf::populate::test_support::{check, context, empty_request, scheme};

        fn request() -> RequestData {
            let mut req = empty_request();
            req.query = "X-My-Header=1&b=2".into();
            req.headers = vec![
                ("x-my-header".into(), "1".into()),
                ("accept".into(), "text/html".into()),
                ("accept".into(), "*/*".into()),
            ];
            req
        }

        fn eval(expr: &str) -> bool {
            let scheme = scheme();
            let mut ctx = context(&scheme);
            request_fields(&mut ctx, &scheme, &request());
            check(&scheme, &ctx, expr)
        }

        #[test]
        fn has_key_on_maps() {
            assert!(eval(r#"has_key(http.request.headers, "x-my-header")"#));
            assert!(eval(r#"has_key(http.request.headers, "accept")"#));
            assert!(!eval(r#"has_key(http.request.headers, "x-other")"#));
            // Header names are stored lowercased; the lookup is exact.
            assert!(!eval(r#"has_key(http.request.headers, "X-My-Header")"#));
            assert!(eval(r#"has_key(http.request.uri.args, "X-My-Header")"#));
        }

        #[test]
        fn has_key_with_a_dynamic_key() {
            assert!(eval(
                r#"has_key(http.request.headers, lower(http.request.uri.args.names[0]))"#
            ));
            assert!(!eval(
                r#"has_key(http.request.headers, http.request.uri.args.names[0])"#
            ));
        }

        #[test]
        fn has_value_on_arrays() {
            assert!(eval(
                r#"has_value(http.request.headers.names, "x-my-header")"#
            ));
            assert!(eval(r#"has_value(http.request.headers.values, "*/*")"#));
            assert!(!eval(
                r#"has_value(http.request.headers.names, "X-My-Header")"#
            ));
            assert!(eval(r#"has_value(http.request.uri.args.values, "2")"#));
            assert!(eval(
                r#"has_value(http.request.headers.names, lower(http.request.uri.args.names[0]))"#
            ));
        }

        #[test]
        fn has_value_on_maps_looks_into_each_name_values() {
            assert!(eval(r#"has_value(http.request.headers, "text/html")"#));
            assert!(eval(r#"has_value(http.request.uri.args, "1")"#));
            assert!(!eval(r#"has_value(http.request.headers, "accept")"#));
        }

        #[test]
        fn value_must_match_the_element_type() {
            let scheme = scheme();
            assert!(
                scheme
                    .parse(r#"has_value(http.request.headers.names, 1)"#)
                    .is_err()
            );
            assert!(
                scheme
                    .parse(r#"has_key(http.request.headers.names, "x")"#)
                    .is_err()
            );
            assert!(scheme.parse(r#"has_key(http.request.headers, 1)"#).is_err());
        }
    }
}
