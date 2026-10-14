use wirefilter_engine::{
    ExpectedType, FunctionArgs, FunctionDefinition, FunctionDefinitionContext, FunctionParam,
    FunctionParamError, LhsValue, ParserSettings, Type,
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
}
