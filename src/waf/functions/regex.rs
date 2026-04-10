use std::fmt;

use regex::bytes::Regex;
use wirefilter_engine::{
    Array, Bytes as WfBytes, BytesExpr, ExpectedType, FunctionArgs, FunctionDefinition,
    FunctionDefinitionContext, FunctionParam, FunctionParamError, GetType, LhsValue,
    ParserSettings, RhsValue, Type, TypedArray,
};

fn compile_regex(pattern: &[u8]) -> Result<Regex, String> {
    let pat_str =
        std::str::from_utf8(pattern).map_err(|e| format!("pattern is not valid UTF-8: {e}"))?;
    Regex::new(pat_str).map_err(|e| format!("invalid regex '{pat_str}': {e}"))
}

fn take_bytes_literal(param: FunctionParam<'_>) -> Vec<u8> {
    match param {
        FunctionParam::Constant(RhsValue::Bytes(b)) => b[..].to_vec(),
        _ => unreachable!("validated in check_param"),
    }
}

pub struct RegexCaptureFunction;

impl fmt::Debug for RegexCaptureFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegexCaptureFunction")
    }
}

impl FunctionDefinition for RegexCaptureFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => next_param.expect_val_type([ExpectedType::Type(Type::Bytes)].into_iter()),
            1 => {
                next_param.expect_const_value::<&BytesExpr, _>(|pat| compile_regex(pat).map(|_| ()))
            }
            _ => unreachable!(),
        }
    }

    fn return_type(
        &self,
        _: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        Type::Array(Type::Bytes.into())
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (2, Some(0))
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let _source = params.next().unwrap();
        let pattern = take_bytes_literal(params.next().unwrap());
        let re = compile_regex(&pattern).unwrap();

        Box::new(move |args| {
            let LhsValue::Bytes(input) = args.next()?.ok()? else {
                return None;
            };
            let captures = re.captures(&input)?;
            let arr = TypedArray::from_iter(captures.iter().map(|m| match m {
                Some(m) => WfBytes::from(m.as_bytes().to_vec()),
                None => WfBytes::from(Vec::new()),
            }));
            Some(LhsValue::Array(arr.into()))
        })
    }
}

pub struct RegexReplaceFunction;

impl fmt::Debug for RegexReplaceFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegexReplaceFunction")
    }
}

impl FunctionDefinition for RegexReplaceFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => next_param.expect_val_type(
                [ExpectedType::Type(Type::Bytes), ExpectedType::Array]
                    .iter()
                    .cloned(),
            ),
            1 => {
                next_param.expect_const_value::<&BytesExpr, _>(|pat| compile_regex(pat).map(|_| ()))
            }
            2 => next_param.expect_const_value::<&BytesExpr, _>(|_| Ok(())),
            _ => unreachable!(),
        }
    }

    fn return_type(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        match params.next().unwrap().get_type() {
            Type::Array(_) => Type::Array(Type::Bytes.into()),
            _ => Type::Bytes,
        }
    }

    fn arg_count(&self) -> (usize, Option<usize>) {
        (3, Some(0))
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let _source = params.next().unwrap();
        let pattern = take_bytes_literal(params.next().unwrap());
        let replacement = take_bytes_literal(params.next().unwrap());
        let re = compile_regex(&pattern).unwrap();

        Box::new(move |args| {
            let arg = args.next()?.ok()?;
            match arg {
                LhsValue::Bytes(b) => {
                    let out = re.replace_all(&b, replacement.as_slice()).into_owned();
                    Some(LhsValue::Bytes(out.into()))
                }
                LhsValue::Array(arr) => {
                    let out: Vec<LhsValue<'_>> = arr
                        .into_iter()
                        .map(|item| match item {
                            LhsValue::Bytes(b) => {
                                let replaced =
                                    re.replace_all(&b, replacement.as_slice()).into_owned();
                                LhsValue::Bytes(replaced.into())
                            }
                            other => other.into_owned(),
                        })
                        .collect();
                    Some(LhsValue::Array(
                        Array::try_from_vec(Type::Bytes, out).unwrap(),
                    ))
                }
                _ => None,
            }
        })
    }
}
