use std::fmt;

use wirefilter_engine::{
    Array, ExpectedType, FunctionArgs, FunctionDefinition, FunctionDefinitionContext,
    FunctionParam, FunctionParamError, GetType, LhsValue, ParserSettings, SimpleFunctionArgKind,
    SimpleFunctionDefinition, SimpleFunctionImpl, SimpleFunctionParam, Type,
};

pub type FnImpl = for<'a> fn(FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>>;

/// Core transform: &[u8] -> Vec<u8>
pub type BytesTransformFn = fn(&[u8]) -> Vec<u8>;

/// Core predicate: &[u8] -> bool
pub type BytesPredicateFn = fn(&[u8]) -> bool;

/// (Bytes field, Bytes literal) -> Bool
pub fn bytes_bytes_to_bool(f: FnImpl) -> SimpleFunctionDefinition {
    SimpleFunctionDefinition {
        params: vec![
            SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Field,
                val_type: Type::Bytes,
            },
            SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Literal,
                val_type: Type::Bytes,
            },
        ],
        opt_params: vec![],
        return_type: Type::Bool,
        implementation: SimpleFunctionImpl::new(f),
    }
}

// ---------------------------------------------------------------------------
// Polymorphic: accepts Bytes OR Array<Bytes>, maps element-wise
// ---------------------------------------------------------------------------

/// Bytes|Array<Bytes> -> Bytes|Array<Bytes>
/// Applies a byte transform to a single value or each element of an array.
pub struct BytesTransformFunction {
    name: &'static str,
    transform: BytesTransformFn,
}

impl BytesTransformFunction {
    pub const fn new(name: &'static str, transform: BytesTransformFn) -> Self {
        Self { name, transform }
    }
}

impl fmt::Debug for BytesTransformFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesTransformFunction({})", self.name)
    }
}

impl FunctionDefinition for BytesTransformFunction {
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
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        match params.next().unwrap().get_type() {
            Type::Array(_) => Type::Array(Type::Bytes.into()),
            _ => Type::Bytes,
        }
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
        let transform = self.transform;
        Box::new(move |args| {
            let arg = args.next()?.ok()?;
            match arg {
                LhsValue::Bytes(b) => Some(LhsValue::Bytes(transform(&b).into())),
                LhsValue::Array(arr) => {
                    let out: Vec<LhsValue<'_>> = arr
                        .into_iter()
                        .map(|item| {
                            if let LhsValue::Bytes(b) = item {
                                LhsValue::Bytes(transform(&b).into())
                            } else {
                                item.into_owned()
                            }
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

/// Bytes|Array<Bytes> -> Bool|Array<Bool>
/// Applies a predicate to a single value or each element of an array.
pub struct BytesPredicateFunction {
    name: &'static str,
    predicate: BytesPredicateFn,
}

impl BytesPredicateFunction {
    pub const fn new(name: &'static str, predicate: BytesPredicateFn) -> Self {
        Self { name, predicate }
    }
}

impl fmt::Debug for BytesPredicateFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BytesPredicateFunction({})", self.name)
    }
}

impl FunctionDefinition for BytesPredicateFunction {
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
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<&FunctionDefinitionContext>,
    ) -> Type {
        match params.next().unwrap().get_type() {
            Type::Array(_) => Type::Array(Type::Bool.into()),
            _ => Type::Bool,
        }
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
        let predicate = self.predicate;
        Box::new(move |args| {
            let arg = args.next()?.ok()?;
            match arg {
                LhsValue::Bytes(b) => Some(LhsValue::Bool(predicate(&b))),
                LhsValue::Array(arr) => {
                    let out: Vec<LhsValue<'_>> = arr
                        .into_iter()
                        .map(|item| {
                            if let LhsValue::Bytes(b) = item {
                                LhsValue::Bool(predicate(&b))
                            } else {
                                LhsValue::Bool(false)
                            }
                        })
                        .collect();
                    Some(LhsValue::Array(
                        Array::try_from_vec(Type::Bool, out).unwrap(),
                    ))
                }
                _ => None,
            }
        })
    }
}
