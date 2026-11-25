use std::borrow::Cow;
use std::fmt;

use wirefilter_engine::{
    Array, Bytes, BytesExpr, ExpectedType, FunctionArgs, FunctionDefinition,
    FunctionDefinitionContext, FunctionParam, FunctionParamError, GetType, LhsValue, LiteralValue,
    ParserSettings, SimpleFunctionArgKind, SimpleFunctionDefinition, SimpleFunctionImpl,
    SimpleFunctionParam, Type,
};

pub type FnImpl = for<'a> fn(FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>>;

/// Core transform: borrowed when the input needed no change.
pub type BytesTransformFn = for<'a> fn(&'a [u8]) -> Cow<'a, [u8]>;

/// A transform configured by the function's literal argument.
pub type Transform = Box<dyn for<'a> Fn(&'a [u8]) -> Cow<'a, [u8]> + Send + Sync>;

/// Builds a [`Transform`] from the literal argument (`None` when an optional
/// one is omitted). An error rejects the rule at parse time.
pub type TransformBuilder = fn(Option<&[u8]>) -> Result<Transform, String>;

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

/// Applies `transform` without copying when the value is borrowed from the
/// request and the transform leaves it alone.
fn apply<'v>(transform: &dyn for<'a> Fn(&'a [u8]) -> Cow<'a, [u8]>, value: Bytes<'v>) -> Bytes<'v> {
    match value {
        Bytes::Borrowed(slice) => transform(slice).into(),
        Bytes::Owned(owned) => {
            let changed = match transform(&owned) {
                Cow::Owned(out) => Some(out),
                Cow::Borrowed(same) if same.len() == owned.len() => None,
                Cow::Borrowed(part) => Some(part.to_vec()),
            };
            match changed {
                Some(out) => out.into(),
                None => Bytes::Owned(owned),
            }
        }
    }
}

enum TransformKind {
    Plain(BytesTransformFn),
    /// `required` is false for an optional trailing literal.
    WithLiteral {
        required: bool,
        build: TransformBuilder,
    },
}

/// Bytes|Array<Bytes> -> Bytes|Array<Bytes>
/// Applies a byte transform to a single value or each element of an array,
/// optionally configured by one string literal (`url_decode(s, "r")`).
pub struct BytesTransformFunction {
    name: &'static str,
    kind: TransformKind,
}

impl BytesTransformFunction {
    pub const fn new(name: &'static str, transform: BytesTransformFn) -> Self {
        Self {
            name,
            kind: TransformKind::Plain(transform),
        }
    }

    /// A transform with an optional string literal argument.
    pub const fn with_optional_literal(name: &'static str, build: TransformBuilder) -> Self {
        Self {
            name,
            kind: TransformKind::WithLiteral {
                required: false,
                build,
            },
        }
    }

    /// A transform with a required string literal argument.
    pub const fn with_required_literal(name: &'static str, build: TransformBuilder) -> Self {
        Self {
            name,
            kind: TransformKind::WithLiteral {
                required: true,
                build,
            },
        }
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
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match (params.len(), &self.kind) {
            (0, _) => next_param.expect_val_type(
                [ExpectedType::Type(Type::Bytes), ExpectedType::Array]
                    .iter()
                    .cloned(),
            ),
            (1, TransformKind::WithLiteral { build, .. }) => {
                next_param.expect_const_value::<&BytesExpr, _>(|lit| build(Some(lit)).map(|_| ()))
            }
            _ => unreachable!("arg_count bounds the parameters"),
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
        match self.kind {
            TransformKind::Plain(_) => (1, Some(0)),
            TransformKind::WithLiteral { required: true, .. } => (2, Some(0)),
            TransformKind::WithLiteral {
                required: false, ..
            } => (1, Some(1)),
        }
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let _source = params.next();
        let transform: Transform = match self.kind {
            TransformKind::Plain(f) => Box::new(f),
            TransformKind::WithLiteral { build, .. } => {
                let literal = params.next().map(|p| match p {
                    FunctionParam::Constant(LiteralValue::Bytes(b)) => b[..].to_vec(),
                    _ => unreachable!("validated in check_param"),
                });
                build(literal.as_deref()).expect("validated in check_param")
            }
        };
        Box::new(move |args| {
            let arg = args.next()?.ok()?;
            match arg {
                LhsValue::Bytes(b) => Some(LhsValue::Bytes(apply(&transform, b))),
                LhsValue::Array(arr) => {
                    let out: Vec<LhsValue<'_>> = arr
                        .into_iter()
                        .map(|item| {
                            if let LhsValue::Bytes(b) = item {
                                LhsValue::Bytes(apply(&transform, b))
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
