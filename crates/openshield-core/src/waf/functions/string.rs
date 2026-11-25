use std::borrow::Cow;
use std::fmt;

use wirefilter_engine::{
    Bytes as WfBytes, BytesExpr, ExpectedType, FunctionArgs, FunctionDefinition,
    FunctionDefinitionContext, FunctionParam, FunctionParamError, LhsValue, LiteralValue,
    ParserSettings, Type, TypedArray,
};

use super::helpers::Transform;

pub fn lower(input: &[u8]) -> Cow<'_, [u8]> {
    if input.iter().any(u8::is_ascii_uppercase) {
        Cow::Owned(input.to_ascii_lowercase())
    } else {
        Cow::Borrowed(input)
    }
}

pub fn upper(input: &[u8]) -> Cow<'_, [u8]> {
    if input.iter().any(u8::is_ascii_lowercase) {
        Cow::Owned(input.to_ascii_uppercase())
    } else {
        Cow::Borrowed(input)
    }
}

pub fn trim(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii())
}

pub fn trim_start(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii_start())
}

pub fn trim_end(input: &[u8]) -> Cow<'_, [u8]> {
    Cow::Borrowed(input.trim_ascii_end())
}

pub fn remove_bytes(set: Option<&[u8]>) -> Result<Transform, String> {
    let set = set.unwrap_or_default();
    if set.is_empty() {
        return Err("remove_bytes needs at least one byte to remove".into());
    }
    let mut remove = [false; 256];
    for &b in set {
        remove[usize::from(b)] = true;
    }
    Ok(Box::new(move |input: &[u8]| {
        if !input.iter().any(|&b| remove[usize::from(b)]) {
            return Cow::Borrowed(input);
        }
        Cow::Owned(
            input
                .iter()
                .copied()
                .filter(|&b| !remove[usize::from(b)])
                .collect(),
        )
    }))
}

const MAX_SPLIT_LIMIT: i64 = 128;

fn bytes_literal(param: FunctionParam<'_>) -> Vec<u8> {
    match param {
        FunctionParam::Constant(LiteralValue::Bytes(b)) => b[..].to_vec(),
        _ => unreachable!("validated in check_param"),
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn split_bytes<'a>(input: &'a [u8], sep: &[u8], limit: usize) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut rest = input;
    while parts.len() + 1 < limit {
        let Some(at) = find(rest, sep) else {
            break;
        };
        parts.push(&rest[..at]);
        rest = &rest[at + sep.len()..];
    }
    parts.push(rest);
    parts
}

pub struct SplitFunction;

impl fmt::Debug for SplitFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SplitFunction")
    }
}

impl FunctionDefinition for SplitFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => next_param.expect_val_type([ExpectedType::Type(Type::Bytes)].into_iter()),
            1 => next_param.expect_const_value::<&BytesExpr, _>(|sep| {
                if sep.is_empty() {
                    Err("split separator must not be empty".into())
                } else {
                    Ok(())
                }
            }),
            2 => next_param.expect_const_value::<&i64, _>(|&limit| {
                if (1..=MAX_SPLIT_LIMIT).contains(&limit) {
                    Ok(())
                } else {
                    Err(format!(
                        "split limit must be between 1 and {MAX_SPLIT_LIMIT}"
                    ))
                }
            }),
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
        (3, Some(0))
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let _source = params.next().unwrap();
        let sep = bytes_literal(params.next().unwrap());
        let limit = match params.next().unwrap() {
            FunctionParam::Constant(LiteralValue::Int(n)) => *n as usize,
            _ => unreachable!("validated in check_param"),
        };

        Box::new(move |args| {
            let LhsValue::Bytes(input) = args.next()?.ok()? else {
                return None;
            };
            let parts = split_bytes(&input, &sep, limit)
                .into_iter()
                .map(|part| WfBytes::from(part.to_vec()));
            Some(LhsValue::Array(TypedArray::from_iter(parts).into()))
        })
    }
}

pub struct JoinFunction;

impl fmt::Debug for JoinFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "JoinFunction")
    }
}

impl FunctionDefinition for JoinFunction {
    fn check_param(
        &self,
        _: &ParserSettings,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        next_param: &FunctionParam<'_>,
        _: Option<&mut FunctionDefinitionContext>,
    ) -> Result<(), FunctionParamError> {
        match params.len() {
            0 => next_param
                .expect_val_type([ExpectedType::Type(Type::Array(Type::Bytes.into()))].into_iter()),
            1 => next_param.expect_const_value::<&BytesExpr, _>(|_| Ok(())),
            _ => unreachable!(),
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
        (2, Some(0))
    }

    fn compile(
        &self,
        params: &mut dyn ExactSizeIterator<Item = FunctionParam<'_>>,
        _: Option<FunctionDefinitionContext>,
    ) -> Box<dyn for<'i, 'a> Fn(FunctionArgs<'i, 'a>) -> Option<LhsValue<'a>> + Sync + Send + 'static>
    {
        let _items = params.next().unwrap();
        let sep = bytes_literal(params.next().unwrap());

        Box::new(move |args| {
            let LhsValue::Array(items) = args.next()?.ok()? else {
                return None;
            };
            let mut out = Vec::new();
            for (i, item) in items.into_iter().enumerate() {
                let LhsValue::Bytes(b) = item else {
                    return None;
                };
                if i > 0 {
                    out.extend_from_slice(&sep);
                }
                out.extend_from_slice(&b);
            }
            Some(LhsValue::Bytes(out.into()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_upper_ascii_only() {
        assert_eq!(&*lower(b"AbC123"), b"abc123");
        assert_eq!(&*upper(b"AbC123"), b"ABC123");
        // Non-ASCII bytes are untouched (ASCII-only casing).
        let utf8 = "É".as_bytes();
        assert_eq!(&*lower(utf8), utf8);
    }

    #[test]
    fn unchanged_input_is_borrowed() {
        assert!(matches!(lower(b"abc"), Cow::Borrowed(_)));
        assert!(matches!(lower(b"Abc"), Cow::Owned(_)));
        assert!(matches!(trim(b"  a  "), Cow::Borrowed(_)));
        let remove = remove_bytes(Some(b"\0")).unwrap();
        assert!(matches!(remove(b"abc"), Cow::Borrowed(_)));
    }

    #[test]
    fn trim_variants() {
        assert_eq!(&*trim(b"  hello  "), b"hello");
        assert_eq!(&*trim(b"\t\n hi \r\n"), b"hi");
        assert_eq!(&*trim_start(b"  hello  "), b"hello  ");
        assert_eq!(&*trim_end(b"  hello  "), b"  hello");
    }

    #[test]
    fn trim_all_whitespace_is_empty() {
        assert_eq!(&*trim(b"    "), b"");
        assert_eq!(&*trim_start(b"    "), b"");
        assert_eq!(&*trim_end(b"    "), b"");
        assert_eq!(&*trim(b""), b"");
    }

    #[test]
    fn remove_bytes_removes_every_listed_byte() {
        let nulls = remove_bytes(Some(b"\0")).unwrap();
        assert_eq!(&*nulls(b"a\0b\0c"), b"abc");
        let whitespace = remove_bytes(Some(b" \t\n\r\x0b\x0c")).unwrap();
        assert_eq!(&*whitespace(b" a b\tc\n"), b"abc");
        assert!(remove_bytes(Some(b"")).is_err());
        assert!(remove_bytes(None).is_err());
    }

    #[test]
    fn split_keeps_remainder_in_last_part() {
        assert_eq!(split_bytes(b"a,b,c", b",", 128), [&b"a"[..], b"b", b"c"]);
        assert_eq!(split_bytes(b"a,b,c", b",", 2), [&b"a"[..], b"b,c"]);
        assert_eq!(split_bytes(b"a,b,c", b",", 1), [&b"a,b,c"[..]]);
        // Multi-byte separator; empty parts are kept.
        assert_eq!(split_bytes(b"a::b::", b"::", 128), [&b"a"[..], b"b", b""]);
        assert_eq!(split_bytes(b"", b",", 128), [&b""[..]]);
    }

    // Expression-level tests: confirm the functions are registered and wired
    // through the scheme the way rules invoke them.
    mod via_scheme {
        use crate::waf::functions::test_support::{eval_array, eval_bytes, scheme};

        const HOST: &str = "http.host";

        #[test]
        fn renamed_case_and_trim_functions() {
            assert!(eval_bytes(r#"upper(http.host) == "ABC""#, HOST, b"abc"));
            assert!(eval_bytes(r#"trim_start(http.host) == "a ""#, HOST, b" a "));
            assert!(eval_bytes(r#"trim_end(http.host) == " a""#, HOST, b" a "));
        }

        #[test]
        fn remove_bytes_with_literal_set() {
            assert!(eval_bytes(
                r#"remove_bytes(http.host, "\x00 ") == "ab""#,
                HOST,
                b"a\0 b"
            ));
            // The set is required and must not be empty.
            assert!(scheme().parse("remove_bytes(http.host)").is_err());
            assert!(
                scheme()
                    .parse(r#"remove_bytes(http.host, "") == """#)
                    .is_err()
            );
        }

        #[test]
        fn split_and_join() {
            assert!(eval_bytes(
                r#"split(http.host, ".", 2)[1] == "b.c""#,
                HOST,
                b"a.b.c"
            ));
            assert!(eval_bytes(
                r#"len(split(http.host, ".", 128)) == 3"#,
                HOST,
                b"a.b.c"
            ));
            assert!(eval_bytes(
                r#"join(split(http.host, ".", 128), "/") == "a/b/c""#,
                HOST,
                b"a.b.c"
            ));
            assert!(eval_array(
                r#"join(http.request.uri.args.values, ",") == "x,y""#,
                "http.request.uri.args.values",
                &[b"x", b"y"],
            ));
            assert!(eval_array(
                r#"join(http.request.uri.args.values, ",") == """#,
                "http.request.uri.args.values",
                &[],
            ));
        }

        #[test]
        fn split_rejects_bad_literals() {
            let s = scheme();
            assert!(s.parse(r#"len(split(http.host, "", 2)) == 1"#).is_err());
            assert!(s.parse(r#"len(split(http.host, ".", 0)) == 1"#).is_err());
            assert!(s.parse(r#"len(split(http.host, ".", 129)) == 1"#).is_err());
        }
    }
}
