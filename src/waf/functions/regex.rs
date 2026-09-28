use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

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

/// Compiled patterns shared across all `regex_match` occurrences, so a rule
/// template repeated per target (and identical patterns across rules) costs a
/// single compiled regex. Entries are never evicted: the cache is bounded by
/// the set of unique patterns ever loaded, and stale entries after a config
/// reload are reused on the next reload rather than recompiled.
static MATCH_CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Arc<regex_automata::meta::Regex>>>> =
    OnceLock::new();

/// Number of unique patterns held by the `regex_match` cache.
pub fn match_cache_size() -> usize {
    MATCH_CACHE
        .get()
        .map(|c| c.lock().unwrap().len())
        .unwrap_or(0)
}

/// Compile `pattern` the way wirefilter compiles a `matches` operand
/// (byte-mode syntax, LeftmostFirst, same size limits), memoized per pattern.
/// Only called at rule-compile time; execution closures hold the `Arc`.
pub(super) fn cached_match_regex(
    pattern: &[u8],
) -> Result<Arc<regex_automata::meta::Regex>, String> {
    let cache = MATCH_CACHE.get_or_init(Default::default);
    if let Some(re) = cache.lock().unwrap().get(pattern) {
        return Ok(re.clone());
    }

    let pat_str =
        std::str::from_utf8(pattern).map_err(|e| format!("pattern is not valid UTF-8: {e}"))?;
    // Mirrors wirefilter's `Regex::new` (rhs_types/regex/imp_real.rs) with its
    // default ParserSettings, so `regex_match(x, p)` == `x matches p`.
    let re = regex_automata::meta::Builder::new()
        .configure(
            regex_automata::meta::Config::new()
                .match_kind(regex_automata::MatchKind::LeftmostFirst)
                .utf8_empty(false)
                .dfa(false)
                .onepass(false)
                .nfa_size_limit(Some(10 * (1 << 20)))
                .dfa_size_limit(Some(10 * (1 << 20)))
                .hybrid_cache_capacity(2 * (1 << 20))
                .which_captures(regex_automata::nfa::thompson::WhichCaptures::None),
        )
        .syntax(
            regex_automata::util::syntax::Config::new()
                .unicode(false)
                .utf8(false),
        )
        .build(pat_str)
        .map_err(|e| format!("invalid regex '{pat_str}': {e}"))?;

    let re = Arc::new(re);
    let mut cache = cache.lock().unwrap();
    Ok(cache.entry(pattern.to_vec()).or_insert(re).clone())
}

/// `regex_match(Bytes|Array<Bytes>, pattern) -> Bool|Array<Bool>`
///
/// Same semantics as the `matches` operator, but the compiled regex is shared
/// across every occurrence of the pattern (see [`MATCH_CACHE`]). Patterns are
/// usually written as raw strings (`r#"..."#`) so backslashes stay verbatim.
pub struct RegexMatchFunction;

impl fmt::Debug for RegexMatchFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegexMatchFunction")
    }
}

impl FunctionDefinition for RegexMatchFunction {
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
            1 => next_param
                .expect_const_value::<&BytesExpr, _>(|pat| cached_match_regex(pat).map(|_| ())),
            _ => unreachable!(),
        }
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
        let re = cached_match_regex(&pattern).unwrap();

        Box::new(move |args| {
            let arg = args.next()?.ok()?;
            match arg {
                LhsValue::Bytes(b) => Some(LhsValue::Bool(re.is_match(&b[..]))),
                LhsValue::Array(arr) => {
                    let out: Vec<LhsValue<'_>> = arr
                        .into_iter()
                        .map(|item| match item {
                            LhsValue::Bytes(b) => LhsValue::Bool(re.is_match(&b[..])),
                            _ => LhsValue::Bool(false),
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

#[cfg(test)]
mod tests {
    use crate::waf::functions::test_support::eval_bytes;

    const SRC: &str = "http.request.uri";

    #[test]
    fn regex_match_bytes() {
        assert!(eval_bytes(
            r##"regex_match(http.request.uri, r#"^/admin(/|$)"#)"##,
            SRC,
            b"/admin/panel",
        ));
        assert!(!eval_bytes(
            r##"regex_match(http.request.uri, r#"^/admin(/|$)"#)"##,
            SRC,
            b"/administrator",
        ));
    }

    #[test]
    fn regex_match_case_insensitive_flag() {
        assert!(eval_bytes(
            r##"regex_match(http.request.uri, r#"(?i)select\s+"#)"##,
            SRC,
            b"/q?x=SELECT 1",
        ));
    }

    #[test]
    fn regex_match_over_array() {
        use crate::waf::functions::test_support::eval_array;
        const ARGS: &str = "http.request.uri.args.values";
        assert!(eval_array(
            r##"any(regex_match(http.request.uri.args.values[*], r#"[\n\r]"#))"##,
            ARGS,
            &[b"benign", b"evil\r\nSet-Cookie: x"],
        ));
        assert!(!eval_array(
            r##"any(regex_match(http.request.uri.args.values[*], r#"[\n\r]"#))"##,
            ARGS,
            &[b"benign", b"also benign"],
        ));
    }

    #[test]
    fn regex_match_byte_mode_semantics() {
        use crate::waf::functions::test_support::scheme;
        // Byte mode: `\xff` matches the raw byte (input need not be UTF-8)...
        assert!(eval_bytes(
            r##"regex_match(http.request.uri, r#"\xff"#)"##,
            SRC,
            b"ab\xffcd",
        ));
        // ...and a class range ending in the Unicode-mode escape `\x{ff}` is
        // rejected at parse time, exactly like the `matches` operator (this is
        // why the CRS converter rewrites `\x{HH}` to `\xHH`).
        assert!(
            scheme()
                .parse(r##"regex_match(http.request.uri, r#"[\x7f-\x{ff}]"#)"##)
                .is_err()
        );
        assert!(
            scheme()
                .parse(r##"regex_match(http.request.uri, r#"(unclosed"#)"##)
                .is_err()
        );
    }

    #[test]
    fn regex_match_cache_is_shared_per_pattern() {
        use super::super::regex::{cached_match_regex, match_cache_size};
        // Same pattern -> same Arc; a distinct pattern -> new entry.
        let unique = format!("cache-test-{}", std::process::id());
        let a = cached_match_regex(unique.as_bytes()).unwrap();
        let before = match_cache_size();
        let b = cached_match_regex(unique.as_bytes()).unwrap();
        assert!(std::sync::Arc::ptr_eq(&a, &b));
        assert_eq!(match_cache_size(), before);
    }

    #[test]
    fn capture_group_by_index() {
        // [0] is the whole match, [1] is the first capture group.
        assert!(eval_bytes(
            r#"regex_capture(http.request.uri, "id=([0-9]+)")[1] == "42""#,
            SRC,
            b"/path?id=42&x=1",
        ));
    }

    #[test]
    fn capture_whole_match() {
        assert!(eval_bytes(
            r#"regex_capture(http.request.uri, "id=[0-9]+")[0] == "id=42""#,
            SRC,
            b"/path?id=42",
        ));
    }

    #[test]
    fn replace_all_matches() {
        assert!(eval_bytes(
            r#"regex_replace(http.request.uri, "[0-9]+", "N") == "/u/N/p/N""#,
            SRC,
            b"/u/12/p/345",
        ));
    }

    #[test]
    fn replace_no_match_is_unchanged() {
        assert!(eval_bytes(
            r#"regex_replace(http.request.uri, "[0-9]+", "N") == "/static/page""#,
            SRC,
            b"/static/page",
        ));
    }
}
