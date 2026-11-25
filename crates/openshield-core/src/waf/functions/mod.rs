mod decode;
mod detect;
mod encode;
mod generic;
pub mod helpers;
mod json;
mod jwt;
mod regex;
mod string;

use std::sync::Arc;

use helpers::{BytesPredicateFunction, BytesTransformFunction};
pub use jwt::{PRESENT_FIELD, RuleCompiler, VALID_FIELD};
use wirefilter_engine::ConcatFunction;

/// `token_ids` are the token configuration IDs the JWT functions accept.
pub fn register_all(b: &mut wirefilter_engine::SchemeBuilder, token_ids: &[String]) {
    b.add_function("concat", ConcatFunction::new()).unwrap();

    // String transform functions (polymorphic: Bytes|Array<Bytes> ->
    // Bytes|Array<Bytes>)
    b.add_function("lower", BytesTransformFunction::new("lower", string::lower))
        .unwrap();
    b.add_function("upper", BytesTransformFunction::new("upper", string::upper))
        .unwrap();
    b.add_function("trim", BytesTransformFunction::new("trim", string::trim))
        .unwrap();
    b.add_function(
        "trim_start",
        BytesTransformFunction::new("trim_start", string::trim_start),
    )
    .unwrap();
    b.add_function(
        "trim_end",
        BytesTransformFunction::new("trim_end", string::trim_end),
    )
    .unwrap();
    b.add_function(
        "remove_bytes",
        BytesTransformFunction::with_required_literal("remove_bytes", string::remove_bytes),
    )
    .unwrap();
    b.add_function("split", string::SplitFunction).unwrap();
    b.add_function("join", string::JoinFunction).unwrap();

    // String functions (non-polymorphic)
    b.add_function("len", generic::LenFunction).unwrap();
    b.add_function("has_key", generic::HasKeyFunction).unwrap();
    b.add_function("has_value", generic::HasValueFunction)
        .unwrap();
    b.add_function("except", generic::ExceptFunction::exact())
        .unwrap();
    b.add_function("except_matching", generic::ExceptFunction::matching())
        .unwrap();
    b.add_function(
        "starts_with",
        helpers::bytes_bytes_to_bool(generic::starts_with_fn),
    )
    .unwrap();
    b.add_function(
        "ends_with",
        helpers::bytes_bytes_to_bool(generic::ends_with_fn),
    )
    .unwrap();

    // Decoding functions (polymorphic)
    b.add_function(
        "url_decode",
        BytesTransformFunction::with_optional_literal("url_decode", decode::url_decode_with),
    )
    .unwrap();
    b.add_function(
        "decode_base64",
        BytesTransformFunction::new("decode_base64", decode::decode_base64),
    )
    .unwrap();
    b.add_function(
        "hex_decode",
        BytesTransformFunction::new("hex_decode", decode::hex_decode),
    )
    .unwrap();
    b.add_function(
        "html_entity_decode",
        BytesTransformFunction::new("html_entity_decode", decode::html_entity_decode),
    )
    .unwrap();

    // Encoding and hash functions (polymorphic)
    b.add_function(
        "encode_base64",
        BytesTransformFunction::new("encode_base64", encode::encode_base64),
    )
    .unwrap();
    b.add_function(
        "hex_encode",
        BytesTransformFunction::new("hex_encode", encode::hex_encode),
    )
    .unwrap();
    for (name, digest) in [
        ("md5", encode::md5 as helpers::BytesTransformFn),
        ("sha1", encode::sha1),
        ("sha256", encode::sha256),
        ("sha512", encode::sha512),
    ] {
        b.add_function(name, BytesTransformFunction::new(name, digest))
            .unwrap();
    }

    // Security detection functions (polymorphic: Bytes|Array<Bytes> ->
    // Bool|Array<Bool>)
    b.add_function(
        "detect_sqli",
        BytesPredicateFunction::new("detect_sqli", detect::detect_sqli),
    )
    .unwrap();
    b.add_function(
        "detect_xss",
        BytesPredicateFunction::new("detect_xss", detect::detect_xss),
    )
    .unwrap();

    // Regex (patterns compiled once at rule-compile time)
    b.add_function("regex_capture", regex::RegexCaptureFunction)
        .unwrap();
    b.add_function("regex_replace", regex::RegexReplaceFunction)
        .unwrap();

    // JSON
    b.add_function("lookup_json_string", json::LookupJsonStringFunction)
        .unwrap();
    b.add_function("lookup_json_integer", json::LookupJsonIntegerFunction)
        .unwrap();

    // JWT
    let token_ids: Arc<[String]> = token_ids.into();
    for name in [jwt::IS_JWT_VALID, jwt::IS_JWT_PRESENT] {
        b.add_function(name, jwt::JwtFunction::new(token_ids.clone()))
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::{eval_array, eval_bytes};

    const HOST: &str = "http.host";

    #[test]
    fn starts_with_literal() {
        assert!(eval_bytes(
            r#"starts_with(http.host, "he")"#,
            HOST,
            b"hello"
        ));
        assert!(!eval_bytes(
            r#"starts_with(http.host, "xy")"#,
            HOST,
            b"hello"
        ));
    }

    #[test]
    fn ends_with_literal() {
        assert!(eval_bytes(r#"ends_with(http.host, "lo")"#, HOST, b"hello"));
        assert!(!eval_bytes(r#"ends_with(http.host, "xy")"#, HOST, b"hello"));
    }

    #[test]
    fn transform_then_compare() {
        // Polymorphic Bytes path: lower(field) applied before comparison.
        assert!(eval_bytes(r#"lower(http.host) == "abc""#, HOST, b"ABC"));
        // A transform that changes nothing still compares correctly.
        assert!(eval_bytes(r#"lower(http.host) == "abc""#, HOST, b"abc"));
        assert!(eval_bytes(r#"trim(http.host) == "abc""#, HOST, b"  abc "));
    }

    #[test]
    fn transform_over_array() {
        // Polymorphic Array path: lower() maps element-wise over the array,
        // feeding its transformed array into detect_sqli's array path.
        assert!(eval_array(
            "any(detect_sqli(lower(http.request.uri.args.values[*])))",
            "http.request.uri.args.values",
            &[b"benign", b"1' OR '1'='1"],
        ));
        assert!(!eval_array(
            "any(detect_sqli(lower(http.request.uri.args.values[*])))",
            "http.request.uri.args.values",
            &[b"hello", b"world"],
        ));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use wirefilter_engine::{Bytes as WfBytes, ExecutionContext, LhsValue, Scheme, TypedArray};

    /// Build the production scheme (all fields + functions registered).
    pub fn scheme() -> Scheme {
        crate::waf::scheme::build(&[], &[])
    }

    /// Parse and evaluate a boolean `expr` after setting a single `Bytes`
    /// field to `value`. Exercises functions that read one source field —
    /// the way rules actually invoke them.
    pub fn eval_bytes(expr: &str, field: &str, value: &[u8]) -> bool {
        let scheme = scheme();
        let filter = scheme
            .parse(expr)
            .expect("expression should parse")
            .compile();
        let mut ctx = ExecutionContext::new(&scheme);
        let f = scheme.get_field(field).expect("field should exist");
        ctx.set_field_value(f, LhsValue::Bytes(value.to_vec().into()))
            .expect("set field value");
        filter.execute(&ctx).expect("filter should execute")
    }

    /// Like [`eval_bytes`], but sets an `Array<Bytes>` field — exercises the
    /// polymorphic element-wise path (e.g. `func(field[*])`).
    pub fn eval_array(expr: &str, field: &str, values: &[&[u8]]) -> bool {
        let scheme = scheme();
        let filter = scheme
            .parse(expr)
            .expect("expression should parse")
            .compile();
        let mut ctx = ExecutionContext::new(&scheme);
        let f = scheme.get_field(field).expect("field should exist");
        let arr: TypedArray<'static, WfBytes<'static>> =
            TypedArray::from_iter(values.iter().map(|v| WfBytes::from(v.to_vec())));
        ctx.set_field_value(f, arr).expect("set field value");
        filter.execute(&ctx).expect("filter should execute")
    }
}
