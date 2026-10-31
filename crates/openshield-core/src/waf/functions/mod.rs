mod detect;
mod generic;
pub mod helpers;
mod json;
mod jwt;
mod regex;

use std::sync::Arc;

use helpers::{BytesPredicateFunction, BytesTransformFunction};
pub use jwt::{PRESENT_FIELD, RuleCompiler, VALID_FIELD};
use openshield_transforms as transforms;
use wirefilter_engine::ConcatFunction;

/// `token_ids` are the token configuration IDs the JWT functions accept.
pub fn register_all(b: &mut wirefilter_engine::SchemeBuilder, token_ids: &[String]) {
    b.add_function("concat", ConcatFunction::new()).unwrap();

    // String transform functions (polymorphic: Bytes|Array<Bytes> ->
    // Bytes|Array<Bytes>)
    b.add_function(
        "lowercase",
        BytesTransformFunction::new("lowercase", transforms::lowercase),
    )
    .unwrap();
    b.add_function(
        "uppercase",
        BytesTransformFunction::new("uppercase", transforms::uppercase),
    )
    .unwrap();
    b.add_function(
        "trim",
        BytesTransformFunction::new("trim", transforms::trim),
    )
    .unwrap();
    b.add_function(
        "trim_left",
        BytesTransformFunction::new("trim_left", transforms::trim_left),
    )
    .unwrap();
    b.add_function(
        "trim_right",
        BytesTransformFunction::new("trim_right", transforms::trim_right),
    )
    .unwrap();
    b.add_function(
        "remove_nulls",
        BytesTransformFunction::new("remove_nulls", transforms::remove_nulls),
    )
    .unwrap();
    b.add_function(
        "replace_nulls",
        BytesTransformFunction::new("replace_nulls", transforms::replace_nulls),
    )
    .unwrap();
    b.add_function(
        "remove_whitespace",
        BytesTransformFunction::new("remove_whitespace", transforms::remove_whitespace),
    )
    .unwrap();
    b.add_function(
        "compress_whitespace",
        BytesTransformFunction::new("compress_whitespace", transforms::compress_whitespace),
    )
    .unwrap();
    b.add_function(
        "replace_comments",
        BytesTransformFunction::new("replace_comments", transforms::replace_comments),
    )
    .unwrap();
    b.add_function(
        "remove_comments",
        BytesTransformFunction::new("remove_comments", transforms::remove_comments),
    )
    .unwrap();
    b.add_function(
        "cmd_line",
        BytesTransformFunction::new("cmd_line", transforms::cmd_line),
    )
    .unwrap();
    b.add_function(
        "normalize_path",
        BytesTransformFunction::new("normalize_path", transforms::normalize_path),
    )
    .unwrap();
    b.add_function(
        "normalize_path_win",
        BytesTransformFunction::new("normalize_path_win", transforms::normalize_path_win),
    )
    .unwrap();

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
        "url_decode_uni",
        BytesTransformFunction::new("url_decode_uni", transforms::url_decode_uni),
    )
    .unwrap();
    b.add_function(
        "base64_decode",
        BytesTransformFunction::new("base64_decode", transforms::base64_decode),
    )
    .unwrap();
    b.add_function(
        "hex_decode",
        BytesTransformFunction::new("hex_decode", transforms::hex_decode),
    )
    .unwrap();
    b.add_function(
        "html_entity_decode",
        BytesTransformFunction::new("html_entity_decode", transforms::html_entity_decode),
    )
    .unwrap();
    b.add_function(
        "js_decode",
        BytesTransformFunction::new("js_decode", transforms::js_decode),
    )
    .unwrap();
    b.add_function(
        "css_decode",
        BytesTransformFunction::new("css_decode", transforms::css_decode),
    )
    .unwrap();
    b.add_function(
        "escape_seq_decode",
        BytesTransformFunction::new("escape_seq_decode", transforms::escape_seq_decode),
    )
    .unwrap();

    // Encoding functions (polymorphic)
    b.add_function(
        "base64_encode",
        BytesTransformFunction::new("base64_encode", transforms::base64_encode),
    )
    .unwrap();
    b.add_function(
        "hex_encode",
        BytesTransformFunction::new("hex_encode", transforms::hex_encode),
    )
    .unwrap();
    b.add_function("md5", BytesTransformFunction::new("md5", transforms::md5))
        .unwrap();
    b.add_function(
        "sha1",
        BytesTransformFunction::new("sha1", transforms::sha1),
    )
    .unwrap();
    b.add_function(
        "utf8_to_unicode",
        BytesTransformFunction::new("utf8_to_unicode", transforms::utf8_to_unicode),
    )
    .unwrap();

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
        // Polymorphic Bytes path: lowercase(field) applied before comparison.
        assert!(eval_bytes(r#"lowercase(http.host) == "abc""#, HOST, b"ABC"));
        // A transform that changes nothing still compares correctly.
        assert!(eval_bytes(r#"lowercase(http.host) == "abc""#, HOST, b"abc"));
        assert!(eval_bytes(r#"trim(http.host) == "abc""#, HOST, b"  abc "));
    }

    #[test]
    fn transform_over_array() {
        // Polymorphic Array path: lowercase() maps element-wise over the array,
        // feeding its transformed array into detect_sqli's array path.
        assert!(eval_array(
            "any(detect_sqli(lowercase(http.request.uri.args.values[*])))",
            "http.request.uri.args.values",
            &[b"benign", b"1' OR '1'='1"],
        ));
        assert!(!eval_array(
            "any(detect_sqli(lowercase(http.request.uri.args.values[*])))",
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
