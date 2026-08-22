mod decode;
mod detect;
mod encode;
pub mod helpers;
mod json;
mod regex;
mod string;

use helpers::{BytesPredicateFunction, BytesTransformFunction};
use wirefilter_engine::ConcatFunction;

pub fn register_all(b: &mut wirefilter_engine::SchemeBuilder) {
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
        "remove_nulls",
        BytesTransformFunction::new("remove_nulls", string::remove_nulls),
    )
    .unwrap();
    b.add_function(
        "replace_nulls",
        BytesTransformFunction::new("replace_nulls", string::replace_nulls),
    )
    .unwrap();
    b.add_function(
        "remove_whitespace",
        BytesTransformFunction::new("remove_whitespace", string::remove_whitespace),
    )
    .unwrap();

    // String functions (non-polymorphic)
    b.add_function("len", string::len_def()).unwrap();
    b.add_function(
        "starts_with",
        helpers::bytes_bytes_to_bool(string::starts_with_fn),
    )
    .unwrap();
    b.add_function(
        "ends_with",
        helpers::bytes_bytes_to_bool(string::ends_with_fn),
    )
    .unwrap();

    // Decoding functions (polymorphic)
    b.add_function(
        "url_decode_uni",
        BytesTransformFunction::new("url_decode_uni", decode::url_decode_uni),
    )
    .unwrap();
    b.add_function(
        "base64_decode",
        BytesTransformFunction::new("base64_decode", decode::base64_decode),
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

    // Encoding functions (polymorphic)
    b.add_function(
        "base64_encode",
        BytesTransformFunction::new("base64_encode", encode::base64_encode),
    )
    .unwrap();
    b.add_function(
        "hex_encode",
        BytesTransformFunction::new("hex_encode", encode::hex_encode),
    )
    .unwrap();
    b.add_function("sha1", BytesTransformFunction::new("sha1", encode::sha1))
        .unwrap();
    b.add_function(
        "utf8_to_unicode",
        BytesTransformFunction::new("utf8_to_unicode", encode::utf8_to_unicode),
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
}

#[cfg(test)]
pub(crate) mod test_support {
    use wirefilter_engine::{Bytes as WfBytes, ExecutionContext, LhsValue, Scheme, TypedArray};

    /// Build the production scheme (all fields + functions registered).
    pub fn scheme() -> Scheme {
        crate::waf::scheme::build(&[])
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
