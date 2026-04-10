mod decode;
mod detect;
mod encode;
pub mod helpers;
mod regex;
mod string;

use helpers::{BytesPredicateFunction, BytesTransformFunction};
use wirefilter_engine::{AllFunction, AnyFunction, ConcatFunction};

pub fn register_all(b: &mut wirefilter_engine::SchemeBuilder) {
    // Built-in wirefilter functions
    b.add_function("any", AnyFunction::default()).unwrap();
    b.add_function("all", AllFunction::default()).unwrap();
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
}
