use wirefilter_engine::{Bytes as WfBytes, ExecutionContext, LhsValue, Scheme, TypedArray};

use super::{parse_form_urlencoded, set_field, split_pairs};
use crate::waf::data::MultipartPartData;

pub fn body_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    body: &[u8],
    total_size: usize,
    truncated: bool,
    content_type: Option<&str>,
) {
    set_field!(ctx, scheme, "http.request.body.size", Int, total_size);
    set_field!(ctx, scheme, "http.request.body.truncated", Bool, truncated);
    set_field!(ctx, scheme, "http.request.body.raw", Bytes, body);

    let is_form = content_type
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    if is_form {
        let pairs = parse_form_urlencoded(body);
        let (names, values) = split_pairs(&pairs);
        set_field!(ctx, scheme, "http.request.body.form", MapArr, pairs);
        set_field!(ctx, scheme, "http.request.body.form.names", Arr, names);
        set_field!(ctx, scheme, "http.request.body.form.values", Arr, values);
    }
}

pub fn multipart_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    parts: &[MultipartPartData],
) {
    let pairs: Vec<(String, String)> = parts
        .iter()
        .filter_map(|p| p.name.as_ref().map(|n| (n.clone(), p.value.clone())))
        .collect();
    set_field!(ctx, scheme, "http.request.body.multipart", MapArr, pairs);
    set_field!(
        ctx,
        scheme,
        "http.request.body.multipart.values",
        Arr,
        parts.iter().map(|p| p.value.clone()).collect::<Vec<_>>()
    );

    fn arr_arr_field<F>(
        parts: &[MultipartPartData],
        extract: F,
    ) -> TypedArray<'static, TypedArray<'static, WfBytes<'static>>>
    where
        F: Fn(&MultipartPartData) -> &Option<String>,
    {
        TypedArray::from_iter(parts.iter().map(|p| match extract(p) {
            Some(v) => TypedArray::from_iter([WfBytes::from(v.as_bytes().to_vec())]),
            None => TypedArray::new(),
        }))
    }

    for (field, extract_fn) in [
        (
            "http.request.body.multipart.names",
            (|p: &MultipartPartData| &p.name) as fn(&MultipartPartData) -> &Option<String>,
        ),
        (
            "http.request.body.multipart.filenames",
            |p: &MultipartPartData| &p.filename,
        ),
        (
            "http.request.body.multipart.content_types",
            |p: &MultipartPartData| &p.content_type,
        ),
        (
            "http.request.body.multipart.content_dispositions",
            |p: &MultipartPartData| &p.content_disposition,
        ),
        (
            "http.request.body.multipart.content_transfer_encodings",
            |p: &MultipartPartData| &p.content_transfer_encoding,
        ),
    ] {
        set_field!(ctx, scheme, field, arr_arr_field(parts, extract_fn));
    }
}

#[cfg(test)]
mod tests {
    use wirefilter_engine::{ExecutionContext, Scheme};

    use super::{body_fields, multipart_fields};
    use crate::waf::data::MultipartPartData;
    use crate::waf::populate::test_support::{check, context, scheme};

    const FORM: &str = "application/x-www-form-urlencoded";

    fn populate_body(
        body: &[u8],
        content_type: Option<&str>,
    ) -> (Scheme, ExecutionContext<'static>) {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        body_fields(&mut ctx, &scheme, body, body.len(), false, content_type);
        (scheme, ctx)
    }

    #[test]
    fn raw_body_size_and_truncated() {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        body_fields(&mut ctx, &scheme, b"hello", 5, true, None);
        assert!(check(&scheme, &ctx, r#"http.request.body.raw == "hello""#));
        assert!(check(&scheme, &ctx, "http.request.body.size == 5"));
        assert!(check(&scheme, &ctx, "http.request.body.truncated"));
    }

    #[test]
    fn form_body_parsed_into_fields() {
        let (scheme, ctx) = populate_body(b"user=admin&pass=secret", Some(FORM));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.body.form.names[*] == "user")"#
        ));
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.body.form.values[*] == "secret")"#
        ));
    }

    #[test]
    fn non_form_content_type_skips_form_parsing() {
        // Same bytes, but a JSON content-type must not populate form fields.
        let (scheme, ctx) = populate_body(b"user=admin&pass=secret", Some("application/json"));
        assert!(!check(
            &scheme,
            &ctx,
            r#"any(http.request.body.form.values[*] == "secret")"#
        ));
    }

    #[test]
    fn multipart_values_populated() {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        let parts = vec![MultipartPartData {
            name: Some("upload".into()),
            filename: Some("evil.sh".into()),
            content_type: Some("text/x-sh".into()),
            content_disposition: None,
            content_transfer_encoding: None,
            value: "rm -rf /".into(),
        }];
        multipart_fields(&mut ctx, &scheme, &parts);
        assert!(check(
            &scheme,
            &ctx,
            r#"any(http.request.body.multipart.values[*] == "rm -rf /")"#
        ));
    }
}
