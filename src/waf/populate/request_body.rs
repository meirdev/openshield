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
