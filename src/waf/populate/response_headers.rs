use wirefilter_engine::{ExecutionContext, LhsValue, Scheme};

use super::{get_header, set_field, split_pairs};
use crate::waf::data::ResponseData;

fn extract_media_type(content_type: &str) -> &str {
    content_type.split(';').next().unwrap_or("").trim()
}

pub fn response_fields(ctx: &mut ExecutionContext<'static>, scheme: &Scheme, resp: &ResponseData) {
    set_field!(ctx, scheme, "http.response.code", Int, resp.status);

    if let Some(ct) = get_header(&resp.headers, "content-type") {
        set_field!(
            ctx,
            scheme,
            "http.response.content_type.media_type",
            Str,
            extract_media_type(ct)
        );
    }

    let (names, values) = split_pairs(&resp.headers);
    set_field!(
        ctx,
        scheme,
        "http.response.headers",
        MapArr,
        resp.headers.clone()
    );
    set_field!(ctx, scheme, "http.response.headers.names", Arr, names);
    set_field!(ctx, scheme, "http.response.headers.values", Arr, values);
}
