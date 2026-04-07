use wirefilter_engine::{ExecutionContext, LhsValue, Scheme};

use super::set_field;

pub fn response_body_fields(
    ctx: &mut ExecutionContext<'static>,
    scheme: &Scheme,
    body: &[u8],
    total_size: usize,
    truncated: bool,
) {
    set_field!(ctx, scheme, "http.response.body.size", Int, total_size);
    set_field!(ctx, scheme, "http.response.body.truncated", Bool, truncated);
    set_field!(ctx, scheme, "http.response.body.raw", Bytes, body);
}
