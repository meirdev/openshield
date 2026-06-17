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

#[cfg(test)]
mod tests {
    use super::response_body_fields;
    use crate::waf::populate::test_support::{check, context, scheme};

    #[test]
    fn raw_size_and_truncated() {
        let scheme = scheme();
        let mut ctx = context(&scheme);
        response_body_fields(&mut ctx, &scheme, b"<html>", 6, false);
        assert!(check(
            &scheme,
            &ctx,
            r#"http.response.body.raw == "<html>""#
        ));
        assert!(check(&scheme, &ctx, "http.response.body.size == 6"));
        assert!(check(&scheme, &ctx, "not http.response.body.truncated"));
    }
}
