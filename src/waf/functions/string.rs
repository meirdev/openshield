use wirefilter_engine::{
    FunctionArgs, LhsValue, SimpleFunctionArgKind, SimpleFunctionDefinition, SimpleFunctionImpl,
    SimpleFunctionParam, Type,
};

pub fn lower(input: &[u8]) -> Vec<u8> {
    input.to_ascii_lowercase()
}

pub fn upper(input: &[u8]) -> Vec<u8> {
    input.to_ascii_uppercase()
}

pub fn trim(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|&c| !c.is_ascii_whitespace())
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|&c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    input[start..end].to_vec()
}

pub fn trim_start(input: &[u8]) -> Vec<u8> {
    let start = input
        .iter()
        .position(|&c| !c.is_ascii_whitespace())
        .unwrap_or(input.len());
    input[start..].to_vec()
}

pub fn trim_end(input: &[u8]) -> Vec<u8> {
    let end = input
        .iter()
        .rposition(|&c| !c.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(0);
    input[..end].to_vec()
}

pub fn remove_nulls(input: &[u8]) -> Vec<u8> {
    input.iter().copied().filter(|&c| c != 0).collect()
}

pub fn replace_nulls(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .map(|c| if c == 0 { b' ' } else { c })
        .collect()
}

pub fn remove_whitespace(input: &[u8]) -> Vec<u8> {
    input
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

pub fn len_def() -> SimpleFunctionDefinition {
    SimpleFunctionDefinition {
        params: vec![SimpleFunctionParam {
            arg_kind: SimpleFunctionArgKind::Field,
            val_type: Type::Bytes,
        }],
        opt_params: vec![],
        return_type: Type::Int,
        implementation: SimpleFunctionImpl::new(len_fn),
    }
}

fn len_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(b) = args.next()?.ok()? else {
        return None;
    };
    Some(LhsValue::Int(b.len() as i64))
}

pub fn starts_with_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(input) = args.next()?.ok()? else {
        return None;
    };
    let LhsValue::Bytes(prefix) = args.next()?.ok()? else {
        return None;
    };
    Some(LhsValue::Bool(input.starts_with(&prefix)))
}

pub fn ends_with_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(input) = args.next()?.ok()? else {
        return None;
    };
    let LhsValue::Bytes(suffix) = args.next()?.ok()? else {
        return None;
    };
    Some(LhsValue::Bool(input.ends_with(&suffix)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lower_upper_ascii_only() {
        assert_eq!(lower(b"AbC123"), b"abc123");
        assert_eq!(upper(b"AbC123"), b"ABC123");
        // Non-ASCII bytes are untouched (ASCII-only casing).
        let utf8 = "É".as_bytes();
        assert_eq!(lower(utf8), utf8);
    }

    #[test]
    fn trim_variants() {
        assert_eq!(trim(b"  hello  "), b"hello");
        assert_eq!(trim(b"\t\n hi \r\n"), b"hi");
        assert_eq!(trim_start(b"  hello  "), b"hello  ");
        assert_eq!(trim_end(b"  hello  "), b"  hello");
    }

    #[test]
    fn trim_all_whitespace_is_empty() {
        assert_eq!(trim(b"    "), b"");
        assert_eq!(trim_start(b"    "), b"");
        assert_eq!(trim_end(b"    "), b"");
        assert_eq!(trim(b""), b"");
    }

    #[test]
    fn null_handling() {
        assert_eq!(remove_nulls(b"a\0b\0c"), b"abc");
        assert_eq!(replace_nulls(b"a\0b\0c"), b"a b c");
        assert_eq!(remove_nulls(b"abc"), b"abc");
    }

    #[test]
    fn remove_whitespace_strips_interior_too() {
        assert_eq!(remove_whitespace(b" a b\tc\n"), b"abc");
        assert_eq!(remove_whitespace(b"nospace"), b"nospace");
    }

    // Expression-level tests: confirm the functions are registered and wired
    // through the scheme the way rules invoke them.
    mod via_scheme {
        use crate::waf::functions::test_support::eval_bytes;

        const HOST: &str = "http.host";

        #[test]
        fn len_returns_byte_count() {
            assert!(eval_bytes("len(http.host) == 5", HOST, b"hello"));
            assert!(eval_bytes("len(http.host) == 0", HOST, b""));
        }

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
        }

        #[test]
        fn transform_over_array() {
            use crate::waf::functions::test_support::eval_array;
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
}
