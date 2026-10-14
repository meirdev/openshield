pub fn detect_sqli(input: &[u8]) -> bool {
    libinjectionrs::detect_sqli(input).is_injection()
}

pub fn detect_xss(input: &[u8]) -> bool {
    libinjectionrs::detect_xss(input).is_injection()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqli_flags_injection() {
        assert!(detect_sqli(b"1' OR '1'='1"));
        assert!(detect_sqli(
            b"' UNION SELECT username, password FROM users--"
        ));
    }

    #[test]
    fn sqli_ignores_benign() {
        assert!(!detect_sqli(b"hello world"));
        assert!(!detect_sqli(b""));
    }

    #[test]
    fn xss_flags_injection() {
        assert!(detect_xss(b"<script>alert(1)</script>"));
        assert!(detect_xss(b"<img src=x onerror=alert(1)>"));
    }

    #[test]
    fn xss_ignores_benign() {
        assert!(!detect_xss(b"just some plain text"));
        assert!(!detect_xss(b""));
    }

    // Element-wise (polymorphic) path: detect_*(field[*]) over an array of
    // query-arg values, the way real rules scan all params at once.
    mod via_scheme {
        use crate::waf::functions::test_support::eval_array;

        const ARGS: &str = "http.request.uri.args.values";

        #[test]
        fn any_arg_with_sqli_matches() {
            assert!(eval_array(
                "any(detect_sqli(http.request.uri.args.values[*]))",
                ARGS,
                &[b"benign", b"1' OR '1'='1", b"also benign"],
            ));
        }

        #[test]
        fn no_arg_with_sqli_does_not_match() {
            assert!(!eval_array(
                "any(detect_sqli(http.request.uri.args.values[*]))",
                ARGS,
                &[b"hello", b"world"],
            ));
        }

        #[test]
        fn any_arg_with_xss_matches() {
            assert!(eval_array(
                "any(detect_xss(http.request.uri.args.values[*]))",
                ARGS,
                &[b"ok", b"<script>alert(1)</script>"],
            ));
        }
    }
}
