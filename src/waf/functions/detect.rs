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
        assert!(detect_sqli(b"' UNION SELECT username, password FROM users--"));
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
}
