pub fn detect_sqli(input: &[u8]) -> bool {
    libinjectionrs::detect_sqli(input).is_injection()
}

pub fn detect_xss(input: &[u8]) -> bool {
    libinjectionrs::detect_xss(input).is_injection()
}
