//! Injection detection over raw request bytes.
//!
//! [`detect_xss`] reports whether a string would become active content if
//! a page reflected it into HTML, and why. [`detect_sqli`] reports whether a
//! string would change the meaning of an SQL query it was spliced into.

pub mod sqli;
pub mod xss;

#[cfg(feature = "testdata")]
pub mod testdata;

pub use sqli::detect_sqli;
pub use xss::detect_xss;
