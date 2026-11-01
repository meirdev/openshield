//! Input transformations for web application firewalls.
//!
//! Each function takes raw bytes and returns a [`Cow`](std::borrow::Cow):
//! borrowed when the input needed no change, owned otherwise, so a chain of
//! transforms over benign input allocates nothing. The semantics follow
//! ModSecurity's `t:` transformations, quirks included, so rules written
//! against ModSecurity behave the same here; each function's documentation
//! names the transformation it reproduces.

mod decode;
mod encode;
mod string;

pub use decode::{
    base64_decode, css_decode, escape_seq_decode, hex_decode, html_entity_decode, js_decode,
    url_decode_uni,
};
pub use encode::{base64_encode, hex_encode, utf8_to_unicode};
#[cfg(feature = "hash")]
pub use encode::{md5, sha1};
pub use string::{
    cmd_line, compress_whitespace, lowercase, normalize_path, normalize_path_win, remove_comments,
    remove_comments_char, remove_nulls, remove_whitespace, replace_comments, replace_nulls, trim,
    trim_left, trim_right, uppercase,
};
