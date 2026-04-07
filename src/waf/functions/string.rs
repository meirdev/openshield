use std::sync::LazyLock;

use regex::bytes::Regex;
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

pub fn compress_whitespace(input: &[u8]) -> Vec<u8> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[\s]+").unwrap());
    RE.replace_all(input, &b" "[..]).into_owned()
}

pub fn replace_comments(input: &[u8]) -> Vec<u8> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?s)/\*.*?\*/|/\*.*$").unwrap());
    RE.replace_all(input, &b" "[..]).into_owned()
}

pub fn remove_comments_char(input: &[u8]) -> Vec<u8> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/\*|\*/|--|#").unwrap());
    RE.replace_all(input, &b""[..]).into_owned()
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
