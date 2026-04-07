use std::collections::HashMap;
use std::sync::Mutex;

use wirefilter_engine::{
    Bytes as WfBytes, FunctionArgs, LhsValue, SimpleFunctionArgKind, SimpleFunctionDefinition,
    SimpleFunctionImpl, SimpleFunctionParam, Type,
};

lazy_static::lazy_static! {
    static ref REGEX_CACHE: Mutex<HashMap<String, regex::bytes::Regex>> = Mutex::new(HashMap::new());
}

fn get_or_compile_regex(pattern: &str) -> Option<regex::bytes::Regex> {
    let mut cache = REGEX_CACHE.lock().ok()?;
    if let Some(re) = cache.get(pattern) {
        return Some(re.clone());
    }
    match regex::bytes::Regex::new(pattern) {
        Ok(re) => {
            cache.insert(pattern.to_string(), re.clone());
            Some(re)
        }
        Err(e) => {
            log::warn!("regex_capture: invalid pattern '{}': {}", pattern, e);
            None
        }
    }
}

fn regex_capture_fn<'a>(args: FunctionArgs<'_, 'a>) -> Option<LhsValue<'a>> {
    let LhsValue::Bytes(input_bytes) = args.next()?.ok()? else {
        return None;
    };
    let LhsValue::Bytes(pattern_bytes) = args.next()?.ok()? else {
        return None;
    };
    let pattern_str = std::str::from_utf8(&pattern_bytes).ok()?;

    let re = get_or_compile_regex(pattern_str)?;
    let captures = re.captures(&input_bytes)?;

    let arr = wirefilter_engine::TypedArray::from_iter(captures.iter().map(|m| match m {
        Some(m) => WfBytes::from(m.as_bytes().to_vec()),
        None => WfBytes::from(Vec::new()),
    }));
    Some(LhsValue::Array(arr.into()))
}

pub fn regex_capture_def() -> SimpleFunctionDefinition {
    SimpleFunctionDefinition {
        params: vec![
            SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Field,
                val_type: Type::Bytes,
            },
            SimpleFunctionParam {
                arg_kind: SimpleFunctionArgKind::Literal,
                val_type: Type::Bytes,
            },
        ],
        opt_params: vec![],
        return_type: Type::Array(Type::Bytes.into()),
        implementation: SimpleFunctionImpl::new(regex_capture_fn),
    }
}
