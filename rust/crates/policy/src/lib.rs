//! keygate-policy — движок правил для keygate.
//! Без внешних зависимостей. Отдаёт решение через C ABI.

use std::collections::BTreeMap;
use std::ffi::{c_char, CStr, CString};

pub const POLICY_VERSION: &str = "1.0";

#[derive(Debug, Clone)]
enum Value {
    Str(String),
    Num(f64),
    Bool(bool),
}

fn skip_ws(bytes: &[u8], at: &mut usize) {
    while *at < bytes.len() && bytes[*at].is_ascii_whitespace() {
        *at += 1;
    }
}

fn parse_string(bytes: &[u8], at: &mut usize) -> Option<String> {
    if bytes.get(*at) != Some(&b'"') {
        return None;
    }
    *at += 1;
    let mut out = String::new();
    while *at < bytes.len() {
        let ch = bytes[*at];
        *at += 1;
        match ch {
            b'"' => return Some(out),
            b'\\' => {
                let next = *bytes.get(*at)?;
                *at += 1;
                match next {
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => out.push(next as char),
                }
            }
            _ => out.push(ch as char),
        }
    }
    None
}

/// Минимальный парсер плоского JSON: {"key":"value", "num":1, "flag":true}
fn parse_flat(input: &str) -> BTreeMap<String, Value> {
    let mut map = BTreeMap::new();
    let bytes = input.as_bytes();
    let mut at = 0usize;
    skip_ws(bytes, &mut at);
    if bytes.get(at) != Some(&b'{') {
        return map;
    }
    at += 1;
    loop {
        skip_ws(bytes, &mut at);
        if bytes.get(at) == Some(&b'}') {
            break;
        }
        let Some(key) = parse_string(bytes, &mut at) else { break };
        skip_ws(bytes, &mut at);
        if bytes.get(at) != Some(&b':') {
            break;
        }
        at += 1;
        skip_ws(bytes, &mut at);
        let value = match bytes.get(at) {
            Some(b'"') => parse_string(bytes, &mut at).map(Value::Str),
            Some(b't') if input[at..].starts_with("true") => {
                at += 4;
                Some(Value::Bool(true))
            }
            Some(b'f') if input[at..].starts_with("false") => {
                at += 5;
                Some(Value::Bool(false))
            }
            Some(_) => {
                let start = at;
                while at < bytes.len()
                    && (bytes[at].is_ascii_digit()
                        || matches!(bytes[at], b'-' | b'.' | b'e' | b'E' | b'+'))
                {
                    at += 1;
                }
                input[start..at].parse::<f64>().ok().map(Value::Num)
            }
            None => None,
        };
        if let Some(value) = value {
            map.insert(key, value);
        }
        skip_ws(bytes, &mut at);
        if bytes.get(at) == Some(&b',') {
            at += 1;
            continue;
        }
        if bytes.get(at) == Some(&b'}') {
            break;
        }
        break;
    }
    map
}

fn get_str(map: &BTreeMap<String, Value>, key: &str) -> Option<String> {
    match map.get(key) {
        Some(Value::Str(s)) => Some(s.clone()),
        _ => None,
    }
}

fn get_num(map: &BTreeMap<String, Value>, key: &str) -> Option<f64> {
    match map.get(key) {
        Some(Value::Num(n)) => Some(*n),
        _ => None,
    }
}

fn get_bool(map: &BTreeMap<String, Value>, key: &str) -> Option<bool> {
    match map.get(key) {
        Some(Value::Bool(b)) => Some(*b),
        _ => None,
    }
}

fn csv_has(list: &str, item: &str) -> bool {
    list.split(',').any(|part| part.trim() == item)
}

fn escape(input: &str) -> String {
    let mut out = String::new();
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(ch),
        }
    }
    out
}

fn decision(allow: bool, reasons: &[String], ttl: u64) -> String {
    let items: Vec<String> = reasons
        .iter()
        .map(|r| format!("\"{}\"", escape(r)))
        .collect();
    format!(
        "{{\"allow\":{},\"reasons\":[{}],\"effective_ttl\":{},\"policy_version\":\"{}\"}}",
        allow,
        items.join(","),
        ttl,
        POLICY_VERSION
    )
}

/// Чистая Rust-функция принятия решения. Используется и напрямую, и через FFI.
pub fn evaluate(request_json: &str, config_json: &str) -> String {
    let request = parse_flat(request_json);
    let config = parse_flat(config_json);

    let provider = get_str(&request, "provider").unwrap_or_default();
    let scope = get_str(&request, "scope").unwrap_or_default();
    let ttl = get_num(&request, "ttl").unwrap_or(60.0) as u64;

    let allowed_providers = get_str(&config, "allowed_providers")
        .unwrap_or_else(|| "telegram,openai,aws".into());
    let allowed_scopes =
        get_str(&config, "allowed_scopes").unwrap_or_else(|| "read,send,admin".into());
    let max_ttl = get_num(&config, "max_ttl").unwrap_or(300.0) as u64;
    let deny_unknown = get_bool(&config, "deny_unknown").unwrap_or(true);

    let mut reasons: Vec<String> = Vec::new();
    let mut allow = true;

    if provider.is_empty() {
        allow = false;
        reasons.push("provider is required".into());
    } else if !csv_has(&allowed_providers, &provider) {
        allow = false;
        reasons.push(format!("provider '{}' is not allowed", provider));
    }

    if scope.is_empty() {
        allow = false;
        reasons.push("scope is required".into());
    } else if !csv_has(&allowed_scopes, &scope) {
        allow = false;
        reasons.push(format!("scope '{}' is not allowed", scope));
    }

    if ttl == 0 {
        allow = false;
        reasons.push("ttl must be greater than zero".into());
    } else if ttl > max_ttl {
        allow = false;
        reasons.push(format!("ttl {} exceeds max {}", ttl, max_ttl));
    }

    if deny_unknown && provider.starts_with("unknown_") {
        allow = false;
        reasons.push("unknown provider rejected".into());
    }

    let effective_ttl = ttl.min(max_ttl);
    decision(allow, &reasons, effective_ttl)
}

fn read_input(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .ok()
        .map(|s| s.to_string())
}

fn to_c(value: String) -> *mut c_char {
    CString::new(value)
        .unwrap_or_else(|_| CString::new("{\"error\":\"invalid string\"}").unwrap())
        .into_raw()
}

#[no_mangle]
pub extern "C" fn keygate_policy_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn keygate_policy_evaluate(
    request: *const c_char,
    config: *const c_char,
) -> *mut c_char {
    let request = match read_input(request) {
        Some(value) => value,
        None => return to_c("{\"error\":\"null request\"}".into()),
    };
    let config = match read_input(config) {
        Some(value) => value,
        None => return to_c("{\"error\":\"null config\"}".into()),
    };
    to_c(evaluate(&request, &config))
}

#[no_mangle]
pub extern "C" fn keygate_policy_free(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            drop(CString::from_raw(ptr));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_valid_request() {
        let req = r#"{"provider":"telegram","scope":"send","ttl":60}"#;
        let cfg = r#"{"allowed_providers":"telegram,openai","allowed_scopes":"read,send","max_ttl":300}"#;
        assert!(evaluate(req, cfg).contains("\"allow\":true"));
    }

    #[test]
    fn denies_bad_provider() {
        let req = r#"{"provider":"vk","scope":"send","ttl":60}"#;
        let cfg = r#"{"allowed_providers":"telegram","allowed_scopes":"send","max_ttl":300}"#;
        let result = evaluate(req, cfg);
        assert!(result.contains("\"allow\":false"));
        assert!(result.contains("not allowed"));
    }

    #[test]
    fn caps_ttl() {
        let req = r#"{"provider":"telegram","scope":"send","ttl":9999}"#;
        let cfg = r#"{"allowed_providers":"telegram","allowed_scopes":"send","max_ttl":300}"#;
        assert!(evaluate(req, cfg).contains("\"effective_ttl\":300"));
    }
}
