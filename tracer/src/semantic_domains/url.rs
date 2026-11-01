//! Safe raw-input URL branch cardinalities, before document_url validation.
use serde_json::{Value, json};
pub fn document_url_domain(document_source: &Value) -> Value {
    let Some(source) = document_source.as_str() else {
        return json!({"present":false,"port":false,"port_digits":[],"labels":[]});
    };
    // get is deliberately safe on malformed input. Actual original g001 retains
    // rejection authority; this projection never declares a URL valid.
    let suffix = source.get(8..).unwrap_or("");
    let end = suffix
        .bytes()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .unwrap_or(suffix.len());
    let authority = suffix.get(..end).unwrap_or("");
    let mut parts = authority.split(':');
    let host = parts.next().unwrap_or_default();
    let port = parts.next();
    let digits: Vec<Value> = port
        .map(|p| p.bytes().map(|_| json!({})).collect())
        .unwrap_or_default();
    let labels: Vec<Value> = host
        .as_bytes()
        .split(|b| *b == b'.')
        .map(|_| json!({}))
        .collect();
    json!({"present":true,"port":port.is_some(),"port_digits":digits,"labels":labels})
}
