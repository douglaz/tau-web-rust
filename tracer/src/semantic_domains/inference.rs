//! Independent raw-input structural domains for inference shape/history obligations.
use serde_json::{Value, json};
use std::collections::BTreeMap;
fn alias<'a>(v: &Value, choices: &'a [&'a str]) -> &'a str {
    v.as_str()
        .and_then(|s| choices.iter().copied().find(|c| *c == s))
        .unwrap_or("unknown")
}
fn first(v: &Value) -> (&str, &Value) {
    v.as_object()
        .and_then(|o| o.iter().next())
        .map(|(k, v)| (k.as_str(), v))
        .unwrap_or(("", &Value::Null))
}
fn kind(v: &Value) -> &'static str {
    alias(
        v,
        &["account_read", "clock_read", "mint", "completion", "revoke"],
    )
}
pub fn shape(event: &Value) -> Value {
    let (name, body) = first(event);
    let (intent_name, b) = first(body);
    let optional = [
        "issuer_time",
        "clock_received",
        "clock_sent",
        "unit",
        "charge_refusal",
        "automatic_top_up",
        "key_id",
        "cap",
        "expires",
        "model",
        "requested_provider",
        "reported_provider",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "spend",
        "request_id",
    ];
    let fields = if name != "inference_terminal" {
        Vec::new()
    } else {
        body.as_object().map(|o|o.keys().filter(|k|!["call","status"].contains(&k.as_str())).map(|k|json!({"field":if optional.contains(&k.as_str()){k.as_str()}else{"unknown"}})).collect::<Vec<_>>()).unwrap_or_default()
    };
    json!({"kind":alias(&json!(name),&["inference_account","inference_intent","inference_terminal"]),"intent_kind":kind(&json!(intent_name)),"evidence":b.get("evidence").is_some(),"terminal_fields":fields})
}
#[derive(Default)]
pub struct InferenceInputs {
    raw_intents: BTreeMap<u64, Value>,
}
impl InferenceInputs {
    pub fn event(&mut self, n: u64, event: &Value) -> Value {
        let intent = event.get("inference_intent");
        let (intent_name, b) = first(&event["inference_intent"]);
        let terminal_kind = event["inference_terminal"]["call"]
            .as_u64()
            .and_then(|id| self.raw_intents.get(&id))
            .map(|v| first(v).0)
            .unwrap_or("");
        let domain = json!({"exposure":event.get("exposure").is_some(),"account":event.get("inference_account").is_some(),"intent":intent.is_some(),"terminal":event.get("inference_terminal").is_some(),"shape":shape(event),"intent_kind":kind(&json!(intent_name)),"session":b.get("session").is_some(),"evidence":b.get("evidence").is_some(),"terminal_intent_kind":kind(&json!(terminal_kind))});
        if let Some(intent) = intent {
            self.raw_intents.insert(n, intent.clone());
        }
        domain
    }
}
