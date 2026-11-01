//! Independent raw-input domains for reader.rs semantic predicates.
//! Integrate with sibling declaration_shape(), delivery(), inference_shape() planners.
//! These functions never call actual validators, actual History or completed receipts.
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn reader_first(value: &Value) -> (&str, &Value) {
    value
        .as_object()
        .and_then(|o| o.iter().next())
        .map(|(k, v)| (k.as_str(), v))
        .unwrap_or(("unknown", &Value::Null))
}
fn reader_items(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .map(|a| a.iter().map(|_| json!({})).collect())
        .unwrap_or_default()
}
fn reader_modes(value: &Value) -> Value {
    json!({"items":reader_items(value)})
}
fn reader_target(value: &Value) -> Value {
    json!({"inference":value == "inference"})
}
fn reader_resource(value: &Value) -> Value {
    json!({"inference":value == "inference"})
}
fn reader_typed_exact(value: &Value, approval: bool) -> Value {
    // Only finite source shape aliases; fields/contents never become output strings.
    let modes = value.get("restated_modes").is_some();
    let receipt = value.get("receipt_binding").is_some();
    let shape = match (approval, modes, receipt) {
        (false, false, false) => "operation_intent",
        (false, true, false) => "operation_intent.modes",
        (false, false, true) => "operation_intent.receipt",
        (false, true, true) => "operation_intent.modes.receipt",
        (true, false, false) => "operation_approved",
        (true, true, false) => "operation_approved.modes",
        (true, false, true) => "operation_approved.receipt",
        (true, true, true) => "operation_approved.modes.receipt",
    };
    json!({"shape":shape})
}
fn reader_setup(value: &Value) -> Value {
    let (kind, body) = reader_first(value);
    let entries = body["entries"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|approved| {
                    json!({
                        "access":!approved["access"].is_null()
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "kind":match kind {"approval"=>"approval","class"=>"class","requirements"=>"requirements","access"=>"access",_=>"unknown"},
        "entries":entries,
        "declaration":super::declaration_delivery::declaration_shape(body)
    })
}
/// Capture before check_event. Nested dedicated dispatch independently projects its
/// original intent body through the same source rule without validating it.
pub fn reader_event(event: &Value) -> Value {
    let (raw_kind, body) = reader_first(event);
    let kind = if raw_kind.starts_with("inference_") {
        "inference"
    } else {
        match raw_kind {
            "dedicated_reinstall" => "dedicated_reinstall",
            "exposure" => "exposure",
            "goal" => "goal",
            "mode_acceptance" => "mode_acceptance",
            "signature_refusal" => "signature_refusal",
            "connection_refusal" => "connection_refusal",
            "seed" => "seed",
            "command" => "command",
            "intent" => "intent",
            "terminal" => "terminal",
            "operation_intent" => "operation_intent",
            "association" => "association",
            "operation_receipt" => "operation_receipt",
            "operation_response" => "operation_response",
            "operation_observation" => "operation_observation",
            "job_terminal" => "job_terminal",
            "job_observation" => "job_observation",
            "disposition" => "disposition",
            "setup" => "setup",
            "delivery" => "delivery",
            "allocation" => "allocation",
            _ => "unknown",
        }
    };
    let (dedicated_kind, dedicated_body) = reader_first(body);
    let dedicated_alias = match dedicated_kind {
        "approve" => "approve",
        "activation" => "activation",
        "read" => "read",
        "withdraw" => "withdraw",
        "dispatch" => "dispatch",
        _ => "unknown",
    };
    let dedicated_intent = if raw_kind == "dedicated_reinstall" && dedicated_kind == "dispatch" {
        reader_event(&json!({"operation_intent":dedicated_body["intent"]}))
    } else {
        Value::Null
    };
    let job_kind = match body["record"]["kind"].as_str() {
        Some("present") => "present",
        Some("missing") if raw_kind == "job_observation" => "missing",
        Some("incomplete") if raw_kind == "job_observation" => "incomplete",
        _ => "unknown",
    };
    json!({
        "kind":kind,
        "document":super::url::document_url_domain(&body["document_source"]),
        "dedicated":{"kind":dedicated_alias,"modes":reader_modes(&dedicated_body["modes"]),"intent":dedicated_intent},
        "exposure":{
            "exact":{"shape":if body.get("accepted_modes").is_some() {"exposure.accepted"} else {"exposure"}},
            "bounds":reader_items(&body["bound_set"])
        },
        "command":{
            "intent":raw_kind=="intent",
            "provenance":body.get("provenance").is_some(),
            "target":reader_target(&body["provenance"]["target"]),
            "job":body.get("job").is_some(),
            "approval":!body["approval"].is_null()
        },
        "operation_intent":{
            "exact":reader_typed_exact(body,false),
            "approved_exact":reader_typed_exact(&body["approved"],true),
            "resource":reader_resource(&body["resource"]),
            "target":reader_target(&body["target"]),
            "modes":reader_modes(&body["restated_modes"]),
            "receipt":body.get("receipt_binding").is_some_and(|v|!v.is_null())
        },
        "association":{"target":reader_target(&body["target"])},
        "operation_receipt":{"resource":reader_resource(&body["resource"]),"target":reader_target(&body["target"])},
        "operation_observation":{"resource":reader_resource(&body["resource"])},
        "job":{"record_kind":job_kind},
        "setup":reader_setup(body),
        "delivery":super::declaration_delivery::delivery(body),
        "inference":super::inference::shape(event),
        "seed_backup":body.get("seed_backup").is_some()
    })
}

/// This state is derived only from previous RAW events, privately. It is deliberately
/// separate from reader::ModeHistory and never supplies a predicate's actual result.
#[derive(Default)]
pub struct ReaderModeInputs {
    exposed_machines: BTreeSet<String>,
    exposed_sessions: BTreeSet<String>,
    goals: BTreeSet<String>,
    closed_windows: BTreeSet<String>,
    unpinned: BTreeSet<String>,
}
impl ReaderModeInputs {
    pub fn event(&mut self, event: &Value) -> Value {
        let exposure = event.get("exposure");
        let goal = event.get("goal");
        let acceptance = event.get("mode_acceptance");
        let signature = event.get("signature_refusal");
        let machine = event["exposure"]["bound_set"][0]["machine"]
            .as_str()
            .unwrap_or("");
        let exposed_session = event["exposure"]["session"].as_str().unwrap_or("");
        let goal_session = event["goal"]["session"].as_str().unwrap_or("");
        let accepted_session = event["mode_acceptance"]["session"].as_str().unwrap_or("");
        let refused_machine = event["signature_refusal"]["machine"].as_str().unwrap_or("");
        let accepted =
            exposure.is_some_and(|e| e.get("accepted_modes").is_some_and(|v| v != &json!([])));
        let domain = json!({
            "exposure":exposure.is_some(),"goal":goal.is_some(),"acceptance":acceptance.is_some(),"signature":signature.is_some(),
            "exposure_accepted":accepted,
            "exposure_machine_seen":self.exposed_machines.contains(machine),
            "goal_session_exposed":self.exposed_sessions.contains(goal_session),
            "goal_session_seen":self.goals.contains(goal_session),
            "acceptance_session_exposed":self.exposed_sessions.contains(accepted_session),
            "acceptance_window_closed":self.closed_windows.contains(accepted_session),
            "signature_installation_unpinned":self.unpinned.contains(refused_machine)
        });
        if exposure.is_some() {
            self.exposed_machines.insert(machine.to_owned());
            self.exposed_sessions.insert(exposed_session.to_owned());
            if accepted {
                self.unpinned.insert(machine.to_owned());
            }
        }
        if goal.is_some() {
            self.goals.insert(goal_session.to_owned());
        }
        if acceptance.is_some() {
            self.closed_windows.insert(accepted_session.to_owned());
        }
        if let Some(session) = event
            .pointer("/intent/provenance/session")
            .and_then(Value::as_str)
        {
            self.closed_windows.insert(session.to_owned());
        }
        domain
    }
}
