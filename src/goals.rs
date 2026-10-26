//! Session-local goals and the fixed tool protocol.
use crate::dispatch::Operation;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const TURN_BOUND: usize = 10;
pub const SOURCE: &str = "operator_session_goal_card";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Goal {
    pub session: String,
    pub text: String,
    pub source: String,
    pub document_source: Option<String>,
}

impl Goal {
    pub fn valid(&self) -> bool {
        !self.text.trim().is_empty()
            && self.source == SOURCE
            && self
                .document_source
                .as_ref()
                .is_none_or(|s| document_url(s))
    }
}

pub fn document_url(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("https://") else {
        return false;
    };
    if rest
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return false;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|p| {
        p.is_empty()
            || !p.bytes().all(|b| b.is_ascii_digit())
            || p.parse::<u16>().ok().is_none_or(|n| n == 0)
    }) {
        return false;
    }
    let labels: Vec<_> = host.split('.').collect();
    if host.len() > 253
        || labels.iter().any(|label| {
            label.is_empty()
                || label.to_ascii_lowercase().starts_with("xn--")
                || label.len() > 63
                || !label.as_bytes()[0].is_ascii_alphanumeric()
                || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return false;
    }
    let last = labels.last().expect("host has a label");
    // Avoid the browser's alternative numeric IPv4 spellings and invalid numeric hosts.
    host.parse::<std::net::Ipv4Addr>().is_ok() || last.as_bytes()[0].is_ascii_alphabetic()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "name", content = "arguments", deny_unknown_fields)]
pub enum Tool {
    #[serde(rename = "exec")]
    Exec { machine: String, command: String },
    #[serde(rename = "request_harness_job")]
    Job {
        machine: String,
        job: Job,
        arguments: Value,
    },
    #[serde(rename = "request_typed_operation")]
    Typed {
        machine: String,
        operation: Operation,
        arguments: BTreeMap<String, String>,
    },
    #[serde(rename = "done")]
    Done { machine: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Job {
    FetchArtifact,
    ReadyToReset,
    PlaceSecret,
}

impl Job {
    pub fn owner(self) -> &'static str {
        match self {
            Self::FetchArtifact => "twr-i6k.5",
            Self::ReadyToReset => "twr-i6k.3",
            Self::PlaceSecret => "twr-ggw.23",
        }
    }
}
impl Tool {
    pub fn parse(value: &Value) -> Result<Self, String> {
        // Serde structs also accept positional sequences; the wire accepts objects only.
        if !value.is_object() || !value["arguments"].is_object() {
            return Err("tool schema".into());
        }
        let tool: Self = serde_json::from_value(value.clone()).map_err(|_| "tool schema")?;
        if let Self::Job { job, arguments, .. } = &tool {
            let Some(args) = arguments.as_object() else {
                return Err("job arguments".into());
            };
            let fields: &[&str] = if *job == Job::PlaceSecret {
                &[
                    "application",
                    "path",
                    "owner",
                    "mode",
                    "secret_name",
                    "purpose",
                ]
            } else {
                &[]
            };
            if args.len() != fields.len()
                || !fields
                    .iter()
                    .all(|f| args.get(*f).is_some_and(Value::is_string))
            {
                return Err("job arguments".into());
            }
        }
        if matches!(
            &tool,
            Self::Typed {
                operation: Operation::Exec | Operation::Inference,
                ..
            }
        ) {
            return Err("typed operation".into());
        }
        Ok(tool)
    }
    pub fn machine(&self) -> &str {
        match self {
            Self::Exec { machine, .. }
            | Self::Job { machine, .. }
            | Self::Typed { machine, .. }
            | Self::Done { machine } => machine,
        }
    }
}

pub fn definitions() -> Value {
    let spec = |name: &str, properties: Value, required: &[&str]| json!({"name":name,"parameters":{"type":"object","properties":properties,"required":required,"additionalProperties":false}});
    let machine = json!({"type":"string"});
    let mut job = spec(
        "request_harness_job",
        json!({"machine":machine,"job":{"enum":["fetch_artifact","ready_to_reset","place_secret"]},"arguments":{"type":"object"}}),
        &["machine", "job", "arguments"],
    );
    let secret_fields = [
        "application",
        "path",
        "owner",
        "mode",
        "secret_name",
        "purpose",
    ];
    let properties: serde_json::Map<String, Value> = secret_fields
        .iter()
        .map(|f| ((*f).into(), json!({"type":"string"})))
        .collect();
    job["parameters"]["oneOf"] = json!([
        {"properties":{"job":{"enum":["fetch_artifact","ready_to_reset"]},"arguments":{"type":"object","properties":{},"additionalProperties":false}}},
        {"properties":{"job":{"const":"place_secret"},"arguments":{"type":"object","properties":properties,"required":secret_fields,"additionalProperties":false}}}
    ]);
    json!([
        spec(
            "exec",
            json!({"machine":machine,"command":{"type":"string"}}),
            &["machine", "command"]
        ),
        job,
        spec(
            "request_typed_operation",
            json!({"machine":machine,"operation":{"enum":["create","reset","reinstall","destroy","read"]},"arguments":{"type":"object","additionalProperties":{"type":"string"}}}),
            &["machine", "operation", "arguments"]
        ),
        spec("done", json!({"machine":machine}), &["machine"])
    ])
}

pub fn untrusted(source: &str, content: Value) -> Value {
    json!({"type":"untrusted","source":source,"content":content})
}

#[allow(async_fn_in_trait, reason = "one harness worker or host fixture")]
pub trait Driver {
    fn ending(&self) -> bool;
    async fn turn(&mut self, request: &Value) -> Value;
    async fn tool(&mut self, tool: &Tool) -> Value;
    async fn proposal(
        &mut self,
        _candidate: u64,
        _proposal: crate::declaration::Proposal,
        _tool: &Tool,
    ) -> Result<(), String> {
        Err("proposal approval unavailable".into())
    }
}

pub async fn run(
    driver: &mut impl Driver,
    goal: &Goal,
    machine: &str,
    document: Option<String>,
) -> Value {
    let mut context = json!({"bound_set":[machine],"goal":{"type":"operator_goal","text":goal.text},"history":[],"approved_requirements":[]});
    if let Some(text) = document {
        context["document"] = untrusted("fetched_document", json!(text));
    }
    context["declaration_minimum"] =
        serde_json::to_value(crate::declaration::ad_hoc_minimum()).expect("minimum serializes");
    for _ in 0..TURN_BOUND {
        if driver.ending() {
            return json!({"refused":"sessions ended"});
        }
        let request =
            json!({"machine":machine,"messages":[{"role":"user","content":context.to_string()}]});
        let response = driver.turn(&request).await;
        if driver.ending() {
            return json!({"refused":"sessions ended"});
        }
        if response["finished"] != true
            || response.get("refused").is_some()
            || !response["status"]
                .as_u64()
                .is_some_and(|s| (200..300).contains(&s))
        {
            let mut outcome = json!({});
            for key in ["call", "status"] {
                if let Some(value) = response[key].as_u64() {
                    outcome[key] = json!(value);
                }
            }
            for key in ["finished", "unresolved"] {
                if let Some(value) = response[key].as_bool() {
                    outcome[key] = json!(value);
                }
            }
            if response.get("refused").is_some() {
                outcome["refused"] = json!("inference request refused");
            }
            return outcome;
        }
        if let Some(why) = response.get("tool_refusal") {
            context["history"]
                .as_array_mut()
                .expect("history array")
                .push(json!({
                    "call":{"withheld":"credential boundary"},
                    "result":untrusted("tool_output",json!({"refused":why}))
                }));
            continue;
        }
        let body: Value = response["body"]
            .as_str()
            .and_then(|s| serde_json::from_str(s).ok())
            .unwrap_or(Value::Null);
        let Some(calls) = body
            .pointer("/choices/0/message/tool_calls")
            .and_then(Value::as_array)
        else {
            return json!({"refused":"tool calls"});
        };
        if calls.len() != 1 {
            return json!({"refused":"one tool call required"});
        }
        let tool = match Tool::parse(&calls[0]) {
            Ok(tool) => tool,
            Err(why) => return json!({"refused":why}),
        };
        if tool.machine() != machine {
            return json!({"refused":"bound set"});
        }
        if let Some(value) = body.pointer("/choices/0/message/proposal") {
            let proposal = match crate::declaration::Proposal::parse(value) {
                Ok(p) => p,
                Err(why) => return json!({"refused":why}),
            };
            if proposal.machine() != machine {
                return json!({"refused":"proposal target"});
            }
            let Some(candidate) = response["call"].as_u64() else {
                return json!({"refused":"proposal identity"});
            };
            let approved = serde_json::to_value(&proposal).expect("proposal serializes");
            if let Err(why) = driver.proposal(candidate, proposal, &tool).await {
                return json!({"refused":why});
            }
            context["approved_requirements"]
                .as_array_mut()
                .expect("requirements array")
                .push(json!({"type":"operator_approved_intended_requirements","value":approved}));
        }
        #[cfg(all(target_arch = "wasm32", feature = "tracer"))]
        crate::testonly::session_point("requirements_dispatch").await;
        if driver.ending() {
            return json!({"refused":"sessions ended"});
        }
        let result = driver.tool(&tool).await;
        if matches!(tool, Tool::Done { .. }) && result["done"] == true {
            return json!({"done":true});
        }
        let call = if result["refused"] == "tool credential boundary" {
            json!({"withheld":"credential boundary"})
        } else {
            calls[0].clone()
        };
        context["history"]
            .as_array_mut()
            .expect("history array")
            .push(json!({"call":call,"result":untrusted("tool_output",result)}));
    }
    json!({"refused":"turn bound"})
}

/// The job-availability decision is deliberately after the shared command check.
#[derive(Debug)]
pub enum BoxAdmission {
    Held(crate::harness::AppendRefusal),
    Refused(crate::harness::AppendRefusal),
    JobUnavailable(&'static str),
}
pub async fn check_job(
    journal: &impl crate::harness::Journal,
    machine: &str,
    job: Job,
) -> BoxAdmission {
    match journal.check(machine).await {
        Err(
            refusal @ crate::harness::AppendRefusal::Policy(crate::dispatch::DispatchRefusal::Held(
                _,
            )),
        ) => BoxAdmission::Held(refusal),
        Err(refusal) => BoxAdmission::Refused(refusal),
        Ok(()) => BoxAdmission::JobUnavailable(job.owner()),
    }
}
