//! Original seed-gate operations, with private operands and source-derived call requirements.
use super::{Worker, completion, history};
use serde_json::{Value, json};
use std::{cell::RefCell, collections::BTreeMap, sync::Mutex};

struct Original {
    worker: Worker,
    args: Value,
    site: &'static str,
    input_ok: bool,
}
thread_local! { static ACTIVE: RefCell<Option<Original>> = const { RefCell::new(None) }; }
static EVENTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());

pub struct Dispatch;
impl Dispatch {
    pub fn begin(site: &'static str, run: &super::Run<'_>, worker: &Worker, args: &Value) -> Self {
        let mut expected = json!({"machine":"fixture","relay":run.relay.url,"host":"127.0.0.1","port":run.sshd.port,"user":super::SSH_USER,"command":super::COMMAND});
        if history::active_case_id().is_some_and(|id| id.ends_with(".p001")) {
            expected["fail_append"] = json!(false);
            expected["tamper_auth"] = json!(false);
        }

        ACTIVE.with_borrow_mut(|active| {
            assert!(active.is_none(), "nested seed refusal");
            *active = Some(Original {
                worker: worker.clone(),
                args: args.clone(),
                site,
                input_ok: *args == expected,
            });
        });
        Self
    }
}
impl Drop for Dispatch {
    fn drop(&mut self) {
        ACTIVE.with_borrow_mut(|active| {
            active.take();
        });
    }
}
fn record(site: &'static str, operation: &str, family: Option<&str>, worker: &Worker, ok: bool) {
    let (identity, page) = history::worker_identity(&worker.session);
    EVENTS.lock().unwrap().push(json!({"site":site,"operation":operation,"family":family,"worker":identity,"page":page,"ok":ok && history::selected_worker_matches(page, worker),"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor()}));
}
pub fn operation(operation: &str, worker: &Worker, args: Option<&Value>) {
    ACTIVE.with_borrow(|active| {
        if let Some(original) = active {
            record(
                original.site,
                operation,
                None,
                worker,
                original.input_ok
                    && original.worker == *worker
                    && args.is_none_or(|a| *a == original.args),
            );
        }
    });
}
pub fn allocation(site: &'static str, worker: &Worker, family: &str) {
    record(site, "allocate", Some(family), worker, true);
}
pub fn snapshot() -> Value {
    json!(*EVENTS.lock().unwrap())
}

fn program(case: &Value) -> Vec<(String, String, Value)> {
    let mut result = Vec::new();
    let mut gated = 0;
    let mut first = 0;
    let mut next = 0;
    let mut dispatch = 0;
    for predicate in case["assertions"].as_array().unwrap() {
        let site = predicate.as_str().unwrap();
        let allocation = match site {
            "seed_cases.a012" => {
                let source = if case["site_id"] == "seed_cases.c004" {
                    "seed.failed_append.allocations"
                } else if gated < 3 {
                    "seed.create.display_allocations"
                } else {
                    "seed.create.mismatch_allocations"
                };
                let slot = gated % 3;
                gated += 1;
                Some((source, slot))
            }
            "seed_cases.a023" => {
                let slot = first;
                first += 1;
                Some(("seed.completion.first_allocations", slot))
            }
            "seed_cases.a026" => {
                let slot = next;
                next += 1;
                Some(("seed.completion.next_allocations", slot))
            }
            _ => None,
        };
        if let Some((source, slot)) = allocation {
            let family = ["machines", "passes", "handoffs"]
                .get(slot)
                .expect("closed allocation family domain");
            result.push((source.into(), "allocate".into(), json!(family)));
        } else if site == "seed_cases.a013" {
            let source = if case["site_id"] == "seed_cases.c002" {
                "seed.create.refused_dispatch"
            } else if dispatch == 0 {
                "seed.reentry.displayed_refusal"
            } else {
                "seed.reentry.answering_refusal"
            };
            dispatch += 1;
            for operation in ["inspect", "run", "collect", "inspect"] {
                result.push((source.into(), operation.into(), Value::Null));
            }
        }
    }
    result
}

pub fn validate(report: &Value) -> Result<(), String> {
    let error = "original seed operation source, operand or invocation mismatch";
    let key = completion::inventory();
    let execution: Vec<_> = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .clone()
    };
    let mut expected: BTreeMap<String, Vec<_>> = key["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| execution.contains(&c["id"]))
        .map(|c| (c["id"].as_str().unwrap().into(), program(c)))
        .collect();
    let states = super::reader_checks::caller_states(report);
    let workers = history::worker_states(report);
    let pages = history::source_page_states(report)?;
    let events = report["helper_history"].as_array().ok_or(error)?;
    let mut previous = 0;
    for event in report["seed_operations"].as_array().ok_or(error)? {
        let cursor = event["history_cursor"].as_u64().ok_or(error)? as usize;
        let at = event["at_ns"].as_u64().ok_or(error)?;
        let case = event["case"].as_str().ok_or(error)?;
        let state = states.get(cursor).ok_or(error)?;
        let expected_invocation = key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == case)
            .ok_or(error)?["invocation"]
            .as_u64()
            .ok_or(error)?;
        let owner = state.owner.as_ref().ok_or(error)?;
        let page = event["page"].as_u64().ok_or(error)?;
        if event.as_object().is_none_or(|o| o.len() != 9)
            || event["ok"] != true
            || at < previous
            || at > report["duration_ns"].as_u64().ok_or(error)?
            || owner.0 != "seed_cases.run"
            || owner.1 != "inside"
            || owner.2 != case
            || state.invocation != expected_invocation
            || cursor > 0 && events[cursor - 1]["at_ns"].as_u64().ok_or(error)? > at
            || cursor < events.len() && events[cursor]["at_ns"].as_u64().ok_or(error)? < at
            || pages[cursor]
                .get(if expected_invocation == 1 {
                    "tracer"
                } else {
                    "served"
                })
                .is_none_or(|p| *p != page)
            || workers[cursor]
                .get(&page)
                .is_none_or(|w| event["worker"] != *w)
        {
            return Err(error.into());
        }
        let want = expected
            .get_mut(case)
            .filter(|v| !v.is_empty())
            .ok_or(error)?
            .remove(0);
        if event["site"] != want.0 || event["operation"] != want.1 || event["family"] != want.2 {
            return Err(error.into());
        }
        previous = at;
    }
    if expected.values().any(|v| !v.is_empty()) {
        return Err(error.into());
    }
    Ok(())
}
