//! Original finite DOM polling queries. Raw expressions and returned values stay private.
use crate::{completion, history};
use serde_json::{Value, json};
use std::sync::Mutex;
static INPUTS: Mutex<Vec<Value>> = Mutex::new(Vec::new());

fn source(site: &str) -> Option<(&'static str, &'static str)> {
    Some(match site {
        "goal.card.accept_visible" | "goal.status.accept_visible" => {
            ("true", "!!document.querySelector('[data-goal-accept]')")
        }
        "goal.context.done_visible" => (
            "true",
            "document.querySelector('[data-goal-outcome]')?.textContent==='Goal loop ended: done.'",
        ),
        "goal.status.other_accept_visible" => (
            "true",
            "!!document.querySelector('[data-machine=fixture-other] [data-goal-accept]')",
        ),
        "goal.status.other_done_visible" => (
            "true",
            "document.querySelector('[data-machine=fixture-other] [data-goal-outcome]')?.textContent === 'Goal loop ended: done.'",
        ),
        "delivery.card.applications_visible" => (
            "two",
            "document.querySelectorAll('[data-delivery-application]').length",
        ),
        _ => return None,
    })
}

pub struct PageValue {
    value: crate::cdp::OriginalEvaluation,
    source: usize,
    kind: &'static str,
}
#[must_use]
pub struct Poll {
    ready: bool,
    source: Option<usize>,
}
impl From<bool> for Poll {
    fn from(ready: bool) -> Self {
        Self {
            ready,
            source: None,
        }
    }
}
impl Poll {
    pub fn consume(self, binding: &crate::observer::poll_boundary::Binding) -> bool {
        let (call, attempt) = binding.coordinates();
        let Some(source) = self.source else {
            return self.ready;
        };
        let mut rows = INPUTS.lock().unwrap();
        let row = &mut rows[source - 1];
        let ok = row["call"] == call
            && row["attempt"] == attempt
            && row["used_ns"].is_null()
            && row["operand_ok"] == true
            && row["comparison_count"] == 1
            && row["comparison_result"] == self.ready;
        row["operand_ok"] = json!(ok);
        row["used_ns"] = json!(completion::now());
        self.ready && ok
    }
}
impl PageValue {
    fn compared(self, result: bool, operand_ok: bool) -> Poll {
        let mut rows = INPUTS.lock().unwrap();
        let row = &mut rows[self.source - 1];
        row["comparison_count"] = json!(row["comparison_count"].as_u64().unwrap() + 1);
        row["comparison_ns"] = json!(completion::now());
        row["comparison_result"] = json!(result);
        row["operand_ok"] = json!(operand_ok && row["ready"] == result);
        Poll {
            ready: result,
            source: Some(self.source),
        }
    }
    pub fn equals_true(self) -> Poll {
        let result = *self.value == true;
        let operand_ok = self.kind == "true";
        self.compared(result, operand_ok)
    }
    pub fn equals_two(self) -> Poll {
        let result = *self.value == 2;
        let operand_ok = self.kind == "two";
        self.compared(result, operand_ok)
    }
}

pub async fn evaluate(
    call: usize,
    site: &str,
    attempt: usize,
    run: &crate::Run<'_>,
    session: &str,
    expression: &str,
) -> Result<PageValue, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let value = run.browser.evaluate_original(session, expression).await?;
    let (kind, expected) = source(site).ok_or("unknown original page query")?;
    let ready = if kind == "true" {
        *value == true
    } else {
        *value == 2
    };
    let mut inputs = INPUTS.lock().unwrap();
    let id = inputs.len() + 1;
    inputs.push(json!({"source":id,"call":call,"attempt":attempt,"kind":kind,"page":history::page_id(session),"start_ns":start,"end_ns":completion::now(),"history_cursor":cursor,"query_ok":value.within(start,cursor)&&value.matches(session,expected),"ready":ready,"used_ns":null,"operand_ok":null,"comparison_ns":null,"comparison_count":0,"comparison_result":null}));
    Ok(PageValue {
        value,
        source: id,
        kind,
    })
}

pub fn snapshot() -> Value {
    json!(*INPUTS.lock().unwrap())
}

pub fn validate(report: &Value) -> Result<(), String> {
    let error = "original page query/value/predicate provenance mismatch";
    let rules = completion::inventory()["page_query_sources"]
        .as_object()
        .ok_or(error)?;
    let calls = report["observer_calls"].as_array().ok_or(error)?;
    let rows = report["page_query_inputs"].as_array().ok_or(error)?;
    let mut expected = Vec::new();
    for (index, call) in calls.iter().enumerate() {
        if let Some(kind) = rules.get(call["site"].as_str().ok_or(error)?) {
            if !matches!(kind.as_str(), Some("true" | "two")) {
                return Err(error.into());
            }
            for poll in call["polls"].as_array().ok_or(error)? {
                expected.push((index + 1, call, kind, poll));
            }
        }
    }
    if rows.len() != expected.len() {
        return Err(error.into());
    }
    let mut previous = 0;
    for (index, (row, (call, owner, kind, poll))) in rows.iter().zip(expected).enumerate() {
        let start = row["start_ns"].as_u64().ok_or(error)?;
        let end = row["end_ns"].as_u64().ok_or(error)?;
        let used = row["used_ns"].as_u64().ok_or(error)?;
        if row.as_object().is_none_or(|o| o.len() != 15)
            || row["source"] != index + 1
            || row["call"] != call
            || row["attempt"] != poll["attempt"]
            || row["kind"] != *kind
            || row["page"] != owner["page"]
            || row["history_cursor"] != poll["start_cursor"]
            || row["history_cursor"] != poll["end_cursor"]
            || row["query_ok"] != true
            || row["operand_ok"] != true
            || row["comparison_count"] != 1
            || row["comparison_result"] != row["ready"]
            || row["comparison_ns"]
                .as_u64()
                .is_none_or(|at| at < end || at > used)
            || !row["ready"].is_boolean()
            || row["ready"] != poll["ready"]
            || start < previous
            || start < poll["start_ns"].as_u64().ok_or(error)?
            || end < start
            || used < end
            || used > poll["end_ns"].as_u64().ok_or(error)?
        {
            return Err(error.into());
        }
        previous = used;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn original_query_and_consumed_result_are_both_required() {
        let base = json!({"observer_calls":[{"site":"goal.card.accept_visible","page":1,"polls":[{"attempt":1,"ready":true,"start_ns":1,"end_ns":5,"start_cursor":3,"end_cursor":3}]}],"page_query_inputs":[{"source":1,"call":1,"attempt":1,"kind":"true","page":1,"start_ns":2,"end_ns":3,"history_cursor":3,"query_ok":true,"ready":true,"used_ns":4,"operand_ok":true,"comparison_ns":3,"comparison_count":1,"comparison_result":true}]});
        validate(&base).unwrap();
        for (field, value) in [
            ("query_ok", json!(false)),
            ("operand_ok", json!(false)),
            ("comparison_count", json!(0)),
            ("comparison_count", json!(2)),
            ("comparison_result", json!(false)),
            ("comparison_ns", json!(1)),
            ("ready", json!(false)),
            ("call", json!(2)),
            ("history_cursor", json!(4)),
        ] {
            let mut bad = base.clone();
            bad["page_query_inputs"][0][field] = value;
            assert!(validate(&bad).is_err());
        }
        let mut bad = base.clone();
        bad["page_query_inputs"] = json!([]);
        assert!(validate(&bad).is_err());
        validate(&base).unwrap();
    }
}
