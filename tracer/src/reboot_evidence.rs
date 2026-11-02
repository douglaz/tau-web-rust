//! Closed observations for the ordinary reboot assertion. No raw worker values escape.
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CollectionState {
    Finished,
    Running,
    Ended,
    Missing,
    OtherMachine,
    Incomplete,
    Absent,
    Unrecognized,
}
impl CollectionState {
    fn observe(value: &Value) -> Self {
        match value.as_str() {
            Some("finished") => Self::Finished,
            Some("running") => Self::Running,
            Some("ended") => Self::Ended,
            Some("missing") => Self::Missing,
            Some("other_machine") => Self::OtherMachine,
            Some("incomplete") => Self::Incomplete,
            None if value.is_null() => Self::Absent,
            _ => Self::Unrecognized,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    Unresolved,
    Finished,
    Disposed,
    Cancelled,
    Absent,
    Unrecognized,
}
#[derive(Debug, Serialize)]
pub struct Job {
    call: u64,
    collection: CollectionState,
    call_state: CallState,
    terminal: Option<bool>,
}
impl Job {
    pub fn observe(call: u64, collection: &Value, state: &Value) -> Self {
        let observed = state["calls"]
            .as_array()
            .and_then(|calls| calls.iter().find(|c| c["call"] == call));
        let call_state = match observed.map(|c| c["state"].as_str()) {
            Some(Some("unresolved")) => CallState::Unresolved,
            Some(Some("finished")) => CallState::Finished,
            Some(Some("disposed")) => CallState::Disposed,
            Some(Some("cancelled")) => CallState::Cancelled,
            None if state["calls"].is_array() => CallState::Absent,
            _ => CallState::Unrecognized,
        };
        Self {
            call,
            collection: CollectionState::observe(&collection["state"]),
            call_state,
            terminal: state["terminals"]
                .as_array()
                .map(|ts| ts.iter().any(|t| t["call"] == call)),
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Fixture {
    pub setup_ms: u64,
    pub boundary_alive: bool,
    pub boundary_stopped: bool,
    pub record_present: bool,
    pub exit_present: bool,
    pub record_boot_matches: bool,
    pub after_alive: bool,
    pub after_exit_present: bool,
    pub record_boot_preserved: bool,
    pub missing_record_absent: bool,
}
#[derive(Debug, Serialize)]
pub struct Checks {
    boot_changed: bool,
    running_ended: bool,
    missing_missing: bool,
    running_unresolved: bool,
    missing_unresolved: bool,
    running_no_terminal: bool,
    missing_no_terminal: bool,
}
#[derive(Debug, Serialize)]
pub struct Reboot {
    boot_changed: bool,
    running: Job,
    missing: Job,
    fixture: Fixture,
    checks: Checks,
}
impl Reboot {
    pub fn observe(boot_changed: bool, running: Job, missing: Job, fixture: Fixture) -> Self {
        let checks = Checks {
            boot_changed,
            running_ended: running.collection == CollectionState::Ended,
            missing_missing: missing.collection == CollectionState::Missing,
            running_unresolved: running.call_state == CallState::Unresolved,
            missing_unresolved: missing.call_state == CallState::Unresolved,
            running_no_terminal: running.terminal == Some(false),
            missing_no_terminal: missing.terminal == Some(false),
        };
        Self {
            boot_changed,
            running,
            missing,
            fixture,
            checks,
        }
    }
    pub fn holds(&self) -> bool {
        let c = &self.checks;
        c.boot_changed
            && c.running_ended
            && c.missing_missing
            && c.running_unresolved
            && c.missing_unresolved
            && c.running_no_terminal
            && c.missing_no_terminal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fixture() -> Fixture {
        Fixture {
            setup_ms: 31001,
            boundary_alive: true,
            boundary_stopped: true,
            record_present: true,
            exit_present: false,
            record_boot_matches: true,
            after_alive: false,
            after_exit_present: false,
            record_boot_preserved: true,
            missing_record_absent: true,
        }
    }
    #[test]
    fn absent_unrecognized_and_terminal_observations_are_distinct() {
        let state = json!({"calls":[{"call":2,"state":"SENTINEL"}],"terminals":[{"call":2}]});
        let running = Job::observe(2, &json!({"state":"SENTINEL"}), &state);
        let missing = Job::observe(3, &Value::Null, &state);
        let value = Reboot::observe(false, running, missing, fixture());
        assert!(!value.holds());
        let safe = json!(value);
        assert_eq!(safe["running"]["collection"], "unrecognized");
        assert_eq!(safe["running"]["call_state"], "unrecognized");
        assert_eq!(safe["running"]["terminal"], true);
        assert_eq!(safe["missing"]["collection"], "absent");
        assert_eq!(safe["missing"]["call_state"], "absent");
        assert_eq!(safe["missing"]["terminal"], false);
        assert!(!safe.to_string().contains("SENTINEL"));
        let absent = json!(Job::observe(2, &Value::Null, &Value::Null));
        assert_eq!(absent["call_state"], "unrecognized");
        assert!(absent["terminal"].is_null());
        assert!(safe.to_string().len() < 2048);
    }
    #[test]
    fn each_of_the_seven_observations_is_required() {
        let baseline = json!({"calls":[{"call":2,"state":"unresolved"},{"call":3,"state":"unresolved"}],"terminals":[]});
        for operand in 0..8 {
            let mut state = baseline.clone();
            if operand == 3 {
                state["calls"][0]["state"] = json!("finished");
            }
            if operand == 4 {
                state["calls"][1]["state"] = json!("disposed");
            }
            if operand == 5 {
                state["terminals"] = json!([{"call":2}]);
            }
            if operand == 6 {
                state["terminals"] = json!([{"call":3}]);
            }
            let value = Reboot::observe(
                operand != 0,
                Job::observe(
                    2,
                    &json!({"state":if operand==1 {"finished"} else {"ended"}}),
                    &state,
                ),
                Job::observe(
                    3,
                    &json!({"state":if operand==2 {"ended"} else {"missing"}}),
                    &state,
                ),
                fixture(),
            );
            assert_eq!(value.holds(), operand == 7);
            let failed = json!(value)["checks"]
                .as_object()
                .unwrap()
                .values()
                .filter(|b| b.as_bool() == Some(false))
                .count();
            assert_eq!(failed, usize::from(operand != 7));
        }
    }
}
