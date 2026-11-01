//! Independent safe auxiliary domains. No checked helper, History, completion list,
//! mnemonic, credential, name, index value or secret-derived hash supplies an output ID.
//! Integrate the descriptor schema checks as well as the grammar expansion.
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn auxiliary_site(site: &str) -> &'static str {
    match site {
        "reader.call.main.pre_no_pin" => "reader.call.main.pre_no_pin",
        "reader.call.main.pre_no_pass" => "reader.call.main.pre_no_pass",
        "reader.call.seed.created" => "reader.call.seed.created",
        "reader.call.seed.envelope_finished" => "reader.call.seed.envelope_finished",
        "reader.call.binding.saved" => "reader.call.binding.saved",
        "reader.call.mode.original" => "reader.call.mode.original",
        "reader.call.session_end.original" => "reader.call.session_end.original",
        "reader.call.lifecycle.original" => "reader.call.lifecycle.original",
        "reader.call.main.created" => "reader.call.main.created",
        "reader.call.seed.collision_completion" => "reader.call.seed.collision_completion",
        "reader.call.seed.mismatch_absence" => "reader.call.seed.mismatch_absence",
        "reader.call.seed.completion" => "reader.call.seed.completion",
        "reader.call.seed.completion_reopened" => "reader.call.seed.completion_reopened",
        "reader.call.seed.failed_completion_absence" => {
            "reader.call.seed.failed_completion_absence"
        }
        "reader.call.seed.redisplay_completion" => "reader.call.seed.redisplay_completion",
        "reader.call.seed.allocations_after_completion" => {
            "reader.call.seed.allocations_after_completion"
        }
        "reader.call.setup.approved" => "reader.call.setup.approved",
        "reader.call.goal.leakage_scan" => "reader.call.goal.leakage_scan",
        "reader.call.inference.leakage" => "reader.call.inference.leakage",
        "reader.call.binding.authorized_key_source" => "reader.call.binding.authorized_key_source",
        "reader.call.binding.authentication_index" => "reader.call.binding.authentication_index",
        "reader.call.binding.opened_source" => "reader.call.binding.opened_source",
        "reader.call.binding.allocated_pass_source" => "reader.call.binding.allocated_pass_source",
        "reader.call.main.leakage" => "reader.call.main.leakage",
        "reader.call.main.recorded_command" => "reader.call.main.recorded_command",
        "reader.call.main.pre_disposition" => "reader.call.main.pre_disposition",
        "reader.call.main.replacement_terminal" => "reader.call.main.replacement_terminal",
        "reader.call.seed.failed_completion_current" => {
            "reader.call.seed.failed_completion_current"
        }
        "reader.call.seed.failed_completion_baseline" => {
            "reader.call.seed.failed_completion_baseline"
        }
        "reader.call.setup.pre_approval" => "reader.call.setup.pre_approval",
        "reader.call.setup.classified" => "reader.call.setup.classified",
        "reader.call.typed.original" => "reader.call.typed.original",
        "reader.call.typed.reset_confirmed" => "reader.call.typed.reset_confirmed",
        "reader.call.typed.disposition_confirmed" => "reader.call.typed.disposition_confirmed",
        "reader.call.job.new_shapes" => "reader.call.job.new_shapes",
        "reader.call.job.disposition_source" => "reader.call.job.disposition_source",
        "reader.call.job.older_source" => "reader.call.job.older_source",
        "reader.call.hold.original" => "reader.call.hold.original",
        "reader.call.hold.stop_augmented" => "reader.call.hold.stop_augmented",
        "reader.call.hold.legacy_source" => "reader.call.hold.legacy_source",
        "reader.call.hold.unreachable_source" => "reader.call.hold.unreachable_source",
        "reader.call.hold.destructive_source" => "reader.call.hold.destructive_source",
        "reader.call.binding.unbound_refusal" => "reader.call.binding.unbound_refusal",
        "reader.call.binding.authentication_journal" => {
            "reader.call.binding.authentication_journal"
        }
        "reader.call.binding.exposure_ledger" => "reader.call.binding.exposure_ledger",
        "reader.call.mode.signature_refusal" => "reader.call.mode.signature_refusal",
        "reader.call.inference.sent_read_original" => "reader.call.inference.sent_read_original",
        "reader.call.inference.core_terminals" => "reader.call.inference.core_terminals",
        "reader.call.inference.reload_revoke" => "reader.call.inference.reload_revoke",
        "reader.call.session_end.rekey_evidence" => "reader.call.session_end.rekey_evidence",
        "reader.call.lifecycle.dedicated_original" => "reader.call.lifecycle.dedicated_original",
        "reader.call.lifecycle.dedicated_successor" => "reader.call.lifecycle.dedicated_successor",
        "reader.call.lifecycle.original_mint" => "reader.call.lifecycle.original_mint",
        "reader.call.lifecycle_repairs.clock_terminal" => {
            "reader.call.lifecycle_repairs.clock_terminal"
        }
        "reader.call.lifecycle_repairs.command_release" => {
            "reader.call.lifecycle_repairs.command_release"
        }
        "reader.call.goal.recorded" => "reader.call.goal.recorded",
        "reader.call.goal.before_turn" => "reader.call.goal.before_turn",
        "reader.call.goal.after_turn" => "reader.call.goal.after_turn",
        "reader.call.goal_admission.holding_source" => "reader.call.goal_admission.holding_source",
        "reader.call.goal_admission.stale_cleanup" => "reader.call.goal_admission.stale_cleanup",
        "reader.call.declaration.approved" => "reader.call.declaration.approved",
        "reader.call.declaration.tightened" => "reader.call.declaration.tightened",
        "reader.call.declaration.lifecycle" => "reader.call.declaration.lifecycle",
        "reader.call.delivery.results" => "reader.call.delivery.results",
        "reader.call.delivery.findings" => "reader.call.delivery.findings",
        "reader.call.delivery.lifecycle" => "reader.call.delivery.lifecycle",
        "reader.call.delivery.incomplete" => "reader.call.delivery.incomplete",
        "reader.call.delivery.amendment" => "reader.call.delivery.amendment",
        "reader.call.delivery.report_success" => "reader.call.delivery.report_success",
        "reader.call.delivery.report_failure" => "reader.call.delivery.report_failure",
        "reader.call.settle_unresolved.disposition_source" => {
            "reader.call.settle_unresolved.disposition_source"
        }
        "reader.call.binding.contracts_source" => "reader.call.binding.contracts_source",
        _ => "unknown",
    }
}
fn auxiliary_empty(count: usize) -> Vec<Value> {
    (0..count).map(|_| json!({})).collect()
}
fn auxiliary_records(records: &[(u64, Vec<u8>)]) -> Vec<Value> {
    records
        .iter()
        .map(|(_, bytes)| {
            // This independent input projection precedes the actual auxiliary parser loop.
            // Its parse result never supplies an actual guard result; malformed input still
            // reaches original mnemonic/backups/passes errors in the actual helper.
            let raw = serde_json::from_slice::<Value>(bytes).unwrap_or(Value::Null);
            json!({
                "backup":raw.pointer("/allocation/seed_backup").is_some(),
                "pass":raw.pointer("/allocation/reserve/family").is_some_and(|v|v == "passes"),
                "machine_entries":raw.pointer("/setup/approval/entries").and_then(Value::as_array).map(|entries|entries.iter().map(|entry|json!({"key":match entry["entry"]["machine"].as_str() {Some("fixture")=>"machine.first",Some("fixture-other")=>"machine.second",_=>"other"}})).collect::<Vec<_>>()).unwrap_or_default()
            })
        })
        .collect()
}

/// Contains the actual source fixture applicability, read from the independently
/// admitted helper_owner_sequences row and its preparation ordinal. Fields are private
/// so a caller-supplied build/enrol label cannot construct its own expectation.
pub struct AuxiliaryPrepareSource {
    active: bool,
    machines: usize,
    pass_birth: bool,
    served: bool,
    enrol: bool,
}
impl AuxiliaryPrepareSource {
    pub fn from_source_row(row: &Value, ordinal: usize) -> Option<Self> {
        let domain = ordinal
            .checked_sub(1)
            .and_then(|i| row["prepare_domains"].as_array().and_then(|a| a.get(i)))?;
        let scenario = row["scenario"].as_str()?;
        let owner = row["owner"].as_str()?;
        let case = row["case"].as_str().unwrap_or("");
        let active = domain["active"].as_bool()?;
        let classes = domain["classes"].as_array();
        if (active && classes.is_none())
            || classes.is_some_and(|a| a.iter().any(|v| !v.is_boolean()))
        {
            return None;
        }
        let machines = classes.map_or(0, Vec::len);
        let pass_birth = if active && machines > 0 {
            domain["pass"].as_bool()?
        } else {
            false
        };
        // These are source call sites, not observed page labels. They are the five
        // served preparations and one explicit prepare_without_enrolment source slot.
        let served = (scenario == "main.run" && owner == "inside" && case == "main.c001.p001")
            || (scenario == "binding_cases.run" && case.ends_with(".p002"))
            || (scenario == "mode_cases.run" && owner == "after" && case == "mode_cases.c001.p001");
        let enrol = !(scenario == "main.run"
            && owner == "inside"
            && case == "main.c012.p001"
            && ordinal == 1);
        Some(Self {
            active,
            machines,
            pass_birth,
            served,
            enrol,
        })
    }
    fn relay_key(&self) -> bool {
        self.active && self.machines > 0 && !self.served && self.enrol
    }
}

/// Gather BEFORE main's displayed-mnemonic helper loop. The actual phrases remain
/// private. Only input cardinality and finite source/equality aliases are serialized.
pub struct AuxiliaryDisplayedInputs {
    displayed: BTreeSet<String>,
}
impl AuxiliaryDisplayedInputs {
    pub fn from_messages(messages: &crate::auxiliary::Messages) -> Self {
        messages.bind_domain();
        let displayed = messages
            .iter()
            .filter_map(|m| {
                m.pointer("/from/seed_backup_display")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        Self { displayed }
    }
    pub fn preview_domain(&self) -> Value {
        json!({"displayed":auxiliary_empty(self.displayed.len())})
    }
    fn fields(&self, records: &[(u64, Vec<u8>)]) -> (Vec<Value>, Vec<Value>, &'static str) {
        let first = records
            .first()
            .and_then(|(_, b)| serde_json::from_slice::<Value>(b).ok());
        let current = first
            .as_ref()
            .and_then(|v| v.pointer("/seed/mnemonic"))
            .and_then(Value::as_str);
        // A BTreeSet has at most one current seed. Thus an existing earlier-seed
        // lookup reaches one or two predicate invocations, never an unbounded loop.
        // Capture this before the actual .find() invokes Opened::mnemonic repeatedly.
        let position = current.and_then(|m| self.displayed.iter().position(|p| p != m));
        let count = position.map_or(0, |i| i + 1);
        let search = if (1..=2).contains(&count) {
            "found"
        } else {
            "unknown"
        };
        (
            auxiliary_empty(self.displayed.len()),
            auxiliary_empty(count),
            search,
        )
    }
}

fn auxiliary_backup_shape(
    site: &str,
    source_case: &str,
    root_count: usize,
    records: &[Value],
) -> &'static str {
    let positions: Vec<_> = records
        .iter()
        .enumerate()
        .filter_map(|(i, r)| (r["backup"] == true).then_some(i))
        .collect();
    let good = match site {
        "reader.call.seed.collision_completion" | "reader.call.seed.completion" => {
            root_count == 2 && positions == [1]
        }
        "reader.call.seed.mismatch_absence" | "reader.call.seed.failed_completion_absence" => {
            root_count == 1 && positions.is_empty()
        }
        "reader.call.seed.completion_reopened" => match source_case {
            "seed_cases.c003.p001" | "seed_cases.c003.p002" => root_count == 5 && positions == [1],
            "seed_cases.c003.p003" | "seed_cases.c003.p004" => root_count == 2 && positions == [1],
            _ => false,
        },
        "reader.call.seed.redisplay_completion" => {
            root_count >= 3 && positions == [1, root_count - 1]
        }
        _ => false,
    };
    if good { "complete" } else { "unknown" }
}

/// root_site/source_role/source_case and source_prepare MUST come from the independently
/// expected root caller slot, not from a completed helper. root_count is the originating
/// independent numeric-file census. The actual Opened must retain only its originating
/// root-instance association; do not derive an identity by hashing secret input.
pub fn auxiliary_root(
    root_site: &str,
    source_role: &str,
    source_case: &str,
    root_count: usize,
    raw: &Value,
    source_prepare: Option<&AuxiliaryPrepareSource>,
) -> Value {
    let site = auxiliary_site(root_site);
    let rows = raw["records"].as_array().cloned().unwrap_or_default();
    let record_domain = if rows.len() == root_count {
        "complete"
    } else {
        "unknown"
    };
    let backup_domain = auxiliary_backup_shape(site, source_case, root_count, &rows);
    let mut machines = Vec::new();
    let mut relay_key = false;
    let mut final_opened = false;
    let mut expected_pass_count = None;
    if let Some(p) = source_prepare
        && p.active
        && p.machines > 0
    {
        final_opened = match site {
            "reader.call.binding.opened_source" => !p.pass_birth,
            "reader.call.binding.allocated_pass_source" => p.pass_birth,
            _ => false,
        };
        if final_opened {
            machines.push(json!({"key":"machine.first"}));
            if p.machines >= 2 {
                machines.push(json!({"key":"machine.second"}));
            }
            relay_key = p.relay_key();
        }
        expected_pass_count = match site {
            "reader.call.binding.opened_source" => {
                Some(usize::from(!p.pass_birth && p.relay_key()))
            }
            "reader.call.binding.allocated_pass_source" if p.pass_birth => Some(1),
            _ => None,
        };
    }
    let pass_count = rows.iter().filter(|r| r["pass"] == true).count();
    let pass_domain = if expected_pass_count == Some(pass_count) {
        "complete"
    } else {
        "unknown"
    };
    let key = match source_role {
        "fixture" => "machine.first",
        "fixture_other" => "machine.second",
        _ => "unknown",
    };
    let machine_index_records: Vec<_> = rows
        .iter()
        .scan(false, |found, row| {
            if *found {
                return None;
            }
            *found = row["machine_entries"]
                .as_array()
                .is_some_and(|entries| entries.iter().any(|entry| entry["key"] == key));
            Some(json!({"found":*found}))
        })
        .collect();
    let displayed_rows = raw["displayed"].clone();
    let search_rows = raw["earlier_search"].clone();
    let earlier = raw["earlier"].clone();
    json!({
        "site":site,"record_domain":record_domain,"backup_domain":backup_domain,"pass_domain":pass_domain,
        "records":rows,"three":auxiliary_empty(3),"setup_entries":auxiliary_empty(2),
        "final_opened":final_opened,"machine_keys":machines,"relay_key":relay_key,"relay":{"key":"pass.first"},
        "key":key,"machine_first":{"key":"machine.first"},"machine_index_records":machine_index_records,
        "displayed":displayed_rows,"earlier_search":search_rows,"earlier":earlier,
        "nonseed_records":auxiliary_empty(root_count.saturating_sub(1)),
        "tracer":site == "reader.call.main.leakage" && source_case == "main.c022.p002"
    })
}

/// Absence uses five source-fixed phrases (one explicit seed plus four checked-in
/// collision vectors), two source roles, and two source indices. Each occurrence of
/// the required absence check owns this complete independent caller vector.
pub fn auxiliary_absence() -> Value {
    json!({"phrases":(0..5).map(|_|json!({"roles":[
        {"keys":[{"key":"machine.first"},{"key":"machine.second"}]},
        {"keys":[{"key":"pass.first"},{"key":"pass.second"}]}
    ]})).collect::<Vec<_>>()})
}

/// Use the literal expected caller from constructor-caller-rules.json. The actual
/// setup_events parameter must separately map its actual slice to the same roster
/// alias; an observed successful child count never generates this source caller list.
pub fn auxiliary_constructor(caller: &str, roster: &str) -> Value {
    let caller = match caller {
        "reader.aux.call.main.inference_setup" => "reader.aux.call.main.inference_setup",
        "reader.aux.call.main.no_pin_setup" => "reader.aux.call.main.no_pin_setup",
        "reader.aux.call.main.no_pass_setup" => "reader.aux.call.main.no_pass_setup",
        "reader.aux.call.hold.setup" => "reader.aux.call.hold.setup",
        "reader.aux.call.mode.setup" => "reader.aux.call.mode.setup",
        "reader.aux.call.inference.sent_read_setup" => "reader.aux.call.inference.sent_read_setup",
        "reader.aux.call.session_end.setup" => "reader.aux.call.session_end.setup",
        "reader.aux.call.lifecycle.setup" => "reader.aux.call.lifecycle.setup",
        "reader.aux.call.goal_admission.initial_base" => {
            "reader.aux.call.goal_admission.initial_base"
        }
        "reader.aux.call.goal_admission.holding_base" => {
            "reader.aux.call.goal_admission.holding_base"
        }
        "reader.aux.call.goal.initial_base" => "reader.aux.call.goal.initial_base",
        "reader.aux.call.declaration.initial.first" => "reader.aux.call.declaration.initial.first",
        "reader.aux.call.declaration.initial.decision" => {
            "reader.aux.call.declaration.initial.decision"
        }
        "reader.aux.call.declaration.initial.proposal_writer" => {
            "reader.aux.call.declaration.initial.proposal_writer"
        }
        "reader.aux.call.declaration.initial.requirements" => {
            "reader.aux.call.declaration.initial.requirements"
        }
        "reader.aux.call.delivery.prepare.initial" => "reader.aux.call.delivery.prepare.initial",
        "reader.aux.call.delivery.amendment.initial" => {
            "reader.aux.call.delivery.amendment.initial"
        }
        "reader.aux.call.delivery.report_success.initial" => {
            "reader.aux.call.delivery.report_success.initial"
        }
        "reader.aux.call.delivery.report_failure.initial" => {
            "reader.aux.call.delivery.report_failure.initial"
        }
        _ => "unknown",
    };
    let roster = match roster {
        "one" => "one",
        "two" => "two",
        "three" => "three",
        _ => "unknown",
    };
    json!({"caller":caller,"roster":roster})
}

/// Only these safe raw fields belong in public root evidence. Consumers obtain
/// every source flag/program choice from the independent caller/prepare registry.
pub fn auxiliary_raw_root(
    records: &[(u64, Vec<u8>)],
    displayed: Option<&AuxiliaryDisplayedInputs>,
) -> Value {
    let (displayed_rows, search_rows, earlier) = displayed.map_or_else(
        || (Vec::new(), Vec::new(), "unknown"),
        |d| d.fields(records),
    );
    json!({
        "records":auxiliary_records(records),"displayed":displayed_rows,
        "earlier_search":search_rows,"earlier":earlier,"reload_revoke":null
    })
}
