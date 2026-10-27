use super::*;
use crate::delivery::{self, Measurements, ResultSet};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub machine: String,
    pub requirements: u64,
    pub class: crate::dispatch::MachineClass,
    pub declaration: crate::declaration::Declaration,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Check {
    pub session: String,
    pub authority: Authority,
    pub measurements: Measurements,
    pub result: ResultSet,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Check {
        check: Box<Check>,
    },
    Application {
        machine: String,
        name: String,
    },
    /// The smallest recovery seam: no sheet import/recovery machinery is supplied here.
    FindingsUnknown {
        machine: String,
    },
    /// Evidence from the later placing-session producer, with no secret value or provider.
    SubsequentPlacement {
        machine: String,
        session: String,
    },
}
#[derive(Clone, Default)]
pub(super) struct Machine {
    checks: Vec<Check>,
    findings: Vec<delivery::Finding>,
    unknown: bool,
    applications: Vec<String>,
    placements_since_check: Vec<String>,
    placing_sessions: std::collections::BTreeSet<String>,
}
#[derive(Clone, Default)]
pub(super) struct State(BTreeMap<String, Machine>);

impl<S: Storage> Store<S> {
    pub fn delivery_authority(&self, session: &str, machine: &str) -> Result<Authority, String> {
        let live = self.live_goal_session(session)?;
        if !live.bound_set.iter().any(|m| m == machine) {
            return Err("bound set".into());
        }
        if self.pending_requirements.contains_key(session) {
            return Err("proposal approval pending".into());
        }
        self.journaled_delivery_authority(machine)
    }
    fn journaled_delivery_authority(&self, machine: &str) -> Result<Authority, String> {
        self.dispatch.check_installation(machine)?;
        let m = &self.dispatch.approved_entries[machine];
        let declaration = m
            .declaration
            .clone()
            .ok_or("approved declaration missing")?;
        declaration.validate_ad_hoc_minimum()?;
        Ok(Authority {
            machine: machine.into(),
            requirements: m.requirements.len() as u64,
            class: m.class.ok_or("class missing")?,
            declaration,
        })
    }
    pub async fn delivery_check(
        &mut self,
        session: &str,
        authority: Authority,
        mut measurements: Measurements,
    ) -> Result<(), String> {
        if self.delivery_authority(session, &authority.machine)? != authority {
            return Err("stale delivery authority".into());
        }
        let m = self
            .delivery
            .0
            .get(&authority.machine)
            .cloned()
            .unwrap_or_default();
        // A recorded placement in this session cannot be forgotten by a later producer.
        measurements.placing_session |= m.placing_sessions.contains(session);
        let result = delivery::evaluate(
            &authority.declaration,
            authority.class,
            &measurements,
            &m.findings,
            m.unknown,
        );
        self.delivery_record(Record::Check {
            check: Box::new(Check {
                session: session.into(),
                authority,
                measurements,
                result,
            }),
        })
        .await
    }
    pub fn refuse_finding_acceptance(&self) -> Result<(), String> {
        Err(
            "a finding clears only on a re-check after a fix or journaled declaration amendment"
                .into(),
        )
    }
    pub async fn record_application(
        &mut self,
        session: &str,
        machine: &str,
        name: String,
    ) -> Result<(), String> {
        self.delivery_authority(session, machine)?;
        self.delivery_record(Record::Application {
            machine: machine.into(),
            name,
        })
        .await
    }
    async fn delivery_record(&mut self, record: Record) -> Result<(), String> {
        let state = self.validate_delivery(&record)?;
        self.commit(&Event::Delivery(record)).await?;
        self.delivery = state;
        Ok(())
    }
    pub(super) fn validate_delivery(&self, record: &Record) -> Result<State, String> {
        if !crate::redaction::Redacted::inference_value_is_safe(
            self,
            &serde_json::to_value(record).expect("delivery serializes"),
            &[],
        ) {
            return Err("delivery credential boundary".into());
        }
        let machine = match record {
            Record::Check { check } => &check.authority.machine,
            Record::Application { machine, .. }
            | Record::FindingsUnknown { machine }
            | Record::SubsequentPlacement { machine, .. } => machine,
        };
        if !self.dispatch.approved_entries.contains_key(machine) {
            return Err("delivery machine missing".into());
        }
        let mut state = self.delivery.clone();
        let m = state.0.entry(machine.clone()).or_default();
        match record {
            Record::Check { check } => {
                if m.placing_sessions.contains(&check.session)
                    && !check.measurements.placing_session
                {
                    return Err("delivery omits placing-session qualification".into());
                }
                if check.authority != self.journaled_delivery_authority(machine)? {
                    return Err("stale delivery authority".into());
                }
                if !self.exposure_ledger.iter().any(|e| {
                    e.session == check.session && e.bound_set.iter().any(|b| b.machine == *machine)
                }) {
                    return Err("delivery session provenance".into());
                }
                let result = delivery::evaluate(
                    &check.authority.declaration,
                    check.authority.class,
                    &check.measurements,
                    &m.findings,
                    m.unknown,
                );
                if result != check.result {
                    return Err("delivery result differs from evidence".into());
                }
                m.findings = result.findings.clone();
                m.unknown = m.unknown && !result.complete;
                m.checks.push(check.as_ref().clone());
                // An unavailable/partial attempt is not the final demonstration. Keep
                // placement evidence until a complete re-check, including across replay.
                if result.complete {
                    m.placements_since_check.clear();
                }
            }
            Record::Application { name, .. } => {
                if name.is_empty() || m.applications.contains(name) {
                    return Err("empty or repeated application name on machine".into());
                }
                m.applications.push(name.clone());
            }
            Record::FindingsUnknown { .. } => {
                m.unknown = true;
            }
            Record::SubsequentPlacement { session, .. } => {
                if !self.exposure_ledger.iter().any(|e| {
                    e.session == *session && e.bound_set.iter().any(|b| b.machine == *machine)
                }) {
                    return Err("placement session provenance".into());
                }
                m.placements_since_check.push(session.clone());
                m.placing_sessions.insert(session.clone());
            }
        }
        Ok(state)
    }
    #[cfg(any(test, feature = "tracer"))]
    pub async fn fixture_delivery_record(&mut self, record: Record) -> Result<(), String> {
        self.delivery_record(record).await
    }
    pub fn delivery_view(&self) -> Value {
        self.dispatch.approved_entries.keys().map(|machine| {
            let m = self.delivery.0.get(machine).cloned().unwrap_or_default();
            let last = m.checks.last();
            let completed = m.checks.iter().rfind(|c| c.result.complete);
            let current = last.is_some_and(|c| self.journaled_delivery_authority(machine).as_ref() == Ok(&c.authority));
            let completed_current = completed.is_some_and(|c| self.journaled_delivery_authority(machine).as_ref() == Ok(&c.authority));
            // A completed verdict may stand through unavailable reads, but must never
            // conceal new findings, restored unknown state or changed requirements.
            let unavailable_only = last.is_some_and(|c| c.result.fields.iter().all(|f| matches!(f.status,
                delivery::Status::Checked | delivery::Status::Unavailable)));
            let verdict = if m.unknown { "findings unknown — re-check required" }
                else if !m.findings.is_empty() { "handed over with findings" }
                else if completed_current && unavailable_only && completed.is_some_and(|c| c.result.delivered) { "Delivered" }
                else { "delivery evidence not yet supplied" };
            let reports: Vec<_> = self.dispatch.calls.values().filter(|c| c.intent.machine == *machine)
                .map(|c| json!({"command": c.intent.command, "terminal":self.dispatch.terminals.iter().find(|t| t.terminal.call == c.intent.call),
                    "evidence":self.dispatch.jobs.iter().filter(|e| e.evidence.call == c.intent.call).collect::<Vec<_>>()})).collect();
            let value = json!({"machine":machine,"verdict":verdict,"fixture_limit":delivery::FIXTURE_LIMIT,
                "findings":m.findings.iter().map(|f|json!({"field":f.field,"class":f.class(),"detail":f.detail})).collect::<Vec<_>>(),
                "findings_unknown":m.unknown,"last_check":last,"current_declaration_checked":current,
                "last_completed_check":completed,"completed_declaration_current":completed_current,
                "verdict_is_historical":last.is_some_and(|c|!c.result.complete) || !completed_current || !m.placements_since_check.is_empty(),
                "placement_eligible":!m.unknown && current && m.placements_since_check.is_empty() && last.is_some_and(|c|c.result.placement_eligible),
                "applications":m.applications,"subsequent_placement_sessions":m.placements_since_check,
                "report_label":delivery::REPORT_LABEL,"reports":reports});
            // Recheck current holdings at rendering, including names and historical output.
            if crate::redaction::Redacted::inference_value_is_safe(self, &value, &[]) { value }
            else { json!({"machine":machine,"verdict":"delivery display withheld at credential boundary","fixture_limit":delivery::FIXTURE_LIMIT}) }
        }).collect::<Vec<_>>().into()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
