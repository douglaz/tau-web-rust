//! Bounded admission over retained references and the serializer's control envelopes.
use super::*;
use crate::poc::inference::EchoFilter;

const REFUSAL: &str = "inference configuration refused: credential conflicts with task references; use a different credential";

impl<S: Storage> Store<S> {
    /// Counters and generated session suffixes have symbolic decimal domains. All numeric
    /// spellings normalize identically, including the checked u64 maximum and encryption cap.
    /// The digit-erasure abstraction also forgets fixed digits, deliberately over-refusing.
    /// No completed step, result, pending report or historical transcript is visited here.
    pub(super) fn poc_admission(
        &self,
        filter: &EchoFilter,
        task: Option<&Task>,
        exposure: Option<&Exposure>,
    ) -> Result<(), String> {
        crate::poc::inference::work::scope(|| {
            self.poc_templates(task, exposure, Domains::default(), |bytes, hexadecimal| {
                if filter.symbolic_match(bytes)?
                    || filter.protect_bytes(bytes)?.as_slice() != bytes
                    || (hexadecimal && filter.symbolic_hex_match(bytes)?)
                {
                    return Err(REFUSAL.into());
                }
                Ok(())
            })
        })
    }

    fn poc_templates(
        &self,
        task: Option<&Task>,
        exposure: Option<&Exposure>,
        domains: Domains,
        mut accept: impl FnMut(&[u8], bool) -> Result<(), String>,
    ) -> Result<(), String> {
        let id = task.map_or("", |t| t.id.as_str());
        let goal = task.map_or("", |t| t.goal.as_str());
        let checks = task.map_or_else(Vec::new, |t| t.checks.clone());
        let machine = exposure
            .and_then(|e| e.bound_set.first())
            .map(|b| b.machine.as_str())
            .or_else(|| task.map(|t| t.machine.as_str()))
            .unwrap_or("");
        // An unknown structural identity is refused rather than silently omitting its envelope.
        let identity = if let Some(exposure) = exposure {
            if exposure.bound_set.len() != 1 {
                return Err(REFUSAL.into());
            }
            exposure.bound_set[0].identity.clone()
        } else if !machine.is_empty() {
            self.dispatch
                .approved_entries
                .get(machine)
                .ok_or(REFUSAL)?
                .approved
                .identity
                .clone()
        } else {
            Identity {
                seed: self.seed().ok_or(REFUSAL)?.id(),
                derivation_version: domains.decimal(),
                family: Family::Machines,
                index: domains.decimal(),
            }
        };
        emit(
            &mut accept,
            &json!({"seed":self.seed().ok_or(REFUSAL)?.id(), "id":id,
            "machine":machine, "goal":goal, "checks":checks}),
        )?;
        // The synthetic session represents every generated decimal suffix, without enumerating
        // revisions or relying on the current record number. Actual retained sessions also run
        // through each envelope, preserving spans at both ends of their serialized strings.
        let symbolic_session = format!("session-{}", domains.decimal::<u64>());
        let mut sessions = vec![symbolic_session.as_str()];
        if let Some(task) = task {
            sessions.push(&task.start_session);
            sessions.extend(task.continuation_sessions.iter().map(String::as_str));
        }
        if let Some(exposure) = exposure {
            sessions.push(&exposure.session);
        }
        for session in sessions {
            emit(
                &mut accept,
                &Event::Goal(crate::goals::Goal {
                    session: session.into(),
                    text: goal.into(),
                    source: crate::goals::SOURCE.into(),
                    document_source: None,
                }),
            )?;
            let command = Event::Poc(Record::Command {
                binding: Binding {
                    task: id.into(),
                    revision: domains.decimal(),
                    session: session.into(),
                },
                intent: Intent {
                    call: domains.decimal(),
                    machine: machine.into(),
                    command: String::new(),
                    approval: Some(Approval::HarnessPin {
                        machine: machine.into(),
                        fingerprint: self
                            .poc_target(machine)
                            .map_or("", |target| target.pin.as_str())
                            .into(),
                    }),
                    job: Some(String::new()),
                    provenance: Some(crate::dispatch::CommandProvenance {
                        target: crate::dispatch::Target::Entry(machine.into()),
                        session: Some(session.into()),
                        requester: crate::dispatch::Requester::Session,
                    }),
                },
            });
            let bytes = Zeroizing::new(serde_json::to_vec(&command).map_err(|_| REFUSAL)?);
            accept(&bytes, true)?;
            for mode in [Mode::NoBrief, Mode::NoArtifactPin] {
                emit(
                    &mut accept,
                    &Event::ModeAcceptance(Acceptance {
                        session: session.into(),
                        mode,
                    }),
                )?;
            }
            for accepted_modes in [vec![], vec![Mode::NoArtifactPin]] {
                emit(
                    &mut accept,
                    &Event::Exposure(Exposure {
                        session: session.into(),
                        bound_set: vec![BoundMachine {
                            machine: machine.into(),
                            identity: identity.clone(),
                        }],
                        accepted_modes,
                    }),
                )?;
            }
            emit(
                &mut accept,
                &Event::Poc(Record::Authorize {
                    id: id.into(),
                    expected: domains.decimal(),
                    session: session.into(),
                }),
            )?;
            emit(
                &mut accept,
                &Event::Poc(Record::Create {
                    id: id.into(),
                    session: session.into(),
                    checks: checks.clone(),
                    limits: Limits {
                        requests: domains.decimal(),
                        steps: domains.decimal(),
                    },
                }),
            )?;
            emit(
                &mut accept,
                &Event::Poc(Record::Start {
                    id: id.into(),
                    session: session.into(),
                    checks: checks.clone(),
                    limits: Limits {
                        requests: domains.decimal(),
                        steps: domains.decimal(),
                    },
                }),
            )?;
        }
        for change in [
            Change::Abandon,
            Change::Raise(Limits {
                requests: domains.decimal(),
                steps: domains.decimal(),
            }),
            Change::Request,
            Change::PrepareCheck,
            Change::RetryChecks,
            Change::Settle,
            Change::Inspect,
            Change::Wait {
                why: String::new(),
                running: false,
            },
            Change::Wait {
                why: String::new(),
                running: true,
            },
        ] {
            emit(
                &mut accept,
                &Event::Poc(Record::Change {
                    id: id.into(),
                    expected: domains.decimal(),
                    change,
                }),
            )?;
        }
        emit(
            &mut accept,
            &Event::Poc(Record::Change {
                id: id.into(),
                expected: domains.decimal(),
                change: Change::Wait {
                    why: crate::poc::wait::RUNNING.into(),
                    running: true,
                },
            }),
        )?;
        let mut result = Ok(());
        crate::poc::wait::visit(|pattern| {
            if result.is_err() {
                return;
            }
            let hexadecimal = pattern.contains("{job}");
            let why = crate::poc::wait::render(&pattern, domains.decimal(), "", PAYLOAD);
            let event = Event::Poc(Record::Change {
                id: id.into(),
                expected: domains.decimal(),
                change: Change::Wait {
                    why,
                    running: false,
                },
            });
            result = (|| {
                let bytes = Zeroizing::new(serde_json::to_vec(&event).map_err(|_| REFUSAL)?);
                // A payload is a hole. Scan each fixed side with its own adjacent envelope;
                // never invent known bytes by concatenating across an unknown remote detail.
                for part in std::str::from_utf8(&bytes)
                    .map_err(|_| REFUSAL)?
                    .split(PAYLOAD)
                {
                    accept(part.as_bytes(), hexadecimal)?;
                }
                Ok(())
            })();
        });
        result
    }
}

const PAYLOAD: &str = "{payload}";

// Only these unsigned, bounded domains can populate a symbolic decimal. Field type inference
// makes a signed, floating, wider or otherwise unknown event field fail at the template site.
trait Decimal {
    fn bound(maximum: bool) -> Self;
}
impl Decimal for u64 {
    fn bound(maximum: bool) -> Self {
        if maximum { Self::MAX } else { 0 }
    }
}
impl Decimal for u32 {
    fn bound(maximum: bool) -> Self {
        if maximum { Self::MAX } else { 0 }
    }
}
#[derive(Default, Clone, Copy)]
struct Domains {
    maximum: bool,
}
impl Domains {
    fn decimal<T: Decimal>(self) -> T {
        T::bound(self.maximum)
    }
}

// Each template uses the actual event serializer, including field ordering and escaping.
fn emit(
    accept: &mut impl FnMut(&[u8], bool) -> Result<(), String>,
    value: &impl Serialize,
) -> Result<(), String> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| REFUSAL)?);
    accept(&bytes, false)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    #[test]
    fn poc_journal_admission_covers_empty_tasks_retained_goals_checks_and_seed() {
        let mut s = crate::store::inference::tests::ready();
        let session = s.sessions[0].identity.clone();
        block_on(s.enter_goal(&session, "install and run a small service".into(), None)).unwrap();
        block_on(s.accept_mode(&session, Mode::NoBrief)).unwrap();
        assert!(s.poc.is_empty());
        assert!(
            s.poc_configuration_key(b"\"expected\":18446744073709551615,\"change\":")
                .is_err()
        );
        let task =
            block_on(s.poc_create(&session, vec!["systemctl is-active example.service".into()]))
                .unwrap();
        for key in [
            task.goal.as_bytes(),
            task.checks[0].as_bytes(),
            s.seed().unwrap().id().as_bytes(),
        ] {
            assert!(s.poc_configuration_key(key).is_err());
        }
    }
    #[test]
    fn poc_admission_decimal_domains_have_nonhex_boundaries() {
        // Couple the text-format fields to the producers' unsigned, 20-digit domains too.
        let _: fn(&str, u64, u64) -> String = crate::poc::wait::decode_length;
        let _: fn(u64) -> String = crate::poc::wait::decimal;
        let _: fn(&str, u64, &str, &str) -> String = crate::poc::wait::render;
        let _: fn(crate::poc::wait::Shape, u64, &str, &str) -> String =
            crate::poc::wait::Shape::render;
        use crate::store::poc::tests::FixedIdentifiers;
        // Fix seed and all subsequent task/session identifiers for the retained-reference rows.
        let _identifiers = FixedIdentifiers::new();
        let mut store = crate::store::poc::tests::ready();
        let task = crate::store::poc::tests::create_task(&mut store);
        for task in [None, Some(&task)] {
            for exposure in [None, store.exposure_ledger.first()] {
                let mut low = Vec::new();
                let mut high = Vec::new();
                for (maximum, out) in [(false, &mut low), (true, &mut high)] {
                    store
                        .poc_templates(task, exposure, Domains { maximum }, |bytes, hex| {
                            out.push((bytes.to_vec(), hex));
                            Ok(())
                        })
                        .unwrap();
                }
                assert_eq!(low.len(), high.len());
                let mut fields = 0;
                for ((low, hx), (high, hy)) in low.iter().zip(&high) {
                    assert_eq!(hx, hy);
                    // Symbolic values are constrained by Decimal's only implementations, u32/u64.
                    // Comparing both domains also catches an untracked hard-coded numeric field.
                    for maximum in [u64::MAX.to_string(), u32::MAX.to_string()] {
                        for (at, _) in std::str::from_utf8(high).unwrap().match_indices(&maximum) {
                            fields += 1;
                            assert!((1..=20).contains(&maximum.len()));
                            assert!(at > 0 && at + maximum.len() < high.len());
                            assert!(
                                !high[at - 1].is_ascii_hexdigit()
                                    && (high[at - 1] != b'-' || high[..at].ends_with(b"session-"))
                                    && high[at - 1] != b'+'
                            );
                            assert!(!high[at + maximum.len()].is_ascii_hexdigit());
                        }
                    }
                    let erase = |s: &[u8]| {
                        s.iter()
                            .copied()
                            .filter(|b| !b.is_ascii_digit())
                            .collect::<Vec<_>>()
                    };
                    assert_eq!(
                        erase(low),
                        erase(high),
                        "only symbolic decimal bytes may vary"
                    );
                    if task.is_none()
                        && exposure.is_none()
                        && let Ok(value) = serde_json::from_slice::<Value>(high)
                    {
                        fn numbers(value: &Value) {
                            match value {
                                Value::Number(n) => assert!(
                                    matches!(n.as_u64(), Some(u64::MAX) | Some(4294967295)),
                                    "untracked or signed decimal {n}"
                                ),
                                Value::Array(a) => a.iter().for_each(numbers),
                                Value::Object(o) => o.values().for_each(numbers),
                                _ => (),
                            }
                        }
                        numbers(&value);
                    }
                }
                assert!(
                    fields > 100,
                    "walk the complete inventory, including Wait counters"
                );
                eprintln!(
                    "decimal inventory task={} exposure={} templates={} symbolic_fields={fields}",
                    task.is_some(),
                    exposure.is_some(),
                    low.len()
                );
            }
        }
    }
}
