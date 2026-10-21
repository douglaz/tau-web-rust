//! Typed fixture operations and the shared resource barrier, from `STA-24` and `SEC-4`.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Resource {
    Entry(String),
    Inference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Entry(String),
    AllocationIndex(u32),
    VendorMachine(String),
    Inference,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Association {
    pub target: Target,
    pub entry: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Create,
    Reset,
    Reinstall,
    Destroy,
    Exec,
    Read,
    Inference,
}

impl Operation {
    pub fn changes_running(self) -> bool {
        matches!(self, Self::Reset | Self::Reinstall | Self::Destroy)
    }

    pub fn mutation(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Reset | Self::Reinstall | Self::Destroy
        )
    }
}

/// Values rendered on the operation's approval, never shell text (`ARC-4`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub arguments: BTreeMap<String, String>,
    pub cost_bound: u64,
    pub bundle_commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationApproval {
    pub resource: Resource,
    pub target: Target,
    pub operation: Operation,
    pub session: String,
    pub facts: Facts,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Requester {
    Session,
    Operator,
    HarnessFlow,
}

/// Where a command came from, with no per-operation approval or structured facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandProvenance {
    pub target: Target,
    pub session: Option<String>,
    pub requester: Requester,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub target: Target,
    pub operation: Operation,
    pub session: String,
    pub requester: Requester,
    pub facts: Facts,
    pub approved: Option<OperationApproval>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationIntent {
    pub call: u64,
    pub resource: Resource,
    pub target: Target,
    pub operation: Operation,
    pub session: String,
    pub requester: Requester,
    pub facts: Facts,
    pub approved: OperationApproval,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OperationCall {
    #[serde(flatten)]
    pub intent: OperationIntent,
    #[serde(flatten)]
    pub state: CallState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reports {
    Confirmed,
    Ended,
    Unknown,
}

/// Fixture contract: a status read reports the operation's effect observed. Ended or a
/// boot change never confirms it. This is not a vendor's reconciliation contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub resource: Resource,
    pub operation: Operation,
    pub reports: Reports,
    /// Snapshot at read time; a delayed result cannot settle a later call.
    pub calls: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservationRecord {
    pub number: u64,
    pub observation: Observation,
    pub settled: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Assumption {
    pub continuation: Continuation,
    pub outcome: Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum RequestRefusal {
    Unmapped,
    Facts,
    UnsupportedOperation { operation: Operation },
    Barrier { calls: Vec<u64> },
    Continuation { in_force: DestructiveDisposition },
}

impl Dispatch {
    /// Associations are supplied by the harness, independently of each request. Their
    /// persistence belongs to the approved-entry allocation work.
    pub fn associate(&mut self, association: Association) -> Result<(), String> {
        if association.target == Target::Inference {
            return Err("inference cannot be associated with a machine entry".into());
        }
        // `resolve` reads an entry target as that entry, so any other mapping would never apply.
        if let Target::Entry(entry) = &association.target
            && entry != &association.entry
        {
            return Err("an entry target names only its own entry".into());
        }
        if let Some(old) = self
            .associations
            .iter()
            .find(|a| a.target == association.target)
        {
            return if old == &association {
                Ok(())
            } else {
                Err("target already associated".into())
            };
        }
        self.current_installations
            .entry(association.entry.clone())
            .or_default();
        self.associations.push(association);
        Ok(())
    }

    pub fn resolve(&self, target: &Target) -> Option<Resource> {
        if target == &Target::Inference {
            Some(Resource::Inference)
        } else if let Target::Entry(entry) = target {
            self.associations
                .iter()
                .any(|a| &a.entry == entry)
                .then(|| Resource::Entry(entry.clone()))
        } else {
            self.associations
                .iter()
                .find(|a| &a.target == target)
                .map(|a| Resource::Entry(a.entry.clone()))
        }
    }

    pub(super) fn call_state(&self, id: u64) -> Option<&CallState> {
        self.calls
            .get(&id)
            .map(|c| &c.state)
            .or_else(|| self.typed_calls.get(&id).map(|c| &c.state))
    }

    pub(super) fn call_state_mut(&mut self, id: u64) -> Option<&mut CallState> {
        if let Some(call) = self.calls.get_mut(&id) {
            Some(&mut call.state)
        } else {
            self.typed_calls.get_mut(&id).map(|c| &mut c.state)
        }
    }

    pub fn call_resource(&self, id: u64) -> Option<Resource> {
        self.calls
            .get(&id)
            .map(|c| Resource::Entry(c.intent.machine.clone()))
            .or_else(|| self.typed_calls.get(&id).map(|c| c.intent.resource.clone()))
    }

    pub fn call_operation(&self, id: u64) -> Option<Operation> {
        self.calls
            .get(&id)
            .map(|_| Operation::Exec)
            .or_else(|| self.typed_calls.get(&id).map(|c| c.intent.operation))
    }

    pub fn call_ids(&self) -> Vec<u64> {
        self.intent_order.clone()
    }

    pub fn unresolved(&self, resource: &Resource) -> Vec<u64> {
        self.call_ids()
            .into_iter()
            .filter(|id| {
                self.call_resource(*id).as_ref() == Some(resource)
                    && self.call_state(*id) == Some(&CallState::Unresolved)
            })
            .collect()
    }

    pub fn standing_for(&self, resource: &Resource) -> Option<&DispositionRecord> {
        match resource {
            Resource::Entry(entry) => self.standing.get(entry),
            Resource::Inference => self.inference_standing.as_ref(),
        }
    }

    pub fn check_request(&self, request: &Request) -> Result<Resource, RequestRefusal> {
        let resource = self
            .resolve(&request.target)
            .ok_or(RequestRefusal::Unmapped)?;
        let expected = OperationApproval {
            resource: resource.clone(),
            target: request.target.clone(),
            operation: request.operation,
            session: request.session.clone(),
            facts: request.facts.clone(),
        };
        if request.approved.as_ref() != Some(&expected)
            || (request.operation == Operation::Inference) != (resource == Resource::Inference)
        {
            return Err(RequestRefusal::Facts);
        }
        self.check_operation(&resource, request.operation, request.requester)?;
        Ok(resource)
    }

    /// Shared admission over journal-derived calls from both planes (`STA-20`, `STA-24`).
    pub fn check_operation(
        &self,
        resource: &Resource,
        operation: Operation,
        requester: Requester,
    ) -> Result<(), RequestRefusal> {
        if matches!(operation, Operation::Read | Operation::Inference) {
            return Ok(());
        }
        let calls: Vec<_> = self
            .unresolved(resource)
            .into_iter()
            .filter(|id| {
                let old = self.call_operation(*id).expect("recorded call");
                operation.mutation()
                    || (operation == Operation::Exec
                        && (old.changes_running() || old == Operation::Exec))
            })
            .collect();
        if !calls.is_empty() {
            return Err(RequestRefusal::Barrier { calls });
        }
        if let Some(record) = self.standing_for(resource) {
            let continuation = record.disposition.continuation;
            let permits = match continuation {
                Continuation::DestructiveReinstall => operation == Operation::Reinstall,
                Continuation::Abandonment => {
                    operation == Operation::Destroy && requester == Requester::HarnessFlow
                }
                Continuation::AsIfDone | Continuation::AsIfNotDone => true,
            };
            if !permits {
                return Err(RequestRefusal::Continuation {
                    in_force: DestructiveDisposition {
                        disposition: record.number,
                        continuation,
                    },
                });
            }
        }
        Ok(())
    }

    pub fn prepare(
        &self,
        number: u64,
        request: &Request,
    ) -> Result<OperationIntent, RequestRefusal> {
        let resource = self.check_request(request)?;
        Ok(OperationIntent {
            call: number,
            resource,
            target: request.target.clone(),
            operation: request.operation,
            session: request.session.clone(),
            requester: request.requester,
            facts: request.facts.clone(),
            approved: request.approved.clone().expect("checked approval"),
        })
    }

    /// Applies a committed intent, including the continuation boundary, at replay too.
    /// Admission is checked before append; replay trusts the recorded harness assignment,
    /// never associations that might have been supplied differently since the dispatch.
    pub fn operation_intent(&mut self, number: u64, intent: OperationIntent) -> Result<(), String> {
        if number != intent.call || self.call_state(number).is_some() {
            return Err("intent identity is not its unique record number".into());
        }
        if intent.approved
            != (OperationApproval {
                resource: intent.resource.clone(),
                target: intent.target.clone(),
                operation: intent.operation,
                session: intent.session.clone(),
                facts: intent.facts.clone(),
            })
            || (intent.operation == Operation::Inference)
                != (intent.resource == Resource::Inference)
        {
            return Err("intent differs from its approval".into());
        }
        if let Resource::Entry(entry) = &intent.resource {
            let installation = self.current_installations.entry(entry.clone()).or_default();
            if intent.operation == Operation::Reinstall {
                *installation += 1;
            }
        }
        let ends = self.standing_for(&intent.resource).is_some_and(|record| {
            match record.disposition.continuation {
                Continuation::DestructiveReinstall => intent.operation == Operation::Reinstall,
                Continuation::Abandonment => {
                    intent.operation == Operation::Destroy
                        && intent.requester == Requester::HarnessFlow
                }
                _ => false,
            }
        });
        if ends {
            match &intent.resource {
                Resource::Entry(entry) => {
                    self.standing.remove(entry);
                }
                Resource::Inference => self.inference_standing = None,
            }
        }
        let state = if intent.operation == Operation::Read {
            CallState::NoEffect
        } else {
            CallState::Unresolved
        };
        self.typed_calls
            .insert(number, OperationCall { intent, state });
        self.intent_order.push(number);
        Ok(())
    }

    /// Capture before contact, not when a delayed status response arrives.
    pub fn observation(
        &self,
        resource: Resource,
        operation: Operation,
        reports: Reports,
    ) -> Observation {
        let calls = self
            .call_ids()
            .into_iter()
            .filter(|id| {
                self.call_resource(*id).as_ref() == Some(&resource)
                    && self.call_operation(*id) == Some(operation)
            })
            .collect();
        Observation {
            resource,
            operation,
            reports,
            calls,
        }
    }

    pub fn observe(&mut self, number: u64, observation: Observation) -> Result<Vec<u64>, String> {
        for id in &observation.calls {
            if self.call_resource(*id).as_ref() != Some(&observation.resource)
                || self.call_operation(*id) != Some(observation.operation)
            {
                return Err("observation names no matching call".into());
            }
        }
        let mut settled = Vec::new();
        if observation.reports == Reports::Confirmed && observation.operation.mutation() {
            for id in &observation.calls {
                if self.call_state(*id) == Some(&CallState::Unresolved) {
                    *self.call_state_mut(*id).expect("checked call") = CallState::Confirmed {
                        observation: number,
                    };
                    settled.push(*id);
                }
            }
        }
        self.observations.push(ObservationRecord {
            number,
            observation,
            settled: settled.clone(),
        });
        Ok(settled)
    }
}
