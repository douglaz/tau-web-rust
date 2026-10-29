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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Association {
    pub target: Target,
    pub entry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssociationRecord {
    pub number: u64,
    pub association: StoredAssociation,
}

/// Closed abstractions of the approved LNVPS request and externally validated result.
/// These types do not perform TLS or vendor response validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptOperation {
    Order,
    Stop,
    Restart,
}

impl ReceiptOperation {
    pub fn operation(self) -> Operation {
        match self {
            Self::Order => Operation::Create,
            Self::Stop => Operation::Destroy,
            Self::Restart => Operation::Reset,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReceiptBinding {
    pub operation: ReceiptOperation,
    pub account: u64,
    pub signed_request: u64,
}

impl<'de> Deserialize<'de> for ReceiptBinding {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BindingObject;
        impl<'de> serde::de::Visitor<'de> for BindingObject {
            type Value = ReceiptBinding;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a receipt binding object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                map: A,
            ) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Fields {
                    operation: ReceiptOperation,
                    account: u64,
                    signed_request: u64,
                }
                let fields =
                    Fields::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
                Ok(ReceiptBinding {
                    operation: fields.operation,
                    account: fields.account,
                    signed_request: fields.signed_request,
                })
            }
        }
        // deserialize_map refuses positional arrays while preserving duplicate-member checks.
        deserializer.deserialize_map(BindingObject)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptSource {
    BrowserVendorTls,
    ArbitraryResponse,
    JobOutput,
    NotifyEvent,
    ProposedText,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Receipt {
    pub source: ReceiptSource,
    pub call: u64,
    pub resource: Resource,
    pub target: Target,
    pub binding: ReceiptBinding,
    pub validated: bool,
    pub returned_vendor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReceiptRecord {
    pub number: u64,
    pub receipt: StoredReceipt,
    /// What this event settled when received, never rewritten by a later association.
    pub settled: Vec<u64>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_binding: Option<ReceiptBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restated_modes: Vec<crate::modes::Mode>,
    pub resource: Resource,
    pub target: Target,
    pub operation: Operation,
    pub session: String,
    pub requester: Requester,
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
    pub receipt_binding: Option<ReceiptBinding>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_binding: Option<ReceiptBinding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restated_modes: Vec<crate::modes::Mode>,
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
    SessionsEnded,
    Modes,
    BoundSet,
    Unmapped,
    IdentityExclusion { records: Vec<u64> },
    Facts,
    InstallationFacts { why: String },
    UnsupportedOperation { operation: Operation },
    Barrier { calls: Vec<u64> },
    Continuation { in_force: DestructiveDisposition },
}

impl Dispatch {
    /// Apply only validated canonical evidence. Quarantine never enters the map.
    pub(crate) fn associate_stored(
        &mut self,
        number: u64,
        association: StoredAssociation,
    ) -> Result<(), String> {
        self.validate_association(number, &association)?;
        let entry = self.association_entry(&association)?.to_owned();
        if association.admitted() {
            let raw = Association {
                target: association.target().ok_or("mapped target missing")?.clone(),
                entry,
            };
            if self.association_duplicate(&raw)? {
                return Ok(());
            }
            self.associations.push(raw);
        }
        self.association_records.push(AssociationRecord {
            number,
            association,
        });
        self.settle_receipts();
        Ok(())
    }

    fn receipt_association(&self, receipt: &ReceiptRecord) -> Option<&AssociationRecord> {
        let intent = self.receipt_intent(receipt.number, &receipt.receipt)?;
        let id = receipt.receipt.facts().returned_vendor?;
        if receipt.receipt.returned_presence() != ReturnedPresence::Retained {
            return None;
        }
        self.association_records.iter().find(|record| {
            record.association.admitted()
                && record.association.target() == Some(&Target::VendorMachine(id.clone()))
                && self
                    .association_entry(&record.association)
                    .is_ok_and(|entry| intent.resource == Resource::Entry(entry.into()))
        })
    }

    fn settle_receipts(&mut self) -> Vec<u64> {
        let mut settled = Vec::new();
        for record in &self.receipts {
            let Some(intent) = self.receipt_intent(record.number, &record.receipt) else {
                continue;
            };
            let call_id = intent.call;
            let order = record.receipt.facts().binding.operation == ReceiptOperation::Order;
            let association = self.receipt_association(record).map(|r| r.number);
            if order && association.is_none() {
                continue;
            }
            let call = self
                .typed_calls
                .get_mut(&call_id)
                .expect("earlier typed intent");
            if call.state == CallState::Unresolved {
                call.state = CallState::ReceiptConfirmed {
                    receipt: record.number,
                    association: if order { association } else { None },
                };
                settled.push(call_id);
            }
        }
        settled
    }

    pub(crate) fn receive_stored(
        &mut self,
        number: u64,
        receipt: StoredReceipt,
    ) -> Result<Vec<u64>, String> {
        self.validate_receipt(number, &receipt)?;
        self.receipts.push(ReceiptRecord {
            number,
            receipt,
            settled: Vec::new(),
        });
        let settled = self.settle_receipts();
        self.receipts.last_mut().expect("just received").settled = settled.clone();
        Ok(settled)
    }

    pub fn resolve(&self, target: &Target) -> Option<Resource> {
        if target == &Target::Inference {
            Some(Resource::Inference)
        } else if let Target::Entry(entry) = target {
            self.approved_entries
                .contains_key(entry)
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
        if request.facts.arguments.iter().any(|(key, value)| {
            [
                "class",
                "answer",
                "access_model",
                "setup",
                "entries",
                "question",
                "goal",
                "proposal",
            ]
            .contains(&key.as_str())
                || value == "sealed"
        }) {
            return Err(RequestRefusal::Facts);
        }
        if matches!(request.operation, Operation::Create | Operation::Reinstall)
            && let Resource::Entry(machine) = &resource
        {
            self.check_installation(machine)
                .map_err(|why| RequestRefusal::InstallationFacts { why })?;
        }
        let expected = OperationApproval {
            receipt_binding: request.receipt_binding.clone(),
            restated_modes: request
                .approved
                .as_ref()
                .map(|a| a.restated_modes.clone())
                .unwrap_or_default(),
            resource: resource.clone(),
            target: request.target.clone(),
            operation: request.operation,
            session: request.session.clone(),
            requester: request.requester,
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
        if operation == Operation::Create
            && let Resource::Entry(entry) = resource
        {
            let records = self.identity_exclusions(entry);
            if !records.is_empty() {
                return Err(RequestRefusal::IdentityExclusion { records });
            }
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
            receipt_binding: request.receipt_binding.clone(),
            restated_modes: request
                .approved
                .as_ref()
                .expect("checked approval")
                .restated_modes
                .clone(),
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
        if intent
            .restated_modes
            .iter()
            .enumerate()
            .any(|(i, mode)| intent.restated_modes[..i].contains(mode))
            || (!matches!(intent.operation, Operation::Destroy | Operation::Reinstall)
                && !intent.restated_modes.is_empty())
        {
            return Err("invalid restated modes".into());
        }
        if intent.approved
            != (OperationApproval {
                receipt_binding: intent.receipt_binding.clone(),
                restated_modes: intent.restated_modes.clone(),
                resource: intent.resource.clone(),
                target: intent.target.clone(),
                operation: intent.operation,
                session: intent.session.clone(),
                requester: intent.requester,
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
