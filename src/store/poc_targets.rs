//! Atomic existing-machine enrollment, replay and public connection identities.
use super::*;
use crate::dispatch::{
    Access, ApprovedEntry, ClassAnswer, ClassRecord, MachineEntry, Period, RecurringCost,
    SetupApproval, SetupRecord, Unit,
};
use crate::poc::targets::TargetRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    target: TargetRecord,
    machine_identity: Identity,
    relay_identity: Identity,
    class_answer: ClassAnswer,
    access: Access,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub target: TargetRecord,
    pub approve_existing: bool,
    pub class_answer: ClassAnswer,
    pub approve_maintained_access: bool,
}

pub(super) fn eligible_pass(allocation: &Metadata) -> Option<&Identity> {
    allocation
        .entries()
        .iter()
        .find(|entry| {
            entry.identity.family == Family::Passes
                && entry.identity.seed == allocation.seed()
                && matches!(
                    entry.status,
                    allocation::Status::Reserved | allocation::Status::Created
                )
        })
        .map(|entry| &entry.identity)
}

impl<S: Storage> Store<S> {
    #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
    pub(crate) fn test_poc_replace_target(
        &mut self,
        machine: &str,
        target: TargetRecord,
    ) -> Result<TargetRecord, String> {
        let record = self
            .poc_targets
            .get_mut(machine)
            .ok_or("missing fixture target")?;
        Ok(std::mem::replace(&mut record.target, target))
    }

    pub fn poc_target(&self, machine: &str) -> Option<&TargetRecord> {
        self.poc_targets.get(machine).map(|record| &record.target)
    }

    pub fn poc_targets_view(&self) -> Value {
        self.poc_targets
            .values()
            .map(|record| serde_json::to_value(&record.target).expect("target serializes"))
            .collect::<Vec<_>>()
            .into()
    }

    fn poc_projections(&self, record: &Record) -> Result<(Dispatch, Metadata), String> {
        record.target.validate()?;
        if let Some(old) = self.poc_targets.get(&record.target.machine) {
            return if old == record {
                Ok((self.dispatch.clone(), self.allocation().clone()))
            } else {
                Err("stored target is immutable; use a fresh store and a new machine name".into())
            };
        }
        if let Some(purchase) = &self.procurement {
            if purchase.target.as_ref() != Some(&record.target)
                || purchase.machine != record.target.machine
                || purchase.identity != record.machine_identity
                || purchase.relay_identity != record.relay_identity
                || purchase.class_answer != record.class_answer
                || record.access != Access::ad_hoc()
            {
                return Err("purchase handoff identity conflicts".into());
            }
            return Ok((self.dispatch.clone(), self.allocation().clone()));
        }
        if !self.dispatch.approved_entries.is_empty() || !self.poc_targets.is_empty() {
            return Err(
                "existing-machine setup requires a fresh store without another setup approval"
                    .into(),
            );
        }
        if self
            .commands
            .iter()
            .any(|(_, entry)| entry.machine == record.target.machine)
            || self
                .dispatch
                .calls
                .values()
                .any(|call| call.intent.machine == record.target.machine)
            || self.exposure_ledger.iter().any(|exposure| {
                exposure
                    .bound_set
                    .iter()
                    .any(|bound| bound.machine == record.target.machine)
            })
        {
            return Err("machine name already has unrelated command history".into());
        }
        let mut allocation = self.allocation().clone();
        let mut dispatch = self.dispatch.clone();
        // These facts describe an already owned machine; zero is no new procurement charge.
        let approved = ApprovedEntry {
            entry: MachineEntry {
                machine: record.target.machine.clone(),
                vendor: "operator".into(),
                product: "existing machine".into(),
                region: "operator supplied".into(),
                cost: RecurringCost {
                    amount: 0,
                    unit: Unit::Sat,
                    period: Period::Month,
                },
            },
            identity: record.machine_identity.clone(),
            access: Some(record.access.clone()),
        };
        dispatch.apply_setup(
            &mut allocation,
            &SetupRecord::Approval(SetupApproval {
                entries: vec![approved],
                monthly_sat: 0,
                annual_sat: 0,
            }),
        )?;
        dispatch.apply_setup(
            &mut allocation,
            &SetupRecord::Class(ClassRecord {
                machine: record.target.machine.clone(),
                answer: record.class_answer,
                class: record.class_answer.class(),
            }),
        )?;
        if let Some(existing) = eligible_pass(&allocation) {
            if existing != &record.relay_identity {
                return Err("enrollment relay identity differs from eligible pass".into());
            }
        } else {
            if record.relay_identity.family != Family::Passes {
                return Err("enrollment needs a relay-pass identity".into());
            }
            allocation
                .apply(&allocation::Event::Reserve(record.relay_identity.clone()))
                .map_err(|e| e.to_string())?;
        }
        Ok((dispatch, allocation))
    }

    pub async fn poc_enroll(&mut self, enrollment: Enrollment) -> Result<(), String> {
        self.authority.ordinary()?;
        if self.procurement.is_some() {
            return Err("A purchase already owns this store; Resume that machine.".into());
        }
        if self.inference.ended {
            return Err("sessions ended".into());
        }
        enrollment.target.validate()?;
        // Reject authority rather than persist redacted connection fields. This precedes
        // even identity selection, and includes active/retained credential generations.
        if !crate::poc::inference::safe(
            self,
            &serde_json::to_value(&enrollment.target).map_err(|_| "target encoding")?,
            &[],
        ) {
            return Err(
                "existing-machine target contains protected or unscannable material".into(),
            );
        }
        if !enrollment.approve_existing || !enrollment.approve_maintained_access {
            return Err("existing-machine and maintained-access approvals are required".into());
        }
        if let Some(old) = self.poc_targets.get(&enrollment.target.machine) {
            if old.target != enrollment.target || old.class_answer != enrollment.class_answer {
                return Err("stored target and class are immutable; use a fresh store and a new machine name".into());
            }
            self.check_bindable_identity(&old.machine_identity, "existing-machine enrollment")?;
            self.check_bindable_identity(&old.relay_identity, "relay-pass enrollment")?;
            return Ok(());
        }
        let machine_identity = self
            .allocation()
            .issue(Family::Machines)
            .map_err(|e| e.to_string())?;
        let relay_identity = match eligible_pass(self.allocation()) {
            Some(identity) => identity.clone(),
            None => self
                .allocation()
                .issue(Family::Passes)
                .map_err(|e| e.to_string())?,
        };
        let record = Record {
            target: enrollment.target,
            machine_identity,
            relay_identity,
            class_answer: enrollment.class_answer,
            access: Access::ad_hoc(),
        };
        let (mut dispatch, allocation) = self.poc_projections(&record)?;
        dispatch.setup_approval = Some(self.next);
        self.commit(&Event::PocTarget(record.clone())).await?;
        self.dispatch = dispatch;
        self.allocation = Some(allocation);
        self.poc_targets
            .insert(record.target.machine.clone(), record);
        Ok(())
    }

    pub(super) fn replay_poc_target(&mut self, number: u64, record: &Record) -> Result<(), String> {
        let (mut dispatch, allocation) = self.poc_projections(record)?;
        if !self.poc_targets.contains_key(&record.target.machine) {
            dispatch.setup_approval = Some(number);
        }
        self.dispatch = dispatch;
        self.allocation = Some(allocation);
        self.poc_targets
            .insert(record.target.machine.clone(), record.clone());
        Ok(())
    }

    pub async fn poc_bind(&mut self, machine: &str) -> Result<String, String> {
        self.authority.ordinary()?;
        if let Some(session) = self.sessions.iter().find(|session| {
            !session.ended.get() && session.bound_set.iter().any(|name| name == machine)
        }) {
            return Ok(session.identity.clone());
        }
        crate::poc::targets::resolve(self, machine)?;
        #[cfg(target_arch = "wasm32")]
        let approval = crate::poc::inference::approval()?;
        #[cfg(all(not(target_arch = "wasm32"), any(test, feature = "tracer")))]
        let approval = crate::binding::InferenceApproval::synthetic();
        #[cfg(all(not(target_arch = "wasm32"), not(any(test, feature = "tracer"))))]
        let approval = native_approval()?;
        #[cfg(target_arch = "wasm32")]
        let credit = crate::poc::credit::browser::selected();
        #[cfg(not(target_arch = "wasm32"))]
        let credit = false;
        self.admit_with_credit(machine, &[], approval, credit).await
    }

    /// Operator-authored declaration candidate. It uses the ordinary goal/session,
    /// classification, access and journaled requirements approval checks.
    pub fn poc_propose_requirements(&mut self, session: &str, value: &Value) -> Result<(), String> {
        let proposal = crate::declaration::Proposal::parse(value)?;
        if !matches!(proposal, crate::declaration::Proposal::Declaration { .. }) {
            return Err("PoC requires a declaration proposal".into());
        }
        self.poc_target(proposal.machine())
            .ok_or("machine has no stored target or pin")?;
        if !crate::poc::inference::safe(self, value, &[]) {
            return Err("declaration contains protected or unscannable material".into());
        }
        let candidate = self
            .poc_requirement_candidate
            .checked_add(1)
            .ok_or("proposal counter exhausted")?;
        self.poc_requirement_candidate = candidate;
        let tool = crate::goals::Tool::Done {
            machine: proposal.machine().into(),
        };
        self.propose_requirements(session, candidate, proposal, &tool)
    }

    pub fn poc_public_keys(&self, machine: &str) -> Result<Value, String> {
        self.authority.ordinary()?;
        let record = self
            .poc_targets
            .get(machine)
            .ok_or("machine has no stored target or pin")?;
        self.check_bindable_identity(&record.machine_identity, "public client key")?;
        self.check_bindable_identity(&record.relay_identity, "public relay key")?;
        if eligible_pass(self.allocation()) != Some(&record.relay_identity) {
            return Err("enrolled relay pass is no longer transport authority".into());
        }
        self.poc_identity_public_keys(machine, &record.machine_identity)
    }

    pub(super) fn poc_identity_public_keys(
        &self,
        machine: &str,
        identity: &Identity,
    ) -> Result<Value, String> {
        let seed = self.seed().ok_or("seed unavailable")?;
        let client = seed
            .ssh_client_key(identity.derivation_version, identity.index)
            .map_err(|_| "client public key unavailable")?;
        let relay = self.relay_key().ok_or("relay public key unavailable")?;
        let mut wire = Vec::with_capacity(51);
        wire.extend_from_slice(&11u32.to_be_bytes());
        wire.extend_from_slice(b"ssh-ed25519");
        wire.extend_from_slice(&32u32.to_be_bytes());
        wire.extend_from_slice(&client.public_key());
        let authorized_keys = format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(wire)
        );
        Ok(
            json!({"machine":machine,"authorized_keys":authorized_keys,"relay_pubkey":hex::encode(relay.public_key())}),
        )
    }

    pub(super) fn purchase_target_record(
        target: TargetRecord,
        identity: Identity,
        relay_identity: Identity,
        class_answer: ClassAnswer,
    ) -> Record {
        Record {
            target,
            machine_identity: identity,
            relay_identity,
            class_answer,
            access: Access::ad_hoc(),
        }
    }
}

#[cfg(all(feature = "tracer", target_arch = "wasm32"))]
impl<S: Storage + Clone> Store<S> {
    pub(crate) async fn test_poc_prepare_release(
        &mut self,
        output: String,
    ) -> Result<crate::jobs::Evidence, String> {
        let session = self.poc_bind("machine-a").await?;
        self.enter_goal(&session, "Inspect a small service".into(), None)
            .await?;
        self.accept_mode(&session, crate::modes::Mode::NoBrief)
            .await?;
        self.poc_propose_requirements(&session, &json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()}))?;
        let candidate = self.pending_requirements[&session].candidate;
        self.approve_requirements(&session, "machine-a", candidate)
            .await?;
        let entry = Entry {
            machine: "machine-a".into(),
            command: b"true".to_vec(),
            provenance: None,
        };
        let pin = self
            .poc_target("machine-a")
            .ok_or("fixture target")?
            .pin
            .clone();
        let call = self
            .append(
                &entry,
                &Approval::HarnessPin {
                    machine: entry.machine.clone(),
                    fingerprint: pin,
                },
            )
            .await
            .map_err(|_| "fixture intent")?;
        let intent = &self.dispatch.calls[&call].intent;
        Ok(crate::jobs::Evidence {
            call,
            job: intent.job.clone().ok_or("fixture job")?,
            record: crate::jobs::Record::Present {
                machine: hex::encode("machine-a"),
                command: intent.command.clone(),
                boot: "boot-a".into(),
                current_boot: "boot-a".into(),
                pid: 42,
                alive: false,
                exit_status: Some(7),
                stdout: hex::encode(output),
                stderr: String::new(),
            },
        })
    }

    pub(crate) fn test_poc_release_counts(&self) -> Value {
        json!({"terminals": self.dispatch.terminals.len(),
            "collectable": self.dispatch.collectable("machine-a").len(),
            "launches": self.dispatch.calls.len()})
    }

    pub(crate) async fn test_poc_journal(&self, needle: &str) -> Result<Value, String> {
        let mut reader = Store::new(self.storage.clone(), DataKey(self.key.0), self.id.clone());
        let mut contains = false;
        let mut provider_protection = 0;
        let mut poc_pauses = 0;
        let mut account_records = 0;
        let mut account_contains = false;
        let mut mint_names = Vec::new();
        for number in 0..self.next {
            let bytes = self.storage.read(&number.to_string()).await?;
            let event = reader.open(number, &bytes)?;
            provider_protection += usize::from(matches!(event, Event::ProviderProtection(_)));
            poc_pauses += usize::from(matches!(
                &event,
                Event::Poc(poc::Record::Change {
                    change: poc::Change::Pause(_),
                    ..
                })
            ));
            let encoded = Zeroizing::new(
                serde_json::to_string(&event).map_err(|_| "fixture event encoding")?,
            );
            if let Event::PocCreditAccount(account) = &event {
                account_records += 1;
                if !needle.is_empty()
                    && (account.credit_id.0.as_str() == needle
                        || account.default_key.0.as_str() == needle)
                {
                    account_contains = true;
                } else {
                    contains |= encoded.contains(needle);
                }
            } else {
                contains |= encoded.contains(needle);
            }
            if let Event::PocCredit(crate::store::credit::Record::MintName(mint)) = &event {
                mint_names.push(mint.name.clone());
            }
            reader.previous = Address(Sha256::digest(&bytes).into());
        }
        Ok(
            json!({"contains":contains,"account_records":account_records,"account_contains":account_contains,"mint_names":mint_names,"records":self.next,"provider_protection":provider_protection,"poc_pauses":poc_pauses,"machines":self.allocation().next_unused().machines,"passes":self.allocation().next_unused().passes,"targets":self.poc_targets.len()}),
        )
    }
}

impl<S: Storage + Clone, K: Kdf> Local<S, K> {
    pub async fn poc_enroll(&mut self, request: &str) -> Value {
        if let Some(why) = self.dispatch_refusal() {
            return self.report(Some(why));
        }
        let Ok(value) = serde_json::from_str::<Value>(request) else {
            return self.report(Some("invalid existing-machine enrollment"));
        };
        if !value.is_object() || !value.get("target").is_some_and(Value::is_object) {
            return self.report(Some("invalid existing-machine enrollment"));
        }
        // Parse the original again so duplicate fields remain invalid as well.
        let Ok(enrollment) = serde_json::from_str::<Enrollment>(request) else {
            return self.report(Some("invalid existing-machine enrollment"));
        };
        let result = self.store().expect("unlocked").poc_enroll(enrollment).await;
        self.report(result.as_ref().err().map(String::as_str))
    }
    pub async fn poc_bind(&mut self, machine: &str) -> Value {
        if let Some(why) = self.dispatch_refusal() {
            return self.report(Some(why));
        }
        let result = self.store().expect("unlocked").poc_bind(machine).await;
        self.report(result.as_ref().err().map(String::as_str))
    }
    pub async fn poc_accept(&mut self, request: &str) -> Value {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            session: String,
            #[serde(default)]
            checks: Vec<String>,
        }
        let result = async {
            if let Some(why) = self.dispatch_refusal() {
                return Err(why.into());
            }
            if !serde_json::from_str::<Value>(request).is_ok_and(|v| v.is_object()) {
                return Err("invalid PoC acceptance".into());
            }
            let request: Request =
                serde_json::from_str(request).map_err(|_| "invalid PoC acceptance")?;
            let store = self.store().ok_or("locked")?;
            store
                .poc_start(&request.session, request.checks)
                .await
                .map(|_| ())
        }
        .await;
        self.report(result.as_ref().err().map(String::as_str))
    }

    pub fn poc_propose_requirements(&mut self, request: &str) -> Value {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            session: String,
            proposal: Value,
        }
        let result = (|| {
            if let Some(why) = self.dispatch_refusal() {
                return Err(why.into());
            }
            if !serde_json::from_str::<Value>(request).is_ok_and(|v| v.is_object()) {
                return Err("invalid PoC declaration request".into());
            }
            let request: Request =
                serde_json::from_str(request).map_err(|_| "invalid PoC declaration request")?;
            self.store()
                .ok_or("locked")?
                .poc_propose_requirements(&request.session, &request.proposal)
        })();
        self.report(result.as_ref().err().map(String::as_str))
    }

    pub fn poc_public_keys(&mut self, machine: &str) -> Value {
        if let Some(why) = self.dispatch_refusal() {
            return json!({"refused":why});
        }
        match self.store().expect("unlocked").poc_public_keys(machine) {
            Ok(keys) => keys,
            Err(why) => json!({"refused":why}),
        }
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

/// Isolated in-memory fixture for measuring the production durable transition in actual WASM.
/// No transport, OPFS writes, real credential or active operator session is used.
#[cfg(all(feature = "tracer", target_arch = "wasm32"))]
pub(crate) async fn test_poc_job_evidence(
    output: String,
    stderr: String,
    key: String,
    previous_key: String,
    command: Option<String>,
    sudo: bool,
) -> Result<Value, String> {
    struct Fixed;
    impl Kdf for Fixed {
        async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
            Ok(WrappingKey([9; 32]))
        }
    }
    let pass = || LocalPassphrase::new(b"fixture job settlement passphrase".to_vec());
    let mut store = create(MemoryStorage::default(), &Fixed, pass())
        .await
        .map_err(|_| "fixture create")?;
    store.seed_backup(allocation::Completion::Skipped).await?;
    let target = TargetRecord {
        machine: "machine-a".into(),
        relay: "wss://relay.invalid/".into(),
        profile: "v1".into(),
        host: "192.0.2.1".into(),
        port: 22,
        user: "arch".into(),
        elevation: if sudo {
            crate::jobs::Elevation::SudoNoninteractive
        } else {
            crate::jobs::Elevation::None
        },
        pin: format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode([7; 32])
        ),
    };
    store
        .poc_enroll(Enrollment {
            target: target.clone(),
            approve_existing: true,
            class_answer: ClassAnswer::No,
            approve_maintained_access: true,
        })
        .await?;
    let session = store.poc_bind("machine-a").await?;
    store
        .enter_goal(&session, "Inspect a small service".into(), None)
        .await?;
    store
        .accept_mode(&session, crate::modes::Mode::NoBrief)
        .await?;
    store.poc_propose_requirements(&session, &json!({"kind":"declaration","machine":"machine-a","declaration":crate::declaration::ad_hoc_minimum()}))?;
    let candidate = store.pending_requirements[&session].candidate;
    store
        .approve_requirements(&session, "machine-a", candidate)
        .await?;
    let entry = Entry {
        machine: "machine-a".into(),
        command: command.unwrap_or_else(|| "true".into()).into_bytes(),
        provenance: None,
    };
    let call = store
        .append(
            &entry,
            &Approval::HarnessPin {
                machine: entry.machine.clone(),
                fingerprint: target.pin.clone(),
            },
        )
        .await
        .map_err(|_| "fixture append")?;
    if !previous_key.is_empty() {
        store.remember_poc_credential(previous_key.as_bytes());
    }
    if !key.is_empty() {
        store.remember_poc_credential(key.as_bytes());
    }
    let intent = &store.dispatch.calls[&call].intent;
    let evidence = crate::jobs::Evidence {
        call,
        job: intent.job.clone().ok_or("fixture job")?,
        record: crate::jobs::Record::Present {
            machine: hex::encode("machine-a"),
            command: intent.command.clone(),
            boot: "boot-a".into(),
            current_boot: "boot-a".into(),
            pid: 42,
            alive: false,
            exit_status: Some(7),
            stdout: hex::encode(output),
            stderr: hex::encode(stderr),
        },
    };
    let before = store.storage.files();
    let report = match store.job_evidence(&evidence).await {
        Ok(report) => report,
        Err(why) => {
            let recovered = unlock(
                MemoryStorage::with_files(store.storage.files()),
                &Fixed,
                pass(),
            )
            .await?;
            return Ok(json!({"withheld":why,"phase":"settlement",
                "terminals":store.dispatch.terminals.len(),
                "collectable":store.collectable("machine-a").await?.len(),
                "admitted":store.check("machine-a").await.is_ok(),
                "unchanged":store.storage.files()==before,
                "replayed":recovered.dispatch.calls==store.dispatch.calls
                    && recovered.dispatch.jobs==store.dispatch.jobs,
                "launches":store.dispatch.calls.len()}));
        }
    };
    let done = crate::harness::Done {
        seq: call,
        sent: crate::jobs::launch_with_elevation(
            &evidence.job,
            &entry.machine,
            &entry.command,
            target.elevation,
        )
        .into_bytes(),
        recorded: entry,
        stdout: report.stdout.as_bytes().to_vec(),
        stderr: report.stderr.as_bytes().to_vec(),
        exit_status: report.exit_status.unwrap_or(0),
        terminal: report.number.unwrap(),
        host_key: target.pin,
        evidence: report.clone(),
    };
    let mut releases = Vec::new();
    let mut values = vec![serde_json::to_value(&report).map_err(|_| "fixture report")?];
    values.extend(crate::harness::release_forms(&done));
    for value in values {
        match store.protect_command_results(&value) {
            Ok(value) => releases.push(value),
            Err(why) => {
                return Ok(json!({"withheld":why,"phase":"release",
                "terminals":store.dispatch.terminals.len(),
                "collectable":store.collectable("machine-a").await?.len()}));
            }
        }
    }
    let released = &releases[0];
    let admitted = store.check("machine-a").await.is_ok();
    let settled = store.storage.files();
    let duplicate_refused =
        store.job_evidence(&evidence).await.is_err() && store.storage.files() == settled;
    let mut recovered = unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        pass(),
    )
    .await?;
    let canonical_replayed = recovered.dispatch.jobs == store.dispatch.jobs
        && recovered.dispatch.calls == store.dispatch.calls;
    // Display equality below deliberately uses the same transient protection context.
    for key in [&key, &previous_key]
        .into_iter()
        .filter(|key| !key.is_empty())
    {
        recovered.remember_poc_credential(key.as_bytes());
    }
    let replayed = canonical_replayed
        && recovered.dispatch.jobs == store.dispatch.jobs
        && recovered.dispatch.calls == store.dispatch.calls
        && recovered.collectable("machine-a").await?.is_empty()
        && recovered.dispatch.calls.len() == 1
        && recovered.dispatch.terminals.len() == 1
        && recovered.protect_command_results(
            &serde_json::to_value(recovered.dispatch.jobs.last()).map_err(|_| "fixture replay")?,
        )? == *released;
    let mut reader = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    let mut contains = false;
    for number in 0..store.next {
        let bytes = store.storage.read(&number.to_string()).await?;
        let event = reader.open(number, &bytes)?;
        let serialized = serde_json::to_string(&event).map_err(|_| "fixture event")?;
        for key in [&key, &previous_key]
            .into_iter()
            .filter(|key| !key.is_empty())
        {
            contains |= [
                key.to_string(),
                hex::encode(key),
                base64::engine::general_purpose::STANDARD.encode(key),
            ]
            .iter()
            .any(|form| serialized.contains(form));
        }
        reader.previous = Address(Sha256::digest(&bytes).into());
    }
    Ok(
        json!({"report":released,"served":releases[2],"collected":releases[3],"held_dispatch":releases[6],"canonical_replayed":canonical_replayed,"admitted":admitted,"replayed":replayed,"journal_contains_key":contains,
        "collectable":store.collectable("machine-a").await?.len(),
        "terminals":store.dispatch.terminals.len(),"launches":store.dispatch.calls.len(),
        "duplicate_refused":duplicate_refused}),
    )
}

#[cfg(all(not(target_arch = "wasm32"), not(any(test, feature = "tracer"))))]
fn native_approval() -> Result<crate::binding::InferenceApproval, String> {
    Err("explicit inference approval required".into())
}
