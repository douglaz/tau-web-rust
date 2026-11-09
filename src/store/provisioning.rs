//! One durable procurement. Possibly-sent intents have no retry or discard transition.
use super::*;
use crate::dispatch::{
    Access, ApprovedEntry, BillingInterval, ClassAnswer, MachineEntry, Period, RecurringCost, Unit,
};
use crate::poc::provisioning::{
    self as protocol, Api, BillingTerms, Charge, REFUSED, Selection, array, id, number, payment_id,
    text, timestamp, unique_ids,
};
use crate::poc::targets::TargetRecord;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Purchase {
    pub origin: String,
    pub machine: String,
    pub identity: Identity,
    pub relay_identity: Identity,
    pub class_answer: ClassAnswer,
    pub account: String,
    pub relay: String,
    pub selected: Selection,
    pub approved_at: u64,
    #[serde(default)]
    pub pending_selection: Option<Selection>,
    pub registration_sent: bool,
    pub ssh_key: Option<Value>,
    pub create: Option<Create>,
    pub vm: Option<Value>,
    pub invoice: Option<Invoice>,
    #[serde(default)]
    pub billing: Option<Billing>,
    pub payment: Option<Value>,
    pub publication: Option<Value>,
    pub target: Option<TargetRecord>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Create {
    pub before: Vec<Value>,
    pub started: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Billing {
    pub vm_id: u64,
    pub terms: BillingTerms,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invoice {
    pub before: Vec<String>,
    pub started: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Record {
    Approved(Box<Purchase>),
    TermsChanged(Selection),
    Reapproved {
        selected: Selection,
        approved_at: u64,
    },
    RegistrationSent,
    Registered(Value),
    CreateSent(Create),
    Associated(Value),
    BillingQuoted(Billing),
    InvoiceSent(Invoice),
    Payment(Value),
    Observation(Value),
    Handoff {
        target: TargetRecord,
        publication: Value,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Approval {
    pub origin: String,
    pub machine: String,
    pub relay: String,
    pub class_answer: ClassAnswer,
    pub approve_charge: bool,
    pub approve_maintained_access: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Choice {
    pub offer_id: u64,
    pub image_id: u64,
    pub resources: Option<Value>,
}

impl<S: Storage> Store<S> {
    pub(crate) fn remember_provider_filter(&mut self, filter: crate::poc::inference::EchoFilter) {
        if let Some(known) = self.provider_filters.first_mut() {
            known.merge(filter);
        } else {
            self.provider_filters.push(filter);
        }
    }
    pub(crate) async fn protect_provider_request(
        &mut self,
        fingerprints: crate::poc::inference::EchoFingerprints,
    ) -> Result<(), String> {
        self.commit(&Event::ProviderProtection(fingerprints.clone()))
            .await?;
        self.remember_provider_filter(fingerprints.filter());
        Ok(())
    }
    fn procurement_ready(&self) -> Result<(), String> {
        self.authority.ordinary()?;
        if self.inference.ended || self.failed.is_some() || self.allocation().seed_backup_owed() {
            return Err("Complete unlock and seed backup before procurement.".into());
        }
        Ok(())
    }
    pub(crate) fn procurement_account(&self, account: &str) -> Result<(), String> {
        self.procurement_ready()?;
        if self
            .procurement
            .as_ref()
            .is_some_and(|p| p.account != account)
        {
            return Err("Re-enter the same provider account used for this purchase.".into());
        }
        Ok(())
    }
    pub(crate) fn procurement_origin(&self) -> &str {
        self.procurement
            .as_ref()
            .map_or(&self.provider_origin, |p| &p.origin)
    }
    pub(crate) fn procurement_configure(
        &mut self,
        account: &protocol::Account,
        secret: &[u8],
        origin: &str,
    ) -> Result<(), String> {
        let normalized = protocol::provider_origin(origin)?;
        self.procurement_account(&account.public())?;
        let filter = account.filter(secret);
        if !crate::poc::inference::safe(self, &json!([origin, normalized]), &[secret]) {
            return Err("Provider origin contains protected or unscannable material.".into());
        }
        for value in [origin, normalized.as_str()] {
            if filter.protect_bytes(value.as_bytes())?.as_slice() != value.as_bytes() {
                return Err("Provider origin contains protected or unscannable material.".into());
            }
        }
        // A bound Purchase always wins, including after re-entry with another field value.
        if self.procurement.is_none() && self.provider_origin != normalized {
            self.procurement_selection = None;
            self.provider_origin = normalized;
        }
        self.remember_provider_filter(filter);
        Ok(())
    }
    fn check_api(&self, api: &impl Api) -> Result<(), String> {
        api.current()?;
        self.procurement_account(&api.account())
    }
    async fn provider_read(
        &mut self,
        api: &mut impl Api,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<Value, String> {
        self.check_api(api)?;
        let url = protocol::request_url(self.procurement_origin(), path)?;
        if let Some(fingerprints) = api.prepare(method, &url, body.as_ref())? {
            self.protect_provider_request(fingerprints).await?;
        }
        self.check_api(api)?;
        let result = api.request(method, &url, body).await;
        if let Some(filter) = api.take_filter() {
            self.remember_provider_filter(filter);
        }
        self.check_api(api)?;
        let value = result?;
        if !crate::poc::inference::safe(self, &value, &[]) {
            return Err(REFUSED.into());
        }
        Ok(value)
    }
    pub(crate) fn procurement_review_selection(&self) -> Option<&Selection> {
        match &self.procurement {
            Some(purchase) => purchase.pending_selection.as_ref(),
            None => self.procurement_selection.as_ref(),
        }
    }
    pub(crate) fn procurement_billing(&self) -> Option<&Billing> {
        self.procurement.as_ref().and_then(|p| p.billing.as_ref())
    }
    pub(crate) fn procurement_view(&self) -> Value {
        let Some(p) = &self.procurement else {
            return json!({"origin":self.procurement_origin(),"selection":self.procurement_selection});
        };
        let phase = if p.pending_selection.is_some() {
            "terms_changed"
        } else if p.target.is_some() {
            "handed_off"
        } else if p.payment.is_some() {
            "payment_readiness"
        } else if p.invoice.is_some() {
            "invoice_uncertain"
        } else if p.vm.is_some() {
            "initial_invoice"
        } else if p.create.is_some() {
            "create_uncertain"
        } else if p.ssh_key.is_some() {
            "registered"
        } else if p.registration_sent {
            "registration_uncertain"
        } else {
            "approved"
        };
        json!({"origin":p.origin,"phase":phase,"machine":p.machine,"account":p.account,"selection":p.pending_selection.as_ref().unwrap_or(&p.selected),"approved_selection":p.selected,"relay":p.relay,"class_answer":p.class_answer,"identity":p.identity,"ssh_key_id":p.ssh_key.as_ref().map(|k|&k["id"]),"vm_id":p.vm.as_ref().map(|vm|&vm["id"]),"billing":p.billing,"payment":p.payment,"auto_renewal_enabled":p.vm.as_ref().and_then(|vm|vm.get("auto_renewal_enabled")),"target":p.target,"publication":p.publication,"public_keys":self.poc_identity_public_keys(&p.machine,&p.identity).ok()})
    }
    pub(crate) async fn procurement_catalogue(
        &mut self,
        api: &mut impl Api,
    ) -> Result<Value, String> {
        self.check_api(api)?;
        let catalogue = self
            .provider_read(api, "GET", "/api/v1/vm/templates", None)
            .await?;
        array(&catalogue["templates"])?;
        if let Some(custom) = catalogue.get("custom_template") {
            array(custom)?;
        }
        let images = self
            .provider_read(api, "GET", "/api/v1/image", None)
            .await?;
        let (catalogue, images) = protocol::catalogue_public(catalogue, images)?;
        Ok(json!({"offers":catalogue,"images":images}))
    }
    pub(crate) async fn procurement_select(
        &mut self,
        api: &mut impl Api,
        choice: Choice,
    ) -> Result<(), String> {
        // Invalidate the prior candidate even when the replacement fails validation.
        self.procurement_selection = None;
        self.check_api(api)?;
        if self
            .procurement
            .as_ref()
            .is_some_and(|p| p.create.is_some())
            || (self.procurement.is_none() && !self.dispatch.approved_entries.is_empty())
            || !self.poc_targets.is_empty()
        {
            return Err("This store already owns a machine or outstanding purchase.".into());
        }
        let selected = self.procurement_fetch_selection(api, choice).await?;
        if self.procurement.is_some() {
            self.procurement_commit(Record::TermsChanged(selected))
                .await
        } else {
            self.procurement_selection = Some(selected);
            Ok(())
        }
    }
    async fn procurement_fetch_selection(
        &mut self,
        api: &mut impl Api,
        choice: Choice,
    ) -> Result<Selection, String> {
        let catalogue = self.procurement_catalogue(api).await?;
        let field = if choice.resources.is_some() {
            "custom_template"
        } else {
            "templates"
        };
        let offers = array(&catalogue["offers"][field])?;
        let offer = offers
            .iter()
            .find(|o| id(o).ok() == Some(choice.offer_id))
            .ok_or(REFUSED)?
            .clone();
        let image = array(&catalogue["images"])?
            .iter()
            .find(|i| id(i).ok() == Some(choice.image_id))
            .ok_or(REFUSED)?
            .clone();
        let charge = if let Some(r) = &choice.resources {
            // Validate resources with provisional terms before making even the price request.
            let provisional = Selection {
                offer: offer.clone(),
                image: image.clone(),
                resources: Some(r.clone()),
                charge: Charge {
                    currency: "BTC".into(),
                    amount: 1,
                    interval_amount: number(&offer, "interval_amount")?,
                    interval_type: text(&offer, "interval_type", 5)?.into(),
                },
            };
            provisional.validate()?;
            let price = self
                .provider_read(
                    api,
                    "POST",
                    "/api/v1/vm/custom-template/price",
                    Some(r.clone()),
                )
                .await?;
            Charge::parse(&price)?
        } else {
            Charge::parse(&offer["cost_plan"])?
        };
        let selected = Selection {
            offer,
            image,
            resources: choice.resources,
            charge,
        };
        selected.validate()?;
        Ok(selected)
    }
    pub(crate) async fn procurement_approve(
        &mut self,
        api: &mut impl Api,
        approval: Approval,
    ) -> Result<(), String> {
        self.check_api(api)?;
        if approval.origin != self.procurement_origin() {
            return Err("The displayed provider origin is stale; review the current origin and selection again.".into());
        }
        // Refuse unsafe authority before selecting identities or recording approval.
        if !crate::poc::inference::safe(
            self,
            &serde_json::to_value(&approval).map_err(|_| "approval encoding")?,
            &[],
        ) {
            return Err("Purchase authority contains protected or unscannable material.".into());
        }
        if !approval.approve_charge || !approval.approve_maintained_access {
            return Err(
                "Explicit exact charge and maintained-access approvals are required.".into(),
            );
        }
        let existing = self.procurement.clone();
        if let Some(p) = &existing {
            if p.create.is_some() || p.pending_selection.is_none() {
                return Err(
                    "Saved purchase terms cannot be changed after a possible create; Refresh only."
                        .into(),
                );
            }
            if approval.machine != p.machine
                || approval.relay != p.relay
                || approval.class_answer != p.class_answer
            {
                return Err(
                    "Renewed approval must retain the saved machine, relay and class.".into(),
                );
            }
        } else if !self.dispatch.approved_entries.is_empty() || !self.poc_targets.is_empty() {
            return Err("This store already owns a machine or outstanding purchase.".into());
        }
        let selected = existing
            .as_ref()
            .and_then(|p| p.pending_selection.clone())
            .or_else(|| self.procurement_selection.clone())
            .ok_or("Fetch and choose an offer before approval.")?;
        // Approval authorizes exactly the displayed terms, never a newly fetched change.
        let fresh = self
            .procurement_fetch_selection(
                api,
                Choice {
                    offer_id: id(&selected.offer)?,
                    image_id: id(&selected.image)?,
                    resources: selected.resources.clone(),
                },
            )
            .await?;
        if !fresh.same_terms(&selected) {
            if existing.is_some() {
                self.procurement_commit(Record::TermsChanged(fresh)).await?;
            } else {
                self.procurement_selection = Some(fresh);
            }
            return Err("The offer or price changed; review and approve the new terms.".into());
        }
        if existing.is_some() {
            return self
                .procurement_commit(Record::Reapproved {
                    selected,
                    approved_at: api.now(),
                })
                .await;
        }
        let record = Purchase {
            origin: self.procurement_origin().into(),
            machine: approval.machine,
            identity: self
                .allocation()
                .issue(Family::Machines)
                .map_err(|e| e.to_string())?,
            relay_identity: match super::poc_targets::eligible_pass(self.allocation()) {
                Some(i) => i.clone(),
                None => self
                    .allocation()
                    .issue(Family::Passes)
                    .map_err(|e| e.to_string())?,
            },
            class_answer: approval.class_answer,
            account: api.account(),
            relay: approval.relay,
            selected,
            approved_at: api.now(),
            pending_selection: None,
            registration_sent: false,
            ssh_key: None,
            create: None,
            vm: None,
            invoice: None,
            billing: None,
            payment: None,
            publication: None,
            target: None,
        };
        self.procurement_commit(Record::Approved(Box::new(record)))
            .await?;
        self.procurement_selection = None;
        Ok(())
    }
    fn procurement_projection(&self, record: &Record) -> Result<Purchase, String> {
        if let Record::Approved(p) = record {
            if self.procurement.is_some()
                || !self.dispatch.approved_entries.is_empty()
                || !self.poc_targets.is_empty()
            {
                return Err(REFUSED.into());
            }
            p.selected.validate()?;
            if protocol::provider_origin(&p.origin)? != p.origin {
                return Err(REFUSED.into());
            }
            if p.account.len() != 64
                || !p.account.bytes().all(|b| b.is_ascii_hexdigit())
                || !crate::poc::targets::valid_relay(&p.relay)
                || p.machine.is_empty()
                || p.machine.len() > 64
                || !p.machine.as_bytes()[0].is_ascii_alphanumeric()
                || !p
                    .machine
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                || p.pending_selection.is_some()
                || p.registration_sent
                || p.ssh_key.is_some()
                || p.create.is_some()
                || p.vm.is_some()
                || p.billing.is_some()
                || p.invoice.is_some()
                || p.payment.is_some()
                || p.target.is_some()
                || p.publication.is_some()
            {
                return Err(REFUSED.into());
            }
            if p.identity
                != self
                    .allocation()
                    .issue(Family::Machines)
                    .map_err(|e| e.to_string())?
            {
                return Err(REFUSED.into());
            }
            let relay = super::poc_targets::eligible_pass(self.allocation())
                .cloned()
                .map(Ok)
                .unwrap_or_else(|| {
                    self.allocation()
                        .issue(Family::Passes)
                        .map_err(|e| e.to_string())
                })?;
            if relay != p.relay_identity {
                return Err(REFUSED.into());
            }
            return Ok(*p.clone());
        }
        let mut p = self.procurement.clone().ok_or(REFUSED)?;
        match record {
            Record::Approved(_) => unreachable!(),
            Record::TermsChanged(selected) => {
                if p.create.is_some() || p.vm.is_some() || p.target.is_some() {
                    return Err(REFUSED.into());
                }
                selected.validate()?;
                p.pending_selection = Some(selected.clone());
            }
            Record::Reapproved {
                selected,
                approved_at,
            } => {
                if p.create.is_some()
                    || p.vm.is_some()
                    || p.target.is_some()
                    || p.pending_selection.as_ref() != Some(selected)
                    || *approved_at < p.approved_at
                {
                    return Err(REFUSED.into());
                }
                selected.validate()?;
                p.selected = selected.clone();
                p.approved_at = *approved_at;
                p.pending_selection = None;
            }
            Record::RegistrationSent => {
                if p.registration_sent {
                    return Err(REFUSED.into());
                }
                p.registration_sent = true;
            }
            Record::Registered(key) => {
                if !p.registration_sent || p.ssh_key.is_some() {
                    return Err(REFUSED.into());
                }
                id(key)?;
                text(key, "name", 128)?;
                timestamp(text(key, "created", 40)?)?;
                p.ssh_key = Some(key.clone());
            }
            Record::CreateSent(intent) => {
                if p.pending_selection.is_some()
                    || p.ssh_key.is_none()
                    || p.create.is_some()
                    || p.vm.is_some()
                    || intent.started < p.approved_at
                    || intent.before.len() > 128
                    || unique_ids(&json!(intent.before)).is_err()
                {
                    return Err(REFUSED.into());
                }
                for vm in &intent.before {
                    protocol::validate_vm(vm)?;
                }
                p.create = Some(intent.clone());
            }
            Record::Associated(vm) => {
                let intent = p.create.as_ref().ok_or(REFUSED)?;
                if p.vm.is_some()
                    || intent.before.iter().any(|old| old["id"] == vm["id"])
                    || !p.selected.matches(
                        vm,
                        id(p.ssh_key.as_ref().ok_or(REFUSED)?)?,
                        intent.started,
                    )
                {
                    return Err(REFUSED.into());
                }
                p.vm = Some(vm.clone());
            }
            Record::BillingQuoted(billing) => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                if billing.vm_id != id(vm)? || p.invoice.is_some() || p.payment.is_some() {
                    return Err(REFUSED.into());
                }
                billing.terms.validate()?;
                p.billing = Some(billing.clone());
            }
            Record::InvoiceSent(intent) => {
                if p.billing
                    .as_ref()
                    .is_none_or(|b| p.vm.as_ref().is_none_or(|vm| id(vm).ok() != Some(b.vm_id)))
                    || p.vm.is_none()
                    || p.invoice.is_some()
                    || p.payment.is_some()
                    || !intent.before.is_empty()
                {
                    return Err(REFUSED.into());
                }
                p.invoice = Some(intent.clone());
            }
            Record::Payment(payment) => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                if !protocol::suitable_payment(
                    payment,
                    id(vm)?,
                    &p.billing
                        .as_ref()
                        .filter(|b| id(vm).ok() == Some(b.vm_id))
                        .ok_or(REFUSED)?
                        .terms,
                    timestamp(text(vm, "created", 40)?)?,
                ) || p.payment.as_ref().is_some_and(|old| {
                    old["id"] != payment["id"]
                        || old["created"] != payment["created"]
                        || old["data"] != payment["data"]
                        || old["expires"] != payment["expires"]
                        || (old["is_paid"] == true && payment["is_paid"] != true)
                }) {
                    return Err(REFUSED.into());
                }
                p.payment = Some(payment.clone());
            }
            Record::Observation(vm) => {
                let old = p.vm.as_ref().ok_or(REFUSED)?;
                if old["id"] != vm["id"]
                    || old["created"] != vm["created"]
                    || !p.selected.matches(
                        vm,
                        id(p.ssh_key.as_ref().ok_or(REFUSED)?)?,
                        p.create.as_ref().ok_or(REFUSED)?.started,
                    )
                {
                    return Err(REFUSED.into());
                }
                if let Some(target) = &p.target {
                    let (_, pin) = protocol::published_pin(vm)?;
                    if target.pin != pin || target.host != protocol::allocated_ipv4(vm)? {
                        return Err(
                            "Published identity conflicts with the immutable target.".into()
                        );
                    }
                }
                p.vm = Some(vm.clone());
            }
            Record::Handoff {
                target,
                publication,
            } => {
                let vm = p.vm.as_ref().ok_or(REFUSED)?;
                let (key, pin) = protocol::published_pin(vm)?;
                let expected = TargetRecord {
                    machine: p.machine.clone(),
                    relay: p.relay.clone(),
                    profile: "v1".into(),
                    host: protocol::allocated_ipv4(vm)?,
                    port: 22,
                    user: "arch".into(),
                    elevation: crate::jobs::Elevation::SudoNoninteractive,
                    pin,
                };
                if p.target.is_some()
                    || p.payment.as_ref().is_none_or(|pay| pay["is_paid"] != true)
                    || vm["status"]["state"] != "running"
                    || target != &expected
                    || publication
                        != &json!({"origin":p.origin,"vm_id":vm["id"],"created":vm["created"],"selected_key":key,"host_ssh_keys":vm["host_ssh_keys"]})
                {
                    return Err(REFUSED.into());
                }
                target.validate()?;
                p.target = Some(target.clone());
                p.publication = Some(publication.clone());
            }
        }
        Ok(p)
    }
    fn apply_procurement(
        &mut self,
        number: u64,
        record: &Record,
        p: Purchase,
    ) -> Result<(), String> {
        if matches!(record, Record::Approved(_) | Record::Reapproved { .. }) {
            let charge = &p.selected.charge;
            let approved = ApprovedEntry {
                entry: MachineEntry {
                    machine: p.machine.clone(),
                    vendor: "LNVPS".into(),
                    product: text(&p.selected.offer, "name", 128)?.into(),
                    region: text(&p.selected.offer["region"], "name", 128)?.into(),
                    cost: RecurringCost {
                        amount: charge.amount,
                        unit: match charge.currency.as_str() {
                            "BTC" => Unit::Millisat,
                            "EUR" => Unit::EurCent,
                            _ => Unit::UsdCent,
                        },
                        period: Period::Billing {
                            count: charge.interval_amount,
                            interval: match charge.interval_type.as_str() {
                                "day" => BillingInterval::Day,
                                "month" => BillingInterval::Month,
                                _ => BillingInterval::Year,
                            },
                        },
                    },
                },
                identity: p.identity.clone(),
                access: Some(Access::ad_hoc()),
            };
            let mut dispatch = self.dispatch.clone();
            let mut allocation = self.allocation().clone();
            if matches!(record, Record::Approved(_)) {
                dispatch.apply_poc_purchase(&mut allocation, approved, p.class_answer)?;
            } else {
                let old = dispatch
                    .approved_entries
                    .get_mut(&p.machine)
                    .ok_or(REFUSED)?;
                if old.approved.identity != p.identity
                    || old.answer != Some(p.class_answer)
                    || old.approved.access != approved.access
                {
                    return Err(REFUSED.into());
                }
                old.approved = approved;
            }
            if let Some(pass) = super::poc_targets::eligible_pass(&allocation) {
                if pass != &p.relay_identity {
                    return Err(REFUSED.into());
                }
            } else {
                allocation
                    .apply(&allocation::Event::Reserve(p.relay_identity.clone()))
                    .map_err(|e| e.to_string())?;
            }
            dispatch.setup_approval = Some(number);
            self.dispatch = dispatch;
            self.allocation = Some(allocation);
        }
        self.procurement = Some(p.clone());
        if let Record::Handoff { target, .. } = record {
            let record = Self::purchase_target_record(
                target.clone(),
                p.identity,
                p.relay_identity,
                p.class_answer,
            );
            self.replay_poc_target(number, &record)?;
        }
        Ok(())
    }
    pub(super) fn replay_procurement(
        &mut self,
        number: u64,
        record: &Record,
    ) -> Result<(), String> {
        let next = self.procurement_projection(record)?;
        self.apply_procurement(number, record, next)
    }
    async fn procurement_commit(&mut self, record: Record) -> Result<(), String> {
        self.procurement_ready()?;
        let next = self.procurement_projection(&record)?;
        let number = self.commit(&Event::Procurement(record.clone())).await?;
        self.apply_procurement(number, &record, next)
    }
    async fn history(&mut self, api: &mut impl Api, vm: u64) -> Result<Vec<Value>, String> {
        let result = self
            .provider_read(
                api,
                "GET",
                &format!("/api/v1/vm/{vm}/payments?limit=100&offset=0"),
                None,
            )
            .await?;
        let rows = array(&result)?;
        if rows.len() >= 100 {
            return Err(
                "Payment history incomplete; Refresh without issuing another invoice.".into(),
            );
        }
        let mut ids = std::collections::BTreeSet::new();
        for row in rows {
            if !ids.insert(payment_id(row)?) || number(row, "vm_id")? != vm {
                return Err(REFUSED.into());
            }
        }
        Ok(rows.clone())
    }
    async fn initial_billing_quote(&mut self, api: &mut impl Api) -> Result<Billing, String> {
        let p = self.procurement.clone().ok_or(REFUSED)?;
        let vm_id = id(p.vm.as_ref().ok_or(REFUSED)?)?;
        // The quote is for this same approved machine, not an unverified current configuration.
        let vm = self
            .provider_read(api, "GET", &format!("/api/v1/vm/{vm_id}"), None)
            .await?;
        self.procurement_commit(Record::Observation(vm)).await?;
        let value = self
            .provider_read(
                api,
                "GET",
                &format!("/api/v1/vm/{vm_id}/renew/quote?method=lightning&intervals=1"),
                None,
            )
            .await?;
        Ok(Billing {
            vm_id,
            terms: BillingTerms::parse(&value)?,
        })
    }
    async fn associate_payment(&mut self, api: &mut impl Api, issue: bool) -> Result<(), String> {
        let p = self.procurement.clone().ok_or(REFUSED)?;
        let vm = p.vm.as_ref().ok_or(REFUSED)?;
        let vm_id = id(vm)?;
        let history = self.history(api, vm_id).await?;
        if !history.is_empty() {
            if history.len() != 1 {
                return Err(
                    "Initial payment evidence conflicts or is ambiguous; no invoice issued.".into(),
                );
            }
            let billing = match p.billing {
                Some(billing) => billing,
                None => {
                    let billing = self.initial_billing_quote(api).await?;
                    self.procurement_commit(Record::BillingQuoted(billing.clone()))
                        .await?;
                    billing
                }
            };
            if !protocol::suitable_payment(
                &history[0],
                vm_id,
                &billing.terms,
                timestamp(text(vm, "created", 40)?)?,
            ) {
                return Err("Initial payment evidence conflicts or cannot be established from the saved one-period quote; no invoice issued.".into());
            }
            return self
                .procurement_commit(Record::Payment(history[0].clone()))
                .await;
        }
        if p.invoice.is_some() {
            return Err("Initial invoice outcome unknown; Refresh payment history later. It will never be reissued.".into());
        }
        let fresh = self.initial_billing_quote(api).await?;
        if p.billing.as_ref() != Some(&fresh) {
            self.procurement_commit(Record::BillingQuoted(fresh))
                .await?;
            return Err("Review the current initial Lightning quote and explicitly approve issuance for the first approved billing period.".into());
        }
        if !issue {
            return Err("Approve issuance of the initial Lightning invoice for the first approved billing period.".into());
        }
        let current = self
            .procurement
            .as_ref()
            .and_then(|p| p.vm.as_ref())
            .ok_or(REFUSED)?;
        if current.get("expires").is_some_and(|v| !v.is_null())
            || current.get("subscription_id").is_some_and(|v| !v.is_null())
        {
            return Err("Existing billing evidence prevents initial invoice issuance.".into());
        }
        self.procurement_commit(Record::InvoiceSent(Invoice {
            before: Vec::new(),
            started: api.now(),
        }))
        .await?;
        let payment = self
            .provider_read(
                api,
                "GET",
                &format!("/api/v1/vm/{vm_id}/renew?method=lightning&intervals=1"),
                None,
            )
            .await?;
        self.procurement_commit(Record::Payment(payment)).await
    }
    /// Explicit bounded progress. Refresh never sends a create or invoice whose intent exists.
    pub(crate) async fn procurement_resume(
        &mut self,
        api: &mut impl Api,
        issue_invoice: bool,
    ) -> Result<(), String> {
        self.check_api(api)?;
        let mut p = self
            .procurement
            .clone()
            .ok_or("Approve a fetched selection first.")?;
        if p.target.is_some() {
            return Ok(());
        }
        if p.pending_selection.is_some() {
            return Err(
                "The offer or price changed; review and approve the new terms before creating."
                    .into(),
            );
        }
        if p.registration_sent && p.ssh_key.is_none() {
            self.provider_read(api, "GET", "/api/v1/ssh-key", None)
                .await?;
            return Err("SSH registration outcome unknown. The provider list has no public-key material to prove a match; no insertion or order is retried.".into());
        }
        if p.ssh_key.is_none() {
            let public = self.poc_identity_public_keys(&p.machine, &p.identity)?;
            self.procurement_commit(Record::RegistrationSent).await?;
            let key=self.provider_read(api,"POST","/api/v1/ssh-key",Some(json!({"name":format!("tau-{}",p.identity.index),"key_data":public["authorized_keys"]}))).await?;
            self.procurement_commit(Record::Registered(key)).await?;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        if p.vm.is_none() {
            if p.create.is_none() {
                let fresh = self
                    .procurement_fetch_selection(
                        api,
                        Choice {
                            offer_id: id(&p.selected.offer)?,
                            image_id: id(&p.selected.image)?,
                            resources: p.selected.resources.clone(),
                        },
                    )
                    .await?;
                if !fresh.same_terms(&p.selected) {
                    self.procurement_commit(Record::TermsChanged(fresh)).await?;
                    return Err("The offer or price changed; review and approve the new terms before creating.".into());
                }
                let before = self.provider_read(api, "GET", "/api/v1/vm", None).await?;
                unique_ids(&before)?;
                for vm in array(&before)? {
                    protocol::validate_vm(vm)?;
                }
                let before = array(&before)?.clone();
                let started = api.now();
                self.procurement_commit(Record::CreateSent(Create { before, started }))
                    .await?;
                #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
                crate::testonly::session_point("procurement_create_intent").await;
                self.check_api(api)?;
                let (path, body) = p.selected.create(id(p.ssh_key.as_ref().ok_or(REFUSED)?)?);
                let vm = self.provider_read(api, "POST", path, Some(body)).await?;
                self.procurement_commit(Record::Associated(vm)).await?;
            } else {
                let intent = p.create.as_ref().ok_or(REFUSED)?;
                let after = self.provider_read(api, "GET", "/api/v1/vm", None).await?;
                unique_ids(&after)?;
                if array(&after)?.len() > 8 {
                    return Err("Create inventory exceeds the bounded reconciliation limit; no order is retried.".into());
                }
                let mut candidates = Vec::new();
                for vm in array(&after)? {
                    if !intent.before.iter().any(|old| old["id"] == vm["id"]) {
                        // Require complete matching list and detail evidence, never uniqueness alone.
                        let detail = self
                            .provider_read(api, "GET", &format!("/api/v1/vm/{}", id(vm)?), None)
                            .await?;
                        let key = id(p.ssh_key.as_ref().ok_or(REFUSED)?)?;
                        if !p.selected.matches(vm, key, intent.started)
                            || !p.selected.matches(&detail, key, intent.started)
                            || vm["id"] != detail["id"]
                            || vm["created"] != detail["created"]
                        {
                            return Err(
                                "Create evidence incomplete or conflicting; no order is retried."
                                    .into(),
                            );
                        }
                        candidates.push(detail);
                    }
                }
                if candidates.len() != 1 {
                    return Err("Create outcome unknown: zero or multiple evidenced machines. Refresh later; no order is retried.".into());
                }
                self.procurement_commit(Record::Associated(candidates.remove(0)))
                    .await?;
            }
            #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
            crate::testonly::session_point("procurement_associated").await;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        if p.payment.is_none() {
            self.associate_payment(api, issue_invoice).await?;
            p = self.procurement.clone().ok_or(REFUSED)?;
        }
        let vm_id = id(p.vm.as_ref().ok_or(REFUSED)?)?;
        let payment = p.payment.as_ref().ok_or(REFUSED)?;
        let updated = self
            .provider_read(
                api,
                "GET",
                &format!("/api/v1/payment/{}", payment_id(payment)?),
                None,
            )
            .await?;
        self.procurement_commit(Record::Payment(updated.clone()))
            .await?;
        if updated["is_paid"] != true {
            if timestamp(text(&updated, "expires", 40)?)? <= api.now() {
                return Err("Initial invoice expired; this purchase remains paused with the same VM/payment. Reissue is unsupported.".into());
            }
            return Err(
                "Waiting for external payment of the displayed initial invoice; Refresh later."
                    .into(),
            );
        }
        let vm = self
            .provider_read(api, "GET", &format!("/api/v1/vm/{vm_id}"), None)
            .await?;
        self.procurement_commit(Record::Observation(vm.clone()))
            .await?;
        if vm["status"]["state"] != "running" {
            return Err(
                "Waiting for provider boot readiness; unknown state is not ready. Refresh later."
                    .into(),
            );
        }
        let (key, pin) = protocol::published_pin(&vm)?;
        let target = TargetRecord {
            machine: p.machine,
            relay: p.relay,
            profile: "v1".into(),
            host: protocol::allocated_ipv4(&vm)?,
            port: 22,
            user: "arch".into(),
            elevation: crate::jobs::Elevation::SudoNoninteractive,
            pin,
        };
        self.procurement_commit(Record::Handoff {target,publication:json!({"origin":p.origin,"vm_id":vm_id,"created":vm["created"],"selected_key":key,"host_ssh_keys":vm["host_ssh_keys"]})}).await
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
