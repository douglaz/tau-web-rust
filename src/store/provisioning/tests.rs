use super::*;
use crate::poc::provisioning::tests as fixtures;

struct Fixed;
impl Kdf for Fixed {
    async fn derive(&self, _: LocalPassphrase, _: &Salt) -> Result<WrappingKey, String> {
        Ok(WrappingKey([9; 32]))
    }
}
fn pass() -> LocalPassphrase {
    LocalPassphrase::new(b"local provisioning fixture".to_vec())
}
fn ready() -> Store<MemoryStorage> {
    let mut s = block_on(create(MemoryStorage::default(), &Fixed, pass())).unwrap();
    block_on(s.seed_backup(allocation::Completion::Skipped)).unwrap();
    s
}
fn reopen(s: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(s.storage.files()),
        &Fixed,
        pass(),
    ))
    .unwrap()
}
struct Fixture {
    custom: bool,
    current_selection: Selection,
    fail_catalogue: bool,
    returned_popularity: Option<f64>,
    billing_terms: BillingTerms,
    fail_quote: bool,
    protection_fault: Option<(String, MemoryStorage, Fault)>,
    prepared_protection: Option<crate::poc::inference::EchoFingerprints>,
    response_filter: Option<crate::poc::inference::EchoFilter>,
    observe_dispatch: Option<Box<dyn Fn()>>,
    after_read_clock: Option<(String, u64)>,
    response_echo: Option<String>,
    vm_change: Option<(String, Value)>,
    created: Option<String>,
    advance_before_create: u64,
    calls: Vec<String>,
    urls: Vec<String>,
    signed_requests: Vec<Value>,
    record_signatures: bool,
    machines: Vec<Value>,
    payments: Vec<Value>,
    history_response: Option<Value>,
    read_errors: std::collections::BTreeMap<String, protocol::ReadError>,
    read_values: std::collections::BTreeMap<String, Value>,
    status: u16,
    lose_create: bool,
    lose_invoice: bool,
    invoice_nanoseconds: bool,
    lose_registration: bool,
    account: String,
    clock: u64,
    fault_after: Option<(String, MemoryStorage, Fault)>,
}
impl Fixture {
    fn new(custom: bool) -> Self {
        Self {
            custom,
            current_selection: fixtures::selection(custom),
            fail_catalogue: false,
            returned_popularity: None,
            billing_terms: fixtures::billing_terms(),
            fail_quote: false,
            protection_fault: None,
            prepared_protection: None,
            response_filter: None,
            observe_dispatch: None,
            after_read_clock: None,
            response_echo: None,
            vm_change: None,
            created: None,
            advance_before_create: 0,
            calls: Vec::new(),
            urls: Vec::new(),
            signed_requests: Vec::new(),
            record_signatures: false,
            machines: Vec::new(),
            payments: Vec::new(),
            history_response: None,
            read_errors: Default::default(),
            read_values: Default::default(),
            status: 200,
            lose_create: false,
            lose_invoice: false,
            invoice_nanoseconds: false,
            lose_registration: false,
            account: "a".repeat(64),
            clock: timestamp("2026-11-06T14:00:00Z").unwrap(),
            fault_after: None,
        }
    }
    fn count(&self, request: &str) -> usize {
        self.calls.iter().filter(|c| c.as_str() == request).count()
    }
}
impl Api for Fixture {
    fn response_status(&self) -> u16 {
        self.status
    }
    fn prepare(
        &mut self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Option<crate::poc::inference::EchoFingerprints>, String> {
        if self.record_signatures {
            let auth = protocol::Account::parse(hex::encode([7; 32]).as_bytes())
                .unwrap()
                .authorization(
                    path,
                    method,
                    body.map(Value::to_string).as_deref().map(str::as_bytes),
                    self.clock,
                    &[5; 32],
                )
                .unwrap();
            self.signed_requests.push(
                serde_json::from_slice(
                    &base64::engine::general_purpose::STANDARD
                        .decode(auth.strip_prefix("Nostr ").unwrap())
                        .unwrap(),
                )
                .unwrap(),
            );
        }
        let path = path
            .split_once("/api/v1/")
            .map(|(_, p)| format!("/api/v1/{p}"))
            .ok_or(REFUSED)?;
        if self
            .protection_fault
            .as_ref()
            .is_some_and(|(route, _, _)| *route == format!("{method} {path}"))
        {
            let (_, storage, fault) = self.protection_fault.take().unwrap();
            storage.fault(fault);
            return Ok(Some(
                crate::poc::inference::EchoFilter::new(&[b"synthetic request scan material"])
                    .fingerprints(),
            ));
        }
        Ok(if self.observe_dispatch.is_some() {
            self.prepared_protection.clone()
        } else {
            self.prepared_protection.take()
        })
    }

    fn account(&self) -> String {
        self.account.clone()
    }
    fn take_filter(&mut self) -> Option<crate::poc::inference::EchoFilter> {
        self.response_filter.take()
    }
    fn now(&self) -> u64 {
        self.clock
    }
    fn current(&self) -> Result<(), String> {
        Ok(())
    }
    async fn request(
        &mut self,
        method: &str,
        path: &str,
        _body: Option<Value>,
    ) -> Result<Value, protocol::ReadError> {
        self.urls.push(path.into());
        if self.record_signatures {
            assert_eq!(
                self.signed_requests.last().unwrap()["tags"][0],
                json!(["u", path])
            );
        }
        let path = path
            .split_once("/api/v1/")
            .map(|(_, p)| format!("/api/v1/{p}"))
            .ok_or(REFUSED)?;
        self.calls.push(format!("{method} {path}"));
        if let Some(observe) = &self.observe_dispatch {
            observe();
        }
        let result = if let Some(error) = self.read_errors.remove(&path) {
            Err(error)
        } else if let Some(value) = self.read_values.remove(&path) {
            Ok(value)
        } else {
            let result: Result<Value, String> = match (method, path.as_str()) {
                ("GET", "/api/v1/vm/templates") => {
                    if self.fail_catalogue {
                        return Err("catalogue unavailable".into());
                    }
                    let mut fixed = if self.custom {
                        fixtures::offer()
                    } else {
                        self.current_selection.offer.clone()
                    };
                    if let Some(echo) = &self.response_echo {
                        fixed["name"] = echo.clone().into();
                    }
                    Ok(
                        json!({"templates":[fixed],"custom_template":[if self.custom { self.current_selection.offer.clone() } else { fixtures::custom() }]}),
                    )
                }
                ("GET", "/api/v1/image") => Ok(json!([self.current_selection.image])),
                ("POST", "/api/v1/vm/custom-template/price") => {
                    Ok(serde_json::to_value(&self.current_selection.charge).unwrap())
                }
                ("POST", "/api/v1/ssh-key") => {
                    if self.lose_registration {
                        Err("lost".into())
                    } else {
                        Ok(json!({"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"}))
                    }
                }
                ("GET", "/api/v1/ssh-key") => {
                    Ok(json!([{"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"}]))
                }
                ("GET", "/api/v1/vm") => Ok(json!(self.machines)),
                ("POST", "/api/v1/vm" | "/api/v1/vm/custom-template") => {
                    self.clock += self.advance_before_create;
                    self.advance_before_create = 0;
                    let mut vm = fixtures::vm(&self.current_selection, 11);
                    if let Some(popularity) = self.returned_popularity {
                        vm["image"]["popularity"] = json!(popularity);
                    }
                    if let Some(created) = &self.created {
                        vm["created"] = created.clone().into();
                    }
                    if let Some((pointer, value)) = &self.vm_change {
                        *vm.pointer_mut(pointer).unwrap() = value.clone();
                    }
                    self.machines.push(vm.clone());
                    if self.lose_create {
                        Err("lost".into())
                    } else {
                        Ok(vm)
                    }
                }
                ("GET", "/api/v1/vm/11/payments?limit=100&offset=0") => Ok(self
                    .history_response
                    .clone()
                    .unwrap_or_else(|| json!(self.payments))),
                ("GET", "/api/v1/vm/11/renew/quote?method=lightning&intervals=1") => {
                    if self.fail_quote {
                        Err("quote unavailable".into())
                    } else {
                        Ok(serde_json::to_value(&self.billing_terms).unwrap())
                    }
                }
                ("GET", "/api/v1/vm/11/renew?method=lightning&intervals=1") => {
                    let mut p = fixtures::payment(11);
                    if let Some(created) = &self.created {
                        p["created"] = created.clone().into();
                    }
                    for field in ["amount", "currency", "tax", "processing_fee", "time"] {
                        p[field] =
                            serde_json::to_value(&self.billing_terms).unwrap()[field].clone();
                    }
                    if self.invoice_nanoseconds {
                        p["created"] = json!("2026-11-06T14:00:00.999999999Z");
                        p["expires"] = json!("2026-11-07T14:00:00.841873964Z");
                    }
                    self.payments.push(p.clone());
                    if self.lose_invoice {
                        Err("lost".into())
                    } else {
                        Ok(p)
                    }
                }
                ("GET", "/api/v1/vm/11") => Ok(self.machines[0].clone()),
                ("GET", "/api/v1/vm/12") => Ok(self.machines[1].clone()),
                ("GET", "/api/v1/payment/aabb") => Ok(self.payments[0].clone()),
                _ => Err("unexpected fixture route".into()),
            };
            result.map_err(Into::into)
        };
        if self
            .fault_after
            .as_ref()
            .is_some_and(|(route, _, _)| route == &format!("{method} {path}"))
        {
            let (_, storage, fault) = self.fault_after.take().unwrap();
            storage.fault(fault);
        }
        if self
            .after_read_clock
            .as_ref()
            .is_some_and(|(route, _)| route == &path)
        {
            self.clock = self.after_read_clock.take().unwrap().1;
        }
        result
    }
}
fn approve(s: &mut Store<MemoryStorage>, api: &mut Fixture) {
    block_on(s.procurement_select(
        api,
        Choice {
            offer_id: if api.custom { 2 } else { 1 },
            image_id: 3,
            resources: api.current_selection.resources.clone(),
        },
    ))
    .unwrap();
    block_on(s.procurement_approve(
        api,
        Approval {
            origin: s.procurement_origin().into(),
            machine: "machine-a".into(),
            relay: "wss://relay.invalid/".into(),
            class_answer: ClassAnswer::No,
            approve_charge: true,
            approve_maintained_access: true,
        },
    ))
    .unwrap();
}
fn issue_invoice(s: &mut Store<MemoryStorage>, api: &mut Fixture) -> Result<(), String> {
    if s.procurement.as_ref().is_none_or(|p| p.billing.is_none()) {
        let result = block_on(s.procurement_resume(api, false));
        if s.procurement.as_ref().is_none_or(|p| p.billing.is_none()) {
            return result;
        }
    }
    block_on(s.procurement_resume(api, true))
}

fn nanosecond_invoice() -> (Store<MemoryStorage>, Fixture) {
    let mut s = ready();
    let mut api = Fixture::new(false);
    api.invoice_nanoseconds = true;
    approve(&mut s, &mut api);
    assert!(
        issue_invoice(&mut s, &mut api)
            .unwrap_err()
            .contains("Waiting for external payment")
    );
    assert_eq!(
        s.procurement.as_ref().unwrap().payment,
        Some(api.payments[0].clone())
    );
    (s, api)
}

fn whole_second_reading(api: &mut Fixture) {
    api.payments[0]["created"] = json!("2026-11-06T14:00:00Z");
    api.payments[0]["expires"] = json!("2026-11-07T14:00:00Z");
}

#[test]
fn provisioning_payment_timestamps_truncate_through_handoff_and_replay() {
    let (mut s, mut api) = nanosecond_invoice();
    let purchase = s.procurement.clone().unwrap();
    whole_second_reading(&mut api);
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("Waiting for external payment")
    );
    assert_eq!(
        s.procurement.as_ref().unwrap().payment,
        Some(api.payments[0].clone())
    );
    api.payments[0]["is_paid"] = json!(true);
    block_on(s.procurement_resume(&mut api, false)).unwrap();
    let mut loaded = reopen(&s);
    assert_eq!(loaded.procurement, s.procurement);
    block_on(loaded.procurement_resume(&mut api, false)).unwrap();
    let accepted = loaded.procurement.as_ref().unwrap();
    assert_eq!(accepted.payment, Some(api.payments[0].clone()));
    assert_eq!(accepted.identity, purchase.identity);
    assert_eq!(accepted.relay_identity, purchase.relay_identity);
    assert_eq!(accepted.machine, purchase.machine);
    assert_eq!(accepted.invoice, purchase.invoice);
    assert_eq!(
        accepted.vm.as_ref().unwrap()["id"],
        purchase.vm.as_ref().unwrap()["id"]
    );
    assert_eq!(
        accepted.payment.as_ref().unwrap()["id"],
        purchase.payment.as_ref().unwrap()["id"]
    );
    assert_eq!(loaded.poc_target("machine-a").unwrap().host, "192.0.2.10");
    assert_eq!(
        loaded.dispatch.approved_entries["machine-a"]
            .approved
            .identity,
        purchase.identity
    );
    assert_eq!(api.count("POST /api/v1/vm"), 1);
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        1
    );
}

#[test]
fn provisioning_payment_timestamps_base_shape_reopens_before_paid_reading() {
    let (s, mut api) = nanosecond_invoice();
    let purchase = s.procurement.clone();
    let mut loaded = reopen(&s);
    assert_eq!(loaded.procurement, purchase);
    whole_second_reading(&mut api);
    api.payments[0]["is_paid"] = json!(true);
    block_on(loaded.procurement_resume(&mut api, false)).unwrap();
    assert_eq!(
        loaded.procurement.as_ref().unwrap().payment,
        Some(api.payments[0].clone())
    );
    assert!(loaded.poc_target("machine-a").is_some());
    assert_eq!(reopen(&loaded).procurement, loaded.procurement);
    assert_eq!(api.count("POST /api/v1/vm"), 1);
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        1
    );
}

#[test]
fn provisioning_payment_timestamps_and_exact_identity_refusals_preserve_saved_state() {
    for (field, value) in [
        ("created", json!("2026-11-06T14:00:01Z")),
        ("expires", json!("2026-11-07T14:00:01Z")),
        ("id", json!("aabc")),
        ("data", json!({"lightning":"lnbc1otherfixtureinvoice"})),
        ("created", json!("not a timestamp")),
        ("expires", json!("not a timestamp")),
    ] {
        let (mut s, mut api) = nanosecond_invoice();
        let saved = s.procurement.clone();
        let files = s.storage.files();
        whole_second_reading(&mut api);
        let mut reading = api.payments[0].clone();
        reading[field] = value;
        if field == "id" || field == "data" || reading[field].as_str().unwrap().ends_with('Z') {
            assert!(protocol::suitable_payment(
                &reading,
                11,
                &api.billing_terms,
                api.clock
            ));
        }
        assert_eq!(
            block_on(s.procurement_commit(Record::Payment(reading))).unwrap_err(),
            REFUSED
        );
        assert_eq!(s.procurement, saved, "{field}");
        assert_eq!(s.storage.files(), files, "{field}");
        assert_eq!(reopen(&s).procurement, saved);
    }
}

#[test]
fn provisioning_payment_timestamps_paid_cannot_regress() {
    let (mut s, mut api) = nanosecond_invoice();
    api.payments[0]["is_paid"] = json!(true);
    block_on(s.procurement_commit(Record::Payment(api.payments[0].clone()))).unwrap();
    let saved = s.procurement.clone();
    let files = s.storage.files();
    whole_second_reading(&mut api);
    for paid in [json!(false), Value::Null] {
        api.payments[0]["is_paid"] = paid;
        assert_eq!(
            block_on(s.procurement_commit(Record::Payment(api.payments[0].clone()))).unwrap_err(),
            REFUSED
        );
        assert_eq!(s.procurement, saved);
        assert_eq!(s.storage.files(), files);
    }
    assert_eq!(reopen(&s).procurement, saved);
}

#[test]
fn provisioning_payment_timestamps_expired_unpaid_still_pauses() {
    for elapsed in [0, 1] {
        let (mut s, mut api) = nanosecond_invoice();
        whole_second_reading(&mut api);
        api.clock = timestamp(api.payments[0]["expires"].as_str().unwrap()).unwrap() + elapsed;
        assert!(
            block_on(s.procurement_resume(&mut api, false))
                .unwrap_err()
                .contains("expired")
        );
        assert_eq!(
            s.procurement.as_ref().unwrap().payment,
            Some(api.payments[0].clone())
        );
        assert!(s.poc_target("machine-a").is_none());
        api.payments[0]["is_paid"] = json!(true);
        block_on(s.procurement_resume(&mut api, false)).unwrap();
        assert!(s.poc_target("machine-a").is_some());
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
        assert_eq!(reopen(&s).procurement, s.procurement);
    }
}

#[test]
fn provisioning_initial_invoice_subscription_id_does_not_establish_billing() {
    for subscription in [Some(json!(21)), None, Some(Value::Null)] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        assert!(
            block_on(s.procurement_resume(&mut api, false))
                .unwrap_err()
                .contains("initial Lightning")
        );
        let p = s.procurement.as_ref().unwrap();
        assert_eq!(p.vm.as_ref().unwrap()["subscription_id"], 21);
        assert!(p.vm.as_ref().unwrap()["expires"].is_null());
        assert_eq!(p.billing.as_ref().unwrap().terms, api.billing_terms);
        assert!(p.invoice.is_none());
        assert!(api.payments.is_empty());
        match subscription {
            Some(value) => api.machines[0]["subscription_id"] = value,
            None => {
                api.machines[0]
                    .as_object_mut()
                    .unwrap()
                    .remove("subscription_id");
            }
        }
        let before = api.calls.len();
        assert_eq!(
            issue_invoice(&mut s, &mut api).unwrap_err(),
            "Waiting for external payment of the displayed initial invoice; Refresh later."
        );
        let p = s.procurement.as_ref().unwrap();
        assert!(p.invoice.is_some());
        assert!(p.payment.is_some());
        assert!(p.target.is_none());
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
        let calls = &api.calls[before..];
        let position = |route| calls.iter().position(|call| call == route).unwrap();
        assert!(
            position("GET /api/v1/vm/11/payments?limit=100&offset=0")
                < position("GET /api/v1/vm/11/renew?method=lightning&intervals=1")
        );
        assert_eq!(reopen(&s).procurement, s.procurement);
    }
}

#[test]
fn provisioning_initial_invoice_fresh_expiry_prevents_issuance() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("initial Lightning")
    );
    let p = s.procurement.as_ref().unwrap();
    assert!(p.vm.as_ref().unwrap()["expires"].is_null());
    assert_eq!(p.billing.as_ref().unwrap().terms, api.billing_terms);
    assert!(p.invoice.is_none());
    assert!(api.payments.is_empty());
    api.machines[0]["expires"] = json!("2026-12-06T14:00:00Z");
    let before_status = api.count("GET /api/v1/vm/11");
    let before_history = api.count("GET /api/v1/vm/11/payments?limit=100&offset=0");
    assert_eq!(
        issue_invoice(&mut s, &mut api).unwrap_err(),
        "Existing billing evidence prevents initial invoice issuance."
    );
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(
        p.vm.as_ref().unwrap()["expires"],
        api.machines[0]["expires"]
    );
    assert!(p.invoice.is_none());
    assert!(p.payment.is_none());
    assert!(api.payments.is_empty());
    assert_eq!(api.count("GET /api/v1/vm/11"), before_status + 1);
    assert_eq!(
        api.count("GET /api/v1/vm/11/payments?limit=100&offset=0"),
        before_history + 1
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    assert_eq!(reopen(&s).procurement, s.procurement);
}

fn history_rows(count: usize) -> Vec<Value> {
    (0..count)
        .map(|n| {
            let mut row = fixtures::payment(11);
            row["id"] = json!(format!("{n:04x}"));
            row
        })
        .collect()
}

fn assert_history_refused(api: &mut Fixture, reason: &str) {
    let mut s = ready();
    approve(&mut s, api);
    assert_eq!(
        block_on(s.procurement_resume(api, true)).unwrap_err(),
        reason
    );
    let p = s.procurement.as_ref().unwrap();
    assert!(p.payment.is_none());
    assert!(p.invoice.is_none());
    assert!(p.billing.is_none());
    assert_eq!(
        api.count("GET /api/v1/vm/11/payments?limit=100&offset=0"),
        1
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    assert_eq!(reopen(&s).procurement, s.procurement);
}

#[test]
fn provisioning_history_empty_array_saves_quote_without_issuance() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert_eq!(
        block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
        "Review the current initial Lightning quote and explicitly approve issuance for the first approved billing period."
    );
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(p.billing.as_ref().unwrap().terms, fixtures::billing_terms());
    assert!(p.payment.is_none());
    assert!(p.invoice.is_none());
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1"),
        1
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    assert_eq!(reopen(&s).procurement, s.procurement);
}

#[test]
fn provisioning_history_exactly_100_rows_is_incomplete() {
    let mut api = Fixture::new(false);
    api.payments = history_rows(100);
    assert_history_refused(
        &mut api,
        "Payment history incomplete; Refresh without issuing another invoice.",
    );
}

#[test]
fn provisioning_history_101_through_128_rows_is_incomplete() {
    for count in [101, 127, 128] {
        let mut api = Fixture::new(false);
        api.payments = history_rows(count);
        assert_history_refused(
            &mut api,
            "Payment history incomplete; Refresh without issuing another invoice.",
        );
    }
}

#[test]
fn provisioning_history_129_rows_exceeds_array_bound() {
    let mut api = Fixture::new(false);
    api.payments = history_rows(129);
    assert_history_refused(&mut api, REFUSED);
}

#[test]
fn provisioning_history_nested_pagination_is_refused() {
    let mut api = Fixture::new(false);
    api.history_response = Some(json!({"data":[],"total":0,"limit":100,"offset":0}));
    assert_history_refused(&mut api, REFUSED);
}

#[test]
fn provisioning_history_other_nonarrays_are_refused() {
    for value in [Value::Null, json!(true), json!(0), json!(""), json!({})] {
        let mut api = Fixture::new(false);
        api.history_response = Some(value);
        assert_history_refused(&mut api, REFUSED);
    }
}

#[test]
fn provisioning_history_complete_multiple_rows_remain_ambiguous() {
    for count in [2, 99] {
        let mut api = Fixture::new(false);
        api.payments = history_rows(count);
        assert_history_refused(
            &mut api,
            "Initial payment evidence conflicts or is ambiguous; no invoice issued.",
        );
    }
}

#[test]
fn provisioning_history_duplicate_wrong_vm_and_missing_identity_are_refused() {
    for mode in ["duplicate", "wrong_vm", "missing_id", "missing_vm"] {
        let mut api = Fixture::new(false);
        api.payments = history_rows(1);
        match mode {
            "duplicate" => api.payments.push(api.payments[0].clone()),
            "wrong_vm" => api.payments[0]["vm_id"] = json!(12),
            "missing_id" => {
                api.payments[0].as_object_mut().unwrap().remove("id");
            }
            _ => {
                api.payments[0].as_object_mut().unwrap().remove("vm_id");
            }
        }
        assert_history_refused(&mut api, REFUSED);
    }
}

#[test]
fn provisioning_history_missing_payment_terms_cannot_issue_invoice() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    api.payments.push(fixtures::payment(11));
    api.payments[0].as_object_mut().unwrap().remove("time");
    assert_eq!(
        block_on(s.procurement_resume(&mut api, true)).unwrap_err(),
        "Initial payment evidence conflicts or cannot be established from the saved one-period quote; no invoice issued."
    );
    let p = s.procurement.as_ref().unwrap();
    assert_eq!(p.billing.as_ref().unwrap().terms, fixtures::billing_terms());
    assert!(p.payment.is_none());
    assert!(p.invoice.is_none());
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    assert_eq!(reopen(&s).procurement, s.procurement);
}

#[test]
fn provisioning_fixed_and_custom_encrypted_same_identity_handoff_and_replay() {
    for custom in [false, true] {
        let mut s = ready();
        let mut api = Fixture::new(custom);
        approve(&mut s, &mut api);
        let identity = s.procurement.as_ref().unwrap().identity.clone();
        let before = s.poc_identity_public_keys("machine-a", &identity).unwrap();
        assert!(s.poc_target("machine-a").is_none());
        assert!(
            block_on(s.procurement_resume(&mut api, false))
                .unwrap_err()
                .contains("initial Lightning")
        );
        assert!(
            issue_invoice(&mut s, &mut api)
                .unwrap_err()
                .contains("Waiting for external payment")
        );
        api.payments[0]["is_paid"] = true.into();
        block_on(s.procurement_resume(&mut api, false)).unwrap();
        let mut loaded = reopen(&s);
        block_on(loaded.procurement_resume(&mut api, false)).unwrap();
        assert_eq!(loaded.poc_target("machine-a"), s.poc_target("machine-a"));
        assert_eq!(loaded.poc_target("machine-a").unwrap().host, "192.0.2.10");
        assert_eq!(loaded.poc_public_keys("machine-a").unwrap(), before);
        assert_eq!(
            loaded.dispatch.approved_entries["machine-a"]
                .approved
                .identity,
            identity
        );
        assert_eq!(
            loaded.dispatch.approved_entries["machine-a"]
                .approved
                .entry
                .cost
                .amount,
            1000000
        );
        assert_eq!(loaded.procurement_view()["auto_renewal_enabled"], true);
        assert_eq!(
            api.count(if custom {
                "POST /api/v1/vm/custom-template"
            } else {
                "POST /api/v1/vm"
            }),
            1
        );
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
        for bytes in s.storage.files().values() {
            assert!(!String::from_utf8_lossy(bytes).contains("192.0.2.10"));
        }
        assert!(block_on(loaded.poc_bind("machine-a")).is_ok());
        assert!(
            loaded.dispatch.check_installation("machine-a").is_err(),
            "ordinary declaration remains necessary"
        );
    }
}
#[test]
fn provisioning_lost_create_and_invoice_reconcile_without_resend() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    api.lose_create = true;
    approve(&mut s, &mut api);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let mut s = reopen(&s);
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("initial Lightning")
    );
    api.lose_invoice = true;
    assert!(issue_invoice(&mut s, &mut api).is_err());
    let mut s = reopen(&s);
    assert!(
        issue_invoice(&mut s, &mut api)
            .unwrap_err()
            .contains("external payment")
    );
    assert_eq!(s.procurement_view()["vm_id"], 11);
    assert_eq!(s.procurement_view()["payment"]["id"], "aabb");
    assert_eq!(api.count("POST /api/v1/vm"), 1);
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        1
    );
}
#[test]
fn provisioning_unknown_create_stays_read_only_across_reload_and_empty_conflicting_multiple_evidence()
 {
    for mode in ["empty", "incomplete", "conflicting", "multiple"] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        api.lose_create = true;
        approve(&mut s, &mut api);
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        match mode {
            "empty" => api.machines.clear(),
            "incomplete" => {
                api.machines[0].as_object_mut().unwrap().remove("ssh_key");
            }
            "conflicting" => api.machines[0]["image"]["id"] = 999.into(),
            _ => api
                .machines
                .push(fixtures::vm(&fixtures::selection(false), 12)),
        }
        let mut s = reopen(&s);
        for _ in 0..2 {
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        }
        assert_eq!(api.count("POST /api/v1/vm"), 1);
        assert!(s.procurement.as_ref().unwrap().vm.is_none());
        assert!(
            block_on(s.procurement_select(
                &mut api,
                Choice {
                    offer_id: 1,
                    image_id: 3,
                    resources: None
                }
            ))
            .is_err()
        );
    }
}
#[test]
fn provisioning_registration_uncertainty_never_inserts_or_creates_again() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    api.lose_registration = true;
    approve(&mut s, &mut api);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let mut s = reopen(&s);
    let error = block_on(s.procurement_resume(&mut api, false)).unwrap_err();
    assert_eq!(api.count("POST /api/v1/ssh-key"), 1);
    assert!(error.contains("no public-key material"));
    assert_eq!(api.count("POST /api/v1/vm"), 0);
}
#[test]
fn provisioning_expired_invoice_and_empty_publication_preserve_identities() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(issue_invoice(&mut s, &mut api).is_err());
    api.clock += 2 * 86400;
    assert!(
        issue_invoice(&mut s, &mut api)
            .unwrap_err()
            .contains("expired")
    );
    api.clock -= 2 * 86400;
    api.payments[0]["is_paid"] = true.into();
    api.machines[0]["host_ssh_keys"] = json!([]);
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("published host key")
    );
    assert!(s.poc_target("machine-a").is_none());
    api.machines[0]["host_ssh_keys"] = json!([fixtures::publication()]);
    let mut s = reopen(&s);
    block_on(s.procurement_resume(&mut api, false)).unwrap();
    assert_eq!(s.procurement_view()["vm_id"], 11);
    assert_eq!(api.count("POST /api/v1/vm"), 1);
}

#[test]
fn provisioning_pre_send_gap_and_uncertain_identity_appends_never_create_twice() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    block_on(s.procurement_commit(Record::RegistrationSent)).unwrap();
    block_on(s.procurement_commit(Record::Registered(
        json!({"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"}),
    )))
    .unwrap();
    block_on(s.procurement_commit(Record::CreateSent(Create {
        before: Vec::new(),
        started: api.now(),
    })))
    .unwrap();
    let mut loaded = reopen(&s);
    assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
    assert_eq!(api.count("POST /api/v1/vm"), 0);
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        api.fault_after = Some(("POST /api/v1/vm".into(), s.storage.clone(), fault));
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        let mut loaded = reopen(&s);
        assert!(
            block_on(loaded.procurement_resume(&mut api, false))
                .unwrap_err()
                .contains("initial Lightning")
        );
        assert_eq!(api.count("POST /api/v1/vm"), 1);
        assert_eq!(loaded.procurement_view()["vm_id"], 11);
    }
}

#[test]
fn provisioning_create_and_invoice_intent_failures_send_no_effect() {
    for route in [
        "GET /api/v1/vm",
        "GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1",
    ] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        if route.contains("renew/quote") {
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        }
        // An unchanged quote is the final read before the initial invoice intent.
        api.fault_after = Some((route.into(), s.storage.clone(), Fault::Fail(1)));
        assert!(issue_invoice(&mut s, &mut api).is_err());
        assert!(
            api.fault_after.is_none(),
            "The intended response must arm the append fault"
        );
        assert_eq!(
            api.count("POST /api/v1/vm"),
            usize::from(route.contains("renew/quote"))
        );
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            0
        );
    }
}
#[test]
fn provisioning_failed_intent_write_sends_nothing_and_account_cannot_change() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    api.account = "b".repeat(64);
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("same provider account")
    );
    assert_eq!(api.count("POST /api/v1/ssh-key"), 0);
    api.account = "a".repeat(64);
    s.storage.fault(Fault::Fail(1));
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert_eq!(api.count("POST /api/v1/ssh-key"), 0);
}
#[test]
fn provisioning_provider_echoes_never_enter_journal_or_public_context() {
    let mut s = ready();
    let credential = hex::encode([7; 32]);
    let a = protocol::Account::parse(credential.as_bytes()).unwrap();
    s.remember_provider_filter(a.filter(credential.as_bytes()));
    for text in [
        credential.clone(),
        hex::encode(credential.as_bytes()),
        base64::engine::general_purpose::STANDARD.encode(credential.as_bytes()),
    ] {
        let value = json!({"name":text});
        assert!(!crate::poc::inference::safe(&s, &value, &[]));
        assert_ne!(s.protect_output(&value).unwrap(), value);
    }
    // Hexadecimal account custody must not activate inference structural refusal.
    assert!(s.poc_credential_filters.borrow().is_empty());
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    let mut echoed = fixtures::vm(&fixtures::selection(false), 11);
    echoed["template"]["name"] = credential.into();
    let next = s.next;
    assert!(block_on(s.commit(&Event::Procurement(Record::Associated(echoed)))).is_err());
    assert_eq!(s.next, next);
}

#[test]
fn provisioning_fresh_store_preserves_report_shape_until_selection() {
    let s = ready();
    let mut local = Local::new(s.storage.clone(), Fixed);
    block_on(local.open());
    block_on(local.unlock(pass()));
    assert!(local.report(None).get("procurement").is_none());
    assert!(local.inspect().get("procurement").is_none());
    let mut api = Fixture::new(false);
    block_on(local.store().unwrap().procurement_select(
        &mut api,
        Choice {
            offer_id: 1,
            image_id: 3,
            resources: None,
        },
    ))
    .unwrap();
    assert!(local.report(None)["procurement"]["selection"].is_object());
}

fn approval() -> Approval {
    Approval {
        origin: protocol::ORIGIN.into(),
        machine: "machine-a".into(),
        relay: "wss://relay.invalid/".into(),
        class_answer: ClassAnswer::No,
        approve_charge: true,
        approve_maintained_access: true,
    }
}

#[test]
fn provisioning_delayed_fixed_and_custom_terms_require_same_identity_reapproval_across_reload() {
    for custom in [false, true] {
        for reload in [false, true] {
            for change in ["price", "resources"] {
                let mut s = ready();
                let mut api = Fixture::new(custom);
                approve(&mut s, &mut api);
                let original = s.procurement.clone().unwrap();
                let public = s
                    .poc_identity_public_keys(&original.machine, &original.identity)
                    .unwrap();
                if change == "price" {
                    api.current_selection.charge.amount *= 2;
                    if !custom {
                        api.current_selection.offer["cost_plan"]["amount"] =
                            api.current_selection.charge.amount.into();
                    }
                } else if custom {
                    api.current_selection.offer["max_cpu"] = json!(9);
                } else {
                    api.current_selection.offer["cpu"] = json!(2);
                }
                if reload {
                    s = reopen(&s);
                }
                assert!(
                    block_on(s.procurement_resume(&mut api, false))
                        .unwrap_err()
                        .contains("review and approve")
                );
                assert_eq!(api.count("POST /api/v1/vm"), 0);
                assert_eq!(api.count("POST /api/v1/vm/custom-template"), 0);
                assert_eq!(api.count("POST /api/v1/ssh-key"), 1);
                assert!(s.procurement.as_ref().unwrap().create.is_none());
                assert_eq!(s.procurement.as_ref().unwrap().selected, original.selected);
                assert_eq!(s.procurement_view()["phase"], "terms_changed");
                let pending = s
                    .procurement
                    .as_ref()
                    .unwrap()
                    .pending_selection
                    .clone()
                    .unwrap();
                let mut s = reopen(&s);
                assert_eq!(
                    s.procurement.as_ref().unwrap().pending_selection.as_ref(),
                    Some(&pending)
                );
                assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
                let mut changed_identity = approval();
                changed_identity.machine = "machine-b".into();
                assert!(block_on(s.procurement_approve(&mut api, changed_identity)).is_err());
                let mut missing_consent = approval();
                missing_consent.approve_charge = false;
                assert!(block_on(s.procurement_approve(&mut api, missing_consent)).is_err());
                block_on(s.procurement_approve(&mut api, approval())).unwrap();
                let renewed = s.procurement.as_ref().unwrap();
                assert_eq!(renewed.identity, original.identity);
                assert_eq!(renewed.relay_identity, original.relay_identity);
                assert_eq!(renewed.account, original.account);
                assert_eq!(renewed.selected, pending);
                assert!(renewed.pending_selection.is_none());
                assert_eq!(
                    s.poc_identity_public_keys(&original.machine, &original.identity)
                        .unwrap(),
                    public
                );
                assert_eq!(s.dispatch.approved_entries.len(), 1);
                assert_eq!(
                    s.dispatch.approved_entries["machine-a"]
                        .approved
                        .entry
                        .cost
                        .amount,
                    api.current_selection.charge.amount
                );
                let mut s = reopen(&s);
                assert!(
                    block_on(s.procurement_resume(&mut api, false))
                        .unwrap_err()
                        .contains("initial Lightning")
                );
                assert_eq!(api.count("POST /api/v1/ssh-key"), 1);
                assert_eq!(
                    api.count(if custom {
                        "POST /api/v1/vm/custom-template"
                    } else {
                        "POST /api/v1/vm"
                    }),
                    1
                );
                assert_eq!(s.procurement.as_ref().unwrap().identity, original.identity);
            }
        }
    }
}

#[test]
fn provisioning_unavailable_terms_never_create_and_pending_approval_is_checked_again() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    api.fail_catalogue = true;
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert!(s.procurement.as_ref().unwrap().create.is_none());
    assert_eq!(api.count("POST /api/v1/vm"), 0);
    api.fail_catalogue = false;
    api.current_selection.offer["cpu"] = json!(2);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    api.current_selection.offer["cpu"] = json!(3);
    assert!(
        block_on(s.procurement_approve(&mut api, approval()))
            .unwrap_err()
            .contains("review and approve")
    );
    assert_eq!(s.procurement.as_ref().unwrap().selected.offer["cpu"], 1);
    assert_eq!(s.procurement_view()["selection"]["offer"]["cpu"], 3);
    assert_eq!(api.count("POST /api/v1/vm"), 0);
    let pending = s
        .procurement
        .as_ref()
        .unwrap()
        .pending_selection
        .clone()
        .unwrap();
    assert!(
        s.procurement_projection(&Record::CreateSent(Create {
            before: vec![],
            started: api.clock
        }))
        .is_err()
    );
    let mut loaded = reopen(&s);
    block_on(loaded.procurement_approve(&mut api, approval())).unwrap();
    assert_eq!(loaded.procurement.as_ref().unwrap().selected, pending);
}

#[test]
fn provisioning_reapproval_and_reselection_cannot_reset_uncertain_create() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    api.lose_create = true;
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let original = s.procurement.clone().unwrap();
    api.machines.clear();
    let mut selected = original.selected.clone();
    selected.charge.amount *= 2;
    selected.offer["cost_plan"]["amount"] = selected.charge.amount.into();
    for _ in 0..2 {
        let mut loaded = reopen(&s);
        assert!(block_on(loaded.procurement_approve(&mut api, approval())).is_err());
        assert!(
            block_on(loaded.procurement_select(
                &mut api,
                Choice {
                    offer_id: 1,
                    image_id: 3,
                    resources: None
                }
            ))
            .is_err()
        );
        assert!(
            loaded
                .procurement_projection(&Record::TermsChanged(selected.clone()))
                .is_err()
        );
        assert!(
            loaded
                .procurement_projection(&Record::Reapproved {
                    selected: selected.clone(),
                    approved_at: api.clock
                })
                .is_err()
        );
        assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
        assert_eq!(loaded.procurement, Some(original.clone()));
        s = loaded;
    }
    assert_eq!(api.count("POST /api/v1/vm"), 1);
}

#[test]
fn provisioning_image_statistic_drift_survives_association_reconciliation_observation_and_replay() {
    for lost in [false, true] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        api.current_selection.image["popularity"] = json!(0.1001);
        api.returned_popularity = Some(0.1002);
        api.lose_create = lost;
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        let mut s = reopen(&s);
        if lost {
            assert!(
                block_on(s.procurement_resume(&mut api, false))
                    .unwrap_err()
                    .contains("initial Lightning")
            );
        }
        assert_eq!(s.procurement_view()["vm_id"], 11);
        assert!(issue_invoice(&mut s, &mut api).is_err());
        api.payments[0]["is_paid"] = json!(true);
        api.machines[0]["image"]["popularity"] = json!(0.1003);
        let good = api.machines[0].clone();
        api.machines[0]["image"]["version"] = json!("different");
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        assert!(s.poc_target("machine-a").is_none());
        api.machines[0] = good;
        block_on(s.procurement_resume(&mut api, false)).unwrap();
        let loaded = reopen(&s);
        assert_eq!(loaded.poc_target("machine-a"), s.poc_target("machine-a"));
        assert_eq!(api.count("POST /api/v1/vm"), 1);
    }
}

#[test]
fn provisioning_multiple_incomplete_and_conflicting_invoice_evidence_never_reissues() {
    for mode in ["multiple", "incomplete", "conflicting", "empty"] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        api.lose_invoice = true;
        assert!(issue_invoice(&mut s, &mut api).is_err());
        let original = s.procurement.clone().unwrap();
        match mode {
            "multiple" => {
                let mut second = api.payments[0].clone();
                second["id"] = json!("aabc");
                api.payments.push(second);
            }
            "incomplete" => {
                api.payments[0].as_object_mut().unwrap().remove("time");
            }
            "conflicting" => {
                api.payments[0]["amount"] = json!(2);
            }
            _ => api.payments.clear(),
        }
        for _ in 0..2 {
            let mut loaded = reopen(&s);
            assert!(issue_invoice(&mut loaded, &mut api).is_err());
            assert_eq!(loaded.procurement, Some(original.clone()));
            s = loaded;
        }
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
        assert_eq!(api.count("POST /api/v1/vm"), 1);
    }
}

#[test]
fn provisioning_invalidated_custom_resources_can_be_reselected_on_the_same_purchase() {
    let mut s = ready();
    let mut api = Fixture::new(true);
    approve(&mut s, &mut api);
    let original = s.procurement.clone().unwrap();
    api.current_selection.offer["min_cpu"] = json!(3);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert_eq!(api.count("POST /api/v1/vm/custom-template"), 0);
    let mut resources = fixtures::custom_resources();
    resources["cpu"] = json!(3);
    api.current_selection.resources = Some(resources.clone());
    block_on(s.procurement_select(
        &mut api,
        Choice {
            offer_id: 2,
            image_id: 3,
            resources: Some(resources),
        },
    ))
    .unwrap();
    let mut s = reopen(&s);
    block_on(s.procurement_approve(&mut api, approval())).unwrap();
    assert!(
        block_on(s.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("initial Lightning")
    );
    assert_eq!(s.procurement.as_ref().unwrap().identity, original.identity);
    assert_eq!(
        s.procurement.as_ref().unwrap().relay_identity,
        original.relay_identity
    );
    assert_eq!(api.count("POST /api/v1/ssh-key"), 1);
    assert_eq!(api.count("POST /api/v1/vm/custom-template"), 1);
}

#[test]
fn provisioning_returned_registration_and_payment_append_uncertainty_preserves_no_retry() {
    for route in [
        "POST /api/v1/ssh-key",
        "GET /api/v1/vm/11/renew?method=lightning&intervals=1",
    ] {
        for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
            let landed = matches!(fault, Fault::LandThenFail(_));
            let mut s = ready();
            let mut api = Fixture::new(false);
            approve(&mut s, &mut api);
            if route.contains("renew") {
                assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            }
            api.fault_after = Some((route.into(), s.storage.clone(), fault));
            assert!(issue_invoice(&mut s, &mut api).is_err());
            let mut loaded = reopen(&s);
            if route.contains("renew") {
                assert!(
                    issue_invoice(&mut loaded, &mut api)
                        .unwrap_err()
                        .contains("external payment")
                );
                assert_eq!(loaded.procurement_view()["payment"]["id"], "aabb");
            } else {
                let result = block_on(loaded.procurement_resume(&mut api, false)).unwrap_err();
                if landed {
                    assert!(result.contains("initial Lightning"));
                } else {
                    assert!(result.contains("no public-key material"));
                }
            }
            assert_eq!(api.count(route), 1);
            assert!(api.count("POST /api/v1/vm") <= 1);
        }
    }
}

#[test]
fn provisioning_invoice_pre_send_gap_replays_without_issuance() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    block_on(s.procurement_commit(Record::InvoiceSent(Invoice {
        before: vec![],
        started: api.clock,
    })))
    .unwrap();
    let original = s.procurement.clone();
    let mut loaded = reopen(&s);
    for _ in 0..2 {
        assert!(
            issue_invoice(&mut loaded, &mut api)
                .unwrap_err()
                .contains("never be reissued")
        );
    }
    assert_eq!(loaded.procurement, original);
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
}

#[test]
fn provisioning_associated_vm_and_payment_identities_are_immutable_after_replay() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(issue_invoice(&mut s, &mut api).is_err());
    let loaded = reopen(&s);
    let p = loaded.procurement.as_ref().unwrap();
    let mut other_vm = p.vm.clone().unwrap();
    other_vm["id"] = json!(12);
    assert!(
        loaded
            .procurement_projection(&Record::Associated(other_vm.clone()))
            .is_err()
    );
    assert!(
        loaded
            .procurement_projection(&Record::Observation(other_vm))
            .is_err()
    );
    let mut other_payment = p.payment.clone().unwrap();
    other_payment["id"] = json!("aabc");
    assert!(
        loaded
            .procurement_projection(&Record::Payment(other_payment))
            .is_err()
    );
    let mut other_creation = p.vm.clone().unwrap();
    other_creation["created"] = json!("2026-11-06T14:00:01Z");
    assert!(
        loaded
            .procurement_projection(&Record::Observation(other_creation))
            .is_err()
    );
    assert_eq!(loaded.procurement, s.procurement);
}

fn handoff(p: &Purchase) -> Record {
    let vm = p.vm.as_ref().unwrap();
    let (key, pin) = protocol::published_pin(vm).unwrap();
    Record::Handoff {
        target: TargetRecord {
            machine: p.machine.clone(),
            relay: p.relay.clone(),
            profile: "v1".into(),
            host: protocol::allocated_ipv4(vm).unwrap(),
            port: 22,
            user: "arch".into(),
            elevation: crate::jobs::Elevation::SudoNoninteractive,
            pin,
        },
        publication: json!({"origin":p.origin,"vm_id":vm["id"],"created":vm["created"],"selected_key":key,"host_ssh_keys":vm["host_ssh_keys"]}),
    }
}

#[test]
fn provisioning_unpaid_unknown_payment_and_boot_cannot_handoff_or_overwrite_a_target() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(issue_invoice(&mut s, &mut api).is_err());
    let loaded = reopen(&s);
    assert!(
        loaded
            .procurement_projection(&handoff(loaded.procurement.as_ref().unwrap()))
            .is_err()
    );
    assert!(loaded.poc_target("machine-a").is_none());
    for paid in [json!(null), json!(false)] {
        api.payments[0]["is_paid"] = paid;
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        assert!(s.poc_target("machine-a").is_none());
    }
    api.payments[0]["is_paid"] = json!(true);
    for state in [json!(null), json!("starting"), json!("unknown")] {
        api.machines[0]["status"]["state"] = state;
        assert!(
            block_on(s.procurement_resume(&mut api, false))
                .unwrap_err()
                .contains("boot readiness")
        );
        assert!(s.poc_target("machine-a").is_none());
        let loaded = reopen(&s);
        assert!(
            loaded
                .procurement_projection(&handoff(loaded.procurement.as_ref().unwrap()))
                .is_err()
        );
    }
    api.machines[0]["status"]["state"] = json!("running");
    block_on(s.procurement_commit(Record::Observation(api.machines[0].clone()))).unwrap();
    let mut conflict = handoff(s.procurement.as_ref().unwrap());
    if let Record::Handoff { target, .. } = &mut conflict {
        target.pin = format!("SHA256:{}", "A".repeat(43));
    }
    assert!(s.procurement_projection(&conflict).is_err());
    let mut foreign = handoff(s.procurement.as_ref().unwrap());
    if let Record::Handoff { publication, .. } = &mut foreign {
        publication["vm_id"] = json!(12);
    }
    assert!(s.procurement_projection(&foreign).is_err());
    block_on(s.procurement_resume(&mut api, false)).unwrap();
    let target = s.poc_target("machine-a").cloned();
    let original = s.procurement.clone();
    let mut changed_address = api.machines[0].clone();
    changed_address["ip_assignments"][0]["ip"] = json!("192.0.2.11/24");
    assert!(
        s.procurement_projection(&Record::Observation(changed_address))
            .is_err()
    );
    assert!(
        s.procurement_projection(&handoff(s.procurement.as_ref().unwrap()))
            .is_err()
    );
    assert_eq!(s.poc_target("machine-a").cloned(), target);
    assert_eq!(s.procurement, original);
    assert_eq!(reopen(&s).poc_target("machine-a").cloned(), target);
}

#[test]
fn provisioning_existing_enrolled_machine_cannot_be_replaced_by_a_purchase() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    let target = TargetRecord {
        machine: "existing".into(),
        relay: "wss://relay.invalid/".into(),
        profile: "v1".into(),
        host: "192.0.2.9".into(),
        port: 22,
        user: "arch".into(),
        elevation: crate::jobs::Elevation::SudoNoninteractive,
        pin: fixtures::publication()["fingerprint_sha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    block_on(s.poc_enroll(super::super::poc_targets::Enrollment {
        target: target.clone(),
        approve_existing: true,
        class_answer: ClassAnswer::No,
        approve_maintained_access: true,
    }))
    .unwrap();
    let mut loaded = reopen(&s);
    assert!(
        block_on(loaded.procurement_select(
            &mut api,
            Choice {
                offer_id: 1,
                image_id: 3,
                resources: None
            }
        ))
        .is_err()
    );
    assert!(block_on(loaded.procurement_approve(&mut api, approval())).is_err());
    assert!(loaded.procurement.is_none());
    assert_eq!(loaded.poc_target("existing"), Some(&target));
    assert_eq!(api.count("POST /api/v1/ssh-key"), 0);
    assert_eq!(api.count("POST /api/v1/vm"), 0);
}

#[test]
fn provisioning_cpu_constraints_gate_direct_lost_create_observation_and_replay() {
    for custom in [false, true] {
        for mode in ["direct", "lost", "later"] {
            for (field, bad) in [
                ("cpu_arch", json!(null)),
                ("cpu_arch", json!("arm64")),
                ("cpu_mfg", json!(null)),
                ("cpu_mfg", json!("amd")),
                ("cpu_features", json!(null)),
                ("cpu_features", json!(["AES"])),
            ] {
                let mut s = ready();
                let mut api = Fixture::new(custom);
                api.current_selection.offer["cpu_mfg"] = json!("intel");
                api.current_selection.offer["cpu_features"] = json!(["AES", "AVX2"]);
                approve(&mut s, &mut api);
                let original_identity = s.procurement.as_ref().unwrap().identity.clone();
                let pointer = format!("/template/{field}");
                if mode != "later" {
                    api.vm_change = Some((pointer.clone(), bad.clone()));
                }
                api.lose_create = mode == "lost";
                assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
                if mode == "later" {
                    assert!(issue_invoice(&mut s, &mut api).is_err());
                    api.payments[0]["is_paid"] = json!(true);
                    *api.machines[0].pointer_mut(&pointer).unwrap() = bad;
                }
                let mut loaded = reopen(&s);
                assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
                assert!(loaded.poc_target("machine-a").is_none());
                assert_eq!(
                    loaded.procurement.as_ref().unwrap().identity,
                    original_identity
                );
                assert_eq!(
                    api.count(if custom {
                        "POST /api/v1/vm/custom-template"
                    } else {
                        "POST /api/v1/vm"
                    }),
                    1
                );
                if mode == "later" {
                    assert_eq!(loaded.procurement_view()["vm_id"], 11);
                    let mut good = api.machines[0].clone();
                    for (field, value) in [
                        ("cpu_arch", json!("x86_64")),
                        ("cpu_mfg", json!("INTEL")),
                        ("cpu_features", json!(["avx2", "AES", "FMA"])),
                    ] {
                        good["template"][field] = value;
                    }
                    api.machines[0] = good;
                    block_on(loaded.procurement_resume(&mut api, false)).unwrap();
                    assert!(reopen(&loaded).poc_target("machine-a").is_some());
                } else {
                    assert!(loaded.procurement.as_ref().unwrap().vm.is_none());
                }
            }
        }
    }
}

#[test]
fn provisioning_documented_clock_skew_survives_direct_reconciliation_readiness_and_replay() {
    for custom in [false, true] {
        for lost in [false, true] {
            for skew in [-60i64, -2, 2, 60] {
                let mut s = ready();
                let mut api = Fixture::new(custom);
                api.clock = api.clock.checked_add_signed(skew).unwrap();
                approve(&mut s, &mut api);
                api.lose_create = lost;
                assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
                let mut loaded = reopen(&s);
                assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
                assert_eq!(loaded.procurement_view()["vm_id"], 11);
                assert!(issue_invoice(&mut loaded, &mut api).is_err());
                api.payments[0]["is_paid"] = json!(true);
                block_on(loaded.procurement_resume(&mut api, false)).unwrap();
                assert!(reopen(&loaded).poc_target("machine-a").is_some());
                assert_eq!(
                    api.count(if custom {
                        "POST /api/v1/vm/custom-template"
                    } else {
                        "POST /api/v1/vm"
                    }),
                    1
                );
            }
        }
    }
}

#[test]
fn provisioning_outside_clock_evidence_preserves_uncertain_intent_without_resend() {
    for lost in [false, true] {
        for skew in [-121i64, 61] {
            let mut s = ready();
            let mut api = Fixture::new(false);
            api.clock = api.clock.checked_add_signed(skew).unwrap();
            approve(&mut s, &mut api);
            api.lose_create = lost;
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            let original = s.procurement.clone();
            let mut loaded = reopen(&s);
            for _ in 0..2 {
                assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
            }
            assert_eq!(loaded.procurement, original);
            assert!(loaded.procurement.as_ref().unwrap().vm.is_none());
            assert_eq!(api.count("POST /api/v1/vm"), 1);
        }
    }
}

#[test]
fn provisioning_actual_request_signature_encodings_never_reach_response_journal_or_output() {
    use zeroize::Zeroizing;
    let input = Zeroizing::new(hex::encode([7; 32]));
    let account = protocol::Account::parse(input.as_bytes()).unwrap();
    let auth = account
        .authorization(
            "https://api.lnvps.net/api/v1/vm/templates",
            "GET",
            None,
            42,
            &[5; 32],
        )
        .unwrap();
    let event = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(auth.strip_prefix("Nostr ").unwrap())
            .unwrap(),
    );
    let signed: Value = serde_json::from_slice(&event).unwrap();
    let signature = signed["sig"].as_str().unwrap();
    let raw = Zeroizing::new(hex::decode(signature).unwrap());
    let mixed: String = signature
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    for form in [
        base64::engine::general_purpose::STANDARD.encode(raw.as_slice()),
        signature.to_uppercase(),
        mixed,
    ] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        api.response_filter = Some(protocol::request_filter(&auth).unwrap());
        api.response_echo = Some(form.clone());
        assert!(
            block_on(s.procurement_catalogue(&mut api)).is_err(),
            "Request signature echo must be refused before response publication"
        );
        let value = json!({"name":form});
        assert!(
            !crate::poc::inference::safe(&s, &value, &[]),
            "Signature encoding must not reach model context"
        );
        assert!(
            s.protect_output(&value).unwrap() != value,
            "Signature encoding must not reach output"
        );
        let mut echoed = fixtures::vm(&fixtures::selection(false), 11);
        echoed["template"]["name"] = value["name"].clone();
        let next = s.next;
        assert!(
            block_on(s.commit(&Event::Procurement(Record::Associated(echoed)))).is_err(),
            "Exact serialized journal must reject request signatures"
        );
        assert_eq!(s.next, next);
        assert!(
            s.poc_credential_filters.borrow().is_empty(),
            "Provider request custody is separate from inference admission"
        );
    }
}

#[test]
fn provisioning_fiat_plan_uses_authoritative_lightning_quote_and_provider_period() {
    for currency in ["EUR", "USD"] {
        let mut s = ready();
        let mut api = Fixture::new(true);
        api.current_selection.charge.currency = currency.into();
        api.current_selection.charge.amount = 1500;
        api.billing_terms.time = 2678400;
        api.billing_terms.amount = 2345678;
        approve(&mut s, &mut api);
        assert!(
            block_on(s.procurement_resume(&mut api, true))
                .unwrap_err()
                .contains("Review the current initial Lightning quote")
        );
        assert!(s.procurement.as_ref().unwrap().invoice.is_none());
        let billing = s.procurement.as_ref().unwrap().billing.clone().unwrap();
        assert_eq!(billing.terms.time, 2678400);
        assert_eq!(billing.terms.currency, "BTC");
        let mut loaded = reopen(&s);
        assert!(
            block_on(loaded.procurement_resume(&mut api, true))
                .unwrap_err()
                .contains("external payment")
        );
        assert_eq!(loaded.procurement.as_ref().unwrap().billing, Some(billing));
        assert_eq!(
            loaded
                .procurement
                .as_ref()
                .unwrap()
                .selected
                .charge
                .currency,
            currency
        );
        api.payments[0]["is_paid"] = json!(true);
        block_on(loaded.procurement_resume(&mut api, false)).unwrap();
        assert!(reopen(&loaded).poc_target("machine-a").is_some());
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
    }
}

#[test]
fn provisioning_changed_or_unavailable_initial_quote_requires_review_and_never_resets_sent_invoice()
{
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let original = s.procurement.as_ref().unwrap().billing.clone().unwrap();
    api.billing_terms.amount += 1;
    api.billing_terms.tax += 1;
    api.billing_terms.processing_fee += 1;
    api.billing_terms.time += 86400;
    assert!(
        block_on(s.procurement_resume(&mut api, true))
            .unwrap_err()
            .contains("Review the current initial Lightning quote")
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    assert!(s.procurement.as_ref().unwrap().billing.as_ref() != Some(&original));
    let mut loaded = reopen(&s);
    api.fail_quote = true;
    assert!(block_on(loaded.procurement_resume(&mut api, true)).is_err());
    assert!(loaded.procurement.as_ref().unwrap().invoice.is_none());
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    api.fail_quote = false;
    api.lose_invoice = true;
    assert!(block_on(loaded.procurement_resume(&mut api, true)).is_err());
    let saved = loaded
        .procurement
        .as_ref()
        .unwrap()
        .billing
        .clone()
        .unwrap();
    let mut sent_replacement = saved.clone();
    sent_replacement.terms.amount += 1;
    assert!(
        loaded
            .procurement_projection(&Record::BillingQuoted(sent_replacement))
            .is_err()
    );
    let quotes = api.count("GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1");
    api.billing_terms.amount += 99;
    let mut loaded = reopen(&loaded);
    assert!(
        block_on(loaded.procurement_resume(&mut api, false))
            .unwrap_err()
            .contains("external payment")
    );
    assert_eq!(
        loaded.procurement.as_ref().unwrap().billing,
        Some(saved.clone())
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1"),
        quotes
    );
    let mut replacement = saved;
    replacement.terms.amount += 1;
    assert!(
        loaded
            .procurement_projection(&Record::BillingQuoted(replacement))
            .is_err()
    );
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        1
    );
}

#[test]
fn provisioning_existing_paid_or_unpaid_initial_history_reuses_authoritative_quote_without_issuance()
 {
    for paid in [false, true] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        approve(&mut s, &mut api);
        api.fault_after = Some((
            "POST /api/v1/vm".into(),
            s.storage.clone(),
            Fault::LandThenFail(3),
        ));
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        let mut loaded = reopen(&s);
        let mut payment = fixtures::payment(11);
        payment["is_paid"] = json!(paid);
        api.payments.push(payment);
        let result = block_on(loaded.procurement_resume(&mut api, false));
        assert_eq!(loaded.procurement_view()["payment"]["id"], "aabb");
        if paid {
            result.unwrap();
            assert!(loaded.poc_target("machine-a").is_some());
        } else {
            assert!(result.unwrap_err().contains("external payment"));
        }
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            0
        );
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1"),
            1
        );
    }
}

#[test]
fn provisioning_billing_intent_requires_saved_terms_and_failed_quote_append_sends_no_invoice() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    api.fault_after = Some((
        "POST /api/v1/vm".into(),
        s.storage.clone(),
        Fault::LandThenFail(3),
    ));
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    let mut loaded = reopen(&s);
    assert!(loaded.procurement.as_ref().unwrap().vm.is_some());
    assert!(loaded.procurement.as_ref().unwrap().billing.is_none());
    assert!(
        loaded
            .procurement_projection(&Record::BillingQuoted(Billing {
                vm_id: 12,
                terms: fixtures::billing_terms()
            }))
            .is_err()
    );
    assert!(
        loaded
            .procurement_projection(&Record::InvoiceSent(Invoice {
                before: vec![],
                started: api.clock
            }))
            .is_err()
    );
    api.fault_after = Some((
        "GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1".into(),
        loaded.storage.clone(),
        Fault::Fail(1),
    ));
    assert!(block_on(loaded.procurement_resume(&mut api, true)).is_err());
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
    let mut loaded = reopen(&loaded);
    assert!(loaded.procurement.as_ref().unwrap().billing.is_none());
    assert!(
        block_on(loaded.procurement_resume(&mut api, true))
            .unwrap_err()
            .contains("Review the current initial Lightning quote")
    );
    assert!(loaded.procurement.as_ref().unwrap().invoice.is_none());
    assert_eq!(
        api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
        0
    );
}

#[test]
fn provisioning_delayed_creation_evidence_within_action_and_clock_bounds_replays_same_machine() {
    for custom in [false, true] {
        for lost in [false, true] {
            let mut s = ready();
            let mut api = Fixture::new(custom);
            approve(&mut s, &mut api);
            // Model 30s intent/dispatch latency and a provider clock 60s ahead at dispatch.
            api.advance_before_create = 30;
            api.created = Some("2026-11-06T14:01:30Z".into());
            api.lose_create = lost;
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            let mut loaded = reopen(&s);
            assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
            assert_eq!(loaded.procurement_view()["vm_id"], 11);
            assert!(issue_invoice(&mut loaded, &mut api).is_err());
            api.payments[0]["is_paid"] = json!(true);
            block_on(loaded.procurement_resume(&mut api, false)).unwrap();
            let target = loaded.poc_target("machine-a").cloned();
            assert!(target.is_some());
            assert_eq!(reopen(&loaded).poc_target("machine-a").cloned(), target);
            let mut outside = api.machines[0].clone();
            outside["created"] = json!("2026-11-06T14:02:01Z");
            assert!(
                loaded
                    .procurement_projection(&Record::Observation(outside))
                    .is_err()
            );
            assert_eq!(
                api.count(if custom {
                    "POST /api/v1/vm/custom-template"
                } else {
                    "POST /api/v1/vm"
                }),
                1
            );
        }
    }
}

#[test]
fn provisioning_approval_credential_admission_precedes_durable_change() {
    let old = b"fixture~inference~key~482700";
    let current = b"current-inference-key-9751";
    for key in [old.as_slice(), current.as_slice()] {
        for alias in [
            hex::encode(key),
            String::from_utf8(key.to_vec()).unwrap(),
            hex::encode_upper(key),
            base64::engine::general_purpose::STANDARD.encode(key),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key),
            key.iter().map(|b| format!("%{b:02X}")).collect(),
        ] {
            for field in ["machine", "relay"] {
                let mut s = ready();
                let mut api = Fixture::new(false);
                block_on(s.procurement_select(
                    &mut api,
                    Choice {
                        offer_id: 1,
                        image_id: 3,
                        resources: None,
                    },
                ))
                .unwrap();
                s.remember_poc_credential(old);
                s.remember_poc_credential(current);
                let mut request = approval();
                if field == "machine" {
                    request.machine = alias.clone();
                } else {
                    request.relay = format!("wss://relay.invalid/{alias}/");
                }
                let files = s.storage.files();
                let allocation = s.allocation().clone();
                let end = s.records().end;
                let calls = api.calls.clone();
                let error = block_on(s.procurement_approve(&mut api, request)).unwrap_err();
                assert!(
                    error.contains("protected or unscannable"),
                    "{field}: {alias}"
                );
                assert_eq!(s.storage.files(), files, "approval must not append");
                assert_eq!(s.records().end, end);
                assert_eq!(s.allocation(), &allocation);
                assert_eq!(api.calls, calls, "refusal precedes provider traffic");
                assert!(s.procurement.is_none());
                assert!(s.dispatch.approved_entries.is_empty());
                let replayed = reopen(&s);
                assert!(replayed.procurement.is_none());
                assert_eq!(replayed.allocation(), &allocation);
                assert_eq!(replayed.storage.files(), files);
            }
        }
    }
    let mut safe = ready();
    safe.remember_poc_credential(old);
    safe.remember_poc_credential(current);
    approve(&mut safe, &mut Fixture::new(false));
    assert!(reopen(&safe).procurement.is_some());
}

#[test]
fn provisioning_approval_unscannable_authority_preserves_state() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    block_on(s.procurement_select(
        &mut api,
        Choice {
            offer_id: 1,
            image_id: 3,
            resources: None,
        },
    ))
    .unwrap();
    block_on(s.synthetic_scan_fixture(
        "credential".into(),
        Zeroizing::new(b"required-secret-1234".to_vec()),
    ))
    .unwrap();
    s.clear_scan_working_copies();
    let files = s.storage.files();
    let allocation = s.allocation().clone();
    let calls = api.calls.clone();
    assert!(
        block_on(s.procurement_approve(&mut api, approval()))
            .unwrap_err()
            .contains("protected or unscannable")
    );
    assert_eq!(s.storage.files(), files);
    assert_eq!(s.allocation(), &allocation);
    assert_eq!(api.calls, calls);
    assert!(s.procurement.is_none());
}

#[test]
fn provisioning_custom_caps_gate_direct_reconciliation_status_and_authenticated_replay() {
    for mode in ["direct", "lost", "later"] {
        for missing in [false, true] {
            let mut s = ready();
            let mut api = Fixture::new(true);
            api.current_selection = fixtures::capped_selection();
            approve(&mut s, &mut api);
            let approved = s.procurement.clone().unwrap();
            let mut bad = fixtures::vm(&approved.selected, 11);
            if missing {
                bad["template"]["limits"] = json!({"network_mbps":500});
            } else {
                bad["template"]["limits"]["cpu_limit"] = json!(0.25);
                bad["template"]["limits"]["disk_iops_read"] = json!(2500);
            }
            if mode != "later" {
                api.vm_change =
                    Some(("/template/limits".into(), bad["template"]["limits"].clone()));
            }
            api.lose_create = mode == "lost";
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            if mode == "later" {
                assert!(issue_invoice(&mut s, &mut api).is_err());
                api.payments[0]["is_paid"] = json!(true);
                api.machines[0] = bad.clone();
            }
            let invalid = if mode == "later" {
                Record::Observation(bad.clone())
            } else {
                Record::Associated(bad.clone())
            };
            assert!(
                s.procurement_projection(&invalid).is_err(),
                "shared replay projection refuses caps"
            );
            let mut forged = reopen(&s);
            block_on(forged.commit(&Event::Procurement(invalid))).unwrap();
            assert!(
                block_on(unlock(
                    MemoryStorage::with_files(forged.storage.files()),
                    &Fixed,
                    pass()
                ))
                .is_err(),
                "authenticated journal replay must refuse conflicting caps"
            );
            for _ in 0..2 {
                let mut loaded = reopen(&s);
                assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
                let p = loaded.procurement.as_ref().unwrap();
                assert_eq!(p.identity, approved.identity);
                assert_eq!(p.relay_identity, approved.relay_identity);
                assert_eq!(p.selected, approved.selected);
                assert_eq!(p.account, approved.account);
                assert!(p.create.is_some());
                assert!(p.target.is_none());
                assert_eq!(p.vm.is_some(), mode == "later");
                assert_eq!(api.count("POST /api/v1/vm/custom-template"), 1);
                assert_eq!(
                    api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
                    usize::from(mode == "later")
                );
                assert!(loaded.poc_target("machine-a").is_none());
                s = loaded;
            }
            api.machines[0] = fixtures::vm(&approved.selected, 11);
            if mode == "later" {
                block_on(s.procurement_resume(&mut api, false)).unwrap();
                assert!(reopen(&s).poc_target("machine-a").is_some());
            } else {
                assert!(
                    block_on(s.procurement_resume(&mut api, false))
                        .unwrap_err()
                        .contains("initial Lightning")
                );
                assert_eq!(reopen(&s).procurement_view()["vm_id"], 11);
            }
            assert_eq!(api.count("POST /api/v1/vm/custom-template"), 1);
        }
    }
}

#[test]
fn provisioning_unmetered_transfer_gates_direct_reconciliation_status_and_authenticated_replay() {
    for custom in [false, true] {
        for mode in ["direct", "lost", "later"] {
            let mut s = ready();
            let mut api = Fixture::new(custom);
            if custom {
                api.current_selection
                    .offer
                    .as_object_mut()
                    .unwrap()
                    .remove("transfer");
                api.current_selection
                    .resources
                    .as_mut()
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .remove("transfer_gb");
            }
            approve(&mut s, &mut api);
            let approved = s.procurement.clone().unwrap();
            let mut bad = fixtures::vm(&approved.selected, 11);
            bad["template"]["transfer_gb"] = json!(1);
            if mode != "later" {
                api.vm_change = Some(("/template".into(), bad["template"].clone()));
            }
            api.lose_create = mode == "lost";
            assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            if mode == "later" {
                assert!(issue_invoice(&mut s, &mut api).is_err());
                api.payments[0]["is_paid"] = json!(true);
                api.machines[0] = bad.clone();
            }
            let invalid = if mode == "later" {
                Record::Observation(bad.clone())
            } else {
                Record::Associated(bad.clone())
            };
            assert!(
                s.procurement_projection(&invalid).is_err(),
                "shared projection refuses an unapproved transfer cap"
            );
            let mut forged = reopen(&s);
            block_on(forged.commit(&Event::Procurement(invalid))).unwrap();
            assert!(
                block_on(unlock(
                    MemoryStorage::with_files(forged.storage.files()),
                    &Fixed,
                    pass()
                ))
                .is_err(),
                "authenticated replay refuses an unapproved transfer cap"
            );
            for _ in 0..2 {
                let mut loaded = reopen(&s);
                assert!(block_on(loaded.procurement_resume(&mut api, false)).is_err());
                let p = loaded.procurement.as_ref().unwrap();
                assert_eq!(p.identity, approved.identity);
                assert_eq!(p.relay_identity, approved.relay_identity);
                assert_eq!(p.selected, approved.selected);
                assert_eq!(p.account, approved.account);
                assert!(p.create.is_some() && p.target.is_none());
                assert_eq!(p.vm.is_some(), mode == "later");
                assert_eq!(
                    api.count(if custom {
                        "POST /api/v1/vm/custom-template"
                    } else {
                        "POST /api/v1/vm"
                    }),
                    1
                );
                assert_eq!(
                    api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
                    usize::from(mode == "later")
                );
                s = loaded;
            }
            api.machines[0] = fixtures::vm(&approved.selected, 11);
            if mode == "later" {
                block_on(s.procurement_resume(&mut api, false)).unwrap();
                assert!(reopen(&s).poc_target("machine-a").is_some());
            } else {
                assert!(
                    block_on(s.procurement_resume(&mut api, false))
                        .unwrap_err()
                        .contains("initial Lightning")
                );
                assert_eq!(reopen(&s).procurement_view()["vm_id"], 11);
            }
            assert_eq!(
                api.count(if custom {
                    "POST /api/v1/vm/custom-template"
                } else {
                    "POST /api/v1/vm"
                }),
                1
            );
        }
    }
}

#[test]
fn provisioning_missing_limits_refuse_before_approval_and_authenticated_replay() {
    for custom in [false, true] {
        let mut s = ready();
        let original_files = s.storage.files();
        let allocation = s.allocation().clone();
        let mut api = Fixture::new(custom);
        api.current_selection
            .offer
            .as_object_mut()
            .unwrap()
            .remove("limits");
        assert!(
            block_on(s.procurement_select(
                &mut api,
                Choice {
                    offer_id: if custom { 2 } else { 1 },
                    image_id: 3,
                    resources: custom.then(fixtures::custom_resources),
                }
            ))
            .is_err()
        );
        assert!(s.procurement.is_none());
        assert_eq!(s.storage.files(), original_files);
        assert_eq!(s.allocation(), &allocation);
        assert!(api.calls.iter().all(|call| call.starts_with("GET ")));
        api.current_selection = fixtures::selection(custom);
        approve(&mut s, &mut api);
        let mut invalid = s.procurement.clone().unwrap();
        invalid
            .selected
            .offer
            .as_object_mut()
            .unwrap()
            .remove("limits");
        let mut before = block_on(unlock(
            MemoryStorage::with_files(original_files),
            &Fixed,
            pass(),
        ))
        .unwrap();
        assert!(
            before
                .procurement_projection(&Record::Approved(Box::new(invalid.clone())))
                .is_err()
        );
        block_on(before.commit(&Event::Procurement(Record::Approved(Box::new(invalid))))).unwrap();
        assert!(
            block_on(unlock(
                MemoryStorage::with_files(before.storage.files()),
                &Fixed,
                pass()
            ))
            .is_err(),
            "authenticated approval cannot replay without limits evidence"
        );
        assert!(s.procurement.as_ref().unwrap().create.is_none());
    }
}

#[test]
fn provisioning_request_protection_survives_worker_loss_before_response() {
    let input = Zeroizing::new(hex::encode([7; 32]));
    let account = protocol::Account::parse(input.as_bytes()).unwrap();
    let auth = account
        .authorization(
            "https://api.lnvps.net/api/v1/vm/templates",
            "GET",
            None,
            42,
            &[5; 32],
        )
        .unwrap();
    let signed: Value = serde_json::from_slice(
        &base64::engine::general_purpose::STANDARD
            .decode(auth.strip_prefix("Nostr ").unwrap())
            .unwrap(),
    )
    .unwrap();
    let signature = signed["sig"].as_str().unwrap();
    let forms = [
        signature.to_string(),
        signature.to_uppercase(),
        base64::engine::general_purpose::STANDARD.encode(hex::decode(signature).unwrap()),
        signed.to_string(),
        auth.to_string(),
    ];
    let mut s = ready();
    let mut api = Fixture::new(false);
    api.prepared_protection = Some(protocol::request_filter(&auth).unwrap().fingerprints());
    api.fail_catalogue = true;
    assert!(block_on(s.procurement_catalogue(&mut api)).is_err());
    assert_eq!(api.count("GET /api/v1/vm/templates"), 1);
    let mut loaded = reopen(&s);
    loaded.remember_provider_filter(account.filter(input.as_bytes()));
    for form in forms {
        let next = loaded.next;
        api.fail_catalogue = false;
        api.response_echo = Some(form.clone());
        assert!(
            block_on(loaded.procurement_catalogue(&mut api)).is_err(),
            "prior request material must not be published after reload"
        );
        let value = json!({"name":form});
        assert!(!crate::poc::inference::safe(&loaded, &value, &[]));
        assert_ne!(loaded.protect_output(&value).unwrap(), value);
        let mut vm = fixtures::vm(&fixtures::selection(false), 11);
        vm["template"]["name"] = value["name"].clone();
        assert!(block_on(loaded.commit(&Event::Procurement(Record::Associated(vm)))).is_err());
        assert_eq!(
            loaded.next, next,
            "refused evidence never enters the journal"
        );
        let mut reader = Store::new(
            loaded.storage.clone(),
            DataKey(loaded.key.0),
            loaded.id.clone(),
        );
        for number in 0..loaded.next {
            let bytes = block_on(loaded.storage.read(&number.to_string())).unwrap();
            let event = reader.open(number, &bytes).unwrap();
            assert!(
                !serde_json::to_string(&event)
                    .unwrap()
                    .contains(value["name"].as_str().unwrap())
            );
            reader.previous = Address(Sha256::digest(&bytes).into());
        }
    }
    assert!(loaded.poc_credential_filters.borrow().is_empty());
}

#[test]
fn provisioning_failed_protection_append_dispatches_nothing() {
    for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
        let mut s = ready();
        let mut api = Fixture::new(false);
        api.prepared_protection = Some(
            crate::poc::inference::EchoFilter::new(&[b"synthetic request scan material"])
                .fingerprints(),
        );
        s.storage.fault(fault);
        assert!(block_on(s.procurement_catalogue(&mut api)).is_err());
        assert!(
            api.calls.is_empty(),
            "no transport before protection commit succeeds"
        );
    }
}

#[test]
fn provisioning_failed_mutation_protection_keeps_intent_without_dispatch_or_retry() {
    for route in [
        "POST /api/v1/ssh-key",
        "POST /api/v1/vm",
        "GET /api/v1/vm/11/renew?method=lightning&intervals=1",
    ] {
        for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
            let mut s = ready();
            let mut api = Fixture::new(false);
            approve(&mut s, &mut api);
            let invoice = route.contains("/renew?");
            if invoice {
                assert!(
                    block_on(s.procurement_resume(&mut api, false))
                        .unwrap_err()
                        .contains("Review the current initial Lightning quote")
                );
                assert!(s.procurement.as_ref().unwrap().billing.is_some());
                assert!(s.procurement.as_ref().unwrap().invoice.is_none());
            }
            api.protection_fault = Some((route.into(), s.storage.clone(), fault));
            assert!(block_on(s.procurement_resume(&mut api, invoice)).is_err());
            assert_eq!(
                api.count(route),
                0,
                "failed protection append sends no mutation"
            );
            let purchase = s.procurement.clone();
            let mut loaded = reopen(&s);
            for _ in 0..2 {
                assert!(block_on(loaded.procurement_resume(&mut api, invoice)).is_err());
                assert_eq!(
                    api.count(route),
                    0,
                    "persisted intent never dispatches after recovery"
                );
                assert_eq!(loaded.procurement, purchase);
            }
        }
    }
}

#[test]
fn provisioning_request_fingerprint_wire_format_roundtrips_fixed_length_digests() {
    let filter = crate::poc::inference::EchoFilter::new(&[b"synthetic public request material"]);
    let snapshot = filter.fingerprints();
    let encoded = serde_json::to_value(&snapshot).unwrap();
    for pattern in encoded["patterns"].as_array().unwrap() {
        assert_eq!(pattern[2].as_array().unwrap().len(), 32);
        assert_eq!(pattern[3].as_array().unwrap().len(), 32);
    }
    let restored: crate::poc::inference::EchoFingerprints =
        serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(snapshot, restored);
    for input in [
        b"synthetic public request material".as_slice(),
        b"ordinary harmless output".as_slice(),
    ] {
        assert_eq!(
            filter.protect_bytes(input).unwrap(),
            restored.filter().protect_bytes(input).unwrap()
        );
    }
    for length in [0, 31, 33] {
        let mut malformed = encoded.clone();
        malformed["patterns"][0][2] = json!(vec![0u8; length]);
        assert!(
            serde_json::from_value::<crate::poc::inference::EchoFingerprints>(malformed).is_err()
        );
    }
}

fn configure_origin(s: &mut Store<MemoryStorage>, origin: &str) {
    let secret = hex::encode([7; 32]);
    let account = protocol::Account::parse(secret.as_bytes()).unwrap();
    s.procurement_configure(&account, secret.as_bytes(), origin)
        .unwrap();
}

#[test]
fn provisioning_origin_invalid_configuration_is_atomic_and_credential_safe() {
    let mut s = ready();
    let secret = hex::encode([7; 32]);
    let account = protocol::Account::parse(secret.as_bytes()).unwrap();
    configure_origin(&mut s, "https://first.invalid:8443/");
    let mut api = Fixture::new(false);
    api.account = account.public();
    block_on(s.procurement_select(
        &mut api,
        Choice {
            offer_id: 1,
            image_id: 3,
            resources: None,
        },
    ))
    .unwrap();
    let selection = s.procurement_selection.clone();
    let files = s.storage.files();
    let allocation = s.allocation().clone();
    let requests = api.calls.len();
    s.poc_credential_filters
        .borrow_mut()
        .push(crate::poc::inference::EchoFilter::new(&[b"guarded-origin"]));
    for input in [
        "https://@second.invalid",
        "https://second.invalid?",
        "https://second.invalid/..",
        "https://guarded-origin.invalid",
    ] {
        let reason = s
            .procurement_configure(&account, secret.as_bytes(), input)
            .unwrap_err();
        assert!(!reason.contains(input));
        assert_eq!(s.procurement_origin(), "https://first.invalid:8443");
        assert_eq!(s.procurement_selection, selection);
        assert_eq!(s.storage.files(), files);
        assert_eq!(s.allocation(), &allocation);
        assert_eq!(api.calls.len(), requests);
        assert!(s.procurement.is_none());
    }
    let alias = base64::engine::general_purpose::STANDARD_NO_PAD.encode([7; 32]);
    assert!(
        s.procurement_configure(
            &account,
            secret.as_bytes(),
            &format!("https://{alias}.invalid")
        )
        .is_err()
    );
    assert_eq!(s.procurement_origin(), "https://first.invalid:8443");
    assert_eq!(s.storage.files(), files);
}

#[test]
fn provisioning_origin_stale_consent_cannot_cross_identical_providers() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    configure_origin(&mut s, "https://first.invalid");
    let choice = || Choice {
        offer_id: 1,
        image_id: 3,
        resources: None,
    };
    block_on(s.procurement_select(&mut api, choice())).unwrap();
    let mut old = approval();
    old.origin = s.procurement_origin().into();
    let selected = s.procurement_selection.clone();
    configure_origin(&mut s, "https://second.invalid");
    assert!(s.procurement_selection.is_none());
    block_on(s.procurement_select(&mut api, choice())).unwrap();
    assert_eq!(selected, s.procurement_selection);
    let before = s.storage.files();
    let allocation = s.allocation().clone();
    let calls = api.calls.len();
    assert!(
        block_on(s.procurement_approve(&mut api, old))
            .unwrap_err()
            .contains("origin is stale")
    );
    assert_eq!(api.calls.len(), calls);
    assert_eq!(s.storage.files(), before);
    assert_eq!(s.allocation(), &allocation);
    assert!(s.procurement.is_none());
    let mut current = approval();
    current.origin = s.procurement_origin().into();
    block_on(s.procurement_approve(&mut api, current)).unwrap();
    assert_eq!(
        s.procurement.as_ref().unwrap().origin,
        "https://second.invalid"
    );
}

#[test]
fn provisioning_origin_every_route_signed_and_bound_across_resume_reapproval() {
    for custom in [false, true] {
        let mut s = ready();
        let mut api = Fixture::new(custom);
        api.record_signatures = true;
        api.account = protocol::Account::parse(hex::encode([7; 32]).as_bytes())
            .unwrap()
            .public();
        configure_origin(&mut s, "https://bound.invalid:18443/");
        approve(&mut s, &mut api);
        let original = s.procurement.clone().unwrap();
        configure_origin(&mut s, "https://wrong.invalid");
        assert_eq!(s.procurement_origin(), original.origin);
        api.current_selection.charge.amount += 1;
        if !custom {
            api.current_selection.offer["cost_plan"]["amount"] =
                json!(api.current_selection.charge.amount);
        }
        assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
        let mut loaded = reopen(&s);
        configure_origin(&mut loaded, "https://another.invalid");
        let mut renewed = approval();
        renewed.origin = original.origin.clone();
        block_on(loaded.procurement_approve(&mut api, renewed)).unwrap();
        assert_eq!(
            loaded.procurement.as_ref().unwrap().identity,
            original.identity
        );
        assert_eq!(
            loaded.procurement.as_ref().unwrap().relay_identity,
            original.relay_identity
        );
        assert!(issue_invoice(&mut loaded, &mut api).is_err());
        api.payments[0]["is_paid"] = json!(true);
        block_on(loaded.procurement_resume(&mut api, false)).unwrap();
        assert_eq!(
            loaded.procurement_view()["publication"]["origin"],
            original.origin
        );
        let target = loaded.poc_target("machine-a").cloned();
        let mut replayed = reopen(&loaded);
        configure_origin(&mut replayed, "https://wrong.invalid");
        block_on(replayed.procurement_catalogue(&mut api)).unwrap();
        block_on(replayed.procurement_resume(&mut api, false)).unwrap();
        assert_eq!(replayed.poc_target("machine-a").cloned(), target);
        assert_eq!(
            replayed.procurement.as_ref().unwrap().origin,
            original.origin
        );
        // Registration reconciliation is another bound read, with no registration resend.
        let mut uncertain = ready();
        configure_origin(&mut uncertain, &original.origin);
        let mut lost = Fixture::new(custom);
        lost.record_signatures = true;
        lost.account = api.account.clone();
        lost.lose_registration = true;
        approve(&mut uncertain, &mut lost);
        assert!(block_on(uncertain.procurement_resume(&mut lost, false)).is_err());
        uncertain = reopen(&uncertain);
        configure_origin(&mut uncertain, "https://wrong.invalid");
        assert!(block_on(uncertain.procurement_resume(&mut lost, false)).is_err());
        assert_eq!(lost.count("POST /api/v1/ssh-key"), 1);
        assert_eq!(lost.count("GET /api/v1/ssh-key"), 1);
        let urls: Vec<_> = api.urls.iter().chain(&lost.urls).collect();
        for url in urls {
            assert!(
                url.starts_with("https://bound.invalid:18443/api/v1/"),
                "wrong origin: {url}"
            );
        }
        for event in api.signed_requests.iter().chain(&lost.signed_requests) {
            crate::relay_auth::verify_signature(event).unwrap();
            assert!(
                event["tags"][0][1]
                    .as_str()
                    .unwrap()
                    .starts_with("https://bound.invalid:18443/api/v1/")
            );
        }
        for route in [
            "GET /api/v1/vm/templates",
            "GET /api/v1/image",
            "POST /api/v1/ssh-key",
            "GET /api/v1/vm",
            "GET /api/v1/vm/11",
            "GET /api/v1/vm/11/payments?limit=100&offset=0",
            "GET /api/v1/vm/11/renew/quote?method=lightning&intervals=1",
            "GET /api/v1/vm/11/renew?method=lightning&intervals=1",
            "GET /api/v1/payment/aabb",
        ] {
            assert!(api.count(route) > 0, "route not covered: {route}");
        }
        let create = if custom {
            "POST /api/v1/vm/custom-template"
        } else {
            "POST /api/v1/vm"
        };
        assert_eq!(api.count(create), 1);
        assert_eq!(api.count("POST /api/v1/ssh-key"), 1);
        assert_eq!(
            api.count("GET /api/v1/vm/11/renew?method=lightning&intervals=1"),
            1
        );
        if custom {
            assert!(api.count("POST /api/v1/vm/custom-template/price") > 0);
        }
    }
}

/// Rewrite authenticated fixture records with fresh nonces and a complete hash chain.
fn origin_journal(s: &Store<MemoryStorage>, mut edit: impl FnMut(&mut Value)) -> MemoryStorage {
    let storage = MemoryStorage::with_files(s.storage.files());
    let mut previous = hex::encode([0u8; 32]);
    for n in s.records() {
        let mut record: RecordJson =
            serde_json::from_slice(&s.storage.files()[&n.to_string()]).unwrap();
        let nonce: [u8; 12] = decode("nonce", &record.nonce).unwrap();
        let plaintext = cipher(&s.key.0)
            .decrypt(
                &nonce.into(),
                Payload {
                    msg: &URL_SAFE_NO_PAD.decode(&record.ciphertext).unwrap(),
                    aad: record_aad(&s.id, EVENT, n, &record.previous).as_bytes(),
                },
            )
            .unwrap();
        let mut value: Value = serde_json::from_slice(&plaintext).unwrap();
        edit(&mut value["event"]);
        let nonce: [u8; 12] = random().unwrap();
        record.previous = previous;
        record.nonce = URL_SAFE_NO_PAD.encode(nonce);
        record.ciphertext = URL_SAFE_NO_PAD.encode(
            cipher(&s.key.0)
                .encrypt(
                    &nonce.into(),
                    Payload {
                        msg: &serde_json::to_vec(&value).unwrap(),
                        aad: record_aad(&s.id, EVENT, n, &record.previous).as_bytes(),
                    },
                )
                .unwrap(),
        );
        let bytes = serde_json::to_vec(&record).unwrap();
        block_on(storage.write(&n.to_string(), &bytes)).unwrap();
        previous = hex::encode(Sha256::digest(bytes));
    }
    storage
}

#[test]
fn provisioning_origin_explicit_invalid_refuses_replay() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    configure_origin(&mut s, "https://bound.invalid:18443");
    approve(&mut s, &mut api);
    for origin in [
        "",
        "http://bad.invalid",
        "https://bad.invalid/..",
        "https://@bad.invalid",
        "https://bad.invalid?",
        "https://bound.invalid:18443/",
    ] {
        let storage = origin_journal(&s, |event| {
            if let Some(p) = event.pointer_mut("/procurement/approved") {
                p["origin"] = json!(origin);
            }
        });
        assert!(
            block_on(unlock(storage, &Fixed, pass())).is_err(),
            "invalid stored origin admitted: {origin}"
        );
    }
    assert_eq!(reopen(&s).procurement, s.procurement);
}

#[test]
fn provisioning_origin_foreign_publication_refuses_replay() {
    let mut s = ready();
    let mut api = Fixture::new(false);
    configure_origin(&mut s, "https://bound.invalid:18443");
    approve(&mut s, &mut api);
    assert!(issue_invoice(&mut s, &mut api).is_err());
    api.payments[0]["is_paid"] = json!(true);
    block_on(s.procurement_resume(&mut api, false)).unwrap();
    let storage = origin_journal(&s, |event| {
        if let Some(p) = event.pointer_mut("/procurement/handoff/publication") {
            p["origin"] = json!(protocol::ORIGIN);
        }
    });
    assert!(
        block_on(unlock(storage, &Fixed, pass())).is_err(),
        "foreign publication origin cannot establish a target"
    );
    assert_eq!(
        reopen(&s).poc_target("machine-a"),
        s.poc_target("machine-a")
    );
}

#[test]
fn provisioning_origin_normalization_cannot_introduce_candidate_key_material() {
    let mut s = ready();
    configure_origin(&mut s, "https://first.invalid:8443");
    let before = s.storage.files();
    let allocation = s.allocation().clone();
    let alias = format!("{}c", "a".repeat(42));
    let raw = base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&alias)
        .unwrap();
    let secret = hex::encode(&raw);
    let account = protocol::Account::parse(secret.as_bytes()).unwrap();
    let input = format!("https://{}.invalid", alias.to_uppercase());
    assert_eq!(
        protocol::provider_origin(&input).unwrap(),
        format!("https://{alias}.invalid")
    );
    let reason = s
        .procurement_configure(&account, secret.as_bytes(), &input)
        .expect_err("normalized origin must not introduce an encoded provider scalar");
    assert!(reason.contains("protected or unscannable"));
    assert_eq!(s.procurement_origin(), "https://first.invalid:8443");
    assert_eq!(s.storage.files(), before);
    assert_eq!(s.allocation(), &allocation);
    assert!(s.procurement.is_none());
}

#[test]
#[ignore = "requires an explicitly supplied synthetic base-written fixture"]
fn provisioning_base_compatibility_fixture() {
    let path = std::env::var("PURCHASE_COMPAT_FIXTURE")
        .expect("explicit synthetic base-written fixture path");
    let files = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let s = block_on(unlock(MemoryStorage::with_files(files), &Fixed, pass())).unwrap();
    let loaded = reopen(&s);
    assert_eq!(loaded.procurement, s.procurement);
    assert_eq!(loaded.poc_target("machine-a"), s.poc_target("machine-a"));
    assert_eq!(loaded.procurement_view(), s.procurement_view());
    assert_eq!(
        loaded.dispatch.approved_entries["machine-a"]
            .approved
            .identity,
        s.procurement.as_ref().unwrap().identity
    );
    assert_eq!(
        serde_json::to_value(loaded.sessions()).unwrap(),
        serde_json::to_value(s.sessions()).unwrap()
    );
    assert_eq!(loaded.poc_targets_view(), s.poc_targets_view());
    let snapshot = json!({"procurement":s.procurement_view(),"sessions":s.sessions(),"targets":s.poc_targets_view(),"setup":s.dispatch.setup_view(),"tasks":s.poc.values().map(poc::Task::view).collect::<Vec<_>>()});
    let expected = format!("{path}.expected");
    assert_eq!(
        snapshot,
        serde_json::from_slice::<Value>(&std::fs::read(expected).unwrap()).unwrap()
    );
}

fn purchase_events(s: &Store<MemoryStorage>) -> Vec<Event> {
    let mut reader = Store::new(s.storage.clone(), DataKey(s.key.0), s.id.clone());
    s.records()
        .map(|n| {
            let bytes = &s.storage.files()[&n.to_string()];
            let event = reader.open(n, bytes).unwrap();
            reader.previous = Address(Sha256::digest(bytes).into());
            event
        })
        .collect()
}
fn associated_purchase() -> (Store<MemoryStorage>, Fixture) {
    let mut s = ready();
    let mut api = Fixture::new(false);
    approve(&mut s, &mut api);
    assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
    assert!(s.procurement.as_ref().unwrap().vm.is_some());
    (s, api)
}
fn disappear(api: &mut Fixture) {
    api.machines.clear();
    for path in ["/api/v1/vm/11", "/api/v1/vm/11/payments?limit=100&offset=0"] {
        api.read_errors
            .insert(path.into(), protocol::ReadError::NotFound);
    }
    api.calls.clear();
    api.urls.clear();
}
fn observe_protection(s: &Store<MemoryStorage>, api: &mut Fixture) {
    let storage = s.storage.clone();
    let key = s.key.0;
    let id = s.id.clone();
    let baseline = s.next;
    let dispatches = std::cell::Cell::new(0u64);
    api.prepared_protection = Some(
        crate::poc::inference::EchoFilter::new(&[b"synthetic close request material"])
            .fingerprints(),
    );
    api.observe_dispatch = Some(Box::new(move || {
        let mut reader = Store::new(storage.clone(), DataKey(key), id.clone());
        let files = storage.files();
        let mut protections = 0;
        let mut last_protection = false;
        for n in 0..baseline + dispatches.get() + 1 {
            let bytes = &files[&n.to_string()];
            let event = reader.open(n, bytes).unwrap();
            last_protection = matches!(event, Event::ProviderProtection(_));
            if n >= baseline {
                assert!(last_protection);
                protections += 1;
            }
            reader.previous = Address(Sha256::digest(bytes).into());
        }
        assert!(
            last_protection,
            "dispatch requires a committed protection event"
        );
        dispatches.set(dispatches.get() + 1);
        assert_eq!(protections, dispatches.get());
    }));
}

#[test]
fn provisioning_close_success_releases_setup_and_consumes_identities() {
    for stage in 0..3 {
        let (mut s, mut api) = associated_purchase();
        if stage > 0 {
            api.lose_invoice = stage == 1;
            assert!(issue_invoice(&mut s, &mut api).is_err());
            assert!(s.procurement.as_ref().unwrap().invoice.is_some());
        }
        if stage == 2 {
            api.clock = timestamp(
                s.procurement.as_ref().unwrap().payment.as_ref().unwrap()["expires"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        }
        let old = s.procurement.clone().unwrap();
        let allocation = s.allocation().clone();
        let prior = purchase_events(&s);
        let prior_files = s.storage.files();
        let before = s.next;
        disappear(&mut api);
        observe_protection(&s, &mut api);
        block_on(s.procurement_close(&mut api)).unwrap();
        assert_eq!(
            api.calls,
            [
                "GET /api/v1/vm",
                "GET /api/v1/vm/11",
                "GET /api/v1/vm/11/payments?limit=100&offset=0"
            ]
        );
        assert!(api.urls.iter().all(|u| u.starts_with(&old.origin)));
        assert_eq!(s.next, before + 4);
        let events = purchase_events(&s);
        for (name, bytes) in prior_files {
            assert_eq!(s.storage.files()[&name], bytes);
        }
        assert_eq!(
            serde_json::to_value(&events[..prior.len()]).unwrap(),
            serde_json::to_value(&prior).unwrap()
        );
        for event in &events[prior.len()..prior.len() + 3] {
            assert!(matches!(event, Event::ProviderProtection(_)));
        }
        assert!(
            matches!(events.last().unwrap(), Event::Procurement(Record::Closed {vm_id:11, inventory_status:200, detail_status:404, history_status:404, checked_at}) if *checked_at == api.clock)
        );
        assert!(s.procurement.is_none());
        assert!(s.dispatch.approved_entries.is_empty());
        assert!(s.dispatch.associations.is_empty());
        assert!(s.dispatch.current_installations.is_empty());
        assert!(s.dispatch.setup_approval.is_none());
        assert_eq!(s.allocation(), &allocation);
        assert!(
            s.procurement_view()["closed"]
                .as_str()
                .unwrap()
                .contains("recorded no payment")
        );
        assert_eq!(
            s.procurement_view()["closed"]
                .as_str()
                .unwrap()
                .contains("keep your proof of payment"),
            stage == 2
        );
        let mut loaded = reopen(&s);
        assert!(loaded.procurement.is_none());
        assert!(
            block_on(loaded.procurement_close(&mut api)).is_err(),
            "closure is final"
        );
        api.observe_dispatch = None;
        api.prepared_protection = None;
        approve(&mut loaded, &mut api);
        let new = loaded.procurement.as_ref().unwrap();
        assert_ne!(new.identity, old.identity);
        assert_eq!(new.identity.index, old.identity.index + 1);
        assert!(loaded.closed_purchases.iter().any(|p| p == &old));
        let replayed = reopen(&loaded);
        assert_eq!(replayed.procurement, loaded.procurement);
        assert_eq!(replayed.closed_purchases, loaded.closed_purchases);
        assert_eq!(
            replayed.dispatch.approved_entries["machine-a"]
                .approved
                .identity,
            new.identity
        );
    }
}

#[test]
fn provisioning_close_local_refusals_write_and_send_nothing() {
    for case in [
        "paid",
        "unexpired",
        "handoff",
        "unsent",
        "uncertain",
        "wrong-account",
    ] {
        let (mut s, mut api) = if case == "unsent" || case == "uncertain" {
            let mut s = ready();
            let mut api = Fixture::new(false);
            approve(&mut s, &mut api);
            if case == "uncertain" {
                api.lose_create = true;
                assert!(block_on(s.procurement_resume(&mut api, false)).is_err());
            }
            (s, api)
        } else {
            associated_purchase()
        };
        if ["paid", "unexpired", "handoff"].contains(&case) {
            assert!(issue_invoice(&mut s, &mut api).is_err());
            if case != "unexpired" {
                api.payments[0]["is_paid"] = true.into();
                if case == "paid" {
                    block_on(s.procurement_commit(Record::Payment(api.payments[0].clone())))
                        .unwrap();
                } else {
                    block_on(s.procurement_resume(&mut api, false)).unwrap();
                }
            }
        }
        if case == "wrong-account" {
            api.account = "b".repeat(64);
        }
        let files = s.storage.files();
        let p = s.procurement.clone();
        let setup = s.dispatch.setup_view();
        let allocation = s.allocation().clone();
        api.calls.clear();
        let error = block_on(s.procurement_close(&mut api)).unwrap_err();
        if case != "wrong-account" {
            assert_eq!(error, CLOSE_REFUSED, "{case}");
        }
        assert!(api.calls.is_empty(), "{case}");
        assert_eq!(s.storage.files(), files, "{case}");
        assert_eq!(s.procurement, p);
        assert_eq!(s.dispatch.setup_view(), setup);
        assert_eq!(s.allocation(), &allocation);
    }
}

#[test]
fn provisioning_close_provider_refusals_keep_only_dispatched_protections() {
    for case in [
        "detail-ok",
        "403",
        "history-ok",
        "bare-404",
        "500",
        "timeout",
        "transport",
        "inventory-present",
        "inventory-refused",
        "inventory-over-bound",
        "inventory-malformed",
    ] {
        let (mut s, mut api) = associated_purchase();
        let vm = api.machines[0].clone();
        disappear(&mut api);
        let expected = match case {
            "inventory-present" => {
                api.machines.push(vm.clone());
                1
            }
            "inventory-over-bound" => {
                api.machines = (1..=129)
                    .map(|i| {
                        let mut v = vm.clone();
                        v["id"] = json!(100 + i);
                        v
                    })
                    .collect();
                1
            }
            "inventory-malformed" => {
                api.machines.push(json!({"id":99}));
                1
            }
            "inventory-refused" => {
                api.read_errors
                    .insert("/api/v1/vm".into(), "inventory refused".into());
                1
            }
            "history-ok" => {
                api.read_errors
                    .remove("/api/v1/vm/11/payments?limit=100&offset=0");
                3
            }
            "detail-ok" => {
                api.read_errors.remove("/api/v1/vm/11");
                api.read_values.insert("/api/v1/vm/11".into(), vm);
                2
            }
            other => {
                api.read_errors.insert(
                    "/api/v1/vm/11".into(),
                    protocol::ReadError::Refused(if other == "bare-404" {
                        protocol::READ_REFUSED.into()
                    } else {
                        other.into()
                    }),
                );
                2
            }
        };
        let p = s.procurement.clone();
        let setup = s.dispatch.setup_view();
        let allocation = s.allocation().clone();
        let before = s.next;
        observe_protection(&s, &mut api);
        assert!(block_on(s.procurement_close(&mut api)).is_err(), "{case}");
        assert_eq!(api.calls.len(), expected, "{case}");
        assert_eq!(s.next, before + expected as u64);
        assert!(
            purchase_events(&s)
                .iter()
                .skip(before as usize)
                .all(|e| matches!(e, Event::ProviderProtection(_)))
        );
        assert_eq!(s.procurement, p);
        assert_eq!(s.dispatch.setup_view(), setup);
        assert_eq!(s.allocation(), &allocation);
        assert_eq!(reopen(&s).procurement, p);
    }
}

#[test]
fn provisioning_close_append_failures_do_not_release_purchase() {
    for close_fault in [false, true] {
        for fault in [Fault::Fail(1), Fault::LandThenFail(3)] {
            let (mut s, mut api) = associated_purchase();
            disappear(&mut api);
            let p = s.procurement.clone();
            let setup = s.dispatch.setup_view();
            let allocation = s.allocation().clone();
            if close_fault {
                api.fault_after = Some((
                    "GET /api/v1/vm/11/payments?limit=100&offset=0".into(),
                    s.storage.clone(),
                    fault,
                ));
            } else {
                api.protection_fault = Some(("GET /api/v1/vm".into(), s.storage.clone(), fault));
            }
            assert!(block_on(s.procurement_close(&mut api)).is_err());
            assert_eq!(s.procurement, p);
            assert_eq!(s.dispatch.setup_view(), setup);
            assert_eq!(s.allocation(), &allocation);
            assert_eq!(api.calls.len(), if close_fault { 3 } else { 0 });
        }
    }
}

#[test]
fn provisioning_close_replay_checks_recorded_time_statuses_and_finality() {
    let (mut s, mut api) = associated_purchase();
    assert!(issue_invoice(&mut s, &mut api).is_err());
    let expiry = timestamp(
        s.procurement.as_ref().unwrap().payment.as_ref().unwrap()["expires"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let record = Record::Closed {
        vm_id: 11,
        inventory_status: 206,
        detail_status: 404,
        history_status: 404,
        checked_at: expiry,
    };
    let mut missing_id = serde_json::to_value(&record).unwrap();
    missing_id["closed"]
        .as_object_mut()
        .unwrap()
        .remove("vm_id");
    assert!(serde_json::from_value::<Record>(missing_id).is_err());
    assert!(s.procurement_projection(&record).is_ok());
    for edit in [
        json!({"vm_id":12}),
        json!({"inventory_status":404}),
        json!({"detail_status":200}),
        json!({"history_status":200}),
        json!({"checked_at":expiry-1}),
    ] {
        let mut value = serde_json::to_value(&record).unwrap();
        for (k, v) in edit.as_object().unwrap() {
            value["closed"][k] = v.clone();
        }
        let bad: Record = serde_json::from_value(value).unwrap();
        assert!(s.procurement_projection(&bad).is_err());
    }
    block_on(s.procurement_commit(record.clone())).unwrap();
    assert!(s.procurement_projection(&record).is_err());
    for edit in [
        json!({"vm_id":12}),
        json!({"inventory_status":404}),
        json!({"detail_status":200}),
        json!({"history_status":200}),
        json!({"checked_at":expiry-1}),
    ] {
        let tampered = origin_journal(&s, |event| {
            if let Some(closed) = event.pointer_mut("/procurement/closed") {
                for (k, v) in edit.as_object().unwrap() {
                    closed[k] = v.clone();
                }
            }
        });
        assert!(block_on(unlock(tampered, &Fixed, pass())).is_err());
    }
    let missing_association = origin_journal(&s, |event| {
        if event.pointer("/procurement/associated").is_some() {
            *event = json!({"procurement":{"registration_sent":null}});
        }
    });
    assert!(block_on(unlock(missing_association, &Fixed, pass())).is_err());
    assert!(reopen(&s).procurement.is_none());
    let mut duplicate = reopen(&s);
    assert!(
        duplicate
            .replay_procurement(duplicate.next, &record)
            .is_err()
    );
    api.account = "b".repeat(64);
    approve(&mut duplicate, &mut api);
    assert!(block_on(duplicate.procurement_resume(&mut api, false)).is_err());
    let p = duplicate.procurement.as_ref().unwrap().clone();
    let old_vm = fixtures::vm(&p.selected, 11);
    assert!(
        duplicate
            .procurement_projection(&Record::Associated(old_vm))
            .is_err()
    );
    let new_vm = fixtures::vm(&p.selected, 12);
    block_on(duplicate.procurement_commit(Record::Associated(new_vm))).unwrap();
    block_on(duplicate.procurement_commit(Record::BillingQuoted(Billing {
        vm_id: 12,
        terms: fixtures::billing_terms(),
    })))
    .unwrap();
    for spelling in ["aabb", "AABB"] {
        let mut reused = fixtures::payment(12);
        reused["id"] = json!(spelling);
        assert!(
            duplicate
                .procurement_projection(&Record::Payment(reused))
                .is_err(),
            "closed payment id cannot enter a new purchase with spelling {spelling}"
        );
    }
    assert_eq!(reopen(&duplicate).procurement_view()["vm_id"], 12);
    let mut next_payment = fixtures::payment(12);
    next_payment["id"] = json!("bbcc");
    next_payment["is_paid"] = json!(true);
    block_on(duplicate.procurement_commit(Record::Payment(next_payment))).unwrap();
    let next_handoff = handoff(duplicate.procurement.as_ref().unwrap());
    block_on(duplicate.procurement_commit(next_handoff)).unwrap();
    let final_store = reopen(&duplicate);
    assert_eq!(final_store.procurement_view()["vm_id"], 12);
    assert_eq!(final_store.procurement_view()["payment"]["id"], "bbcc");
    assert!(final_store.poc_target("machine-a").is_some());
    assert_eq!(final_store.closed_purchases.len(), 1);
    assert_eq!(
        final_store.closed_purchases[0].vm.as_ref().unwrap()["id"],
        11
    );
}

#[test]
fn provisioning_close_post_read_recheck_uses_current_time() {
    let (mut s, mut api) = associated_purchase();
    assert!(issue_invoice(&mut s, &mut api).is_err());
    api.clock = timestamp(
        s.procurement.as_ref().unwrap().payment.as_ref().unwrap()["expires"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    disappear(&mut api);
    api.after_read_clock = Some((
        "/api/v1/vm/11/payments?limit=100&offset=0".into(),
        api.clock - 1,
    ));
    observe_protection(&s, &mut api);
    let before = s.next;
    let p = s.procurement.clone();
    assert_eq!(
        block_on(s.procurement_close(&mut api)).unwrap_err(),
        CLOSE_REFUSED
    );
    assert_eq!(s.next, before + 3);
    assert_eq!(s.procurement, p);
}

#[test]
fn provisioning_missing_refresh_keeps_earlier_paid_reading() {
    for route in [
        "/api/v1/vm/11",
        "/api/v1/vm/11/payments?limit=100&offset=0",
        "/api/v1/payment/aabb",
    ] {
        let (mut s, mut api) = associated_purchase();
        let saved_payment = route != "/api/v1/vm/11/payments?limit=100&offset=0";
        if saved_payment {
            assert!(issue_invoice(&mut s, &mut api).is_err());
        }
        if route == "/api/v1/vm/11" {
            api.payments[0]["is_paid"] = true.into();
        }
        api.read_errors
            .insert(route.into(), protocol::ReadError::NotFound);
        let before = s.next;
        let error = block_on(s.procurement_resume(&mut api, false)).unwrap_err();
        assert_eq!(error, missing_pause(11));
        assert_eq!(s.next, before + u64::from(route == "/api/v1/vm/11"));
        if route == "/api/v1/vm/11" {
            assert_eq!(
                s.procurement.as_ref().unwrap().payment.as_ref().unwrap()["is_paid"],
                true
            );
            assert!(!close_eligible(s.procurement.as_ref().unwrap(), u64::MAX));
            assert!(
                matches!(purchase_events(&s).last().unwrap(),Event::Procurement(Record::Payment(pay)) if pay["is_paid"]==true)
            );
        } else if !saved_payment {
            assert!(close_eligible(s.procurement.as_ref().unwrap(), api.clock));
        }
        let before = s.next;
        api.read_errors.insert(
            route.into(),
            protocol::ReadError::Refused(protocol::READ_REFUSED.into()),
        );
        assert_eq!(
            block_on(s.procurement_resume(&mut api, false)).unwrap_err(),
            protocol::READ_REFUSED
        );
        assert_eq!(s.next, before + u64::from(route == "/api/v1/vm/11"));
    }
}

#[test]
fn poc_machine_payment_poll_reads_only_saved_payment_without_effects() {
    let (mut store, mut api) = nanosecond_invoice();
    let before = api.calls.len();
    let saved = store.procurement.as_ref().unwrap().clone();
    for _ in 0..3 {
        block_on(store.procurement_payment_check(&mut api)).unwrap();
    }
    assert_eq!(&api.calls[before..], &["GET /api/v1/payment/aabb"; 3]);
    assert_eq!(store.procurement.as_ref().unwrap().invoice, saved.invoice);
    assert_eq!(store.procurement.as_ref().unwrap().vm, saved.vm);
    assert!(store.procurement.as_ref().unwrap().target.is_none());
    api.payments[0]["is_paid"] = json!(true);
    block_on(store.procurement_payment_check(&mut api)).unwrap();
    let after = api.calls.len();
    block_on(store.procurement_payment_check(&mut api)).unwrap();
    assert_eq!(api.calls.len(), after);
    let mut replayed = reopen(&store);
    block_on(replayed.procurement_payment_check(&mut api)).unwrap();
    assert_eq!(api.calls.len(), after);
}
