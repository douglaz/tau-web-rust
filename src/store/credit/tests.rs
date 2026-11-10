use super::*;
use crate::store::inference::tests::Fixed;
const ID: &str = "synthetic-credit-identity-482700";
const KEY: &str = "synthetic-default-credential-482700";
fn account() -> AccountRecord {
    AccountRecord::from_response(
        201,
        &json!({"success":true,"credit_id":ID,"api_key":KEY,"balance":0}),
    )
    .unwrap()
}
fn ready() -> Store<MemoryStorage> {
    block_on(create(
        MemoryStorage::default(),
        &Fixed,
        LocalPassphrase::new(b"credit fixture passphrase".to_vec()),
    ))
    .unwrap()
}
fn reopen(store: &Store<MemoryStorage>) -> Store<MemoryStorage> {
    block_on(unlock(
        MemoryStorage::with_files(store.storage.files()),
        &Fixed,
        LocalPassphrase::new(b"credit fixture passphrase".to_vec()),
    ))
    .unwrap()
}
#[test]
fn poc_credit_account_filter_is_armed_only_after_commit_and_on_every_replay() {
    let mut store = ready();
    assert!(store.poc_credential_filters.borrow().is_empty());
    block_on(store.credit_install(&account())).unwrap();
    assert!(store.credit_account().is_some());
    assert!(store.inference.account.is_none());
    assert_eq!(store.next, 2);
    assert!(block_on(store.credit_install(&account())).is_err());
    for mut current in [store, reopen_after_install()] {
        for text in [ID, KEY] {
            assert!(!crate::poc::inference::safe(
                &current,
                &json!({"goal":text}),
                &[]
            ));
            assert!(
                block_on(current.commit(&Event::Command {
                    machine: "fixture".into(),
                    command: text.into()
                }))
                .is_err()
            );
            assert!(
                !current
                    .protect_output(&json!({"text":text}))
                    .unwrap()
                    .to_string()
                    .contains(text)
            );
            let encoded = hex::encode(text);
            assert!(!crate::poc::inference::safe(&current, &json!(encoded), &[]));
        }
        assert!(!current.credit_view().to_string().contains(ID));
        assert!(!current.credit_view().to_string().contains(KEY));
    }
}
fn reopen_after_install() -> Store<MemoryStorage> {
    let mut store = ready();
    block_on(store.credit_install(&account())).unwrap();
    reopen(&store)
}
#[test]
fn poc_credit_uncertain_account_append_holds_writes_until_replay() {
    for fault in [
        Fault::Fail(1),
        Fault::Fail(2),
        Fault::Fail(3),
        Fault::LandThenFail(3),
    ] {
        let mut store = ready();
        store.storage.fault(fault);
        assert!(block_on(store.credit_install(&account())).is_err());
        assert!(store.credit_ready().is_err());
        assert!(store.credit_account().is_none());
        assert!(store.poc_credential_filters.borrow().is_empty());
        assert!(
            block_on(store.commit(&Event::Command {
                machine: "fixture".into(),
                command: "true".into()
            }))
            .is_err()
        );
        if matches!(fault, Fault::LandThenFail(_)) {
            let mut reopened = reopen(&store);
            assert!(reopened.credit_account().is_some());
            assert!(block_on(reopened.credit_install(&account())).is_err());
        }
    }
}
#[test]
fn poc_credit_only_initial_pair_is_durable_and_session_key_never_journaled() {
    let mut store = ready();
    block_on(store.credit_install(&account())).unwrap();
    let session_key = "synthetic-session-credential-482700";
    store.remember_poc_credential(session_key.as_bytes());
    assert!(
        block_on(store.commit(&Event::Command {
            machine: "fixture".into(),
            command: session_key.into()
        }))
        .is_err()
    );
    block_on(store.commit(&Event::Command {
        machine: "fixture".into(),
        command: "true".into(),
    }))
    .unwrap();
    let mut scan = Store::new(
        store.storage.clone(),
        DataKey(store.key.0),
        store.id.clone(),
    );
    for number in 0..store.next {
        let bytes = block_on(scan.storage.read(&number.to_string())).unwrap();
        let event = scan.open(number, &bytes).unwrap();
        let plain = Zeroizing::new(serde_json::to_string(&event).unwrap());
        assert!(
            !plain.contains(session_key),
            "session key reached a decrypted record"
        );
        if !matches!(event, Event::PocCreditAccount(_)) {
            assert!(!plain.contains(ID) && !plain.contains(KEY));
        }
        scan.previous = Address(Sha256::digest(&bytes).into());
    }
}
#[test]
fn poc_credit_duplicate_account_replay_and_closed_shape_refuse() {
    let mut store = ready();
    block_on(store.credit_install(&account())).unwrap();
    assert!(store.replay_credit_account(&account()).is_err());
    let good = json!({"journal_version":2,"event":{"poc_credit_account":{"credit_id":ID,"default_key":KEY}}});
    assert!(journal::decode(&serde_json::to_vec(&good).unwrap()).is_ok());
    let mut bad = good;
    bad["event"]["poc_credit_account"]["extra"] = json!(true);
    assert!(journal::decode(&serde_json::to_vec(&bad).unwrap()).is_err());
}

#[test]
fn poc_credit_manual_abandon_retains_account_and_invoice_history() {
    let mut store = ready();
    block_on(store.credit_install(&account())).unwrap();
    let invoice = Invoice::from_response(201,&json!({"invoice_id":"invoice-1","lightning_invoice":"lnbc1000synthetic","amount":1000,"currency":"SATS","expires_at":200}),1000,0.7).unwrap();
    block_on(store.credit_commit(Record::Invoice(invoice.clone()))).unwrap();
    assert!(
        block_on(store.credit_commit(Record::Invoice(Invoice {
            id: "invoice-2".into(),
            ..invoice.clone()
        })))
        .is_err()
    );
    block_on(store.credit_commit(Record::Abandoned {
        id: "invoice-1".into(),
    }))
    .unwrap();
    assert_eq!(store.credit_invoice().unwrap().outcome, Payment::Abandoned);
    assert!(!store.credit_invoice().unwrap().may_poll(0));
    block_on(store.credit_commit(Record::Invoice(Invoice {
        id: "invoice-2".into(),
        ..invoice
    })))
    .unwrap();
    let replayed = reopen(&store);
    assert_eq!(replayed.credit.invoices.len(), 2);
    assert_eq!(replayed.credit.invoices[0].outcome, Payment::Abandoned);
    assert_eq!(
        replayed.credit.account.as_ref().unwrap().credit_id.0,
        ID.as_bytes()
    );
    assert!(replayed.credit.balance.is_none());
}

#[test]
fn poc_credit_resolved_history_replays_and_refuses_downgrades() {
    for (status, balance, outcome) in [
        ("Settled", 0.78, Payment::Paid),
        ("Expired", 0.78, Payment::Paid),
        ("Expired", 0.0, Payment::ExpiredUnpaid),
    ] {
        let mut store = ready();
        block_on(store.credit_install(&account())).unwrap();
        let invoice = Invoice::from_response(201,&json!({"invoice_id":"invoice-1","lightning_invoice":"lnbc1000synthetic","amount":1000,"currency":"SATS","expires_at":200}),1000,0.7).unwrap();
        block_on(store.credit_commit(Record::Invoice(invoice.clone()))).unwrap();
        let observed = invoice.observe(
            Some(&json!({"invoice_id":invoice.id,"status":status,"amount_paid":0})),
            Some(balance),
            201,
        );
        assert_eq!(observed, outcome);
        block_on(store.credit_commit(Record::Status {
            id: invoice.id.clone(),
            status: status.into(),
            outcome,
            balance: Some(balance),
        }))
        .unwrap();
        let history = store.credit_invoice().unwrap().clone();
        for fresh in [None, Some(0.0), Some(0.7)] {
            block_on(store.credit_commit(Record::Status {
                id: invoice.id.clone(),
                status: "unreadable".into(),
                outcome,
                balance: fresh,
            }))
            .unwrap();
            assert_eq!(store.credit_invoice(), Some(&history));
            assert_eq!(store.credit.balance, fresh);
        }
        let bad = Record::Status {
            id: invoice.id.clone(),
            status: "unreadable".into(),
            outcome: Payment::Unknown,
            balance: None,
        };
        assert!(block_on(store.credit_commit(bad.clone())).is_err());
        assert!(store.replay_credit(&bad).is_err());
        let mut replayed = reopen(&store);
        assert_eq!(replayed.credit_invoice(), Some(&history));
        assert_eq!(replayed.credit.balance, None);
        block_on(replayed.credit_commit(Record::Invoice(Invoice {
            id: "invoice-2".into(),
            ..invoice
        })))
        .unwrap();
        assert_eq!(replayed.credit.invoices[0], history);
    }
}
