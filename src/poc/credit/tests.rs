use super::*;
use serde_json::json;
fn invoice() -> Invoice {
    Invoice::from_response(201, &json!({"invoice_id":"invoice-1","lightning_invoice":"lnbc1000synthetic","amount":1000,"currency":"SATS","expires_at":200}), 1000, 0.7).unwrap()
}
fn status(name: &str, paid: Value) -> Value {
    json!({"invoice_id":"invoice-1","status":name,"amount_paid":paid})
}
#[test]
fn poc_credit_expired_unpaid_requires_all_three_conditions() {
    let i = invoice();
    for baseline in [0.7, 0.6, 0.0] {
        assert_eq!(
            i.observe(Some(&status("Expired", json!(0))), Some(baseline), 201),
            Payment::ExpiredUnpaid
        );
    }
    for name in ["New", "Invalid", "Unknown", "expired", ""] {
        assert_eq!(
            i.observe(Some(&status(name, json!(0))), Some(0.7), 201),
            Payment::Unknown
        );
    }
    for paid in [
        json!(0.00001),
        json!(-0.1),
        Value::Null,
        json!("0"),
        json!([]),
    ] {
        assert_eq!(
            i.observe(Some(&status("Expired", paid)), Some(0.7), 201),
            Payment::Unknown
        );
    }
    let mut missing = status("Expired", json!(0));
    missing.as_object_mut().unwrap().remove("amount_paid");
    assert_eq!(i.observe(Some(&missing), Some(0.7), 201), Payment::Unknown);
    assert_eq!(
        i.observe(Some(&status("Expired", json!(0))), None, 201),
        Payment::Unknown
    );
    assert_eq!(
        i.observe(Some(&status("Expired", json!(0))), Some(0.8), 201),
        Payment::Paid
    );
    for bad in [f64::NAN, f64::INFINITY, -1.0, 1e13] {
        assert_eq!(
            i.observe(Some(&status("Expired", json!(0))), Some(bad), 201),
            Payment::Unknown
        );
    }
    let mut other = status("Expired", json!(0));
    other["invoice_id"] = json!("other");
    assert_eq!(i.observe(Some(&other), Some(0.7), 201), Payment::Unknown);
    assert_eq!(i.observe(None, Some(0.7), 201), Payment::Unknown);
}
#[test]
fn poc_credit_settled_before_and_after_expiry_retries_balance() {
    for now in [199, 200, 201, 10000] {
        assert_eq!(
            invoice().observe(Some(&status("Settled", json!(0.00001))), Some(0.78), now),
            Payment::Paid
        );
        assert_eq!(
            invoice().observe(Some(&status("Settled", json!(0.00001))), None, now),
            Payment::Seen
        );
    }
    assert_eq!(
        invoice().observe(Some(&status("New", json!(0))), None, 199),
        Payment::Unknown
    );
    assert_eq!(
        invoice().observe(Some(&status("New", json!(0))), Some(0.7), 199),
        Payment::Pending
    );
    assert_eq!(
        invoice().observe(Some(&status("New", json!(0))), None, 200),
        Payment::Unknown
    );
    assert!(invoice().may_poll(260));
    assert!(!invoice().may_poll(261));
    assert_eq!(POLL_SECONDS, 5);
}
#[test]
fn poc_credit_resolved_invoices_survive_failed_reads_and_spending() {
    for (name, paid, balance, outcome) in [
        ("Settled", 0.00001, 0.78, Payment::Paid),
        ("Expired", 0.00001, 0.78, Payment::Paid),
        ("Expired", 0.0, 0.7, Payment::ExpiredUnpaid),
    ] {
        let mut i = invoice();
        i.outcome = i.observe(Some(&status(name, json!(paid))), Some(balance), 201);
        assert_eq!(i.outcome, outcome);
        for fresh in [None, Some(0.7), Some(0.0)] {
            assert_eq!(i.observe(None, fresh, 202), outcome);
            assert_eq!(
                i.observe(Some(&status("Expired", json!(0.00001))), fresh, 202),
                outcome
            );
        }
        assert!(!i.may_poll(202));
    }
}
#[test]
fn poc_credit_invoice_validates_before_payable_projection() {
    let value = json!({"invoice_id":"invoice-1","lightning_invoice":"lnbc1000synthetic","amount":1000,"currency":"SATS","expires_at":200});
    for field in [
        "invoice_id",
        "lightning_invoice",
        "amount",
        "currency",
        "expires_at",
    ] {
        let mut bad = value.clone();
        bad.as_object_mut().unwrap().remove(field);
        assert!(Invoice::from_response(201, &bad, 1000, 0.0).is_err());
    }
    for bolt in [
        "LNBC1000",
        "lnbcUPPER",
        "https://checkout.example",
        "lnbc",
        "lnbc1000<&",
    ] {
        let mut bad = value.clone();
        bad["lightning_invoice"] = json!(bolt);
        assert!(Invoice::from_response(201, &bad, 1000, 0.0).is_err());
    }
    for code in [200, 202, 400, 503] {
        assert!(Invoice::from_response(code, &value, 1000, 0.0).is_err());
    }
    assert!(Invoice::from_response(201, &value, 1001, 0.0).is_err());
    assert!(Invoice::from_response(201, &value, 1000, f64::NAN).is_err());
    assert!(Invoice::from_response(201, &value, 1000, -1.0).is_err());
}
#[test]
fn poc_credit_balance_is_service_reported_and_floored() {
    for bad in [Value::Null, json!("0.78"), json!(-1), json!(1e13)] {
        assert_eq!(balance(&json!({"balance":bad})), None);
    }
    assert_eq!(balance(&json!({"balance":0.789})), Some(0.789));
    assert_eq!(
        display_balance(0.789),
        "Inference credit: 0.78 USD, as reported by the credit service"
    );
}
#[test]
fn poc_credit_mint_names_are_unique_and_bounded() {
    let names: std::collections::BTreeSet<_> = (0..1000).map(|_| mint_name().unwrap()).collect();
    assert_eq!(names.len(), 1000);
    assert!(names.iter().all(|s| s.len() == 25 && identifier(s)));
}
#[test]
fn poc_credit_returned_limits_are_exact_and_closed() {
    let expiry = super::super::provisioning::timestamp("2026-11-11T00:00:00Z").unwrap();
    let mint = Mint {
        session: "session-1".into(),
        name: mint_name().unwrap(),
        requested_cap: CAP,
        requested_expiry: expiry,
        issuer_id: None,
        returned_cap: None,
        returned_expiry: None,
    };
    let good = json!({"status":"success","data":{"_id":"key-1","name":mint.name,"api_key":"session-synthetic-value","usage_limit_usd":0.25,"expire_at":"2026-11-11T00:00:00Z","reset_period":null}});
    assert_eq!(
        returned_mint(&good, &mint).unwrap(),
        ("key-1".into(), "2026-11-11T00:00:00Z".into())
    );
    for (field, bad) in [
        ("usage_limit_usd", json!(0.26)),
        ("reset_period", json!("daily")),
        ("expire_at", json!("2026-11-11T00:01:01Z")),
        ("name", json!("other")),
    ] {
        let mut value = good.clone();
        value["data"][field] = bad;
        assert!(returned_mint(&value, &mint).is_err());
    }
    for field in [
        "usage_limit_usd",
        "reset_period",
        "expire_at",
        "_id",
        "name",
    ] {
        let mut value = good.clone();
        value["data"].as_object_mut().unwrap().remove(field);
        assert!(returned_mint(&value, &mint).is_err());
    }
    for text in [
        "2026-11-11T00:01:00Z",
        "2026-11-10T23:59:00Z",
        "2026-11-11T00:01:00.000Z",
    ] {
        let mut value = good.clone();
        value["data"]["expire_at"] = json!(text);
        assert!(returned_mint(&value, &mint).is_ok());
    }
}
#[test]
fn poc_credit_refusal_never_releases_service_text() {
    assert_eq!(
        inference_failure(401, br#"{"error":{"message":"API key expired"}}"#),
        InferenceFailure::Expired
    );
    assert_eq!(
        inference_failure(
            402,
            br#"{"error":{"message":"Insufficient credit account private-prefix; minimum $0.01"}}"#
        ),
        InferenceFailure::Exhaustion(Some(0.01))
    );
    for code in [401, 402, 403, 429, 500] {
        assert_eq!(
            inference_failure(code, br#"{"error":{"message":"private-prefix"}}"#),
            InferenceFailure::Refused
        );
    }
}

#[test]
fn poc_credit_expiry_fraction_and_recorded_refusal_shapes() {
    let requested = super::super::provisioning::timestamp("2026-11-11T00:00:00Z").unwrap();
    assert!(expiry_matches(requested, "2026-11-11T00:01:00.000000000Z"));
    assert!(!expiry_matches(requested, "2026-11-11T00:01:00.000000001Z"));
    assert!(!expiry_matches(requested, "2026-11-10T23:58:59.999Z"));
    assert!(!expiry_matches(requested, "2026-11-11T00:00:00.Z"));
    assert_eq!(
        inference_failure(
            401,
            br#"{"error":"API key expired","message":"private-prefix"}"#
        ),
        InferenceFailure::Expired
    );
    assert_eq!(inference_failure(402,br#"{"error":"Insufficient credit on credit id private-prefix: this request requires a minimum balance of $0.01 and your current balance is $0.00. Please top up."}"#),InferenceFailure::Exhaustion(Some(0.01)));
    for invalid in [
        br#"{"value":"private-prefix", "bad": ["#.as_slice(),
        br#"["private-prefix",{"bad":]"#.as_slice(),
    ] {
        assert!(decode(invalid).is_err());
    }
    let value = decode(br#"{"value":"first","value":"last"}"#).unwrap();
    assert_eq!(value.0["value"], "last");
}

#[test]
fn poc_credit_account_response_is_validated_as_one_pair() {
    let good = json!({"success":true,"credit_id":"synthetic-credit-identity-482700","api_key":"synthetic-default-credential-482700"});
    assert!(AccountRecord::from_response(201, &good).is_ok());
    for code in [200, 202, 403, 503] {
        assert!(AccountRecord::from_response(code, &good).is_err());
    }
    for field in ["success", "credit_id", "api_key"] {
        let mut value = good.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(AccountRecord::from_response(201, &value).is_err());
    }
    for (field, bad) in [
        ("success", json!(false)),
        ("credit_id", Value::Null),
        ("api_key", json!("")),
        ("api_key", good["credit_id"].clone()),
    ] {
        let mut value = good.clone();
        value[field] = bad;
        assert!(AccountRecord::from_response(201, &value).is_err());
    }
}
