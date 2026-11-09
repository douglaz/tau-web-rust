use super::*;

pub(crate) fn image() -> Value {
    json!({"id":3,"distribution":"archlinux","flavour":"base","version":"rolling","release_date":"2026-10-01T00:00:00Z","cpu_arch":"x86_64","default_username":"arch","encrypted":false,"popularity":0.1})
}
pub(crate) fn offer() -> Value {
    json!({"limits":{},"id":1,"name":"Small fixed","created":"2026-01-01T00:00:00Z","cpu":1,"memory":1073741824u64,"disk_size":10737418240u64,"disk_type":"ssd","disk_interface":"scsi","cpu_arch":"x86_64","cost_plan":{"id":1,"name":"Monthly","currency":"BTC","amount":1000000,"other_price":[],"interval_amount":1,"interval_type":"month"},"region":{"id":1,"name":"Dublin fixture","country_code":"IE","company_id":1}})
}
pub(crate) fn custom() -> Value {
    json!({"limits":{},"id":2,"name":"Custom fixture","region":{"id":2,"name":"London fixture","country_code":"GB","company_id":1},"cpu_arch":"x86_64","min_cpu":1,"max_cpu":8,"min_memory":1073741824u64,"max_memory":8589934592u64,"disks":[{"min_disk":10737418240u64,"max_disk":107374182400u64,"disk_type":"ssd","disk_interface":"scsi"}],"interval_amount":1,"interval_type":"month","transfer":{"min":100,"max":2000,"default":500},"network":{"min":100,"max":1000,"default":500}})
}
pub(crate) fn custom_resources() -> Value {
    json!({"pricing_id":2,"cpu":2,"memory":2147483648u64,"disk":21474836480u64,"disk_type":"ssd","disk_interface":"scsi","ip4_count":1,"ip6_count":0,"transfer_gb":500,"network_mbps":500})
}
pub(crate) fn selection(custom_order: bool) -> Selection {
    Selection {
        offer: if custom_order { custom() } else { offer() },
        image: image(),
        resources: custom_order.then(custom_resources),
        charge: Charge::parse(&offer()["cost_plan"]).unwrap(),
    }
}
pub(crate) fn publication() -> Value {
    let public = ed25519_dalek::SigningKey::from_bytes(&[29; 32]).verifying_key();
    let mut wire = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    wire.extend(public.as_bytes());
    json!({"key_type":"ssh-ed25519","public_key":STANDARD.encode(&wire),"fingerprint_sha256":format!("SHA256:{}",base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&wire)))})
}
pub(crate) fn vm(selected: &Selection, vm_id: u64) -> Value {
    let mut template = if selected.resources.is_some() {
        offer()
    } else {
        selected.offer.clone()
    };
    template["cost_plan"] = serde_json::to_value(&selected.charge).unwrap();
    if let Some(r) = &selected.resources {
        template["id"] = 91.into();
        for field in ["cpu_arch", "cpu_mfg", "cpu_features"] {
            if let Some(value) = selected.offer.get(field) {
                template[field] = value.clone();
            } else {
                template.as_object_mut().unwrap().remove(field);
            }
        }
        template["region"] = selected.offer["region"].clone();
        for field in ["cpu", "memory", "disk_type", "disk_interface"] {
            template[field] = r[field].clone();
        }
        template["disk_size"] = r["disk"].clone();
        if let Some(transfer) = r.get("transfer_gb") {
            template["transfer_gb"] = transfer.clone();
        }
        template["limits"] = selected
            .offer
            .get("limits")
            .cloned()
            .unwrap_or_else(|| json!({}));
        if let Some(network) = r.get("network_mbps") {
            template["limits"]["network_mbps"] = network.clone();
        }
    }
    json!({"id":vm_id,"subscription_id":21,"expires":null,"created":"2026-11-06T14:00:00Z","image":selected.image,"template":template,"ssh_key":{"id":7,"name":"tau-0","created":"2026-11-06T14:00:00Z"},"ip_assignments":[{"id":1,"ip":"192.0.2.10/24","gateway":"192.0.2.1"}],"status":{"state":"running","timestamp":1793973600u64},"auto_renewal_enabled":true,"host_ssh_keys":[publication()]})
}
pub(crate) fn payment(vm: u64) -> Value {
    json!({"id":"aabb","vm_id":vm,"created":"2026-11-06T14:00:00Z","expires":"2026-11-07T14:00:00Z","amount":1000000,"tax":230000,"processing_fee":10000,"currency":"BTC","is_paid":false,"data":{"lightning":"lnbc1fixtureinvoice"},"time":2592000,"is_upgrade":false})
}

pub(crate) fn billing_terms() -> BillingTerms {
    BillingTerms::parse(&payment(11)).unwrap()
}

#[test]
fn provisioning_signs_exact_request_and_unique_read_identity() {
    let input = hex::encode([7; 32]);
    let account = Account::parse(input.as_bytes()).unwrap();
    let url = format!("{ORIGIN}/api/v1/vm");
    let body = b"{\"template_id\":1}";
    let first = account
        .authorization(&url, "POST", Some(body), 42, &[1; 32])
        .unwrap();
    let event: Value = serde_json::from_slice(
        &STANDARD
            .decode(first.strip_prefix("Nostr ").unwrap())
            .unwrap(),
    )
    .unwrap();
    crate::relay_auth::verify_signature(&event).unwrap();
    assert_eq!(event["kind"], 27235);
    assert_eq!(event["pubkey"], account.public());
    assert_eq!(event["tags"][0], json!(["u", url]));
    assert_eq!(event["tags"][1], json!(["method", "POST"]));
    assert_eq!(
        event["tags"][3],
        json!(["payload", hex::encode(Sha256::digest(body))])
    );
    let second = account
        .authorization(&url, "POST", Some(body), 42, &[2; 32])
        .unwrap();
    assert_ne!(*first, *second);
    let mut tampered = event;
    tampered["tags"][0][1] = "https://other.invalid/api/v1/vm".into();
    assert!(crate::relay_auth::verify_signature(&tampered).is_err());
}
#[test]
fn provisioning_provider_credential_has_separate_encoded_protection() {
    for input in ["0".repeat(64), "z".repeat(64), "7".repeat(63)] {
        assert!(Account::parse(input.as_bytes()).is_err());
    }
    let input = hex::encode([7; 32]);
    let a = Account::parse(input.as_bytes()).unwrap();
    let filter = a.filter(input.as_bytes());
    for text in [
        input.clone(),
        hex::encode(input.as_bytes()),
        STANDARD.encode(input.as_bytes()),
        STANDARD.encode([7; 32]),
        input.to_uppercase(),
    ] {
        assert_ne!(
            filter.protect_bytes(text.as_bytes()).unwrap().as_slice(),
            text.as_bytes()
        );
    }
    assert_eq!(
        filter
            .protect_bytes(b"a useful public response")
            .unwrap()
            .as_slice(),
        b"a useful public response"
    );
}
#[test]
fn provisioning_selection_and_full_association_negative_controls() {
    for custom in [false, true] {
        let selected = selection(custom);
        selected.validate().unwrap();
        let matching = vm(&selected, 11);
        assert!(selected.matches(&matching, 7, timestamp("2026-11-06T14:00:00Z").unwrap()));
        for pointer in [
            "/ssh_key/id",
            "/image/id",
            "/template/cpu",
            "/template/memory",
            "/template/disk_size",
            "/template/region/id",
            "/template/cost_plan/amount",
        ] {
            let mut changed = matching.clone();
            *changed.pointer_mut(pointer).unwrap() = 999.into();
            assert!(
                !selected.matches(&changed, 7, timestamp("2026-11-06T14:00:00Z").unwrap()),
                "{pointer}"
            );
        }
        let mut encrypted = selected.clone();
        encrypted.image["encrypted"] = true.into();
        assert!(encrypted.validate().is_err());
        let mut hourly = selected.clone();
        hourly.charge.interval_type = "hour".into();
        if custom {
            hourly.offer["interval_type"] = json!("hour");
        } else {
            hourly.offer["cost_plan"]["interval_type"] = json!("hour");
        }
        assert!(hourly.validate().is_err());
    }
    let mut bad = selection(true);
    bad.resources.as_mut().unwrap()["cpu"] = 9.into();
    assert!(bad.validate().is_err());
}
#[test]
fn provisioning_publication_requires_valid_key_and_local_fingerprint() {
    let mut vm = vm(&selection(false), 11);
    let (_, pin) = published_pin(&vm).unwrap();
    assert!(pin.starts_with("SHA256:"));
    assert_eq!(allocated_ipv4(&vm).unwrap(), "192.0.2.10");
    vm["host_ssh_keys"][0]["fingerprint_sha256"] = "SHA256:other".into();
    assert!(published_pin(&vm).is_err());
    vm["host_ssh_keys"] = json!([]);
    assert!(published_pin(&vm).is_err());
    for ip in [
        "127.0.0.1/8",
        "0.0.0.0/0",
        "192.0.2.1/33",
        "192.0.2.1",
        "evil.invalid/24",
    ] {
        vm["ip_assignments"][0]["ip"] = ip.into();
        assert!(allocated_ipv4(&vm).is_err());
    }
}
#[test]
fn provisioning_payment_link_period_amount_and_dates_are_required() {
    let expected = billing_terms();
    let initial = payment(11);
    assert!(suitable_payment(&initial, 11, &expected, 0));
    for (field, value) in [
        ("vm_id", json!(12)),
        ("time", json!(86400)),
        ("amount", json!(1)),
        ("is_upgrade", json!(true)),
        ("expires", json!("unknown")),
        ("currency", json!("EUR")),
    ] {
        let mut changed = initial.clone();
        changed[field] = value;
        assert!(!suitable_payment(&changed, 11, &expected, 0));
    }
    for bad in [
        "2026-02-30T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-01-01T24:00:00Z",
        "2026-01-01T00:00:00+00:00",
    ] {
        assert!(timestamp(bad).is_err());
    }
}

#[test]
fn provisioning_catalogue_validates_visible_fields_and_discards_unknown_metadata() {
    let mut offers = json!({"templates":[offer()],"custom_template":[custom()]});
    offers["templates"][0]["debug"] = "unpublished metadata".into();
    let (published, images) = catalogue_public(offers.clone(), json!([image()])).unwrap();
    assert!(published["templates"][0].get("debug").is_none());
    assert_eq!(images[0], image());
    for (pointer, value) in [
        ("/templates/0/name", json!({})),
        ("/templates/0/cpu", json!("one")),
        ("/templates/0/region/name", json!("x".repeat(129))),
        ("/templates/0/cost_plan/amount", json!(-1)),
        ("/custom_template/0/min_cpu", json!(100)),
    ] {
        let mut malformed = offers.clone();
        *malformed.pointer_mut(pointer).unwrap() = value;
        assert!(
            catalogue_public(malformed, json!([image()])).is_err(),
            "{pointer}"
        );
    }
    let mut hourly = offer();
    hourly["cost_plan"]["interval_type"] = "hour".into();
    let (published, _) = catalogue_public(json!({"templates":[hourly]}), json!([image()])).unwrap();
    assert_eq!(
        published["templates"][0]["cost_plan"]["interval_type"],
        "hour"
    );
    let mut malformed = image();
    malformed["encrypted"] = "false".into();
    assert!(catalogue_public(offers, json!([malformed])).is_err());
}

#[test]
fn provisioning_image_statistics_are_not_identity_or_approval_terms() {
    for custom in [false, true] {
        let selected = selection(custom);
        let mut current = selected.clone();
        current.image["popularity"] = json!(0.1001);
        assert!(selected.same_terms(&current));
        let mut observed = vm(&selected, 11);
        observed["image"]["popularity"] = json!(0.1001);
        assert!(selected.matches(&observed, 7, timestamp("2026-11-06T14:00:00Z").unwrap()));
        for (field, value) in [
            ("id", json!(4)),
            ("distribution", json!("debian")),
            ("flavour", json!("desktop")),
            ("version", json!("other")),
            ("release_date", json!("2026-10-02T00:00:00Z")),
            ("cpu_arch", json!("arm64")),
            ("default_username", json!("root")),
            ("encrypted", json!(true)),
        ] {
            let mut changed = current.clone();
            changed.image[field] = value.clone();
            assert!(!selected.same_terms(&changed), "{field}");
            observed["image"] = current.image.clone();
            observed["image"][field] = value;
            assert!(
                !selected.matches(&observed, 7, timestamp("2026-11-06T14:00:00Z").unwrap()),
                "{field}"
            );
        }
    }
}

#[test]
fn provisioning_cpu_constraints_and_fixed_limits_require_complete_consistent_evidence() {
    let started = timestamp("2026-11-06T14:00:00Z").unwrap();
    for custom in [false, true] {
        let mut selected = selection(custom);
        selected.offer["cpu_mfg"] = json!("intel");
        selected.offer["cpu_features"] = json!(["AVX2", "AES"]);
        let mut matching = vm(&selected, 11);
        matching["template"]["cpu_arch"] = json!("X86_64");
        matching["template"]["cpu_mfg"] = json!("Intel");
        matching["template"]["cpu_features"] = json!(["aes", "fma", "avx2"]);
        assert!(selected.matches(&matching, 7, started));
        for (field, value) in [
            ("cpu_arch", json!(null)),
            ("cpu_arch", json!("arm64")),
            ("cpu_mfg", json!(null)),
            ("cpu_mfg", json!("amd")),
            ("cpu_features", json!(null)),
            ("cpu_features", json!(["AES"])),
        ] {
            let mut changed = matching.clone();
            changed["template"][field] = value;
            assert!(
                !selected.matches(&changed, 7, started),
                "CPU constraint must be evidenced"
            );
        }
        matching["cpu_arch"] = json!("arm64");
        assert!(
            !selected.matches(&matching, 7, started),
            "Host architecture cannot contradict the image"
        );
    }
    let mut selected = selection(false);
    selected.offer["limits"] = json!({"cpu_limit":0.5,"network_mbps":1000});
    selected.offer["transfer_gb"] = json!(500);
    let matching = vm(&selected, 11);
    assert!(selected.matches(&matching, 7, started));
    for pointer in [
        "/template/limits/cpu_limit",
        "/template/limits/network_mbps",
        "/template/transfer_gb",
    ] {
        let mut changed = matching.clone();
        *changed.pointer_mut(pointer).unwrap() = json!(1);
        assert!(
            !selected.matches(&changed, 7, started),
            "Advertised fixed limits must match"
        );
    }
    let mut missing = matching.clone();
    missing["template"]
        .as_object_mut()
        .unwrap()
        .remove("limits");
    assert!(!selected.matches(&missing, 7, started));
    let mut uncapped = selection(false);
    uncapped.offer["limits"] = json!({});
    assert!(!uncapped.matches(&matching, 7, started));
}

#[test]
fn provisioning_cpu_optional_and_feature_set_normalization_preserves_terms() {
    let mut first = offer();
    first["cpu_mfg"] = json!("Intel");
    first["cpu_features"] = json!(["AES", "AVX2", "AES"]);
    let mut second = first.clone();
    second["cpu_mfg"] = json!("intel");
    second["cpu_features"] = json!(["avx2", "aes"]);
    let (first, _) = catalogue_public(json!({"templates":[first]}), json!([image()])).unwrap();
    let (second, _) = catalogue_public(json!({"templates":[second]}), json!([image()])).unwrap();
    assert!(
        first == second,
        "Equivalent advertised CPU sets do not change terms"
    );
    let mut absent = offer();
    absent["cpu_mfg"] = json!(null);
    absent["cpu_features"] = json!(null);
    let (normalized, _) =
        catalogue_public(json!({"templates":[absent]}), json!([image()])).unwrap();
    assert!(normalized["templates"][0].get("cpu_mfg").is_none());
    assert!(normalized["templates"][0].get("cpu_features").is_none());
}

pub(crate) fn capped_selection() -> Selection {
    let mut selected = selection(true);
    selected.offer["limits"] = json!({"cpu_limit":0.5,"disk_iops_read":5000,
        "disk_iops_write":2500,"disk_mbps_read":500,"disk_mbps_write":250,
        "network_mbps":1000});
    selected
}

#[test]
fn provisioning_custom_inherited_caps_mismatched_refuse_association() {
    let selected = capped_selection();
    let mut observed = vm(&selected, 11);
    observed["template"]["limits"]["cpu_limit"] = json!(0.25);
    observed["template"]["limits"]["disk_iops_read"] = json!(2500);
    assert!(
        !selected.matches(&observed, 7, timestamp("2026-11-06T14:00:00Z").unwrap()),
        "custom inherited caps must match before association"
    );
}

#[test]
fn provisioning_custom_inherited_caps_missing_refuse_association() {
    let selected = capped_selection();
    let mut observed = vm(&selected, 11);
    observed["template"]["limits"] = json!({"network_mbps":500});
    assert!(
        !selected.matches(&observed, 7, timestamp("2026-11-06T14:00:00Z").unwrap()),
        "custom inherited caps must match before association"
    );
}

#[test]
fn provisioning_custom_limits_preserve_each_cap_uncapped_semantics_and_network_override() {
    let started = timestamp("2026-11-06T14:00:00Z").unwrap();
    let selected = capped_selection();
    selected.validate().unwrap();
    let matching = vm(&selected, 11);
    assert_eq!(selected.offer["limits"]["network_mbps"], 1000);
    assert_eq!(matching["template"]["limits"]["network_mbps"], 500);
    assert!(
        selected.matches(&matching, 7, started),
        "explicit selected network overrides only network"
    );
    for field in [
        "cpu_limit",
        "disk_iops_read",
        "disk_iops_write",
        "disk_mbps_read",
        "disk_mbps_write",
        "network_mbps",
    ] {
        let mut changed = matching.clone();
        changed["template"]["limits"][field] = json!(1);
        assert!(!selected.matches(&changed, 7, started), "changed {field}");
        changed["template"]["limits"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(!selected.matches(&changed, 7, started), "missing {field}");
    }
    for limits in [json!({}), json!(null)] {
        let mut changed = matching.clone();
        changed["template"]["limits"] = limits;
        assert!(!selected.matches(&changed, 7, started));
    }
    for advertised in [None, Some(json!({}))] {
        let mut uncapped = selection(true);
        if let Some(limits) = advertised {
            uncapped.offer["limits"] = limits;
        } else {
            uncapped.offer.as_object_mut().unwrap().remove("limits");
            assert!(uncapped.validate().is_err());
            assert!(!uncapped.matches(&vm(&uncapped, 11), 7, started));
            continue;
        }
        let mut observed = vm(&uncapped, 11);
        assert!(uncapped.matches(&observed, 7, started));
        observed["template"]["limits"]["cpu_limit"] = json!(0.5);
        assert!(
            !uncapped.matches(&observed, 7, started),
            "uncapped cannot acquire an unapproved cap"
        );
    }
    let mut inherited = capped_selection();
    inherited.offer.as_object_mut().unwrap().remove("network");
    inherited
        .resources
        .as_mut()
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("network_mbps");
    let observed = vm(&inherited, 11);
    assert_eq!(observed["template"]["limits"]["network_mbps"], 1000);
    assert!(inherited.matches(&observed, 7, started));
}

#[test]
fn provisioning_catalogue_and_selection_require_limits_objects() {
    let started = timestamp("2026-11-06T14:00:00Z").unwrap();
    for custom_order in [false, true] {
        let valid = selection(custom_order);
        let observed = vm(&valid, 11);
        assert!(valid.validate().is_ok());
        assert!(valid.matches(&observed, 7, started));
        for missing in [true, false] {
            let mut selected = valid.clone();
            if missing {
                selected.offer.as_object_mut().unwrap().remove("limits");
            } else {
                selected.offer["limits"] = json!(null);
            }
            let offers = if custom_order {
                json!({"templates":[],"custom_template":[selected.offer]})
            } else {
                json!({"templates":[selected.offer]})
            };
            assert!(
                catalogue_public(offers, json!([image()])).is_err(),
                "missing limits object must refuse catalogue"
            );
            assert!(
                selected.validate().is_err(),
                "missing limits object must refuse selection"
            );
            let mut capped = observed.clone();
            capped["template"]["limits"] = json!({"cpu_limit":0.5});
            assert!(
                !selected.matches(&capped, 7, started),
                "fixed omitted limits must not authorize added caps"
            );
        }
        let mut missing_vm = observed.clone();
        missing_vm["template"]
            .as_object_mut()
            .unwrap()
            .remove("limits");
        assert!(
            !valid.matches(&missing_vm, 7, started),
            "missing returned cap evidence refuses association"
        );
    }
}

#[test]
fn provisioning_transfer_terms_preserve_unmetered_absence_and_validate_allowances() {
    let started = timestamp("2026-11-06T14:00:00Z").unwrap();
    for custom_order in [false, true] {
        let mut selected = selection(custom_order);
        if custom_order {
            selected.offer.as_object_mut().unwrap().remove("transfer");
            selected
                .resources
                .as_mut()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove("transfer_gb");
        }
        selected.validate().unwrap();
        let matching = vm(&selected, 11);
        assert!(selected.matches(&matching, 7, started));
        for cap in [
            json!(0),
            json!(1),
            json!(null),
            json!("500"),
            json!(-1),
            json!(0.5),
        ] {
            let mut changed = matching.clone();
            changed["template"]["transfer_gb"] = cap.clone();
            assert!(
                !selected.matches(&changed, 7, started),
                "unmetered offer cannot acquire a transfer cap: {cap}"
            );
        }
        for invalid in [json!(null), json!("500"), json!(-1), json!(0.5)] {
            let mut malformed = selected.clone();
            malformed.offer["transfer_gb"] = invalid;
            assert!(malformed.validate().is_err());
            let offers = if custom_order {
                json!({"templates":[],"custom_template":[malformed.offer]})
            } else {
                json!({"templates":[malformed.offer]})
            };
            assert!(catalogue_public(offers, json!([image()])).is_err());
        }
        let mut metered = selection(custom_order);
        if !custom_order {
            metered.offer["transfer_gb"] = json!(500);
        }
        metered.validate().unwrap();
        let mut observed = vm(&metered, 11);
        assert!(metered.matches(&observed, 7, started));
        observed["template"]["transfer_gb"] = json!(1);
        assert!(!metered.matches(&observed, 7, started));
        observed["template"]
            .as_object_mut()
            .unwrap()
            .remove("transfer_gb");
        assert!(!metered.matches(&observed, 7, started));
    }
}

#[test]
fn provisioning_origin_strict_grammar_and_normalization() {
    for (input, expected) in [
        ("https://example.invalid", "https://example.invalid"),
        ("https://0xhost", "https://0xhost"),
        ("https://box.0xzz", "https://box.0xzz"),
        ("https://box.0xzz./", "https://box.0xzz."),
        ("https://example.invalid/", "https://example.invalid"),
        ("https://EXAMPLE.invalid:443/", "https://example.invalid"),
        (
            "https://example.invalid:8443",
            "https://example.invalid:8443",
        ),
        ("https://127.0.0.1:18443/", "https://127.0.0.1:18443"),
        ("https://[::1]:18443/", "https://[::1]:18443"),
        ("https://[2001:0DB8::1]:443", "https://[2001:db8::1]"),
        ("https://[::ffff:192.0.2.1]/", "https://[::ffff:c000:201]"),
    ] {
        assert_eq!(provider_origin(input).unwrap(), expected);
    }
    for input in [
        "",
        "http://example.invalid",
        "HTTPS://example.invalid",
        "https://",
        "https:///",
        "https://@example.invalid",
        "https://user:pass@example.invalid",
        "https://example.invalid?",
        "https://example.invalid#",
        "https://example.invalid/?q=1",
        "https://example.invalid/#x",
        "https://example.invalid/a",
        "https://example.invalid/.",
        "https://example.invalid/..",
        "https://example.invalid/a/../",
        "https://example.invalid/%2e/",
        "https://example.invalid//",
        "https://example.invalid\\",
        " https://example.invalid",
        "https://example.invalid ",
        "https://example.\ninvalid",
        "https://example.invalid\t/",
        "https://example.invalid\0",
        "https://[::1",
        "https://::1",
        "https://[127.0.0.1]",
        "https://[::gg]",
        "https://[::1]suffix",
        "https://example.invalid:",
        "https://example.invalid:-1",
        "https://example.invalid:65536",
        "https://example.invalid:443:1",
        "https://example.invalid:+443",
        "https://127.1",
        "https://0177.0.0.1",
        "https://0x7f000001",
        "https://2130706433",
        "https://256.0.0.1",
        "https://example..invalid",
        "https://-example.invalid",
    ] {
        let reason = provider_origin(input).expect_err("forbidden origin must refuse");
        assert!(!reason.contains(input) || input.is_empty());
        assert!(reason.contains("HTTPS provider origin"));
    }
}

#[test]
fn provisioning_decoded_missing_is_bounded_to_read_only_routes_and_error_objects() {
    let paths = [
        "/api/v1/vm/11",
        "/api/v1/vm/11/payments?limit=100&offset=0",
        "/api/v1/payment/aabb",
    ];
    for path in paths {
        for body in [
            br#"{"error":"Resource not found"}"#.as_slice(),
            br#"{"error":"VM not found"}"#,
            br#"{"error":""}"#,
        ] {
            assert!(decoded_missing("GET", path, 404, body));
            for status in [200, 401, 403, 500] {
                assert!(!decoded_missing("GET", path, status, body));
            }
        }
        for body in [
            b"".as_slice(),
            b"missing",
            b"<html>missing</html>",
            b"{",
            br#"{"error":null}"#,
            br#"{"error":404}"#,
            br#"{"error":{}}"#,
            br#"{"data":{"error":"missing"}}"#,
            br#"[{"error":"missing"}]"#,
        ] {
            assert!(!decoded_missing("GET", path, 404, body));
        }
    }
    for path in [
        "/api/v1/vm",
        "/api/v1/vm/templates",
        "/api/v1/ssh-key",
        "/api/v1/vm/11/renew?method=lightning&intervals=1",
        "/api/v1/vm/11/renew/quote?method=lightning&intervals=1",
    ] {
        assert!(!decoded_missing(
            "GET",
            path,
            404,
            br#"{"error":"missing"}"#
        ));
    }
    assert!(!decoded_missing(
        "POST",
        "/api/v1/vm/11",
        404,
        br#"{"error":"missing"}"#
    ));
}
