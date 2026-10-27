use super::*;
pub(crate) fn clean() -> Measurements {
    Measurements {
        inbound: Measured::Value(vec![Inbound {
            proto: Protocol::Tcp,
            port: 22,
            from: From::Any,
        }]),
        outbound: Measured::Value(vec![]),
        services: Measured::Value(vec![]),
        spendable: Measured::Value(false),
        permitted: Measured::Value(vec![]),
        required: Measured::Value(vec![]),
        credentials: Measured::Value(vec![]),
        fixed_default_credentials: Measured::Value(true),
        sshd_posture: Measured::Value(true),
        placing_session: false,
    }
}
pub(crate) fn service(name: &str, lifecycle: Lifecycle) -> Service {
    Service {
        name: name.into(),
        scope: Scope::System,
        lifecycle,
    }
}
fn result(d: &Declaration, m: &Measurements) -> ResultSet {
    evaluate(d, MachineClass::SinglePurpose, m, &[], false)
}

#[test]
fn delivery_empty_constraints_and_obligations_have_opposite_meanings() {
    let d = ad_hoc_minimum();
    let mut m = clean();
    assert!(result(&d, &m).delivered);
    m.inbound = Measured::Value(vec![
        Inbound {
            proto: Protocol::Tcp,
            port: 22,
            from: From::Any,
        },
        Inbound {
            proto: Protocol::Tcp,
            port: 80,
            from: From::Any,
        },
    ]);
    let r = result(&d, &m);
    assert!(!r.delivered, "undeclared socket must prevent delivery");
    assert_eq!(r.findings.len(), 1);
    m = clean();
    m.outbound = Measured::Value(vec![Outbound {
        proto: Protocol::Tcp,
        port: 443,
        host: "extra.example".into(),
    }]);
    assert!(
        result(&d, &m).delivered,
        "no outbound restriction was declared"
    );
    m.permitted = Measured::Value(vec![Material {
        kind: MaterialKind::Public,
        r#where: "/unlisted.pub".into(),
    }]);
    assert!(
        !result(&d, &m).delivered,
        "empty permitted list permits no tenant material"
    );
}
#[test]
fn delivery_concrete_values_require_their_own_identities() {
    let mut d = ad_hoc_minimum();
    let mut m = clean();
    let a = Outbound {
        proto: Protocol::Tcp,
        port: 443,
        host: "api.example".into(),
    };
    d.listeners.outbound = Field::Value(vec![a.clone()]);
    assert!(
        !result(&d, &m).delivered,
        "declared outbound restriction must be in place"
    );
    m.outbound = Measured::Value(vec![a]);
    d.default_credentials = Field::Value(Credentials::Changed(vec!["admin".into()]));
    assert!(
        !result(&d, &m).delivered,
        "named default credential must have been changed"
    );
    m.credentials = Measured::Value(vec!["admin".into()]);
    assert!(result(&d, &m).delivered);
    let key = Material {
        kind: MaterialKind::Public,
        r#where: "/expected.pub".into(),
    };
    d.key_material.permitted = Field::Value(vec![key.clone()]);
    assert!(
        result(&d, &m).delivered,
        "permitted material need not exist"
    );
    m.permitted = Measured::Value(vec![Material {
        r#where: "/elsewhere.pub".into(),
        ..key
    }]);
    assert!(
        !result(&d, &m).delivered,
        "same kind at another location is not permission"
    );
}

#[test]
fn delivery_empty_obligations_require_no_observation_but_empty_constraints_do() {
    let d = ad_hoc_minimum();
    let mut m = clean();
    m.outbound = Measured::Missing;
    m.services = Measured::Missing;
    m.required = Measured::Missing;
    m.credentials = Measured::Missing;
    assert!(
        result(&d, &m).delivered,
        "empty obligations declare nothing to check"
    );
    m.permitted = Measured::Missing;
    assert!(
        !result(&d, &m).delivered,
        "empty tenant-material constraint still needs a measurement"
    );
    m.permitted = Measured::Value(vec![]);
    m.inbound = Measured::Missing;
    assert!(
        !result(&d, &m).delivered,
        "empty answering surface must be observed"
    );
}
#[test]
fn delivery_missing_failed_invalid_unspecified_and_partial_never_deliver() {
    let d = ad_hoc_minimum();
    let mut m = clean();
    m.inbound = Measured::Missing;
    assert!(
        !result(&d, &m).delivered,
        "missing measurement is not an observed empty set"
    );
    m.inbound = Measured::Failed;
    assert!(!result(&d, &m).delivered, "failed read cannot pass");
    m.inbound = Measured::Value(vec![]);
    assert!(
        result(&d, &m).delivered,
        "observed empty answering surface is allowed"
    );
    m = clean();
    m.sshd_posture = Measured::Missing;
    assert!(
        !result(&d, &m).delivered,
        "incomplete fixed check prevents delivery"
    );
    m.sshd_posture = Measured::Value(false);
    assert!(
        !result(&d, &m).placement_eligible,
        "fixed lockdown finding refuses placement"
    );
    let mut view = Intended::from(&d);
    view.inbound = Stated::Unspecified;
    assert!(
        !aggregate(
            fields(&view, MachineClass::SinglePurpose, &clean(), &[]),
            &[],
            false
        )
        .delivered
    );
    view.inbound = Stated::Missing;
    assert_eq!(
        fields(&view, MachineClass::SinglePurpose, &clean(), &[])[1].status,
        Status::SchemaError
    );
    view.inbound = Stated::Invalid;
    assert_eq!(
        fields(&view, MachineClass::SinglePurpose, &clean(), &[])[1].status,
        Status::SchemaError
    );
    let rows = fields(
        &Intended::from(&d),
        MachineClass::SinglePurpose,
        &clean(),
        &[],
    );
    for index in 0..9 {
        let mut partial = rows.clone();
        partial.remove(index);
        assert!(
            !aggregate(partial, &[], false).delivered,
            "missing field {index}"
        );
    }
    assert!(!aggregate(vec![], &[], false).delivered);
}
#[test]
fn delivery_inert_check_identity_and_drift_presence_use_shared_core() {
    let mut view = Intended::from(&ad_hoc_minimum());
    let m = clean();
    view.drift = Stated::Specified(vec![CheckIdentity("maintained-fixture".into())]);
    assert!(
        aggregate(
            fields(&view, MachineClass::SinglePurpose, &m, &[]),
            &[],
            false
        )
        .delivered,
        "drift presence only at delivery"
    );
    view.required = Stated::Specified(vec![CheckIdentity("required-fixture".into())]);
    assert!(
        !aggregate(
            fields(&view, MachineClass::SinglePurpose, &m, &[]),
            &[],
            false
        )
        .delivered,
        "required identity needs evidence"
    );
    let mut m = m;
    m.required = Measured::Value(vec!["required-fixture".into()]);
    assert!(
        aggregate(
            fields(&view, MachineClass::SinglePurpose, &m, &[]),
            &[],
            false
        )
        .delivered
    );
}
#[test]
fn delivery_lifecycle_labels_sticky_findings_and_placing_qualification() {
    let mut d = ad_hoc_minimum();
    let enabled = service("daemon", Lifecycle::EnabledSurvivesReboot);
    let running = service("volatile", Lifecycle::RunningAtDelivery);
    d.services = Field::Value(vec![enabled.clone(), running.clone()]);
    let mut m = clean();
    m.services = Measured::Value(vec![
        ServiceFact {
            service: enabled.clone(),
            state: ServiceState::EnabledRestartNotDemonstrated,
            running_after_last_placement: false,
        },
        ServiceFact {
            service: running.clone(),
            state: ServiceState::StoppedSinceRestart,
            running_after_last_placement: false,
        },
    ]);
    let r = result(&d, &m);
    assert!(r.delivered, "both evidence labels are passing states");
    assert_eq!(
        r.notes.iter().map(|n| n.text.as_str()).collect::<Vec<_>>(),
        [
            "enabled, restart not demonstrated",
            "stopped since a restart, as approved"
        ]
    );
    assert!(r.findings.is_empty());
    m.placing_session = true;
    let r = result(&d, &m);
    assert!(
        !r.delivered,
        "restart note cannot demonstrate running after placement"
    );
    assert!(
        r.placement_eligible,
        "lifecycle-only finding must not refuse placement"
    );
    assert_eq!(r.findings.len(), 1);
    assert_eq!(r.findings[0].class(), FindingClass::Lifecycle);
    m.placing_session = false;
    let sticky = evaluate(&d, MachineClass::SinglePurpose, &m, &r.findings, false);
    assert!(
        !sticky.delivered,
        "restart cannot clear a standing crash finding"
    );
    if let Measured::Value(f) = &mut m.services {
        f[1].state = ServiceState::Running;
    }
    m.placing_session = true;
    assert!(
        !result(&d, &m).delivered,
        "running without post-last-placement evidence is insufficient"
    );
    if let Measured::Value(f) = &mut m.services {
        f[1].running_after_last_placement = true;
    }
    assert!(
        evaluate(&d, MachineClass::SinglePurpose, &m, &r.findings, false).delivered,
        "post-placement running clears through re-check"
    );
    m.sshd_posture = Measured::Value(false);
    assert!(
        !result(&d, &m).delivered,
        "labels never hide another finding"
    );
}

#[test]
fn delivery_enabled_service_needs_its_lifecycle_evidence() {
    let mut d = ad_hoc_minimum();
    let service = service("enabled", Lifecycle::EnabledSurvivesReboot);
    d.services = Field::Value(vec![service.clone()]);
    let mut m = clean();
    m.services = Measured::Value(vec![ServiceFact {
        service,
        state: ServiceState::Running,
        running_after_last_placement: true,
    }]);
    assert!(
        !result(&d, &m).delivered,
        "running alone supplies neither enablement nor restart evidence"
    );
    if let Measured::Value(facts) = &mut m.services {
        facts[0].state = ServiceState::RestartDemonstrated;
    }
    let r = result(&d, &m);
    assert!(r.delivered);
    assert!(
        r.notes.is_empty(),
        "demonstrated restart needs no evidence qualification"
    );
}

#[test]
fn delivery_consumes_each_upstream_lifecycle_difference_without_hiding_others() {
    let mut d = ad_hoc_minimum();
    let services: Vec<_> = ["same_boot_stop", "never_running", "new_promise"]
        .into_iter()
        .map(|name| service(name, Lifecycle::RunningAtDelivery))
        .collect();
    d.services = Field::Value(services.clone());
    let mut m = clean();
    m.services = Measured::Value(
        services
            .into_iter()
            .map(|service| ServiceFact {
                service,
                state: ServiceState::Difference,
                running_after_last_placement: false,
            })
            .collect(),
    );
    let r = result(&d, &m);
    assert!(!r.delivered);
    assert_eq!(
        r.findings.len(),
        3,
        "each upstream lifecycle difference remains visible"
    );
    assert!(
        r.findings
            .iter()
            .all(|f| f.class() == FindingClass::Lifecycle)
    );
}
#[test]
fn delivery_unknown_and_incomplete_checks_preserve_findings() {
    let mut d = ad_hoc_minimum();
    let s = service("stopped", Lifecycle::RunningAtDelivery);
    d.services = Field::Value(vec![s.clone()]);
    let mut m = clean();
    m.services = Measured::Value(vec![ServiceFact {
        service: s,
        state: ServiceState::Difference,
        running_after_last_placement: false,
    }]);
    let r = result(&d, &m);
    assert!(!r.delivered);
    assert_eq!(r.findings.len(), 1);
    let unknown = aggregate(vec![], &r.findings, true);
    assert!(unknown.findings_unknown);
    assert!(!unknown.placement_eligible);
    d.services = Field::Value(vec![]);
    m.services = Measured::Value(vec![]);
    m.sshd_posture = Measured::Failed;
    let incomplete = evaluate(&d, MachineClass::SinglePurpose, &m, &r.findings, true);
    assert_eq!(
        incomplete.findings, r.findings,
        "incomplete re-check never erases earlier findings"
    );
    assert!(incomplete.findings_unknown);
    m.sshd_posture = Measured::Value(true);
    assert!(
        evaluate(&d, MachineClass::SinglePurpose, &m, &r.findings, true).delivered,
        "complete re-check establishes known findings"
    );
}
