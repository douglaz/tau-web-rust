//! Closed original constructor inputs. Authenticated prefixes and private fixture operands stay private.
use crate::{auxiliary, history};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};
const WORDS: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
static ORDINALS: Mutex<BTreeMap<(String, String), usize>> = Mutex::new(BTreeMap::new());
fn ordinal(site: &str) -> Option<usize> {
    let scope = history::active_scenario()?;
    let mut counts = ORDINALS.lock().unwrap();
    let n = counts.entry((scope, site.into())).or_default();
    *n += 1;
    Some(*n)
}
fn seed_id(words: &str) -> Option<String> {
    let seed = bip39::Mnemonic::parse_normalized(words)
        .ok()?
        .to_seed_normalized("");
    let mut bytes = b"tau-web seed id v1\0".to_vec();
    bytes.extend_from_slice(&seed);
    Some(hex::encode(ring::digest::digest(
        &ring::digest::SHA256,
        &bytes,
    )))
}
pub(crate) fn synthetic_approval() -> Value {
    json!({"approved":true,"configuration":{"endpoint":"https://fixture.invalid/completions","model":"fixture"}})
}
fn base(words: &str, machines: &[&str], classes: bool) -> Option<Vec<Value>> {
    let seed = seed_id(words)?;
    let entries:Vec<_>=machines.iter().enumerate().map(|(index,machine)|json!({"entry":{"machine":machine,"vendor":"Fixture vendor","product":"Fixture machine","region":"Fixture region","cost":{"amount":1000,"unit":"sat","period":"month"}},"identity":{"seed":seed,"derivation_version":1,"family":"machines","index":index},"access":{"model":"maintained","profile":"ad-hoc","revision":3}})).collect();
    let mut events = vec![
        json!({"seed":{"mnemonic":words}}),
        json!({"allocation":{"seed_backup":{"seed":seed,"completion":"skipped"}}}),
        json!({"setup":{"approval":{"entries":entries,"monthly_sat":1000*machines.len(),"annual_sat":12000*machines.len()}}}),
    ];
    if classes {
        for machine in machines {
            events.push(json!({"setup":{"class":{"machine":machine,"answer":"no","class":"single_purpose"}}}));
        }
    }
    Some(events)
}
fn original(site: &str, pass: &str) -> Option<Vec<Value>> {
    auxiliary::original_events(site, pass)
}
fn original_base(site: &str, pass: &str, machines: &[&str], classes: bool) -> Option<Vec<Value>> {
    let events = original(site, pass)?;
    base(
        events.first()?.pointer("/seed/mnemonic")?.as_str()?,
        machines,
        classes,
    )
}
fn expose(events: &mut Vec<Value>) {
    let identity = events[2]["setup"]["approval"]["entries"][0]["identity"].clone();
    events.push(json!({"exposure":{"inference_approval":synthetic_approval(),"session":format!("session-{}",events.len()),"bound_set":[{"machine":"fixture","identity":identity}],"accepted_modes":["no_artifact_pin"]}}));
}
fn pin() -> Option<&'static str> {
    crate::PINS
        .iter()
        .find(|(m, _)| *m == "fixture")
        .map(|(_, p)| *p)
}
fn intent(call: usize, operation: &str) -> Value {
    let facts =
        json!({"arguments":{"size":"small"},"cost_bound":12,"bundle_commit":tau_web::SPEC_COMMIT});
    let approved = json!({"resource":{"entry":"fixture"},"target":{"entry":"fixture"},"operation":operation,"session":"fixture-session","requester":"session","facts":facts});
    json!({"operation_intent":{"call":call,"resource":{"entry":"fixture"},"target":{"entry":"fixture"},"operation":operation,"session":"fixture-session","requester":"session","facts":facts,"approved":approved}})
}
pub(super) fn minimum() -> Value {
    json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"})
}
fn service(name: &str, lifecycle: &str) -> Value {
    json!({"name":name,"scope":{"kind":"system"},"lifecycle":lifecycle})
}
fn delivery() -> Option<Vec<Value>> {
    let caller = auxiliary::latest_setup_caller()?;
    let mut d = minimum();
    let declared = match caller.as_str() {
        "reader.aux.call.delivery.prepare.initial" => {
            let (site, n) = crate::observer::current_source()?;
            match (site.as_str(), n) {
                ("delivery.no_declaration.prepare", 1) => false,
                ("delivery.untrusted.prepare" | "delivery.card.prepare", 1) => true,
                ("delivery.notes.prepare", 1..=3) => {
                    let daemon = service("daemon", "enabled-survives-reboot");
                    let volatile = service("volatile", "running-at-delivery");
                    d["services"] = json!(match n {
                        1 => vec![daemon],
                        2 => vec![volatile],
                        _ => vec![daemon, volatile],
                    });
                    true
                }
                ("delivery.finding.prepare", 1) => {
                    d["services"] = json!([service("volatile", "running-at-delivery")]);
                    true
                }
                ("delivery.lifecycle.prepare", 1..=4) => true,
                ("delivery.incomplete.prepare", 1..=4) => {
                    d["services"] = json!([
                        service("volatile", "running-at-delivery"),
                        service("daemon", "enabled-survives-reboot")
                    ]);
                    true
                }
                _ => return None,
            }
        }
        "reader.aux.call.delivery.amendment.initial" => {
            d["services"] = json!([service("amended", "running-at-delivery")]);
            true
        }
        "reader.aux.call.delivery.report_success.initial" => {
            d["services"] = json!([service("daemon", "running-at-delivery")]);
            true
        }
        "reader.aux.call.delivery.report_failure.initial" => true,
        _ => return None,
    };
    let mut events = base(WORDS, &["fixture"], true)?;
    if declared {
        events.push(json!({"setup":{"requirements":{"session":"fixture-contract","candidate":0,"access":{"model":"maintained","profile":"ad-hoc","revision":tau_web::dispatch::ad_hoc_revision()},"proposal":{"kind":"declaration","machine":"fixture","declaration":d}}}}));
    }
    Some(events)
}
fn goal(n: usize, pass: &str) -> Option<Vec<Value>> {
    let mut events = base(WORDS, &["fixture", "fixture-other"], true)?;
    if history::active_scenario().as_deref() == Some("goal_admission_cases.run") {
        return match n {
            1..=4 => Some(events),
            5..=7 => {
                let original = original("reader.call.goal_admission.holding_source", pass)?;
                let intents: Vec<_> = original
                    .iter()
                    .filter_map(|e| e.get("intent"))
                    .filter(|i| {
                        i["machine"] == "fixture"
                            && i["command"] == hex::encode("printf origin-held-job")
                    })
                    .collect();
                if intents.len() != 1 {
                    return None;
                }
                let call = &intents[0]["call"];
                let end = original
                    .iter()
                    .position(|e| e.get("job_terminal").is_some_and(|t| t["call"] == *call))?;
                Some(original[..end].to_vec())
            }
            _ => None,
        };
    }
    match history::active_case_id().as_deref() {
        Some("goal_cases.c005.p001" | "goal_cases.c007.p001") => {
            let call = events.len();
            events.push(json!({"intent":{"call":call,"machine":"fixture","command":hex::encode("holding bytes"),"approval":{"harness_pin":{"machine":"fixture","fingerprint":pin()?}},"job":"0".repeat(48)}}));
            if history::active_case_id().as_deref() == Some("goal_cases.c007.p001") {
                events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"destructive_reinstall","uncertainty":"effect unknown"}}));
            }
        }
        Some("goal_cases.c006.p001") => events.push(intent(events.len(), "create")),
        None
        | Some(
            "goal_cases.c003.p001"
            | "goal_cases.c003.p002"
            | "goal_cases.c004.p001"
            | "goal_cases.c008.p001"
            | "goal_cases.c009.p001"
            | "goal_cases.c010.p001"
            | "goal_cases.c011.p001"
            | "goal_cases.c012.p001",
        ) => {}
        _ => return None,
    }
    Some(events)
}
fn recipe(site: &str, pass: &str, n: usize) -> Option<Vec<Value>> {
    let two = &["fixture", "fixture-other"][..];
    let three = &["fixture", "fixture-other", "unpinned"][..];
    match site {
        "file.main.build.001" => base(WORDS, two, true),
        "file.main.build.003" => original_base("reader.call.main.pre_no_pin", pass, three, false),
        "file.main.build.006" => original_base("reader.call.main.pre_no_pass", pass, two, false),
        "file.binding_cases.build.001" => {
            let original = original("reader.call.binding.saved", pass)?;
            let words = original.first()?.pointer("/seed/mnemonic")?.as_str()?;
            Some(vec![
                json!({"seed":{"mnemonic":words}}),
                json!({"allocation":{"seed_backup":{"seed":seed_id(words)?,"completion":"skipped"}}}),
            ])
        }
        "file.mode_cases.build.001" => {
            let mut events = original_base("reader.call.mode.original", pass, two, true)?;
            expose(&mut events);
            Some(events)
        }
        "file.session_end_cases.build.001" | "file.session_end_cases.build.002" => {
            let mut events = original_base("reader.call.session_end.original", pass, three, true)?;
            if site.ends_with("002") {
                expose(&mut events);
            }
            Some(events)
        }
        "file.lifecycle_cases.build.001" => {
            let mut events = original_base("reader.call.lifecycle.original", pass, three, true)?;
            events.push(
                json!({"inference_account":{"credential":crate::aggregator::original_account()?}}),
            );
            Some(events)
        }
        "file.inference_cases.build.001" => original_base(
            "reader.call.inference.sent_read_original",
            pass,
            three,
            false,
        ),
        "hold.initial" => original_base("reader.call.hold.original", pass, three, false),
        "file.declaration_cases.build.001" => base(WORDS, &["fixture"], true),
        "file.delivery_cases.build.001" => delivery(),
        "file.goal_cases.build.001" => goal(n, pass),
        "file.main.build.004" | "file.main.build.005" => {
            let mut events = original("reader.call.main.pre_disposition", pass)?;
            let call = events.len();
            events.push(json!({"intent":{"call":call,"machine":"fixture","command":hex::encode(crate::COMMAND),"approval":{"harness_pin":{"machine":"fixture","fingerprint":pin()?}}}}));
            events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"destructive_reinstall","uncertainty":"the command outcome is unknown"}}));
            if site.ends_with("005") {
                events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"as_if_not_done","uncertainty":"the command outcome is unknown"}}));
            }
            Some(events)
        }
        "file.typed_cases.build.001" => {
            let original = original("reader.call.typed.original", pass)?;
            let mut events = original.get(..3)?.to_vec();
            match n {
                7 => {}
                1..=6 => {
                    events.push(intent(3, "reset"));
                    match n{
                    2=>events.push(json!({"operation_observation":{"resource":{"entry":"fixture"},"operation":"reset","reports":"confirmed","calls":[3]}})),
                    3..=6=>events.push(json!({"disposition":{"machine":"fixture","calls":[3],"continuation":(["destructive_reinstall","abandonment","as_if_done","as_if_not_done"][n-3]),"uncertainty":"effect not established"}})),
                    _=>{},
                }
                }
                _ => return None,
            }
            Some(events)
        }
        "file.job_cases.build.001" => {
            let mut events = original("reader.call.job.disposition_source", pass)?;
            let continuation = *[
                "destructive_reinstall",
                "abandonment",
                "as_if_done",
                "as_if_not_done",
            ]
            .get(n.checked_sub(1)?)?;
            let call = crate::causal::original_call("job.disposition", n - 1)?;
            events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":continuation,"uncertainty":"the command outcome is unknown"}}));
            Some(events)
        }
        "file.job_cases.build.002" => {
            let mut events = original("reader.call.job.older_source", pass)?;
            let sites: &[&str] = match history::active_case_id().as_deref() {
                Some("job_cases.c004.p001") => &["settle.job_cases.002", "settle.job_cases.003"],
                Some("job_cases.c009.p001") => &["settle.job_cases.006"],
                Some("hold_cases.c003.p001") => &["settle.hold_cases.001"],
                _ => return None,
            };
            for site in sites {
                let slot = crate::settle_inputs::original_slot(site)?;
                events.get(slot)?.get("disposition")?;
                events[slot] = json!({"intent":{"call":slot,"machine":"fixture","command":hex::encode("true"),"approval":null}});
            }
            Some(events)
        }
        "file.hold_cases.build.001" => {
            let mut events = original("reader.call.hold.stop_augmented", pass)?;
            events.push(json!({"command":{"machine":"fixture","command":hex::encode("unreadable legacy command")}}));
            Some(events)
        }
        "file.hold_cases.build.002" => {
            let mut events = original("reader.call.hold.legacy_source", pass)?;
            events.push(json!({"command":{"machine":"fixture","command":hex::encode("true")}}));
            events.push(json!({"intent":{"call":events.len(),"machine":"fixture","command":hex::encode("true"),"approval":{"harness_pin":{"machine":"fixture","fingerprint":"SHA256:fixture"}}}}));
            Some(events)
        }
        "file.hold_cases.build.003" => {
            if n > 7 {
                return None;
            }
            let mut events = original("reader.call.hold.unreachable_source", pass)?;
            let machine = if n == 1 { "unpinned" } else { "fixture" };
            events.push(json!({"intent":{"call":events.len(),"machine":machine,"command":hex::encode("true"),"approval":{"harness_pin":{"machine":machine,"fingerprint":"SHA256:fixture"}},"job":"ab".repeat(24)}}));
            Some(events)
        }
        "file.hold_cases.build.004" => {
            let mut events = original("reader.call.hold.destructive_source", pass)?;
            let call = crate::causal::original_call("hold.destructive.disposed", 0)?;
            events.push(json!({"disposition":{"machine":"fixture","calls":[call],"continuation":"abandonment","uncertainty":"the command outcome is unknown"}}));
            Some(events)
        }
        _ => None,
    }
}
pub fn matches(site: &str, pass: &str, events: &[Value]) -> bool {
    if site == "file.main.build.008" {
        return pass == crate::PASSPHRASE && crate::settle_inputs::construction_valid();
    }
    let pass_ok = if matches!(
        site,
        "file.binding_cases.build.001" | "file.mode_cases.build.001"
    ) {
        matches!(pass, crate::PASSPHRASE | crate::SERVED_PASSPHRASE)
    } else {
        pass == crate::PASSPHRASE
    };
    pass_ok
        && ordinal(site)
            .and_then(|n| recipe(site, pass, n))
            .is_some_and(|expected| expected == events)
}

/// Check the actual encrypted constructor output against its original arguments.
pub fn output_matches(files: &crate::Files, pass: &str, events: &[Value]) -> bool {
    fn check(files: &crate::Files, pass: &str, events: &[Value]) -> Option<()> {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let envelope: Value = serde_json::from_slice(files.get("envelope.json")?).ok()?;
        if envelope.as_object()?.len() != 8
            || envelope["version"] != 1
            || envelope["purpose"] != "local"
            || envelope["kdf"] != "PBKDF2-SHA256"
            || envelope["iterations"] != 600_000
            || files.len() != events.len() + 1
        {
            return None;
        }
        let id = envelope["id"].as_str()?;
        if URL_SAFE_NO_PAD.decode(id).ok()?.len() != 16 {
            return None;
        }
        let salt = URL_SAFE_NO_PAD.decode(envelope["salt"].as_str()?).ok()?;
        if salt.len() != 16 {
            return None;
        }
        let mut wrapping = [0; 32];
        ring::pbkdf2::derive(
            ring::pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(600_000)?,
            &salt,
            pass.as_bytes(),
            &mut wrapping,
        );
        let open = |key: &[u8], nonce: &str, aad: &str, bytes: &str| -> Option<Vec<u8>> {
            let key = ring::aead::LessSafeKey::new(
                ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, key).ok()?,
            );
            let nonce = URL_SAFE_NO_PAD.decode(nonce).ok()?;
            let nonce = ring::aead::Nonce::try_assume_unique_for_key(&nonce).ok()?;
            let mut bytes = URL_SAFE_NO_PAD.decode(bytes).ok()?;
            Some(
                key.open_in_place(nonce, ring::aead::Aad::from(aad.as_bytes()), &mut bytes)
                    .ok()?
                    .to_vec(),
            )
        };
        let data_key = open(
            &wrapping,
            envelope["nonce"].as_str()?,
            &format!("tau-web/local/v1/{id}"),
            envelope["wrapped_key"].as_str()?,
        )?;
        if data_key.len() != 32 {
            return None;
        }
        let mut previous = "0".repeat(64);
        for (number, event) in events.iter().enumerate() {
            let bytes = files.get(&number.to_string())?;
            let record: Value = serde_json::from_slice(bytes).ok()?;
            if record.as_object()?.len() != 6
                || record["id"] != id
                || record["type"] != "event"
                || record["number"] != number
                || record["previous"] != previous
                || crate::reader::record_bytes(&record) != *bytes
            {
                return None;
            }
            let plain = open(
                &data_key,
                record["nonce"].as_str()?,
                &format!("tau-web/local/v1/{id}/event/{number}/{previous}"),
                record["ciphertext"].as_str()?,
            )?;
            if plain != crate::journal::wrap(event).to_string().as_bytes() {
                return None;
            }
            previous = hex::encode(ring::digest::digest(&ring::digest::SHA256, bytes));
        }
        Some(())
    }
    check(files, pass, events).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_constructor_retains_only_the_authenticated_prefix_and_exact_variant() {
        let mut original = base(WORDS, &["fixture", "fixture-other"], false).unwrap();
        original.push(
            json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}),
        );
        let files = crate::reader::build(crate::PASSPHRASE, &original);
        crate::reader::read_at("reader.call.typed.original", &files, crate::PASSPHRASE).unwrap();
        let first = recipe("file.typed_cases.build.001", crate::PASSPHRASE, 1).unwrap();
        assert_eq!(&first[..3], &original[..3]);
        assert_eq!(first[3], intent(3, "reset"));
        assert_eq!(first.len(), 4);
        for n in 3..=6 {
            let events = recipe("file.typed_cases.build.001", crate::PASSPHRASE, n).unwrap();
            assert_eq!(events[4]["disposition"]["calls"], json!([3]));
            assert_eq!(
                events[4]["disposition"]["continuation"],
                [
                    "destructive_reinstall",
                    "abandonment",
                    "as_if_done",
                    "as_if_not_done"
                ][n - 3]
            );
        }
        assert_eq!(
            recipe("file.typed_cases.build.001", crate::PASSPHRASE, 7).unwrap(),
            original[..3]
        );
        assert!(recipe("file.typed_cases.build.001", crate::PASSPHRASE, 8).is_none());
        assert!(recipe("file.typed_cases.build.001", crate::WRONG_PASSPHRASE, 1).is_none());
        assert!(recipe("unknown", crate::PASSPHRASE, 1).is_none());
    }
}
