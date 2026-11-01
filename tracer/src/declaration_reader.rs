//! Independent checks of approved intended requirements in encrypted records.
use crate::semantic;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

fn exact(v: &Value, keys: &[&str]) -> Result<(), String> {
    if semantic::holds(
        semantic::catalogue("declaration.g001", keys),
        v.as_object()
            .is_some_and(|o| o.len() == keys.len() && keys.iter().all(|k| o.contains_key(*k))),
    ) {
        Ok(())
    } else {
        Err("declaration object members".into())
    }
}
fn list(v: &Value, check: impl Fn(&Value) -> Result<(), String>) -> Result<(), String> {
    semantic::entered("declaration.list");

    if v == "unspecified" {
        return Ok(());
    }
    for (source_index, e) in
        semantic::result("declaration.g002", v.as_array().ok_or("declaration list"))?
            .iter()
            .enumerate()
    {
        let _source_slot = semantic::Slot::new("declaration.list", source_index);
        check(e)?;
    }
    Ok(())
}
fn member(v: &Value, key: &str, choices: &[&str]) -> Result<(), String> {
    if semantic::holds(
        semantic::member_site("declaration.g003", key, choices),
        v[key].as_str().is_some_and(|s| choices.contains(&s)),
    ) {
        Ok(())
    } else {
        Err("declaration enum".into())
    }
}
fn identifier(s: &str, account: bool) -> bool {
    semantic::entered(if account {
        "declaration.identifier.account"
    } else {
        "declaration.identifier.service"
    });

    let bytes = s.as_bytes();
    if semantic::rejects(
        "declaration.g004",
        bytes.is_empty() || bytes.len() > if account { 32 } else { 247 },
    ) {
        return false;
    }
    let first = bytes[0];
    if semantic::rejects(
        "declaration.g005",
        !(first == b'_'
            || if account {
                first.is_ascii_lowercase()
            } else {
                first.is_ascii_alphanumeric()
            }),
    ) {
        return false;
    }
    if semantic::rejects(
        "declaration.g006",
        !bytes.iter().all(|c| {
            if account {
                c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(c)
            } else {
                c.is_ascii_alphanumeric() || b"_:.-".contains(c)
            }
        }),
    ) {
        return false;
    }
    semantic::holds(
        "declaration.g007",
        account
            || ![
                "service",
                "socket",
                "timer",
                "target",
                "path",
                "mount",
                "automount",
                "swap",
                "slice",
                "scope",
                "device",
            ]
            .iter()
            .any(|unit| s.rsplit_once('.').is_some_and(|(_, end)| end == *unit)),
    )
}
fn host(s: &str) -> bool {
    semantic::entered("declaration.host");

    if s == "any" {
        return true;
    }
    if let Some((addr, mask)) = s.split_once('/') {
        let Ok(addr) = semantic::result("declaration.g008", addr.parse::<std::net::IpAddr>())
        else {
            return false;
        };
        return semantic::holds(
            "declaration.g009",
            mask.parse::<u8>()
                .is_ok_and(|m| m <= if addr.is_ipv4() { 32 } else { 128 }),
        );
    }
    semantic::holds(
        "declaration.g010",
        !s.is_empty()
            && s.len() <= 253
            && s.as_bytes().split(|c| *c == b'.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && l[0].is_ascii_alphanumeric()
                    && l[l.len() - 1].is_ascii_alphanumeric()
                    && l.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            }),
    )
}
pub(super) fn declaration(v: &Value, multi: bool) -> Result<(), String> {
    semantic::entered(if multi {
        "declaration.schema.multi"
    } else {
        "declaration.schema.single"
    });

    exact(
        v,
        &[
            "version",
            "listeners",
            "services",
            "key_material",
            "drift_checks",
            "required",
            "default_credentials",
        ],
    )?;
    if semantic::rejects("declaration.g011", v["version"].as_u64() != Some(2)) {
        return Err("declaration version".into());
    }
    exact(&v["listeners"], &["inbound", "outbound"])?;
    for (direction, third) in [("inbound", "from"), ("outbound", "host")] {
        list(&v["listeners"][direction], |e| {
            exact(e, &["proto", "port", third])?;
            member(e, "proto", &["tcp", "udp"])?;
            if semantic::rejects(
                "declaration.g012",
                !e["port"].as_u64().is_some_and(|p| (1..=65535).contains(&p)),
            ) {
                return Err("declaration port".into());
            }
            if direction == "inbound" {
                member(e, "from", &["any", "peers", "none"])?;
            } else if semantic::rejects("declaration.g013", !e["host"].as_str().is_some_and(host)) {
                return Err("declaration host".into());
            }
            Ok(())
        })?;
    }
    list(&v["services"], |e| {
        exact(e, &["name", "scope", "lifecycle"])?;
        if semantic::rejects(
            "declaration.g014",
            !e["name"].as_str().is_some_and(|n| identifier(n, false)),
        ) {
            return Err("service name".into());
        }
        member(
            e,
            "lifecycle",
            &["running-at-delivery", "enabled-survives-reboot"],
        )?;
        semantic::result(
            "declaration.g016",
            match e["scope"]["kind"].as_str() {
                Some("system") => exact(&e["scope"], &["kind"]),
                Some("user") => {
                    exact(&e["scope"], &["kind", "account"])?;
                    if semantic::holds(
                        "declaration.g015",
                        e["scope"]["account"]
                            .as_str()
                            .is_some_and(|a| identifier(a, true)),
                    ) {
                        Ok(())
                    } else {
                        Err("service account".into())
                    }
                }
                _ => Err("service scope".into()),
            },
        )
    })?;
    exact(&v["key_material"], &["spendable", "permitted"])?;
    let spendable = &v["key_material"]["spendable"];
    if semantic::rejects(
        "declaration.g017",
        !(spendable.is_boolean() || spendable == "unspecified") || (multi && spendable != false),
    ) {
        return Err("spendable tenant material".into());
    }
    list(&v["key_material"]["permitted"], |e| {
        exact(e, &["kind", "where"])?;
        member(
            e,
            "kind",
            &["public", "watch-only", "private-non-spendable"],
        )?;
        if semantic::rejects(
            "declaration.g018",
            multi && e["kind"] == "private-non-spendable",
        ) {
            return Err("private tenant material".into());
        }
        if semantic::rejects(
            "declaration.g019",
            !e["where"].as_str().is_some_and(|s| {
                s.starts_with('/')
                    && s.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
            }),
        ) {
            return Err("tenant material path".into());
        }
        Ok(())
    })?;
    for field in ["required", "drift_checks"] {
        if semantic::rejects(
            semantic::field_site("declaration.g020", field),
            v[field] != "unspecified" && v[field] != json!([]),
        ) {
            return Err("no signed check library".into());
        }
    }
    if v["default_credentials"] != "none" {
        list(&v["default_credentials"], |e| {
            if semantic::holds(
                "declaration.g021",
                e.as_str().is_some_and(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
                }),
            ) {
                Ok(())
            } else {
                Err("default credential identifier".into())
            }
        })?;
    }
    Ok(())
}
pub(super) fn shape(v: &Value) -> Result<(), String> {
    exact(v, &["session", "candidate", "access", "proposal"])?;
    if semantic::rejects(
        "declaration.g022",
        v["session"].as_str().is_none_or(str::is_empty) || v["candidate"].as_u64().is_none(),
    ) {
        return Err("requirements identity".into());
    }
    let p = &v["proposal"];
    if semantic::rejects(
        "declaration.g023",
        p["machine"].as_str().is_none_or(str::is_empty),
    ) {
        return Err("requirements machine".into());
    }
    semantic::result(
        "declaration.g024",
        match p["kind"].as_str() {
            Some("declaration") => {
                exact(p, &["kind", "machine", "declaration"])?;
                declaration(&p["declaration"], false)
            }
            Some("tighten_class") => {
                exact(p, &["kind", "machine", "class"])?;
                member(p, "class", &["multi_tenant"])
            }
            _ => Err("requirements proposal kind".into()),
        },
    )
}
#[derive(Default)]
pub(super) struct History {
    access: BTreeMap<String, Value>,
    class: BTreeMap<String, String>,
    declarations: BTreeMap<String, Value>,
    approvals: BTreeSet<(String, u64)>,
}
impl History {
    pub fn apply(&mut self, event: &Value) -> Result<(), String> {
        semantic::entered("declaration.history");

        let setup = &event["setup"];
        if let Some(entries) = setup["approval"]["entries"].as_array() {
            if semantic::rejects("declaration.g025", !self.access.is_empty()) {
                return Err("repeated setup approval".into());
            }
            for e in entries {
                self.access.insert(
                    e["entry"]["machine"].as_str().unwrap().into(),
                    e["access"].clone(),
                );
            }
        }
        if setup.get("access").is_some() {
            self.access.insert(
                setup["access"]["machine"].as_str().unwrap().into(),
                setup["access"]["access"].clone(),
            );
        }
        if setup.get("class").is_some() {
            let machine = setup["class"]["machine"].as_str().unwrap();
            if semantic::rejects(
                "declaration.g026",
                !self.access.contains_key(machine) || self.class.contains_key(machine),
            ) {
                return Err("unapproved or repeated class answer".into());
            }
            self.class.insert(
                machine.into(),
                setup["class"]["class"].as_str().unwrap().into(),
            );
        }
        if let Some(r) = setup.get("requirements") {
            let p = &r["proposal"];
            let machine = p["machine"].as_str().unwrap();
            let class = semantic::result(
                "declaration.g027",
                self.class.get(machine).ok_or("requirements lack class"),
            )?;
            if semantic::rejects(
                "declaration.g028",
                self.access.get(machine) != Some(&r["access"]),
            ) {
                return Err("requirements access provenance".into());
            }
            if semantic::rejects(
                "declaration.g029",
                !self.approvals.insert((
                    r["session"].as_str().unwrap().into(),
                    r["candidate"].as_u64().unwrap(),
                )),
            ) {
                return Err("repeated requirements approval".into());
            }
            if p["kind"] == "declaration" {
                declaration(&p["declaration"], class == "multi_tenant")?;
                // Independent semantic check for new ad-hoc approvals, not a schema default.
                if semantic::rejects(
                    "declaration.g030",
                    !p["declaration"]["listeners"]["inbound"]
                        .as_array()
                        .is_some_and(|entries| {
                            entries.contains(&json!({"proto":"tcp","port":22,"from":"any"}))
                        }),
                ) {
                    return Err("ad-hoc approval drops signed inbound minimum".into());
                }
                self.declarations
                    .insert(machine.into(), p["declaration"].clone());
            } else {
                if semantic::rejects("declaration.g031", class != "single_purpose") {
                    return Err("class tightening direction".into());
                }
                if let Some(d) = self.declarations.get(machine) {
                    declaration(d, true)?;
                }
                self.class.insert(machine.into(), "multi_tenant".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn minimum() -> Value {
        json!({"version":2,"listeners":{"inbound":[{"proto":"tcp","port":22,"from":"any"}],"outbound":[]},"services":[],"key_material":{"spendable":false,"permitted":[]},"drift_checks":[],"required":[],"default_credentials":"none"})
    }
    #[test]
    fn independent_reader_refuses_approval_dropping_minimum_but_preserves_schema_meanings() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for inbound in [
            json!([]),
            json!("unspecified"),
            json!([{"proto":"tcp","port":443,"from":"any"}]),
            json!([{"proto":"udp","port":22,"from":"any"}]),
            json!([{"proto":"tcp","port":22,"from":"peers"}]),
            json!([{"proto":"tcp","port":22,"from":"any"},{"proto":"tcp","port":443,"from":"any"}]),
        ] {
            let mut d = minimum();
            d["listeners"]["inbound"] = inbound.clone();
            assert!(declaration(&d, false).is_ok(), "schema: {inbound}");
            let mut events = vec![json!({"seed":{"mnemonic":words}})];
            events.extend(crate::reader::setup_events(words, &["fixture"]));
            events.push(json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}));
            events.push(json!({"setup":{"requirements":{"session":"fixture-approval","candidate":1,"access":{"model":"maintained","profile":"ad-hoc","revision":3},"proposal":{"kind":"declaration","machine":"fixture","declaration":d}}}}));
            let files = crate::reader::build_at(
                "file.declaration_reader.build.001",
                "reader fixture passphrase",
                &events,
            );
            let result = crate::reader::read(&files, "reader fixture passphrase");
            if inbound.as_array().is_some_and(|entries| entries.len() == 2) {
                assert!(result.is_ok(), "goal addition: {inbound}");
            } else {
                assert!(
                    result
                        .err()
                        .expect("invalid ad-hoc approval")
                        .contains("ad-hoc approval drops signed inbound minimum")
                );
            }
        }
    }
    #[test]
    fn independent_declaration_reader_checks_every_presence_grammar_and_scope() {
        let d = minimum();
        assert!(declaration(&d, false).is_ok());
        for field in d.as_object().unwrap().keys() {
            let mut missing = d.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(declaration(&missing, false).is_err(), "{field}");
        }
        for field in [
            "services",
            "drift_checks",
            "required",
            "default_credentials",
        ] {
            let mut unknown = d.clone();
            unknown[field] = json!("unspecified");
            assert!(declaration(&unknown, false).is_ok());
        }
        for (name, scope, valid) in [
            ("hermes", json!({"kind":"system"}), true),
            (
                "_app:1.a-b",
                json!({"kind":"user","account":"_operator-1"}),
                true,
            ),
            ("app.socket", json!({"kind":"system"}), false),
            ("app@instance", json!({"kind":"system"}), false),
            ("app", json!({"kind":"system","account":"root"}), false),
            ("app", json!({"kind":"user"}), false),
            ("app", json!({"kind":"user","account":"1user"}), false),
            ("app", json!({"kind":"user","account":"a".repeat(32)}), true),
            (
                "app",
                json!({"kind":"user","account":"a".repeat(33)}),
                false,
            ),
        ] {
            let mut value = d.clone();
            value["services"] =
                json!([{"name":name,"scope":scope,"lifecycle":"enabled-survives-reboot"}]);
            assert_eq!(declaration(&value, false).is_ok(), valid, "{value}");
        }
        for (field, value) in [
            ("version", json!(1)),
            (
                "required",
                json!([{"name":"invented","check":"id","expect":"root","provenance":"signed_bundle"}]),
            ),
        ] {
            let mut bad = d.clone();
            bad[field] = value;
            assert!(declaration(&bad, false).is_err());
        }
        let mut bad = d;
        bad["key_material"]["spendable"] = json!(true);
        assert!(declaration(&bad, true).is_err());
    }
}
