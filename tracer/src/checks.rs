//! The served build's checks (twr-ggw.2, AC5 and AC6): nothing test-only in its bytes, and the
//! page's Content-Security-Policy exactly `ARC-33`'s.

use crate::keys::relay_public;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use tau_web::testonly::{PIN_SOURCE_MARKER, PINS};

/// The files the served build is: the page, its script, the worker script and the wasm
/// (`ARC-32`). A check over a directory missing one of them would pass on nothing.
pub const SERVED_FILES: &[&str] = &[
    "index.html",
    "boot.js",
    "worker.js",
    "pkg/tau_web.js",
    "pkg/tau_web_bg.wasm",
];

/// `ARC-33`: "`script-src`, `object-src` and `base-uri` stay strict (`script-src 'self'
/// 'wasm-unsafe-eval'`, `object-src 'none'`, `base-uri 'self'`)", and "`connect-src` is
/// permissive for `https:` and `wss:` alike". These four directives with these sources, and
/// nothing else.
pub const ARC_33: &[(&str, &[&str])] = &[
    ("script-src", &["'self'", "'wasm-unsafe-eval'"]),
    ("object-src", &["'none'"]),
    ("base-uri", &["'self'"]),
    ("connect-src", &["https:", "wss:"]),
];

/// What `check-absence` looks for: each fixed fixture seed's derived private and public halves as raw bytes, hex and
/// base64, the SSH client key in OpenSSH's encoding, the pins and the pin source's marker, and the
/// test switches a request can set (`fail_append` among them, which makes the store's append
/// fail).
pub fn needles() -> Vec<(String, Vec<u8>)> {
    let mut needles = Vec::new();
    let phrases = std::iter::once("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        .chain(include_str!("../../tests/vectors/seed-backup-collisions.txt").lines());
    for (fixture, mnemonic) in phrases.enumerate() {
        for role in [0, 3] {
            for index in [0, 1] {
                let private =
                    crate::reader::role_key(mnemonic, role, index).expect("fixture derivation");
                let public = if role == 0 {
                    crate::keys::ed25519(&private)
                        .public_key()
                        .key_data()
                        .ed25519()
                        .expect("Ed25519")
                        .0
                } else {
                    relay_public(&private)
                };
                let key = format!("fixture {fixture} role {role} index {index}");
                for (half, bytes) in [("private", private), ("public", public)] {
                    for (encoding, encoded) in [
                        ("raw", bytes.to_vec()),
                        ("hex", hex::encode(bytes).into_bytes()),
                        ("HEX", hex::encode_upper(bytes).into_bytes()),
                        ("base64", STANDARD_NO_PAD.encode(bytes).into_bytes()),
                        ("base64url", URL_SAFE_NO_PAD.encode(bytes).into_bytes()),
                    ] {
                        needles.push((format!("{key}, {half} half, {encoding}"), encoded));
                    }
                }
                if role == 0 {
                    let openssh = crate::keys::ed25519(&private)
                        .public_key()
                        .to_openssh()
                        .expect("OpenSSH");
                    needles.push((
                        format!("{key}, public half, OpenSSH"),
                        openssh.split(' ').nth(1).expect("blob").as_bytes().to_vec(),
                    ));
                }
            }
        }
    }
    for (machine, pin) in PINS {
        needles.push((
            format!("pin source: the pin for {machine}"),
            pin.as_bytes().to_vec(),
        ));
    }
    needles.push((
        "pin source: its marker".into(),
        PIN_SOURCE_MARKER.as_bytes().to_vec(),
    ));
    for switch in [
        "fail_append",
        "tamper_auth",
        "test_relay_key",
        "test_no_credentials",
        "test_writer",
        "test_hold_move",
        "test_hold_job_read",
        "test_hold_session_point",
        "session_point",
        "session_point_receiver",
        "session_authentication",
        "rekey_session",
        "ssh_point",
        "test_rekey_session",
        "test_cold_inference_route",
        "session_evidence",
        "signature_writer",
        "connection_writer",
        "evidence_writer",
        "finish_writer",
        "response_writer",
        "route_writer",
        "session_connected",
        "test_allocate",
        "test_seed_backup_fail_append",
        "test_completed_reads",
        "test_model_target",
        "test_model_tool",
        "goal_turn",
        "test_inference_origin",
        "test_inference_account",
        "fixture-model",
        "fixture-maker",
        "fixture-provider",
    ] {
        needles.push((format!("test switch: {switch}"), switch.as_bytes().to_vec()));
    }
    needles.push((
        "fixture root password".into(),
        b"fixture-root-password-ggw9!".to_vec(),
    ));
    needles
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.is_dir() {
            files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn require_served_files(dir: &Path) -> Result<(), String> {
    let missing: Vec<_> = SERVED_FILES
        .iter()
        .filter(|f| !dir.join(f).is_file())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} is not a built web directory: no {missing:?}",
            dir.display()
        ))
    }
}

/// AC5: fixture-derived keys, the pin source and the test switches are absent
/// from every file under `dir`. Each finding names the file and what was found.
pub fn absence(dir: &Path) -> Result<(), String> {
    require_served_files(dir)?;
    let mut paths = Vec::new();
    files(dir, &mut paths)?;
    paths.sort();
    let needles = needles();
    let mut found = Vec::new();
    for path in &paths {
        let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
        for (what, needle) in &needles {
            if bytes.windows(needle.len()).any(|w| w == needle.as_slice()) {
                found.push(format!("{}: {what}", path.display()));
            }
        }
    }
    println!(
        "absence: {} files, {} needles checked",
        paths.len(),
        needles.len()
    );
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!("test-only parts found:\n  {}", found.join("\n  ")))
    }
}

/// The value of the page's one `<meta http-equiv="Content-Security-Policy">`, which must come
/// before any script, since a policy in a meta element binds only what follows it.
pub fn page_policy(html: &str) -> Result<String, String> {
    let lower = html.to_ascii_lowercase();
    let mut policies = Vec::new();
    let mut at = 0;
    while let Some(start) = lower[at..].find("<meta").map(|i| at + i) {
        let end = lower[start..]
            .find('>')
            .map(|i| start + i)
            .ok_or("an unclosed <meta")?;
        let attrs = attributes(&html[start + "<meta".len()..end]);
        if attrs
            .get("http-equiv")
            .is_some_and(|v| v.eq_ignore_ascii_case("content-security-policy"))
        {
            let content = attrs.get("content").ok_or("a CSP <meta> with no content")?;
            policies.push((start, content.clone()));
        }
        at = end;
    }
    let [(position, policy)] = policies.as_slice() else {
        return Err(format!(
            "the page carries {} CSP <meta> elements, not exactly one",
            policies.len()
        ));
    };
    if lower
        .find("<script")
        .is_some_and(|script| script < *position)
    {
        return Err("a <script> precedes the CSP <meta>, so the policy does not bind it".into());
    }
    Ok(policy.clone())
}

/// A tag's attributes, names lowercased; values double- or single-quoted.
fn attributes(tag: &str) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    let mut rest = tag.trim_start();
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim().to_ascii_lowercase();
        let value = rest[eq + 1..].trim_start();
        let Some(quote) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some(close) = value[1..].find(quote) else {
            break;
        };
        attrs.insert(name, value[1..1 + close].to_string());
        rest = value[close + 2..].trim_start();
    }
    attrs
}

/// A policy as directives and their sources, order-free. A directive given twice is an error:
/// browsers ignore the second, so it would read as stricter than it is.
pub fn parse_policy(policy: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut directives = BTreeMap::new();
    for directive in policy.split(';') {
        let mut tokens = directive.split_ascii_whitespace();
        let Some(name) = tokens.next() else { continue };
        let name = name.to_ascii_lowercase();
        let sources = tokens.map(str::to_string).collect();
        if directives.insert(name.clone(), sources).is_some() {
            return Err(format!("`{name}` is given twice"));
        }
    }
    Ok(directives)
}

/// AC6: the policy is exactly `ARC-33`'s; otherwise every difference, named.
pub fn policy_differences(policy: &str) -> Result<(), String> {
    let actual = parse_policy(policy)?;
    let expected: BTreeMap<String, BTreeSet<String>> = ARC_33
        .iter()
        .map(|(name, sources)| {
            (
                name.to_string(),
                sources.iter().map(|s| s.to_string()).collect(),
            )
        })
        .collect();
    let mut differences = Vec::new();
    for (name, sources) in &expected {
        match actual.get(name) {
            None => differences.push(format!("`{name}` is missing")),
            Some(got) => {
                for source in sources.difference(got) {
                    differences.push(format!("`{name}` lacks {source}"));
                }
                for source in got.difference(sources) {
                    differences.push(format!("`{name}` adds {source}"));
                }
            }
        }
    }
    for name in actual.keys().filter(|name| !expected.contains_key(*name)) {
        differences.push(format!("`{name}` is not ARC-33's"));
    }
    if differences.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "the policy is not ARC-33's: {}\n  policy: {policy}",
            differences.join("; ")
        ))
    }
}

/// `check-csp`: the served page's policy, parsed, equals `ARC-33`'s.
pub fn csp(dir: &Path) -> Result<(), String> {
    require_served_files(dir)?;
    let page = dir.join("index.html");
    let html = std::fs::read_to_string(&page).map_err(|e| format!("{}: {e}", page.display()))?;
    let policy = page_policy(&html)?;
    policy_differences(&policy)?;
    println!("csp: {} carries ARC-33's policy: {policy}", page.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn absence_detects_a_planted_derived_key() {
        let dir = std::env::temp_dir().join(format!(
            "tau-absence-{}-{}",
            std::process::id(),
            hex::encode(crate::fixtures::urandom::<8>())
        ));
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        for file in super::SERVED_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        assert!(super::absence(&dir).is_ok());
        let (name, key) = super::needles()
            .into_iter()
            .find(|(name, _)| name == "fixture 0 role 0 index 0, private half, raw")
            .unwrap();
        std::fs::write(dir.join("pkg/tau_web_bg.wasm"), key).unwrap();
        assert!(super::absence(&dir).unwrap_err().contains(&name));
        std::fs::write(
            dir.join("pkg/tau_web_bg.wasm"),
            b"fixture-root-password-ggw9!",
        )
        .unwrap();
        assert!(
            super::absence(&dir)
                .unwrap_err()
                .contains("fixture root password")
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn absence_detects_each_planted_inference_needle() {
        let dir = std::env::temp_dir().join(format!(
            "tau-inference-absence-{}-{}",
            std::process::id(),
            hex::encode(crate::fixtures::urandom::<8>())
        ));
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        for file in super::SERVED_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        assert!(super::absence(&dir).is_ok());
        for needle in [
            "test_inference_origin",
            "test_inference_account",
            "fixture-model",
            "fixture-maker",
            "fixture-provider",
        ] {
            std::fs::write(dir.join("pkg/tau_web_bg.wasm"), needle).unwrap();
            assert!(
                super::absence(&dir)
                    .expect_err("planted inference needle escaped check-absence")
                    .contains(needle)
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;

    const ARC_33_POLICY: &str = "script-src 'self' 'wasm-unsafe-eval'; object-src 'none'; base-uri 'self'; connect-src https: wss:";

    fn page(policy: &str) -> String {
        format!(
            "<!doctype html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"{policy}\"><script type=\"module\" src=\"boot.js\"></script>"
        )
    }

    #[test]
    fn arc_33_is_accepted_in_any_order() {
        policy_differences(ARC_33_POLICY).unwrap();
        policy_differences("connect-src wss: https:;base-uri 'self';object-src 'none';script-src 'wasm-unsafe-eval' 'self';").unwrap();
        assert_eq!(page_policy(&page(ARC_33_POLICY)).unwrap(), ARC_33_POLICY);
    }

    #[test]
    fn each_drift_is_named() {
        for (policy, named) in [
            (
                ARC_33_POLICY.replace(" 'wasm-unsafe-eval'", ""),
                "`script-src` lacks 'wasm-unsafe-eval'",
            ),
            (
                ARC_33_POLICY.replace("wss:", "wss: ws:"),
                "`connect-src` adds ws:",
            ),
            (
                ARC_33_POLICY.replace(" object-src 'none';", ""),
                "`object-src` is missing",
            ),
            (
                ARC_33_POLICY.replace(" base-uri 'self';", ""),
                "`base-uri` is missing",
            ),
            (
                format!("default-src 'self'; {ARC_33_POLICY}"),
                "`default-src` is not ARC-33's",
            ),
        ] {
            let refused = policy_differences(&policy).unwrap_err();
            assert!(refused.contains(named), "{refused}");
        }
        assert!(policy_differences(&format!("{ARC_33_POLICY}; object-src *")).is_err());
    }

    #[test]
    fn the_page_must_carry_one_policy_before_any_script() {
        assert!(page_policy("<head><script src=a.js></script>").is_err());
        let twice = page(ARC_33_POLICY).replace("<script", &format!("{}<script", page("x")));
        assert!(page_policy(&twice).is_err());
        let late = "<script src=\"a.js\"></script><meta http-equiv=\"content-security-policy\" content=\"object-src 'none'\">";
        assert!(page_policy(late).unwrap_err().contains("precedes"));
    }
}
