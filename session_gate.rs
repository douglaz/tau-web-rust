//! The `[session]` gate on `bundle/inference.toml` (TASKS T37, `CNF-88`'s build fixtures).
//!
//! The build accepts exactly the `[session]` the specification's reference validator accepts —
//! `validate_session` in `spec/docs/findings/2026-09-22-provider-routing/eligible-set.py` — so
//! the build and the specification's proposing job agree on what a valid bundle is. Every check
//! there is mirrored here, in its order, and nothing is added. `build.rs` and
//! `tests/session_gate.rs` both compile this file, so the tests run the code the build runs.

use toml::{Table, Value};

fn refuse(field: &str, wrong: &str, owners: &str) -> String {
    format!(
        "bundle/inference.toml: {field} {wrong} — a publisher decision the build must not \
         guess ({owners}). Fix it in the specification repository and bump the pin."
    )
}

/// Python's `not v.strip()`. `str::trim` differs from it on exactly U+001C–U+001F, which
/// Python strips and Unicode's `White_Space` does not include.
fn blank(value: &str) -> bool {
    value
        .chars()
        .all(|c| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c))
}

/// `validate_entries`: an array of tables, each carrying exactly `fields`, each a nonempty
/// string.
fn entries<'a>(
    session: &'a Table,
    key: &str,
    fields: &[&str],
    nonempty: bool,
    owners: &str,
) -> Result<Vec<&'a Table>, String> {
    let list = session
        .get(key)
        .and_then(Value::as_array)
        .filter(|list| !(nonempty && list.is_empty()))
        .ok_or_else(|| {
            let wrong = if nonempty {
                "is not a nonempty array"
            } else {
                "is not an array"
            };
            refuse(&format!("[session].{key}"), wrong, owners)
        })?;
    let mut tables = Vec::new();
    for (i, entry) in list.iter().enumerate() {
        let table = entry
            .as_table()
            .filter(|table| table.len() == fields.len())
            .filter(|table| fields.iter().all(|field| table.contains_key(*field)))
            .ok_or_else(|| {
                let wrong = format!("does not carry exactly {}", fields.join(", "));
                refuse(&format!("[session].{key}[{i}]"), &wrong, owners)
            })?;
        for field in fields {
            if !table[*field].as_str().is_some_and(|value| !blank(value)) {
                // The maker is the bundle's to record, never parsed from the slug (SEC-9).
                let owners = match *field {
                    "maker" => format!("{owners}, SEC-9"),
                    _ => owners.to_string(),
                };
                return Err(refuse(
                    &format!("[session].{key}[{i}].{field}"),
                    "is not a nonempty string",
                    &owners,
                ));
            }
        }
        tables.push(table);
    }
    Ok(tables)
}

/// `validate_session`, on the whole of `bundle/inference.toml`. A slug listed twice within one
/// list is accepted, as it is there: the specification has not decided it (TASKS T37).
pub fn session_gate(bundle: &Table) -> Result<(), String> {
    let session = bundle
        .get("session")
        .and_then(Value::as_table)
        .ok_or_else(|| refuse("[session]", "is not a table", "ARC-31b"))?;
    for key in ["context_floor", "depth"] {
        // A TOML integer and nothing else: `5.0`, `"5"` and `true` are not one.
        if !session
            .get(key)
            .and_then(Value::as_integer)
            .is_some_and(|n| n > 0)
        {
            return Err(refuse(
                &format!("[session].{key}"),
                "is not a positive integer",
                "ARC-31b",
            ));
        }
    }
    let allowlist = entries(
        session,
        "allowlist",
        &["slug", "provider"],
        false,
        "TRU-A1a",
    )?;
    let model = entries(
        session,
        "model",
        &["slug", "maker", "provider"],
        true,
        "ARC-31b",
    )?;
    // The two provider strings are compared exactly, neither trimmed nor case-folded, and
    // every candidate against every allowlist entry of its slug.
    for (i, candidate) in model.iter().enumerate() {
        for (j, entry) in allowlist.iter().enumerate() {
            if candidate["slug"] == entry["slug"] && candidate["provider"] != entry["provider"] {
                let wrong = format!(
                    "differs from [session].model[{i}].provider for the slug {}",
                    candidate["slug"]
                );
                return Err(refuse(
                    &format!("[session].allowlist[{j}].provider"),
                    &wrong,
                    "TRU-A1a",
                ));
            }
        }
    }
    if session.contains_key("provider") {
        return Err(refuse(
            "[session].provider",
            "belongs on each entry, not on [session]",
            "ARC-31b",
        ));
    }
    if session.get("retention").and_then(Value::as_str) != Some("strictest") {
        return Err(refuse(
            "[session].retention",
            "is not \"strictest\"",
            "ARC-31a",
        ));
    }
    Ok(())
}
