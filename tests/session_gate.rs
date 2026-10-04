//! `CNF-88`'s build fixtures: what the `[session]` gate accepts and what it refuses. The gate
//! is the file `build.rs` compiles, not a copy of it.

#[path = "../session_gate.rs"]
mod session_gate;

use session_gate::session_gate;

type Edits<'a> = &'a [(&'a str, &'a str)];

/// A `[session]` the gate accepts, key by key, with `edits` applied: a key already there is
/// replaced, an empty replacement removes it, a new key is added.
fn bundle(edits: Edits) -> toml::Table {
    let mut keys: Vec<(&str, &str)> = vec![
        (
            "model",
            r#"[{ slug = "a/one", maker = "A", provider = "a" }]"#,
        ),
        ("allowlist", "[]"),
        ("context_floor", "500000"),
        ("depth", "5"),
        ("retention", r#""strictest""#),
    ];
    for edit in edits {
        keys.retain(|(key, _)| *key != edit.0);
        keys.push(*edit);
    }
    let mut text = String::from("[session]\n");
    for (key, value) in keys.iter().filter(|(_, value)| !value.is_empty()) {
        text.push_str(&format!("{key} = {value}\n"));
    }
    text.parse().unwrap_or_else(|e| panic!("{text}: {e}"))
}

#[test]
fn the_pinned_session_is_accepted() {
    let (_, text) = tau_web::BUNDLE
        .iter()
        .find(|(name, _)| *name == "inference.toml")
        .expect("the pin records bundle/inference.toml");
    let pinned: toml::Table = text.parse().expect("the build parsed it");
    assert_eq!(session_gate(&pinned), Ok(()));
}

#[test]
fn what_the_reference_accepts_is_accepted() {
    let accepted: &[Edits] = &[
        &[],
        // An unknown key under [session], other than `provider`.
        &[("note", r#""kept""#)],
        // A slug in both lists with the identical provider.
        &[("allowlist", r#"[{ slug = "a/one", provider = "a" }]"#)],
        // A slug listed twice within one list: undecided in the specification, so no rule.
        &[(
            "model",
            r#"[{ slug = "a/one", maker = "A", provider = "a" },
                { slug = "a/one", maker = "A", provider = "b" }]"#,
        )],
        &[(
            "allowlist",
            r#"[{ slug = "b/two", provider = "a" }, { slug = "b/two", provider = "b" }]"#,
        )],
        // Whitespace around a value is not an empty value.
        &[(
            "model",
            r#"[{ slug = "a/one", maker = " A ", provider = "a" }]"#,
        )],
    ];
    for edits in accepted {
        assert_eq!(session_gate(&bundle(edits)), Ok(()), "{edits:?}");
    }
}

#[test]
fn what_the_reference_rejects_fails_the_build() {
    // (the edits, the field the refusal names, the owners it cites)
    let refused: &[(Edits, &str, &str)] = &[
        // (b), (c): the context floor and the depth.
        (
            &[("context_floor", "")],
            "[session].context_floor is not a positive integer",
            "(ARC-31b)",
        ),
        (
            &[("context_floor", "0")],
            "[session].context_floor ",
            "(ARC-31b)",
        ),
        (
            &[("context_floor", "500000.0")],
            "[session].context_floor ",
            "(ARC-31b)",
        ),
        (
            &[("context_floor", r#""500000""#)],
            "[session].context_floor ",
            "(ARC-31b)",
        ),
        (
            &[("depth", "")],
            "[session].depth is not a positive integer",
            "(ARC-31b)",
        ),
        (&[("depth", "0")], "[session].depth ", "(ARC-31b)"),
        (&[("depth", "-1")], "[session].depth ", "(ARC-31b)"),
        (&[("depth", "5.0")], "[session].depth ", "(ARC-31b)"),
        (&[("depth", "true")], "[session].depth ", "(ARC-31b)"),
        // (d): the candidate list.
        (
            &[("model", "")],
            "[session].model is not a nonempty array",
            "(ARC-31b)",
        ),
        (&[("model", "[]")], "[session].model ", "(ARC-31b)"),
        (
            &[("model", r#""glm-5.3""#)],
            "[session].model ",
            "(ARC-31b)",
        ),
        // (e): a candidate's key set.
        (
            &[("model", r#"["a/one"]"#)],
            "[session].model[0] does not carry exactly slug, maker, provider",
            "(ARC-31b)",
        ),
        (
            &[("model", r#"[{ slug = "a/one", maker = "A" }]"#)],
            "[session].model[0] ",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = "a", pin = "x" }]"#,
            )],
            "[session].model[0] ",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = "a" }, { slug = "b/two", maker = "B" }]"#,
            )],
            "[session].model[1] ",
            "(ARC-31b)",
        ),
        // (f): a candidate's values.
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = "" }]"#,
            )],
            "[session].model[0].provider is not a nonempty string",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = " \t" }]"#,
            )],
            "[session].model[0].provider ",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = "\u001C\u001D\u001E\u001F" }]"#,
            )],
            "[session].model[0].provider ",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "A", provider = 1 }]"#,
            )],
            "[session].model[0].provider ",
            "(ARC-31b)",
        ),
        (
            &[("model", r#"[{ slug = "", maker = "A", provider = "a" }]"#)],
            "[session].model[0].slug ",
            "(ARC-31b)",
        ),
        (
            &[(
                "model",
                r#"[{ slug = "a/one", maker = "\u001F", provider = "a" }]"#,
            )],
            "[session].model[0].maker ",
            "(ARC-31b, SEC-9)",
        ),
        // (g): the allowlist.
        (
            &[("allowlist", "")],
            "[session].allowlist is not an array",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#""a/one""#)],
            "[session].allowlist ",
            "(TRU-A1a)",
        ),
        // (h): an allowlist entry's key set.
        (
            &[("allowlist", r#"["a/one"]"#)],
            "[session].allowlist[0] does not carry exactly slug, provider",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#"[{ slug = "a/one" }]"#)],
            "[session].allowlist[0] ",
            "(TRU-A1a)",
        ),
        (
            &[(
                "allowlist",
                r#"[{ slug = "a/one", maker = "A", provider = "a" }]"#,
            )],
            "[session].allowlist[0] ",
            "(TRU-A1a)",
        ),
        // (i): an allowlist entry's values.
        (
            &[("allowlist", r#"[{ slug = "a/one", provider = "" }]"#)],
            "[session].allowlist[0].provider is not a nonempty string",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#"[{ slug = "a/one", provider = "\u001C " }]"#)],
            "[session].allowlist[0].provider ",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#"[{ slug = 1, provider = "a" }]"#)],
            "[session].allowlist[0].slug ",
            "(TRU-A1a)",
        ),
        // (j): one slug, two providers — compared exactly.
        (
            &[("allowlist", r#"[{ slug = "a/one", provider = "b" }]"#)],
            "[session].allowlist[0].provider differs from [session].model[0].provider",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#"[{ slug = "a/one", provider = "A" }]"#)],
            "[session].allowlist[0].provider differs",
            "(TRU-A1a)",
        ),
        (
            &[("allowlist", r#"[{ slug = "a/one", provider = "a " }]"#)],
            "[session].allowlist[0].provider differs",
            "(TRU-A1a)",
        ),
        (
            &[(
                "allowlist",
                r#"[{ slug = "a/one", provider = "a" }, { slug = "a/one", provider = "b" }]"#,
            )],
            "[session].allowlist[1].provider differs",
            "(TRU-A1a)",
        ),
        // (k): a provider on [session] itself, whatever it holds.
        (
            &[("provider", r#""a""#)],
            "[session].provider belongs on each entry",
            "(ARC-31b)",
        ),
        (&[("provider", "0")], "[session].provider ", "(ARC-31b)"),
        // (l): the retention request.
        (
            &[("retention", "")],
            "[session].retention is not \"strictest\"",
            "(ARC-31a)",
        ),
        (
            &[("retention", r#""default""#)],
            "[session].retention ",
            "(ARC-31a)",
        ),
        (
            &[("retention", r#""Strictest""#)],
            "[session].retention ",
            "(ARC-31a)",
        ),
    ];
    for (edits, field, owners) in refused {
        let refusal = session_gate(&bundle(edits)).expect_err(&format!("{edits:?}"));
        for part in [
            &format!("bundle/inference.toml: {field}"),
            "a publisher decision the build must not guess",
            *owners,
            "Fix it in the specification repository and bump the pin.",
        ] {
            assert!(refusal.contains(part), "{edits:?}: {refusal}");
        }
    }
}

/// (a): the reference raises on `bundle["session"]`.
#[test]
fn a_bundle_without_a_session_table_fails_the_build() {
    for text in ["", "session = \"glm-5.3\"", "session = []"] {
        let bundle: toml::Table = text.parse().expect(text);
        let refusal = session_gate(&bundle).expect_err(text);
        assert!(
            refusal.contains("bundle/inference.toml: [session] is not a table")
                && refusal.contains("(ARC-31b)"),
            "{text}: {refusal}"
        );
    }
}
