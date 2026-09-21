//! The build gates (TASKS T29, ADR-0031).
//!
//! The build refuses to run unless `spec/` is exactly the pinned tree, and it compiles the
//! publisher-chosen inputs in from that tree: `spec/bundle/`, `spec/docs/tenants/`, and the
//! briefs promoted out of draft — today none, brief 1 is a draft. Every failure here is a
//! build failure on purpose; none of them has an override.

use std::path::Path;

fn git(args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("git {}: {e}", args.join(" ")));
    assert!(
        out.status.success(),
        "git {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .expect("git printed invalid UTF-8")
        .trim()
        .to_string()
}

/// The pin: `spec/`'s commit as recorded in this repository's HEAD, checked against what is
/// actually checked out there. An uncommitted change under `spec/` — including an untracked
/// file, which a scan of `docs/tenants/` would compile in — is a tree that differs from the
/// pin, so it fails too.
fn pinned_spec_commit() -> String {
    let entry = git(&["ls-tree", "HEAD", "spec"]);
    let pin = entry
        .split_whitespace()
        .nth(2)
        .unwrap_or_else(|| panic!("HEAD records no spec/ submodule: {entry:?}"))
        .to_string();
    let head = git(&["-C", "spec", "rev-parse", "HEAD"]);
    assert_eq!(
        head, pin,
        "spec/ is checked out at {head}, the pin is {pin}: run `git submodule update --init`"
    );
    let dirty = git(&["-C", "spec", "status", "--porcelain"]);
    assert!(
        dirty.is_empty(),
        "spec/ differs from the pin {pin}, so this build is not built from it:\n{dirty}"
    );
    pin
}

/// Names under `dir`, sorted, so two machines generate the same build.
fn entries(dir: &str) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {dir} from the pinned tree: {e}"))
        .map(|entry| {
            entry
                .unwrap_or_else(|e| panic!("reading {dir}: {e}"))
                .file_name()
        })
        .map(|name| {
            name.into_string()
                .unwrap_or_else(|name| panic!("{dir}: {name:?} is not UTF-8"))
        })
        .collect();
    names.sort();
    names
}

fn main() {
    let pin = pinned_spec_commit();

    // Cargo watches this package's own files by default, and the gate reads neither its own
    // sources nor anything in them: it reads the pinned tree and the git state that says which
    // commit the pin is. Without these, a pin bump with no `git submodule update` leaves a
    // cached build green on the old tree, which is the drift ADR-0031 exists to prevent.
    println!("cargo::rerun-if-changed=spec");
    println!("cargo::rerun-if-changed=.git/HEAD");
    println!("cargo::rerun-if-changed=.git/index");

    // Every file under bundle/ is compiled in, so every file under bundle/ must parse — a
    // fourth input added there is gated the day it lands, not the day someone remembers it.
    // The two publisher decisions must have been taken: an empty model or provider fails the
    // build rather than letting it guess one (ARC-31, STG-17).
    let mut parsed = 0;
    for name in entries("spec/bundle") {
        if !name.ends_with(".toml") {
            continue; // cors-probe.sh and README.md are not compiled-in inputs
        }
        parsed += 1;
        let path = format!("spec/bundle/{name}");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
        let value: toml::Table = text.parse().unwrap_or_else(|e| panic!("{path}: {e}"));
        if name == "inference.toml" {
            for key in ["model", "provider"] {
                let taken = value
                    .get("session")
                    .and_then(|session| session.get(key))
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| !value.is_empty());
                assert!(
                    taken,
                    "bundle/inference.toml: [session].{key} is empty — a publisher decision \
                     the build must not guess (ARC-31, STG-17). Fill it in the specification \
                     repository and bump the pin."
                );
            }
        }
    }
    assert!(parsed > 0, "spec/bundle/ holds no .toml inputs");

    // The tenant profiles, one directory each (ADR-0030); anything else there is not a tenant.
    let tenants: Vec<String> = entries("spec/docs/tenants")
        .into_iter()
        .filter(|name| Path::new(&format!("spec/docs/tenants/{name}")).is_dir())
        .collect();
    assert!(!tenants.is_empty(), "spec/docs/tenants/ holds no profiles");

    // Briefs ship compiled in once they leave draft (T29, `ARC-11`, ADR-0005), and today none
    // has: each says so in its own prose, which is the only marker the corpus carries. The
    // build watches that sentence, so a brief that loses it stops the build and someone
    // decides here, instead of a promoted brief silently not shipping.
    // ponytail: prose marker; a `status:` field in the brief would be sturdier.
    const DRAFT: &str = "not yet in the signed bundle";
    let mut briefs: Vec<String> = entries("spec/docs/briefs")
        .iter()
        .map(|name| format!("spec/docs/briefs/{name}"))
        .collect();
    for tenant in &tenants {
        let dir = format!("spec/docs/tenants/{tenant}/briefs");
        if Path::new(&dir).is_dir() {
            briefs.extend(entries(&dir).iter().map(|name| format!("{dir}/{name}")));
        }
    }
    for brief in briefs {
        let text = std::fs::read_to_string(&brief).unwrap_or_else(|e| panic!("{brief}: {e}"));
        // The corpus hard-wraps its prose, so the sentence is matched across line breaks.
        let prose = text.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            prose.contains(DRAFT),
            "{brief} no longer says it is \"{DRAFT}\": a brief out of draft is compiled into \
             the build (`ARC-11`, ADR-0005), so wire it in here — or restore the sentence."
        );
    }

    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut generated =
        String::from("/// The tenant profiles compiled in from the pinned tree (ADR-0030).\n");
    generated.push_str("pub const TENANT_PROFILES: &[(&str, &str)] = &[\n");
    for tenant in &tenants {
        let profile = format!("{root}/spec/docs/tenants/{tenant}/profile.md");
        assert!(
            Path::new(&profile).is_file(),
            "spec/docs/tenants/{tenant}/ has no profile.md (ADR-0030)"
        );
        // `{:?}` on a str is a Rust string literal, which is what this is generating.
        generated.push_str(&format!("    ({tenant:?}, include_str!({profile:?})),\n"));
    }
    generated.push_str("];\n");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{out}/tenants.rs"), generated).expect("writing tenants.rs");

    println!("cargo::rustc-env=TAU_SPEC_COMMIT={pin}");
}
