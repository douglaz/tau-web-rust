//! The build gates (TASKS T29, ADR-0031).
//!
//! The build refuses to run unless `spec/` is exactly the pinned tree, and it compiles the
//! publisher-chosen inputs in from that tree: `spec/bundle/`, `spec/docs/tenants/`, and the
//! briefs promoted out of draft — today none, brief 1 is a draft. Every failure here is a
//! build failure on purpose; none of them has an override.

mod session_gate;

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

/// What the pin records at `path`, as paths inside `spec/`, sorted so two machines generate the
/// same build. The tree and never the directory: a file the specification's own `.gitignore`
/// covers is absent from `git status --porcelain` above, so a filesystem scan would compile in
/// something the pinned commit does not contain and the cleanliness check would not notice.
fn pinned(path: &str) -> Vec<String> {
    let mut names: Vec<String> = git(&["-C", "spec", "ls-tree", "-r", "--name-only", "HEAD", path])
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    names.sort();
    names
}

/// A file of the pinned tree, by its path inside `spec/`.
fn read(path: &str) -> String {
    std::fs::read_to_string(format!("spec/{path}")).unwrap_or_else(|e| panic!("spec/{path}: {e}"))
}

/// One `&[(&str, &str)]` of pinned files, as source for the crate to `include!`.
fn emit(out: &mut String, root: &str, doc: &str, name: &str, items: &[(String, String)]) {
    out.push_str(&format!(
        "/// {doc}\npub const {name}: &[(&str, &str)] = &[\n"
    ));
    for (key, path) in items {
        let file = format!("{root}/spec/{path}");
        // `{:?}` on a str is a Rust string literal, which is what this is generating.
        out.push_str(&format!("    ({key:?}, include_str!({file:?})),\n"));
    }
    out.push_str("];\n");
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

    // Every input under bundle/ is compiled in, so every one of them must parse and every one
    // of them is embedded — a fourth input added there is gated and shipped the day it lands,
    // not the day someone remembers it. The publisher's decisions under `[session]` must have
    // been taken: the candidate order with a provider on each entry, the allowlist, the context
    // floor, the depth and the retention request. One the reference validator would refuse
    // fails the build rather than letting it guess (ARC-31a, ARC-31b, TRU-A1a).
    let mut bundle: Vec<(String, String)> = Vec::new();
    for path in pinned("bundle/") {
        if !path.ends_with(".toml") {
            continue; // cors-probe.sh and README.md are checks and prose, not inputs
        }
        let name = path
            .rsplit('/')
            .next()
            .expect("a path has a last segment")
            .to_string();
        let text = read(&path);
        let value: toml::Table = text.parse().unwrap_or_else(|e| panic!("spec/{path}: {e}"));
        if name == "inference.toml" {
            session_gate::session_gate(&value).unwrap_or_else(|refusal| panic!("{refusal}"));
            println!(
                "cargo::rustc-env=TAU_INFERENCE_ORIGIN={}",
                value["aggregator"]["base_url"]
                    .as_str()
                    .expect("aggregator origin")
            );
        }
        bundle.push((name, path));
    }
    assert!(
        !bundle.is_empty(),
        "the pin records no .toml inputs under bundle/"
    );

    // One profile.md per tenant directory (ADR-0030); anything else there is not a tenant.
    let tenant_files = pinned("docs/tenants/");
    let profiles: Vec<(String, String)> = tenant_files
        .iter()
        .filter_map(|path| {
            let (tenant, file) = path.strip_prefix("docs/tenants/")?.split_once('/')?;
            (file == "profile.md").then(|| (tenant.to_string(), path.clone()))
        })
        .collect();
    assert!(!profiles.is_empty(), "the pin records no tenant profiles");

    // Briefs ship compiled in once they leave draft (T29, `ARC-11`, ADR-0005), and today none
    // has: each says so in its own prose, which is the only marker the corpus carries. The
    // build watches that sentence, so a brief that loses it stops the build and someone
    // decides here, instead of a promoted brief silently not shipping.
    // ponytail: prose marker; a `status:` field in the brief would be sturdier.
    const DRAFT: &str = "not yet in the signed bundle";
    let briefs = pinned("docs/briefs/").into_iter().chain(
        tenant_files
            .iter()
            .filter(|p| p.contains("/briefs/"))
            .cloned(),
    );
    for brief in briefs {
        // The corpus hard-wraps its prose, so the sentence is matched across line breaks.
        let prose = read(&brief)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            prose.contains(DRAFT),
            "spec/{brief} no longer says it is \"{DRAFT}\": a brief out of draft is compiled \
             into the build (`ARC-11`, ADR-0005), so wire it in here — or restore the sentence."
        );
    }

    let root = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let mut generated = String::new();
    emit(
        &mut generated,
        &root,
        "The publisher-chosen inputs under `bundle/`, by file name (ADR-0031).",
        "BUNDLE",
        &bundle,
    );
    emit(
        &mut generated,
        &root,
        "The tenant profiles, by tenant (ADR-0030).",
        "TENANT_PROFILES",
        &profiles,
    );
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    std::fs::write(format!("{out}/pinned.rs"), generated).expect("writing pinned.rs");

    println!("cargo::rustc-env=TAU_SPEC_COMMIT={pin}");
}
