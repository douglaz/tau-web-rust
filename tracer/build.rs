#[allow(dead_code)]
mod identity;

fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let (hash, paths) = identity::source(root).expect("complete tracer source identity");
    println!("cargo:rustc-env=TRACER_SOURCE_SHA256={hash}");
    // The identity includes Git's complete source set, including new untracked files
    // anywhere in the repository. Watching existing paths or selected directories
    // cannot detect all additions. An intentionally absent build-output path makes
    // Cargo re-enumerate that set on every invocation, without recursively watching
    // target/, browser profiles, artifacts or the tracker database.
    let scan =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("recheck-source-set");
    println!("cargo:rerun-if-changed={}", scan.display());
    for path in paths {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    // New source files must also invalidate the compiled identity.
    for path in ["src", "tracer", "scripts", "tests", "www", "spec"] {
        println!("cargo:rerun-if-changed={}", root.join(path).display());
    }
}
