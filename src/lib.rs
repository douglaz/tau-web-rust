//! The tau-web harness. No harness code yet: what exists is the build's pin on the
//! specification and the publisher-chosen inputs it compiles in from that pinned tree
//! (ADR-0031). `build.rs` holds the gates.

/// The spec commit this build was compiled from. Every release records it (ADR-0031).
pub const SPEC_COMMIT: &str = env!("TAU_SPEC_COMMIT");

/// The Alpine bootstrap pin and the accepted `apk` signing keys (`ARC-25`, `ARC-25a`).
pub const ARTIFACT_ALPINE_TOML: &str = include_str!("../spec/bundle/artifact-alpine.toml");
/// The procured inference target (`ARC-31`, `ARC-31a`).
pub const INFERENCE_TOML: &str = include_str!("../spec/bundle/inference.toml");
/// Every named cadence and timeout (`STG-20`).
pub const TIMING_TOML: &str = include_str!("../spec/bundle/timing.toml");

include!(concat!(env!("OUT_DIR"), "/tenants.rs"));

#[cfg(test)]
mod tests {
    /// The wiring, not the values: which model or tenant the publisher chose is the
    /// specification's to say (ADR-0031), and the gates in `build.rs` are what hold it.
    #[test]
    fn the_pinned_inputs_are_compiled_in() {
        assert_eq!(super::SPEC_COMMIT.len(), 40, "{}", super::SPEC_COMMIT);
        for bundle in [
            super::ARTIFACT_ALPINE_TOML,
            super::INFERENCE_TOML,
            super::TIMING_TOML,
        ] {
            assert!(!bundle.is_empty());
        }
        assert!(!super::TENANT_PROFILES.is_empty());
        assert!(
            super::TENANT_PROFILES
                .iter()
                .all(|(tenant, profile)| !tenant.is_empty() && !profile.is_empty())
        );
    }
}
