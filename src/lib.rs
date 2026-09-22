//! The tau-web harness. No harness code yet: what exists is the build's pin on the
//! specification and the publisher-chosen inputs it compiles in from that pinned tree
//! (ADR-0031). `build.rs` holds the gates.

/// The spec commit this build was compiled from. Every release records it (ADR-0031).
pub const SPEC_COMMIT: &str = env!("TAU_SPEC_COMMIT");

include!(concat!(env!("OUT_DIR"), "/pinned.rs"));

#[cfg(test)]
mod tests {
    /// The wiring, not the values: which model or tenant the publisher chose is the
    /// specification's to say (ADR-0031), and the gates in `build.rs` are what hold it.
    #[test]
    fn the_pinned_inputs_are_compiled_in() {
        assert_eq!(super::SPEC_COMMIT.len(), 40, "{}", super::SPEC_COMMIT);
        for compiled_in in [super::BUNDLE, super::TENANT_PROFILES] {
            assert!(!compiled_in.is_empty());
            assert!(
                compiled_in
                    .iter()
                    .all(|(name, text)| !name.is_empty() && !text.is_empty())
            );
        }
    }
}
