//! The tau-web harness: the build's pin on the specification and the publisher-chosen inputs
//! it compiles in from that pinned tree (ADR-0031, gated in `build.rs`), and the harness worker's
//! wasm module: one recorded command over a pinned SSH connection through the relay
//! (`harness`). `testonly` is the tracer's, and only the `tracer` feature compiles it.

pub mod harness;
pub mod relay_auth;
#[cfg(feature = "tracer")]
pub mod testonly;

/// The spec commit this build was compiled from. Every release records it (ADR-0031).
pub const SPEC_COMMIT: &str = env!("TAU_SPEC_COMMIT");

include!(concat!(env!("OUT_DIR"), "/pinned.rs"));

/// What code in the harness worker's context can call, in every build.
#[cfg(target_arch = "wasm32")]
mod worker {
    use wasm_bindgen::prelude::wasm_bindgen;

    #[wasm_bindgen(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    /// The spec commit the module was built from, which the page shows once the worker is up.
    #[wasm_bindgen]
    pub fn spec_commit() -> String {
        super::SPEC_COMMIT.to_string()
    }

    /// Runs one command: `request` is JSON naming the machine, the relay's URL, the destination,
    /// the SSH user and the command. The page holds no reference to the worker's instance and
    /// defines no way to reach it; today only the tracer calls it there, over the DevTools
    /// protocol. Another same-origin script can load its own copy of the module, which in the
    /// served build refuses every machine for want of a pin.
    /// The pins, keys and journal never come from the request: the tracer build runs on
    /// `testonly`'s, and the served build on what it has stored, which is nothing yet. The report
    /// is JSON and carries no key material.
    #[wasm_bindgen]
    pub async fn run_command(request: String) -> Result<String, wasm_bindgen::JsValue> {
        use crate::harness::Target;
        let request: serde_json::Value = serde_json::from_str(&request)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("request: {e}")))?;
        let text = |name: &str| request[name].as_str().unwrap_or_default().to_string();
        let target = Target {
            machine: text("machine"),
            relay: text("relay"),
            host: text("host"),
            port: request["port"]
                .as_u64()
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(0),
            user: text("user"),
        };
        let command = text("command");
        #[cfg(feature = "tracer")]
        let report = crate::testonly::run(&target, command.as_bytes(), &request).await;
        #[cfg(not(feature = "tracer"))]
        let report = {
            let outcome = crate::harness::run_command(
                &NothingStored,
                &mut NothingStored,
                &NothingStored,
                &target,
                command.as_bytes(),
            )
            .await;
            serde_json::json!({ "outcome": crate::harness::report(&outcome) })
        };
        Ok(report.to_string())
    }

    /// The served build's sources: no local store exists yet (twr-ggw.5), so no pin, key or
    /// journal is stored, and every machine is refused before any contact (`CHN-R4`).
    #[cfg(not(feature = "tracer"))]
    struct NothingStored;

    #[cfg(not(feature = "tracer"))]
    impl crate::harness::PinSource for NothingStored {
        fn pin(&self, _machine: &str) -> Option<String> {
            None
        }
    }

    #[cfg(not(feature = "tracer"))]
    impl crate::harness::Journal for NothingStored {
        fn append(&mut self, _entry: &crate::harness::Entry) -> Result<u64, String> {
            Err("no journal is stored in this build".into())
        }

        fn read(&self, _seq: u64) -> Option<crate::harness::Entry> {
            None
        }
    }

    #[cfg(not(feature = "tracer"))]
    impl crate::harness::Credentials for NothingStored {
        fn ssh_key(&self) -> Option<russh::keys::PrivateKey> {
            None
        }

        fn relay_key(&self) -> Option<[u8; 32]> {
            None
        }
    }
}

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
