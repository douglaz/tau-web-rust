//! The tau-web harness: the build's pin on the specification and the publisher-chosen inputs
//! it compiles in from that pinned tree (ADR-0031, gated in `build.rs`), and the harness worker's
//! wasm module: one recorded command over a pinned SSH connection through the relay
//! (`harness`), the encrypted local store it records to (`store`), the operator seed and its
//! child keys (`seed`), and the credential types with their `SEC-5` rows (`credential`).
//! `testonly` is the tracer's, and only the `tracer` feature compiles it.

pub mod credential;
pub mod harness;
pub mod relay_auth;
pub mod seed;
pub mod store;
#[cfg(feature = "tracer")]
pub mod testonly;

/// The spec commit this build was compiled from. Every release records it (ADR-0031).
pub const SPEC_COMMIT: &str = env!("TAU_SPEC_COMMIT");

include!(concat!(env!("OUT_DIR"), "/pinned.rs"));

/// What code in the harness worker's context can call, in every build.
#[cfg(target_arch = "wasm32")]
mod worker {
    use crate::credential::LocalPassphrase;
    use crate::harness::{Entry, Journal};
    use crate::store::Local;
    use crate::store::opfs::{Opfs, WebCrypto};
    use js_sys::Uint8Array;
    use std::rc::Rc;
    use tokio::sync::Mutex;
    use wasm_bindgen::prelude::wasm_bindgen;

    type Harness = Local<Opfs, WebCrypto>;

    thread_local! {
        /// The worker's one store. `worker.js` opens it only once it holds the writer lock.
        static LOCAL: Rc<Mutex<Harness>> =
            Rc::new(Mutex::new(Local::new(Opfs::default(), WebCrypto)));
    }

    fn local() -> Rc<Mutex<Harness>> {
        LOCAL.with(Rc::clone)
    }

    #[wasm_bindgen(start)]
    fn start() {
        console_error_panic_hook::set_once();
    }

    /// The spec commit the module was built from, which the page shows once the worker is up.
    #[wasm_bindgen]
    pub fn spec_commit() -> String {
        super::SPEC_COMMIT.to_string()
    }

    /// Reads the store's directory, once `worker.js` holds the writer lock (`STA-1`, `STA-7`):
    /// the state the page shows, as JSON.
    #[wasm_bindgen]
    pub async fn open() -> String {
        local().lock().await.open().await.to_string()
    }

    /// Creates the store with the passphrase's UTF-8 bytes, which are zero-filled at once.
    #[wasm_bindgen]
    pub async fn create(passphrase: Uint8Array) -> String {
        let passphrase = take(&passphrase);
        local().lock().await.create(passphrase).await.to_string()
    }

    /// Unlocks the store with the passphrase's UTF-8 bytes, which are zero-filled at once.
    #[wasm_bindgen]
    pub async fn unlock(passphrase: Uint8Array) -> String {
        let passphrase = take(&passphrase);
        local().lock().await.unlock(passphrase).await.to_string()
    }

    /// The replayed state, for the tracer: whether the store is locked, its record numbers and
    /// its recorded commands. No key material.
    #[wasm_bindgen]
    pub async fn store_state() -> String {
        local().lock().await.inspect().to_string()
    }

    /// The passphrase as the secret type; the JavaScript array it came in is zero-filled.
    fn take(passphrase: &Uint8Array) -> LocalPassphrase {
        let secret = LocalPassphrase::new(passphrase.to_vec());
        passphrase.fill(0, 0, passphrase.length());
        secret
    }

    /// The store's journal, which holds the store only inside an append or a read, so a command
    /// in flight never holds it.
    struct StoreJournal(Rc<Mutex<Harness>>);

    impl Journal for StoreJournal {
        async fn append(&mut self, entry: &Entry) -> Result<u64, String> {
            match self.0.lock().await.store() {
                Some(store) => store.append(entry).await,
                None => Err("the store is locked".into()),
            }
        }

        async fn read(&self, seq: u64) -> Option<Entry> {
            match self.0.lock().await.store() {
                Some(store) => store.read(seq).await,
                None => None,
            }
        }
    }

    /// Runs one command: `request` is JSON naming the machine, the relay's URL, the destination,
    /// the SSH user and the command. The page holds no reference to the worker's instance and
    /// defines no way to reach it; today only the tracer calls it there, over the DevTools
    /// protocol. Another same-origin script can load its own copy of the module, which holds no
    /// unlocked store. While the store is not unlocked, every request is refused before any
    /// contact (`STA-23`). The pins, keys and journal never come from the request: the journal
    /// is the store's, and the tracer build runs on `testonly`'s pins and keys, the served build
    /// on what it has stored, which is none yet. The report is JSON and carries no key material.
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
        let local = local();
        if local.lock().await.store().is_none() {
            return Ok(serde_json::json!({ "outcome": { "refused": "locked" } }).to_string());
        }
        let mut journal = StoreJournal(local);
        #[cfg(feature = "tracer")]
        let report = crate::testonly::run(&target, command.as_bytes(), &request, &mut journal)
            .await
            .map_err(|e| wasm_bindgen::JsValue::from_str(&e))?;
        #[cfg(not(feature = "tracer"))]
        let report = {
            let outcome = crate::harness::run_command(
                &NothingStored,
                &mut journal,
                &NothingStored,
                &target,
                command.as_bytes(),
            )
            .await;
            serde_json::json!({ "outcome": crate::harness::report(&outcome) })
        };
        Ok(report.to_string())
    }

    /// The tracer build's switch on the store: the next append fails at its move, a real OPFS
    /// call (`testonly::run`).
    #[cfg(feature = "tracer")]
    impl crate::testonly::FailAppend for StoreJournal {
        async fn fail_next_append(&self, fail: bool) {
            if let Some(store) = self.0.lock().await.store() {
                store.storage().fail_next_move.set(fail);
            }
        }

        async fn commands(&self) -> Vec<(u64, Entry)> {
            match self.0.lock().await.store() {
                Some(store) => store.commands().to_vec(),
                None => Vec::new(),
            }
        }
    }

    /// The served build's sources: no pin or key is stored yet (twr-ggw.11), so every machine is
    /// refused at the pin lookup, before any contact and any append (`CHN-R4`).
    #[cfg(not(feature = "tracer"))]
    struct NothingStored;

    #[cfg(not(feature = "tracer"))]
    impl crate::harness::PinSource for NothingStored {
        fn pin(&self, _machine: &str) -> Option<crate::credential::HostKeyPin> {
            None
        }
    }

    #[cfg(not(feature = "tracer"))]
    impl crate::harness::Credentials for NothingStored {
        fn ssh_key(&self) -> Option<&crate::credential::SshClientKey> {
            None
        }

        fn relay_key(&self) -> Option<&crate::credential::RelayKey> {
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
