//! The tau-web harness: the build's pin on the specification and the publisher-chosen inputs
//! it compiles in from that pinned tree (ADR-0031, gated in `build.rs`), and the harness worker's
//! wasm module: one recorded command over a pinned SSH connection through the relay
//! (`harness`), the encrypted local store it records to (`store`), the operator seed and its
//! child keys (`seed`), the dedicated seed-backup ceremony, allocation indices for those keys
//! (`allocation`), and the credential types with their `SEC-5` rows (`credential`).
//! `testonly` is the tracer's, and only the `tracer` feature compiles it.

pub mod allocation;
pub mod credential;
pub mod dispatch;
pub mod harness;
pub mod jobs;
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
    use crate::dispatch::{Approval, Terminal};
    use crate::harness::{AppendRefusal, Entry, Journal};
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

    /// The only mnemonic output: the dedicated seed-backup display message, or null.
    #[wasm_bindgen]
    pub async fn seed_backup_display() -> String {
        local().lock().await.seed_backup_display().to_string()
    }

    #[wasm_bindgen]
    pub async fn seed_backup_answer() -> String {
        local().lock().await.seed_backup_answer().to_string()
    }

    #[wasm_bindgen]
    pub async fn seed_backup_reentry(words: Uint8Array) -> String {
        let secret = zeroize::Zeroizing::new(words.to_vec());
        words.fill(0, 0, words.length());
        local()
            .lock()
            .await
            .seed_backup_complete(Some(secret))
            .await
            .to_string()
    }

    #[wasm_bindgen]
    pub async fn seed_backup_skip() -> String {
        local()
            .lock()
            .await
            .seed_backup_complete(None)
            .await
            .to_string()
    }

    /// Called only on a fresh locked worker, after the page terminated the previous one.
    #[wasm_bindgen]
    pub async fn seed_backup_redisplay(passphrase: Uint8Array) -> String {
        let passphrase = take(&passphrase);
        local()
            .lock()
            .await
            .seed_backup_redisplay(passphrase)
            .await
            .to_string()
    }

    #[wasm_bindgen]
    pub async fn setup_approve() -> String {
        local().lock().await.setup_approve().await.to_string()
    }

    #[wasm_bindgen]
    pub async fn setup_answer(request: String) -> String {
        local()
            .lock()
            .await
            .setup_answer(&request)
            .await
            .to_string()
    }

    /// Exercise the real store allocator without adding a served consumer.
    #[cfg(feature = "tracer")]
    #[wasm_bindgen]
    pub async fn test_allocate(family: String) -> String {
        let family = match serde_json::from_value::<crate::allocation::Family>(family.into()) {
            Ok(family) => family,
            Err(_) => return serde_json::json!({"refused":"unknown family"}).to_string(),
        };
        let local = local();
        let mut local = local.lock().await;
        match local.store() {
            Some(store) => match store.allocate(family).await {
                Ok(identity) => serde_json::json!({"identity":identity}).to_string(),
                Err(reason) => serde_json::json!({"refused":reason}).to_string(),
            },
            None => serde_json::json!({"refused":"locked"}).to_string(),
        }
    }

    #[cfg(feature = "tracer")]
    #[wasm_bindgen]
    pub async fn test_seed_backup_fail_append() {
        if let Some(store) = local().lock().await.store() {
            store.storage().fail_next_move.set(true);
        }
    }

    /// The replayed calls, terminal evidence and dispositions, with the store's lock state and
    /// record numbers. No key material.
    #[wasm_bindgen]
    pub async fn store_state() -> String {
        local().lock().await.inspect().to_string()
    }

    /// Hold the real store writer until the tracer releases its promise.
    #[cfg(feature = "tracer")]
    #[wasm_bindgen]
    pub async fn test_writer(
        release: js_sys::Promise,
        acquired: js_sys::Function,
    ) -> Result<(), wasm_bindgen::JsValue> {
        let local = local();
        let _writer = local.lock().await;
        acquired.call0(&wasm_bindgen::JsValue::NULL)?;
        wasm_bindgen_futures::JsFuture::from(release).await?;
        Ok(())
    }

    /// Count completed held-request reads without acquiring the writer.
    #[cfg(feature = "tracer")]
    #[wasm_bindgen]
    pub fn test_completed_reads() -> u32 {
        crate::testonly::completed_reads()
    }

    /// The passphrase as the secret type; the JavaScript array it came in is zero-filled.
    fn take(passphrase: &Uint8Array) -> LocalPassphrase {
        let secret = LocalPassphrase::new(passphrase.to_vec());
        passphrase.fill(0, 0, passphrase.length());
        secret
    }

    /// The store's journal, which holds the store only inside an append or a read, so a command
    /// awaiting its record never holds it.
    struct StoreJournal(Rc<Mutex<Harness>>);

    impl Journal for StoreJournal {
        async fn check(&self, machine: &str) -> Result<(), AppendRefusal> {
            match self.0.lock().await.store() {
                Some(store) => store.check(machine).await,
                None => Err(AppendRefusal::Storage("the store is locked".into())),
            }
        }

        async fn terminal(&mut self, terminal: &Terminal) -> Result<u64, String> {
            match self.0.lock().await.store() {
                Some(store) => store.terminal(terminal).await,
                None => Err("the store is locked".into()),
            }
        }

        async fn append(
            &mut self,
            entry: &Entry,
            approval: &Approval,
        ) -> Result<u64, AppendRefusal> {
            match self.0.lock().await.store() {
                Some(store) => store.append(entry, approval).await,
                None => Err(AppendRefusal::Storage("the store is locked".into())),
            }
        }

        async fn read(&self, seq: u64) -> Option<Entry> {
            match self.0.lock().await.store() {
                Some(store) => store.read(seq).await,
                None => None,
            }
        }

        async fn intent(&self, call: u64) -> Option<crate::dispatch::Intent> {
            match self.0.lock().await.store() {
                Some(store) => store.intent(call).await,
                None => None,
            }
        }

        async fn collectable(&self, machine: &str) -> Result<Vec<crate::dispatch::Intent>, String> {
            match self.0.lock().await.store() {
                Some(store) => store.collectable(machine).await,
                None => Err("the store is locked".into()),
            }
        }

        async fn job_evidence(
            &mut self,
            evidence: &crate::jobs::Evidence,
        ) -> Result<crate::jobs::Report, String> {
            match self.0.lock().await.store() {
                Some(store) => store.job_evidence(evidence).await,
                None => Err("the store is locked".into()),
            }
        }

        async fn job_evidence_unless_stopped(
            &mut self,
            evidence: &crate::jobs::Evidence,
            stop: &crate::harness::Stop,
        ) -> Option<Result<crate::jobs::Report, String>> {
            crate::harness::write::unless_stopped(
                self.0.lock(),
                stop.notified(),
                || stop.stopped(),
                async |mut local| match local.store() {
                    Some(store) => store.job_evidence(evidence).await,
                    None => Err("the store is locked".into()),
                },
            )
            .await
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
        request_operation(request, false).await
    }

    /// Stop the current unresolved-command waits on this machine. Settles nothing.
    #[wasm_bindgen]
    pub fn stop_waits(machine: String) -> usize {
        crate::harness::stop_waits(&machine)
    }

    /// Read a machine's outstanding job records, waiting for its running commands. A call whose
    /// own dispatch still awaits its record is reported not read, and is not read separately.
    #[wasm_bindgen]
    pub async fn collect_jobs(request: String) -> Result<String, wasm_bindgen::JsValue> {
        request_operation(request, true).await
    }

    async fn request_operation(
        request: String,
        collect: bool,
    ) -> Result<String, wasm_bindgen::JsValue> {
        use crate::harness::Target;
        let request: serde_json::Value = serde_json::from_str(&request)
            .map_err(|e| wasm_bindgen::JsValue::from_str(&format!("request: {e}")))?;
        if !crate::harness::valid_request(&request) {
            return Ok(serde_json::json!({"outcome":{"refused":"request"}}).to_string());
        }
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
        if let Some(reason) = local.lock().await.dispatch_refusal() {
            return Ok(serde_json::json!({ "outcome": { "refused": reason } }).to_string());
        }
        let mut journal = StoreJournal(local);
        #[cfg(feature = "tracer")]
        let report =
            crate::testonly::run(&target, command.as_bytes(), &request, &mut journal, collect)
                .await
                .map_err(|e| wasm_bindgen::JsValue::from_str(&e))?;
        #[cfg(not(feature = "tracer"))]
        let report = {
            if collect {
                return Ok(
                    match crate::harness::collect_jobs(
                        &NothingStored,
                        &mut journal,
                        &NothingStored,
                        &target,
                    )
                    .await
                    {
                        Ok(records) => {
                            serde_json::json!({"outcome":{"collected":records}}).to_string()
                        }
                        Err(refusal) => {
                            serde_json::json!({"outcome":refusal.to_json()}).to_string()
                        }
                    },
                );
            }
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

    /// The served build's sources: no pin or key is stored yet (twr-ggw.11). An unapproved
    /// machine is refused at the journal check; an approved entry reaches the pin lookup and
    /// is refused there, before any contact and any append (`CHN-R4`).
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
