//! One box-plane command over a pinned SSH connection through the relay, run in the harness
//! worker (`STA-1`): the host-key pin is looked up before any contact (`CHN-R4`), the relay
//! handshake is paid-tcp-relay's at `844e834` (`WIR-4`–`WIR-8`, owned there per `CHN-15`), the
//! host key is checked inside the SSH key exchange (`SEC-11`), and the command is appended to
//! the journal immediately before it leaves as one `exec` (`ARC-7`, `ARC-8`, `STA-4`).
//!
//! A refusal ends the attempt: nothing here retries or reconnects (`ARC-41`).

#[cfg(target_arch = "wasm32")]
mod run;
#[cfg(target_arch = "wasm32")]
mod wait;
#[cfg(any(target_arch = "wasm32", test))]
pub(crate) mod write;
#[cfg(target_arch = "wasm32")]
pub use run::*;
#[cfg(target_arch = "wasm32")]
pub use wait::Stop;
#[cfg(target_arch = "wasm32")]
pub use wait::stop_waits;

/// Where the session's durable record goes: the local store's journal (`crate::store`). Box-plane
/// work is recorded per command before transmission (`ARC-8`), and a failed append means the
/// command is not sent (`STA-3`).
#[allow(
    async_fn_in_trait,
    reason = "used generically and only on one thread: the browser's worker, or a host test"
)]
pub trait Journal {
    /// Check the unresolved-command hold and disposition before contact; repeat atomically
    /// at append.
    async fn check(&self, machine: &str) -> Result<(), AppendRefusal>;
    /// Commit an intent and its scope admission, returning its call identity only afterwards.
    async fn append(
        &mut self,
        entry: &Entry,
        approval: &crate::dispatch::Approval,
    ) -> Result<u64, AppendRefusal>;
    /// Commit the exit status's terminal record before reporting completion.
    async fn terminal(&mut self, terminal: &crate::dispatch::Terminal) -> Result<u64, String>;
    /// The record appended under `seq`, as replayed or applied.
    async fn read(&self, seq: u64) -> Option<Entry>;
    async fn intent(&self, call: u64) -> Option<crate::dispatch::Intent>;
    /// A read bypasses dispositions and records no intent.
    async fn collectable(&self, machine: &str) -> Result<Vec<crate::dispatch::Intent>, String>;
    async fn job_evidence(
        &mut self,
        evidence: &crate::jobs::Evidence,
    ) -> Result<crate::jobs::Report, String>;
    /// Stop before beginning an evidence append; an append already begun completes whole.
    #[cfg(target_arch = "wasm32")]
    async fn job_evidence_unless_stopped(
        &mut self,
        evidence: &crate::jobs::Evidence,
        stop: &Stop,
    ) -> Option<Result<crate::jobs::Report, String>> {
        if stop.stopped() {
            None
        } else {
            Some(self.job_evidence(evidence).await)
        }
    }
}

/// Where host-key pins come from. Read-only here: no path in this module stores a key it was
/// shown, so a first contact through the relay can never pin one (`CHN-R4`).
pub trait PinSource {
    /// The pin of `machine`'s host key, its SHA-256 fingerprint (`SHA256:…`), if one is stored.
    fn pin(&self, machine: &str) -> Option<crate::credential::HostKeyPin>;
}

/// One command's record: what is sent, to which machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub machine: String,
    pub command: Vec<u8>,
}

/// A policy refusal does not trip the store's failed-append latch.
#[derive(Debug, PartialEq, Eq)]
pub enum AppendRefusal {
    Storage(String),
    Policy(crate::dispatch::DispatchRefusal),
}

impl std::fmt::Display for AppendRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(why) => f.write_str(why),
            Self::Policy(record) => write!(f, "dispatch: {record:?}"),
        }
    }
}
