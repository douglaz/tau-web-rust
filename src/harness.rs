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
pub use run::*;

/// Where the session's durable record goes: the local store's journal (`crate::store`). Box-plane
/// work is recorded per command before transmission (`ARC-8`), and a failed append means the
/// command is not sent (`STA-3`).
#[allow(
    async_fn_in_trait,
    reason = "used generically and only on one thread: the browser's worker, or a host test"
)]
pub trait Journal {
    /// Check the standing disposition before any contact; repeated atomically at append.
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
    Disposition(crate::dispatch::DispatchRefusal),
}

impl std::fmt::Display for AppendRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(why) => f.write_str(why),
            Self::Disposition(record) => write!(
                f,
                "disposition {}: {:?}",
                record.disposition, record.continuation
            ),
        }
    }
}
