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

/// Where the session's durable record goes. Box-plane work is recorded per command before
/// transmission (`ARC-8`), and a failed append means the command is not sent (`STA-3`).
pub trait Journal {
    /// Append one command's record; its sequence number, or why it was refused.
    fn append(&mut self, entry: &Entry) -> Result<u64, String>;
    /// The record appended under `seq`, as stored.
    fn read(&self, seq: u64) -> Option<Entry>;
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
