//! Fixed diagnostics and symbolic fields that can reach a durable collection wait.
//! Producers render these definitions; admission uses the same shapes before accepting a key.
#[derive(Clone, Copy)]
enum Destination {
    Direct,
    Settle,
    Both,
}
macro_rules! fixed {
    ($( $name:ident: $destination:ident = $text:literal; )*) => {
        $(pub(crate) const $name: &str = $text;)*
        const FIXED: &[(&str, Destination)] = &[$(($name, Destination::$destination)),*];
    };
}
fixed! {
    UNKNOWN_TASK: Both = "unknown task";
    TASK_ENCODING: Both = "task encoding";
    TASK_BOUNDARY: Both = "task credential boundary";
    WORK_BOUND: Both = "protected output withheld: protection work bound exceeded";
    VALUE_DEPTH: Both = "protected output withheld: value depth exceeded";
    ENCODING_DEPTH: Both = "protected output withheld: encoding depth exceeded";
    PROTECTED_UNAVAILABLE: Both = "protected output unavailable";
    FIELD_NAME: Both = "inference protected field name invalid";
    FIELD_COLLISION: Both = "inference output withheld after protected field collision";
    FRAGMENTS: Both = "inference output escaped fragment count exceeds the local bound";
    SCAN_UNAVAILABLE: Both = "required scan material unavailable; output withheld";
    SCAN_LENGTH: Both = "scan length";
    SCAN_MARKER: Both = "scan marker contains protected material; output withheld";
    OUTPUT_HEX: Both = "output hex";
    JOB_OUTPUT_HEX: Both = "job output hex";
    OUTPUT_COLLISION: Both = "output key collision after protection";
    UNLOCKED_SEED: Both = "response requires an unlocked seed";
    CREDENTIAL_SCAN: Both = "session credential has no response scan representation";
    DERIVATION: Both = "held credential derivation refused";
    REDACTION_MARKER: Both = "redaction marker cannot exclude held credentials";
    LOCKED: Direct = "locked";
    MISSING_PENDING_JOB: Direct = "missing pending job";
    MISSING_PENDING_IDENTITY: Direct = "missing pending identity";
    TARGET_DIFFERS: Direct = "resolved target differs from task machine";
    TARGET_REQUIRED: Direct = "resolved relay, host and user are required before Resume";
    PIN_REQUIRED: Direct = "trusted host pin missing; configure it before Resume";
    RESULT_ENCODING: Direct = "task result encoding";
    RESULT_PUBLICATION: Direct = "task result publication";
    COMMITTED_MISMATCH: Direct = "committed job record differs from its intent and cannot checkpoint; pending identity retained for inspection; to configure, Abandon local orchestration; remote effects and command holds remain";
    TASK_ENDED: Direct = "task ended";
    SESSION_OWNER: Direct = "session authority belongs to another task; bind a fresh session";
    BOUND_MACHINE: Direct = "fresh authority must bind only the task machine";
    APPROVAL_PENDING: Direct = "proposal approval pending; review the open requirements card and approve explicitly or reject before Resume";
    ACCEPTANCE: Direct = "fresh session requires acceptance of Acting on a goal with no brief";
    SESSIONS_ENDED: Direct = "sessions ended";
    NO_SESSION: Direct = "no live session";
    SESSION_ENDED: Direct = "session ended";
    LIVE_GOAL: Direct = "goal requires a live session";
    SUSPENSION: Direct = "reconciliation or verification required after suspension";
    CAP_EXHAUSTED: Direct = "session cap exhausted";
    SESSION_EXPIRED: Direct = "session expired";
    ISSUER_USAGE: Direct = "incompatible issuer usage";
    ISSUER_ACCEPTANCE: Direct = "incompatible or missing issuer acceptance";
    CLOCK_UNCERTAIN: Direct = "clock uncertain; verification required";
    CLOCK_RANGE: Direct = "clock evidence out of range";
    INVALID_SPEND: Direct = "invalid spend";
    SPEND_EXPONENT: Direct = "invalid spend exponent";
    NONNEGATIVE_SPEND: Direct = "invalid nonnegative spend";
    SPEND_SCALE: Direct = "spend scale";
    SPEND_PRECISION: Direct = "unsupported spend precision";
    SCAN_REQUIRED: Direct = "required scan material unavailable";
    SCAN_ENVELOPE: Direct = "invalid scan envelope";
    SCAN_ENCODING: Direct = "scan envelope encoding";
    SCAN_NONCANONICAL: Direct = "noncanonical scan envelope";
    SCAN_CIPHERTEXT: Direct = "invalid scan ciphertext";
    SCAN_NONCANONICAL_CIPHER: Direct = "noncanonical scan ciphertext";
    SCAN_AUTH: Direct = "scan authentication failed";
    SCAN_MATERIAL: Direct = "invalid scan material";
    SCAN_MATERIAL_ENCODING: Direct = "scan material encoding";
    SCAN_MATERIAL_SHAPE: Direct = "noncanonical or unsupported scan material";
    SCAN_INSTALL: Direct = "scan identity is not awaiting material";
    RUNNING: Direct = "recorded job is running; Resume inspects it again";
    FALLBACK: Direct = "task paused: diagnostic protection failed; inspect authority and configuration before Resume";
    STALE_TASK: Settle = "stale or ended task";
    NO_PENDING: Settle = "task has no pending job";
    NO_EVIDENCE: Settle = "no committed job evidence";
    UNTRUSTWORTHY: Settle = "job outcome is not trustworthy";
    NO_PROPOSAL: Settle = "pending task has no proposal";
    NO_EXIT: Settle = "missing job exit";
    CHECKPOINT_PROTECTION: Settle = "recorded job output requires protection before checkpoint";
    NO_VERIFICATION: Settle = "missing verification record";
    VERIFICATION_MISMATCH: Settle = "verification job mismatch";
    EXCERPT_PROTECTION: Settle = "verification excerpt requires protection before checkpoint";
    REVISION_EXHAUSTED: Settle = "task revision exhausted";
    JOURNAL_REFUSED: Settle = "journal refused";
    ENCRYPTION_REFUSED: Settle = "AES-GCM refused the record";
    MOVE_UNAVAILABLE: Settle = "move: FileSystemHandle.move() is not available";
}
pub(crate) const CHECKPOINT: &str = "recorded result could not be checkpointed: ";
#[derive(Clone, Copy)]
pub(crate) struct Shape(pub(crate) &'static str);
impl Shape {
    pub(crate) fn render(self, number: u64, job: &str, payload: &str) -> String {
        render(self.0, number, job, payload)
    }
}
macro_rules! shapes {
    ($( $name:ident: $destination:ident = $text:literal; )*) => {
        $(pub(crate) const $name: Shape = Shape($text);)*
        const SHAPES: &[(Shape, Destination)] = &[$(($name, Destination::$destination)),*];
    };
}
shapes! {
    NO_OUTCOME: Direct = "collection returned no outcome for pending call {number} job {job}; pending identity retained";
    IDENTITY_MISMATCH: Direct = "collection record identity mismatch for pending call {number} job {job}; pending identity retained";
    COLLECTION_PROTECTION: Direct = "collection failed for pending call {number} job {job}: diagnostic protection failed; pending identity retained";
    COLLECTION_FAILED: Direct = "collection failed for pending call {number}: {payload}; pending identity retained";
    EARLIER_APPEND: Settle = "an earlier append failed ({payload}), so none follows until the worker restarts";
    ENCRYPTION_CAP: Settle = "record {number} would be the 2^32nd encryption under this store's data key";
    ENTROPY: Settle = "getrandom: {payload}";
}
pub(crate) const COLLECTION: Shape =
    Shape("collection {payload} for pending call {number} job {job}; pending identity retained");
macro_rules! causes {
    ($( $name:ident: $detail:literal = $text:literal; )*) => {
        $(pub(crate) const $name: &str = $text;)*
        pub(crate) const CAUSES: &[(&str, bool)] = &[$(($name, $detail)),*];
    };
}
causes! {
    CHECKPOINT_UNCERTAIN: true = "evidence checkpoint not confirmed; observation remains uncertain";
    NOT_READ: true = "not read";
    READ_FAILED: true = "record read failed";
    MALFORMED: false = "has missing or malformed outcome metadata";
    NO_METADATA: false = "has no committed observation metadata";
    FOREIGN: false = "recorded a foreign machine record; record mismatch";
    COMMAND_MISMATCH: false = "recorded a command/record mismatch";
    MISSING: false = "recorded no record found";
    ENDED: false = "recorded process ended without a trustworthy exit status";
    INCOMPLETE: false = "recorded an incomplete job record";
    STILL_RUNNING: false = "recorded job still running";
    FINISHED: false = "returned a finished record without matching committed terminal evidence";
}
/// The callback sees complete reason shapes. Payload markers are holes, never known text.
/// All numbered fields are rendered from u64, and job fields have the tracked hexadecimal domain.
pub(crate) fn visit(mut accept: impl FnMut(String)) {
    for (text, destination) in FIXED
        .iter()
        .copied()
        .chain(SHAPES.iter().map(|(s, d)| (s.0, *d)))
    {
        if matches!(destination, Destination::Direct | Destination::Both) {
            accept(text.into());
        }
        if matches!(destination, Destination::Settle | Destination::Both) {
            accept(format!("{CHECKPOINT}{text}"));
        }
    }
    accept(decode_error(SCAN_NONCE_FIELD, "{payload}"));
    accept(length_parts(SCAN_NONCE_FIELD, "{number}", 12));
    for context in [
        OPFS_CONTEXT,
        crate::store::DIRECTORY,
        crate::store::STAGING,
        MOVE_CONTEXT,
    ] {
        accept(checkpoint(&storage_error(context, "{payload}")));
    }
    accept(checkpoint(&storage_error(
        &move_context(crate::store::STAGING, "{number}"),
        "{payload}",
    )));
    accept(checkpoint(&directory_missing()));
    // Arbitrary storage errors still have the fixed checkpoint prefix.
    accept(format!("{CHECKPOINT}{{payload}}"));
    for (cause, detail) in CAUSES {
        accept(COLLECTION.0.replace("{payload}", cause));
        if *detail {
            accept(
                COLLECTION
                    .0
                    .replace("{payload}", &with_detail(cause, "{payload}")),
            );
        }
    }
}

pub(crate) fn checkpoint(why: &str) -> String {
    format!("{CHECKPOINT}{why}")
}
pub(crate) fn decode_error(field: &str, detail: &str) -> String {
    format!("{field}: not unpadded base64url ({detail})")
}
pub(crate) fn decode_length(field: &str, actual: u64, expected: u64) -> String {
    length_parts(field, &decimal(actual), expected)
}
fn length_parts(field: &str, actual: &str, expected: u64) -> String {
    format!("{field}: {actual} bytes, not {expected}")
}

pub(crate) fn with_detail(category: &str, detail: &str) -> String {
    format!("{category}: {detail}")
}

pub(crate) const OPFS_CONTEXT: &str = "OPFS";
pub(crate) const MOVE_CONTEXT: &str = "move";
pub(crate) fn storage_error(context: &str, detail: &str) -> String {
    format!("{context}: {detail}")
}
pub(crate) fn move_context(from: &str, to: &str) -> String {
    format!("move {from} to {to}")
}
pub(crate) fn directory_missing() -> String {
    storage_error(crate::store::DIRECTORY, "not found")
}

pub(crate) const SCAN_NONCE_FIELD: &str = "scan nonce";
pub(crate) fn decimal(number: u64) -> String {
    number.to_string()
}
pub(crate) fn render(pattern: &str, number: u64, job: &str, payload: &str) -> String {
    pattern
        .replace("{number}", &decimal(number))
        .replace("{job}", job)
        .replace("{payload}", payload)
}
