//! Executable case names and immutable parameter slots; no completion predicates.
use serde_json::{Value, json};
use std::collections::BTreeMap;

const CASES: &[(&str, &str)] = &[
    (
        "main.c001.p001",
        "the served build loads, derives bound credentials and has no pin or request hook",
    ),
    ("main.c002.p001", "create and unlock (twr-ggw.5, CNF-82)"),
    (
        "seed_cases.c001.p001",
        "seed-backup collision control 1: tracer",
    ),
    (
        "seed_cases.c001.p002",
        "seed-backup collision control 2: tracer",
    ),
    (
        "seed_cases.c001.p003",
        "seed-backup collision control 3: tracer",
    ),
    (
        "seed_cases.c001.p004",
        "seed-backup collision control 4: tracer",
    ),
    (
        "seed_cases.c002.p001",
        "seed-backup create, hidden answer and mismatch: tracer",
    ),
    (
        "seed_cases.c003.p001",
        "seed-backup full re-entry and restart: tracer",
    ),
    (
        "seed_cases.c003.p002",
        "seed-backup explicit skip and restart: tracer",
    ),
    ("seed_cases.c004.p001", "seed-backup skip failed OPFS move"),
    (
        "seed_cases.c004.p002",
        "seed-backup full re-entry failed OPFS move",
    ),
    (
        "seed_cases.c005.p001",
        "seed-backup creation-finishing unlock: tracer",
    ),
    (
        "seed_cases.c006.p001",
        "seed-backup interrupted display by lock: tracer",
    ),
    (
        "seed_cases.c006.p002",
        "seed-backup interrupted display by hidden: tracer",
    ),
    (
        "seed_cases.c006.p003",
        "seed-backup interrupted display by pagehide: tracer",
    ),
    (
        "seed_cases.c006.p004",
        "seed-backup interrupted display by pageshow: tracer",
    ),
    (
        "seed_cases.c006.p005",
        "seed-backup interrupted display by close: tracer",
    ),
    (
        "seed_cases.c006.p006",
        "seed-backup interrupted display by crash: tracer",
    ),
    (
        "seed_cases.c006.p007",
        "seed-backup interrupted answering by lock: tracer",
    ),
    (
        "seed_cases.c006.p008",
        "seed-backup interrupted answering by hidden: tracer",
    ),
    (
        "seed_cases.c006.p009",
        "seed-backup interrupted answering by pagehide: tracer",
    ),
    (
        "seed_cases.c006.p010",
        "seed-backup interrupted answering by pageshow: tracer",
    ),
    (
        "seed_cases.c006.p011",
        "seed-backup interrupted answering by close: tracer",
    ),
    (
        "seed_cases.c006.p012",
        "seed-backup interrupted answering by crash: tracer",
    ),
    (
        "seed_cases.c007.p001",
        "seed-backup re-display ends dispatch connections and waits",
    ),
    (
        "seed_cases.c001.p005",
        "seed-backup collision control 1: served",
    ),
    (
        "seed_cases.c001.p006",
        "seed-backup collision control 2: served",
    ),
    (
        "seed_cases.c001.p007",
        "seed-backup collision control 3: served",
    ),
    (
        "seed_cases.c001.p008",
        "seed-backup collision control 4: served",
    ),
    (
        "seed_cases.c002.p002",
        "seed-backup create, hidden answer and mismatch: served",
    ),
    (
        "seed_cases.c003.p003",
        "seed-backup full re-entry and restart: served",
    ),
    (
        "seed_cases.c003.p004",
        "seed-backup explicit skip and restart: served",
    ),
    (
        "seed_cases.c005.p002",
        "seed-backup creation-finishing unlock: served",
    ),
    (
        "seed_cases.c006.p013",
        "seed-backup interrupted display by lock: served",
    ),
    (
        "seed_cases.c006.p014",
        "seed-backup interrupted display by hidden: served",
    ),
    (
        "seed_cases.c006.p015",
        "seed-backup interrupted display by pagehide: served",
    ),
    (
        "seed_cases.c006.p016",
        "seed-backup interrupted display by pageshow: served",
    ),
    (
        "seed_cases.c006.p017",
        "seed-backup interrupted display by close: served",
    ),
    (
        "seed_cases.c006.p018",
        "seed-backup interrupted display by crash: served",
    ),
    (
        "seed_cases.c006.p019",
        "seed-backup interrupted answering by lock: served",
    ),
    (
        "seed_cases.c006.p020",
        "seed-backup interrupted answering by hidden: served",
    ),
    (
        "seed_cases.c006.p021",
        "seed-backup interrupted answering by pagehide: served",
    ),
    (
        "seed_cases.c006.p022",
        "seed-backup interrupted answering by pageshow: served",
    ),
    (
        "seed_cases.c006.p023",
        "seed-backup interrupted answering by close: served",
    ),
    (
        "seed_cases.c006.p024",
        "seed-backup interrupted answering by crash: served",
    ),
    (
        "seed_cases.c007.p002",
        "seed-backup re-display requires passphrase: served",
    ),
    ("setup_cases.c001.p001", "setup ceremony refusal: tracer"),
    (
        "setup_cases.c002.p001",
        "setup batch card and indices: tracer",
    ),
    (
        "setup_cases.c003.p001",
        "setup rejects non-operator inputs: tracer",
    ),
    (
        "setup_cases.c004.p001",
        "setup class questions with nothing preselected: tracer",
    ),
    ("setup_cases.c001.p002", "setup ceremony refusal: served"),
    (
        "setup_cases.c002.p002",
        "setup batch card and indices: served",
    ),
    (
        "setup_cases.c003.p002",
        "setup rejects non-operator inputs: served",
    ),
    (
        "setup_cases.c004.p002",
        "setup class questions with nothing preselected: served",
    ),
    (
        "main.c003.p001",
        "4. the page runs under ARC-33's policy (AC6)",
    ),
    (
        "main.c004.p001",
        "3. a machine with no pin is refused before any contact (AC3)",
    ),
    (
        "main.c005.p001",
        "oversized launch refuses before intent and contact (twr-ggw.71)",
    ),
    (
        "main.c006.p001",
        "5. a wrongly signed AUTH is refused, and nothing is dialed",
    ),
    (
        "main.c007.p001",
        "1. the command is recorded, then sent, and reconciles (AC1)",
    ),
    (
        "main.c008.p001",
        "a failed append is not applied (twr-ggw.5 AC2, STA-3)",
    ),
    (
        "main.c009.p001",
        "close without exit status stays unresolved (twr-ggw.7, STA-8)",
    ),
    (
        "main.c010.p001",
        "dispositions refuse before contact and continuing permits dispatch (twr-ggw.7, STA-24)",
    ),
    (
        "main.c011.p001",
        "2. a host key other than the pin halts the connection (AC2)",
    ),
    (
        "main.c012.p001",
        "6. a relay key with no pass is refused for `pass` (twr-ggw.3)",
    ),
    (
        "main.c013.p001",
        "7. an unrecorded destination is refused for `destination` (twr-ggw.3)",
    ),
    (
        "main.c014.p001",
        "8. a dial the pace does not allow is refused for `pace` (twr-ggw.3)",
    ),
    ("main.c015.p001", "fail closed (twr-ggw.5 AC1, CNF-82)"),
    (
        "main.c016.p001",
        "reload requires unlock again (twr-ggw.5 AC3, CNF-82)",
    ),
    (
        "main.c017.p001",
        "explicit lock requires unlock again, and ends its exec (twr-ggw.5 AC3, CNF-82)",
    ),
    (
        "main.c018.p001",
        "ordinary page hide retains its worker and scheduled command (CNF-82)",
    ),
    (
        "main.c019.p001",
        "a killed worker surfaces an unresolved command and requires unlock (twr-ggw.7, CNF-39)",
    ),
    ("main.c020.p001", "one writer (twr-ggw.5, STA-1, STA-7)"),
    (
        "main.c021.p001",
        "persistent storage (twr-ggw.5 AC6, STA-23)",
    ),
    (
        "typed_cases.c001.p001",
        "typed reset bars commands before contact until durable confirmation",
    ),
    (
        "typed_cases.c002.p001",
        "typed running-system disposition destructive_reinstall: pinned attempt and collection stay permitted",
    ),
    (
        "typed_cases.c002.p002",
        "typed running-system disposition abandonment: pinned attempt and collection stay permitted",
    ),
    (
        "typed_cases.c002.p003",
        "typed running-system disposition as_if_done: pinned attempt and collection stay permitted",
    ),
    (
        "typed_cases.c002.p004",
        "typed running-system disposition as_if_not_done: pinned attempt and collection stay permitted",
    ),
    (
        "job_cases.c001.p001",
        "job drop waits without a second launch (CNF-40)",
    ),
    (
        "job_cases.c002.p001",
        "held request on a dropped running command waits without a second launch (CNF-40)",
    ),
    (
        "job_cases.c003.p001",
        "completed dropped job returns its recorded output and exit (CNF-54)",
    ),
    (
        "job_cases.c004.p001",
        "reboot keeps records; ended and missing calls stay unresolved (CNF-55)",
    ),
    (
        "job_cases.c005.p001",
        "background stdout holder does not hold the command open (STA-20a)",
    ),
    (
        "job_cases.c006.p001",
        "every live command is compared and mismatch survives reload (CNF-56)",
    ),
    (
        "job_cases.c007.p001",
        "collection under each standing disposition preserves it (CNF-110)",
    ),
    (
        "job_cases.c008.p001",
        "live signal reports ended evidence without a terminal",
    ),
    (
        "job_cases.c009.p001",
        "collection continues past an invalid job record file",
    ),
    (
        "hold_cases.c001.p001",
        "held request after replay collects to finished and caller must ask again (CNF-40)",
    ),
    (
        "hold_cases.c002.p001",
        "simultaneous requests share exactly one dispatch result (CNF-40)",
    ),
    (
        "hold_cases.c003.p001",
        "stopped held collection leaves writer free and settles nothing (STA-20)",
    ),
    (
        "hold_cases.c004.p001",
        "stopped evidence append retains the completed read through the worker (STA-20)",
    ),
    (
        "hold_cases.c004.p002",
        "evidence append error retains the completed read and unresolved-command hold (STA-20)",
    ),
    (
        "hold_cases.c005.p001",
        "stopping a shared-result wait does not stop its own dispatch (STA-20)",
    ),
    (
        "hold_cases.c006.p001",
        "legacy and unreadable commands all hold without inventing a record (STA-20)",
    ),
    (
        "hold_cases.c007.p001",
        "held unreachable machines answer once with why nothing was read (STA-20)",
    ),
    (
        "hold_cases.c008.p001",
        "destructive replacement and an unnamed unresolved command both restrict dispatch (STA-24)",
    ),
    (
        "binding_cases.c001.p001",
        "binding is an operator act before contact: tracer",
    ),
    (
        "binding_cases.c002.p001",
        "bound credentials and machine authorized keys: tracer",
    ),
    (
        "binding_cases.c003.p001",
        "exposure ledger survives restart without live bindings: tracer",
    ),
    (
        "binding_cases.c004.p001",
        "seed-backup re-display ends bindings: tracer",
    ),
    (
        "binding_cases.c001.p002",
        "binding is an operator act before contact: served",
    ),
    (
        "binding_cases.c002.p002",
        "bound credentials and machine authorized keys: served",
    ),
    (
        "binding_cases.c003.p002",
        "exposure ledger survives restart without live bindings: served",
    ),
    (
        "binding_cases.c004.p002",
        "seed-backup re-display ends bindings: served",
    ),
    (
        "mode_cases.c001.p001",
        "acceptable weaker modes and pre-contact signature refusal: tracer",
    ),
    (
        "mode_cases.c001.p002",
        "acceptable weaker modes and pre-contact signature refusal: served",
    ),
    (
        "inference_cases.c004.p001",
        "procured inference: tiers, metadata, routing, unresolved spend and redirects",
    ),
    (
        "inference_cases.c005.p001",
        "held completion does not bar the next inference request",
    ),
    (
        "inference_cases.c006.p001",
        "lost completion survives crash and unlock without replay send",
    ),
    (
        "inference_cases.c001.p001",
        "session end during box-plane intent commit prevents exec",
    ),
    (
        "inference_cases.c002.p001",
        "session end before collection read prevents exec",
    ),
    (
        "inference_cases.c002.p002",
        "session end stops held read before acquiring writer",
    ),
    (
        "inference_cases.c003.p001",
        "session end cancels a sent held read",
    ),
    (
        "inference_cases.c003.p002",
        "session end cancels a sent collection read",
    ),
    (
        "session_end_cases.c005.p001",
        "session end fences a cold probe queued ahead of the end writer",
    ),
    (
        "session_end_cases.c006.p001",
        "revoke cold probe control during session end",
    ),
    (
        "session_end_cases.c001.p001",
        "session end closes command at challenge",
    ),
    (
        "session_end_cases.c001.p002",
        "session end closes command at verdict",
    ),
    (
        "session_end_cases.c001.p003",
        "session end closes command at identification",
    ),
    (
        "session_end_cases.c001.p004",
        "session end closes command at kex",
    ),
    (
        "session_end_cases.c001.p005",
        "session end closes command at auth",
    ),
    (
        "session_end_cases.c001.p006",
        "session end closes command at auth-rekey",
    ),
    (
        "session_end_cases.c001.p007",
        "session end closes command at connected-rekey",
    ),
    (
        "session_end_cases.c001.p008",
        "session end closes held at challenge",
    ),
    (
        "session_end_cases.c001.p009",
        "session end closes held at verdict",
    ),
    (
        "session_end_cases.c001.p010",
        "session end closes held at identification",
    ),
    (
        "session_end_cases.c001.p011",
        "session end closes held at kex",
    ),
    (
        "session_end_cases.c001.p012",
        "session end closes held at auth",
    ),
    (
        "session_end_cases.c001.p013",
        "session end closes held at auth-rekey",
    ),
    (
        "session_end_cases.c001.p014",
        "session end closes held at connected-rekey",
    ),
    (
        "session_end_cases.c001.p015",
        "session end closes collection at challenge",
    ),
    (
        "session_end_cases.c001.p016",
        "session end closes collection at verdict",
    ),
    (
        "session_end_cases.c001.p017",
        "session end closes collection at identification",
    ),
    (
        "session_end_cases.c001.p018",
        "session end closes collection at kex",
    ),
    (
        "session_end_cases.c001.p019",
        "session end closes collection at auth",
    ),
    (
        "session_end_cases.c001.p020",
        "session end closes collection at auth-rekey",
    ),
    (
        "session_end_cases.c001.p021",
        "session end closes collection at connected-rekey",
    ),
    (
        "session_end_cases.c007.p001",
        "session end closes a running command without DISCONNECT and preserves unresolved replay",
    ),
    (
        "session_end_cases.c008.p001",
        "session end closes command during begun evidence append with rekey stalled",
    ),
    (
        "session_end_cases.c008.p002",
        "session end closes held during begun evidence append with rekey stalled",
    ),
    (
        "session_end_cases.c008.p003",
        "session end closes collection during begun evidence append with rekey stalled",
    ),
    (
        "session_end_cases.c002.p001",
        "session end fences unbound writer ahead of end snapshot",
    ),
    (
        "session_end_cases.c002.p002",
        "session end fences unbound writer behind end snapshot",
    ),
    (
        "session_end_cases.c002.p003",
        "session end fences bound writer ahead of end snapshot",
    ),
    (
        "session_end_cases.c002.p004",
        "session end fences signature writer ahead of end snapshot",
    ),
    (
        "session_end_cases.c002.p005",
        "session end fences signature writer behind end snapshot",
    ),
    (
        "session_end_cases.c002.p006",
        "session end fences collection writer ahead of end snapshot",
    ),
    (
        "session_end_cases.c003.p001",
        "session end withholds completion body at finish_writer",
    ),
    (
        "session_end_cases.c003.p002",
        "session end withholds completion body at response_writer",
    ),
    (
        "session_end_cases.c004.p001",
        "session end fences queued command evidence append",
    ),
    (
        "session_end_cases.c004.p002",
        "session end completes begun command evidence append",
    ),
    (
        "session_end_cases.c004.p003",
        "session end fences queued held evidence append",
    ),
    (
        "session_end_cases.c004.p004",
        "session end completes begun held evidence append",
    ),
    (
        "session_end_cases.c004.p005",
        "session end fences queued collection evidence append",
    ),
    (
        "session_end_cases.c004.p006",
        "session end completes begun collection evidence append",
    ),
    (
        "lifecycle_cases.c013.p001",
        "processed freeze and return preserve a locked store and allow later explicit unlock (CNF-7/82)",
    ),
    (
        "lifecycle_cases.c007.p001",
        "dedicated standing approvals survive hide with original prerequisites and independent withdrawal (CNF-86)",
    ),
    (
        "lifecycle_cases.c008.p001",
        "dedicated Lock ends old approval; a separately admitted successor alone can reset (CNF-86)",
    ),
    (
        "lifecycle_cases.c008.p002",
        "dedicated worker restart ends old approval; a separately admitted successor alone can reset (CNF-86)",
    ),
    (
        "lifecycle_cases.c009.p001",
        "original fixture aggregate cap includes an in-flight lost reply and never renews (CNF-69/82)",
    ),
    (
        "lifecycle_cases.c012.p001",
        "never-transmitted original mint continues unchanged once after real clock repair (CNF-69/82)",
    ),
    (
        "lifecycle_cases.c001.p001",
        "hidden scheduled work retains original session limits and scan reference (CNF-7/69/82/95/102)",
    ),
    (
        "lifecycle_cases.c010.p001",
        "original expiry equality fences actual hidden sends and cannot be renewed by credit (CNF-69/82)",
    ),
    (
        "lifecycle_cases.c002.p001",
        "page-started goal keeps scheduled hidden context and scans actual model input (CNF-82/95/102)",
    ),
    (
        "lifecycle_cases.c003.p001",
        "freeze refuses a queued command append before it begins (CNF-29/40/82)",
    ),
    (
        "lifecycle_cases.c003.p002",
        "freeze finishes a begun command append whole and fences its send (CNF-29/40/82)",
    ),
    (
        "lifecycle_cases.c004.p001",
        "freeze fences stale model and publication results without replacing their intent (CNF-29/69/82/102)",
    ),
    (
        "lifecycle_cases.c005.p001",
        "actual transport allows the nearest eligible queued send (CNF-69/82)",
    ),
    (
        "lifecycle_cases.c005.p002",
        "actual transport rechecks authority after a queued send boundary (CNF-69/82)",
    ),
    (
        "lifecycle_cases.c006.p001",
        "actual transport refuses carried bytes introduced after request protection (CNF-69/95)",
    ),
    (
        "lifecycle_cases.c011.p001",
        "actual send rejects a reference revision changed after earlier request protection (CNF-95)",
    ),
    (
        "lifecycle_repairs.c008.p001",
        "original mint key custody survives freeze queued for terminal append with use withheld",
    ),
    (
        "lifecycle_repairs.c008.p002",
        "original mint key custody survives freeze during begun terminal append with use withheld",
    ),
    (
        "lifecycle_repairs.c001.p001",
        "clock response queued for terminal append cannot repair after processed freeze",
    ),
    (
        "lifecycle_repairs.c001.p002",
        "clock response during begun terminal append cannot repair after processed freeze",
    ),
    (
        "lifecycle_repairs.c002.p001",
        "command acquired writer validates affected session eligible before intent",
    ),
    (
        "lifecycle_repairs.c002.p002",
        "command acquired writer validates affected session expired before intent",
    ),
    (
        "lifecycle_repairs.c002.p003",
        "command acquired writer validates affected session exhausted before intent",
    ),
    (
        "lifecycle_repairs.c002.p004",
        "command acquired writer validates affected session uncertain before intent",
    ),
    (
        "lifecycle_repairs.c002.p005",
        "command acquired writer validates affected session ended before intent",
    ),
    (
        "lifecycle_repairs.c006.p001",
        "final command release retains committed evidence after session eligible",
    ),
    (
        "lifecycle_repairs.c006.p002",
        "final command release retains committed evidence after session expired",
    ),
    (
        "lifecycle_repairs.c006.p003",
        "final command release retains committed evidence after session ended",
    ),
    (
        "lifecycle_repairs.c006.p004",
        "final command release retains committed evidence after session uncertain",
    ),
    (
        "lifecycle_repairs.c005.p001",
        "individual session eligible during begun goal source append fences document GET",
    ),
    (
        "lifecycle_repairs.c005.p002",
        "individual session expired during begun goal source append fences document GET",
    ),
    (
        "lifecycle_repairs.c005.p003",
        "individual session uncertain during begun goal source append fences document GET",
    ),
    (
        "lifecycle_repairs.c003.p001",
        "page goal document document_send checks affected session eligible",
    ),
    (
        "lifecycle_repairs.c003.p002",
        "page goal document document_send checks affected session expired",
    ),
    (
        "lifecycle_repairs.c003.p003",
        "page goal document document_send checks affected session uncertain",
    ),
    (
        "lifecycle_repairs.c003.p004",
        "page goal document document_send checks affected session ended",
    ),
    (
        "lifecycle_repairs.c003.p005",
        "page goal document document_release checks affected session eligible",
    ),
    (
        "lifecycle_repairs.c003.p006",
        "page goal document document_release checks affected session expired",
    ),
    (
        "lifecycle_repairs.c003.p007",
        "page goal document document_release checks affected session uncertain",
    ),
    (
        "lifecycle_repairs.c003.p008",
        "page goal document document_release checks affected session ended",
    ),
    (
        "lifecycle_repairs.c004.p001",
        "actual final postMessage and DOM keep current state after session eligible",
    ),
    (
        "lifecycle_repairs.c004.p002",
        "actual final postMessage and DOM keep current state after session expired",
    ),
    (
        "lifecycle_repairs.c004.p003",
        "actual final postMessage and DOM keep current state after session uncertain",
    ),
    (
        "lifecycle_repairs.c004.p004",
        "actual final postMessage and DOM keep current state after session ended",
    ),
    (
        "lifecycle_repairs.c007.p001",
        "prepared scanned publication validates final authority after eligible",
    ),
    (
        "lifecycle_repairs.c007.p002",
        "prepared scanned publication validates final authority after expired",
    ),
    (
        "lifecycle_repairs.c007.p003",
        "prepared scanned publication validates final authority after freeze",
    ),
    (
        "lifecycle_repairs.c009.p001",
        "queued actual ordinary publication refreshes current controls after individual session eligible",
    ),
    (
        "lifecycle_repairs.c009.p002",
        "queued actual ordinary publication refreshes current controls after individual session ended",
    ),
    (
        "lifecycle_repairs.c009.p003",
        "queued actual ordinary publication refreshes current controls after individual session uncertain",
    ),
    (
        "lifecycle_repairs.c009.p004",
        "queued actual delivery publication refreshes current controls after individual session eligible",
    ),
    (
        "lifecycle_repairs.c009.p005",
        "queued actual delivery publication refreshes current controls after individual session ended",
    ),
    (
        "lifecycle_repairs.c009.p006",
        "queued actual delivery publication refreshes current controls after individual session uncertain",
    ),
    (
        "inference_cases.c007.p001",
        "session inference key end at lock",
    ),
    (
        "inference_cases.c007.p002",
        "session inference key end at hidden",
    ),
    (
        "inference_cases.c007.p003",
        "session inference key end at pagehide",
    ),
    (
        "inference_cases.c007.p004",
        "session inference key end at reload",
    ),
    (
        "inference_cases.c007.p005",
        "session inference key end at bfcache",
    ),
    (
        "inference_cases.c007.p006",
        "session inference key end at redisplay",
    ),
    (
        "inference_cases.c008.p001",
        "crash leaves key usable until next-unlock sweep",
    ),
    (
        "inference_cases.c008.p002",
        "crash without unlock leaves key usable until expiry",
    ),
    (
        "inference_cases.c009.p001",
        "mint finishing during session end is revoked before the end answers",
    ),
    (
        "inference_cases.c010.p001",
        "identifier-only mint is revoked at session end",
    ),
    (
        "inference_cases.c011.p001",
        "unlock answers while sweep revoke is withheld",
    ),
    (
        "inference_cases.c012.p001",
        "bounded revoke stays unresolved and is never swept twice",
    ),
    (
        "inference_cases.c013.p001",
        "top-up and route refusals send no mint or credentialed request",
    ),
    (
        "inference_cases.c014.p001",
        "inference no-plaintext needles and loopback-only requests",
    ),
    (
        "goal_admission_cases.c001.p001",
        "goal exec queued admission preserves originating runtime session: eligible",
    ),
    (
        "goal_admission_cases.c001.p002",
        "goal exec queued admission preserves originating runtime session: ended",
    ),
    (
        "goal_admission_cases.c001.p003",
        "goal exec queued admission preserves originating runtime session: exhausted",
    ),
    (
        "goal_admission_cases.c001.p004",
        "goal job queued admission preserves originating runtime session: eligible",
    ),
    (
        "goal_admission_cases.c001.p005",
        "goal job queued admission preserves originating runtime session: ended",
    ),
    (
        "goal_admission_cases.c001.p006",
        "goal job queued admission preserves originating runtime session: exhausted",
    ),
    (
        "goal_cases.c001.p001",
        "goal card records one session source and refuses runtime briefs and feeds",
    ),
    (
        "goal_cases.c002.p001",
        "scripted exec and done preserve untrusted typing and keep credentials off the machine",
    ),
    (
        "goal_cases.c003.p001",
        "finished error turn reports metadata without a response body",
    ),
    (
        "goal_cases.c003.p002",
        "finished refused turn displays its refusal",
    ),
    (
        "goal_cases.c004.p001",
        "scripted schema and bound set refusals and direct harness-only job refusals",
    ),
    (
        "goal_cases.c005.p001",
        "model exec and every admitted job collect holding calls and never launch",
    ),
    (
        "goal_cases.c006.p001",
        "model typed create reaches the shared barrier before operator approval",
    ),
    (
        "goal_cases.c007.p001",
        "hostile document cannot clear a destructive disposition",
    ),
    (
        "goal_cases.c008.p001",
        "escaped session credential in a scripted exec is refused before dispatch",
    ),
    (
        "goal_cases.c009.p001",
        "pending document fetch refuses acceptance until its response settles",
    ),
    (
        "goal_cases.c010.p001",
        "document source commits before fetch and session end prevents a late send",
    ),
    (
        "goal_cases.c011.p001",
        "session end aborts an active document request without waiting for it",
    ),
    (
        "goal_cases.c012.p001",
        "goals stay historical after replay and failed documents supply no context",
    ),
    (
        "declaration_cases.c001.p001",
        "declaration proposal waits on the actual page and commits exact goal additions before its companion",
    ),
    (
        "declaration_cases.c002.p001",
        "class tightening is separately approved and survives unlock with the original answer",
    ),
    (
        "declaration_cases.c003.p001",
        "declaration rejection cancels its waiter without a canonical approval",
    ),
    (
        "declaration_cases.c003.p002",
        "declaration session end cancels its waiter without a canonical approval",
    ),
    (
        "declaration_cases.c004.p001",
        "session end queued behind the proposal writer publishes no late approval card",
    ),
    (
        "declaration_cases.c005.p001",
        "declaration approval stops safely at requirements_writer",
    ),
    (
        "declaration_cases.c005.p002",
        "declaration approval stops safely at move",
    ),
    (
        "declaration_cases.c005.p003",
        "declaration approval stops safely at requirements_committed",
    ),
    (
        "declaration_cases.c005.p004",
        "declaration approval stops safely at requirements_dispatch",
    ),
    (
        "declaration_cases.c005.p005",
        "declaration approval stops safely at failed_append",
    ),
    (
        "delivery_cases.c001.p001",
        "delivery refuses absent declaration and untrusted worker measurements",
    ),
    (
        "delivery_cases.c002.p001",
        "delivery card uses durable fixture results and actual application names as text",
    ),
    (
        "delivery_cases.c003.p001",
        "delivery consumes lifecycle evidence notes combination 1",
    ),
    (
        "delivery_cases.c003.p002",
        "delivery consumes lifecycle evidence notes combination 2",
    ),
    (
        "delivery_cases.c003.p003",
        "delivery consumes lifecycle evidence notes combination 3",
    ),
    (
        "delivery_cases.c004.p001",
        "delivery keeps lifecycle-only findings visible until recheck and refuses acceptance",
    ),
    (
        "delivery_cases.c005.p001",
        "delivery stops while delivery_read is suspended",
    ),
    (
        "delivery_cases.c006.p001",
        "delivery grants no late publication at delivery_read",
    ),
    (
        "delivery_cases.c005.p002",
        "delivery stops while delivery_writer is suspended",
    ),
    (
        "delivery_cases.c006.p002",
        "delivery grants no late publication at delivery_writer",
    ),
    (
        "delivery_cases.c006.p003",
        "delivery grants no late publication at move",
    ),
    (
        "delivery_cases.c006.p004",
        "delivery grants no late publication at failed_append",
    ),
    (
        "delivery_cases.c007.p001",
        "delivery failed attempt after placement retains completed verdict (finding=false) through end and reopen",
    ),
    (
        "delivery_cases.c007.p002",
        "delivery failed attempt after placement retains completed verdict (finding=true) through end and reopen",
    ),
    (
        "delivery_cases.c007.p003",
        "delivery missing attempt after placement retains completed verdict (finding=false) through end and reopen",
    ),
    (
        "delivery_cases.c007.p004",
        "delivery missing attempt after placement retains completed verdict (finding=true) through end and reopen",
    ),
    (
        "delivery_cases.c008.p001",
        "delivery amendment retains findings and rejects stale measurement authority before recheck",
    ),
    (
        "delivery_cases.c009.p001",
        "successful real model exec report cannot clear a stopped-service delivery finding",
    ),
    (
        "delivery_cases.c010.p001",
        "failing real model report cannot spoil clean delivery or block placement",
    ),
    (
        "main.c022.p001",
        "no plaintext in the served build (twr-ggw.5 AC4, AC5, CNF-15, STG-10)",
    ),
    (
        "main.c022.p002",
        "no plaintext in the tracer build (twr-ggw.5 AC4, AC5, CNF-15, STG-10)",
    ),
];

pub fn cases() -> Value {
    json!(
        CASES
            .iter()
            .map(|(id, label)| {
                let site = id.rsplit_once('.').unwrap().0;
                json!({"id":id,"site_id":site,"label":label,"scenario_id":scenario(site)})
            })
            .collect::<Vec<_>>()
    )
}

pub fn case_id(site: &str, label: &str) -> String {
    CASES
        .iter()
        .find(|(id, name)| id.rsplit_once('.').unwrap().0 == site && *name == label)
        .map_or_else(|| site.to_owned(), |(id, _)| (*id).to_owned())
}

pub fn scenario(site: &str) -> String {
    format!("{}.serial", site.split('.').next().unwrap())
}

pub fn plan(selection: &BTreeMap<String, String>) -> Result<Value, String> {
    shape(&cases(), selection)
}

// This route follows the early returns in main and the scenario runners. The validators
// also apply it to the independent case key, so removing a catalogue row cannot reduce
// the independently required domain.
fn shape(cases: &Value, selection: &BTreeMap<String, String>) -> Result<Value, String> {
    let get = |name: &str| {
        selection
            .get(&format!("TAU_TRACER_{name}"))
            .map(String::as_str)
    };
    let has = |name: &str| get(name).is_some();
    let mut name = String::new();
    let mut scopes = BTreeMap::from([("main.run".to_string(), 1_u64)]);
    let mut selected = Vec::new();
    let mut support = Vec::new();
    let mut execution = Vec::new();
    for case in cases.as_array().ok_or("invalid case catalogue")? {
        let id = case["id"].as_str().ok_or("missing executable identity")?;
        let (site, slot) = id.rsplit_once('.').ok_or("invalid executable slot")?;
        let module = site.split('.').next().unwrap();
        let mut chosen = false;
        let mut needed = false;
        if has("HOLD_CASE") {
            let filter = get("HOLD_CASE").unwrap();
            name = if filter.contains(',') {
                "hold.union".into()
            } else {
                format!("hold.{filter}")
            };
            let leaf = match (site, slot) {
                ("hold_cases.c001", _) => "drop",
                ("hold_cases.c002", _) => "simultaneous",
                ("hold_cases.c003", _) => "stop",
                ("hold_cases.c004", "p001") => "writer-stop",
                ("hold_cases.c004", "p002") => "append-error",
                ("hold_cases.c005", _) => "shared-stop",
                ("hold_cases.c006", _) => "legacy",
                ("hold_cases.c007", _) => "unreachable",
                ("hold_cases.c008", _) => "destructive",
                _ => "",
            };
            chosen =
                module == "hold_cases" && (filter == "all" || filter.split(',').any(|s| s == leaf));
            needed = matches!(site, "main.c001" | "main.c002");
        } else if has("SEED_CASE") {
            let filter = get("SEED_CASE").unwrap();
            name = format!("seed.{filter}");
            chosen = module == "seed_cases"
                && (filter == "all"
                    || site
                        == if filter == "failed-append" {
                            "seed_cases.c004"
                        } else {
                            "seed_cases.c002"
                        });
            needed = matches!(site, "main.c001" | "main.c002")
                || module == "seed_cases" && site == "seed_cases.c001" && filter != "all";
        } else if has("SETUP_CASE") {
            let filter = get("SETUP_CASE").unwrap();
            name = format!("setup.{filter}");
            chosen = if filter == "existing" {
                matches!(
                    module,
                    "main" | "typed_cases" | "job_cases" | "hold_cases" | "binding_cases"
                ) && !matches!(site, "main.c001" | "main.c002" | "main.c022")
            } else {
                module == "setup_cases"
            };
            needed = matches!(site, "main.c001" | "main.c002");
        } else if has("MODE_CASE") {
            name = "mode.all".into();
            chosen = module == "mode_cases";
            needed = matches!(site, "main.c001" | "main.c002");
        } else if has("DELIVERY") {
            let filter = get("DELIVERY_CASE").unwrap_or("all");
            name = format!("delivery.{filter}");
            chosen = module == "delivery_cases"
                && match filter {
                    "all" => true,
                    "reports" => matches!(site, "delivery_cases.c009" | "delivery_cases.c010"),
                    "incomplete" => site == "delivery_cases.c007",
                    _ => false,
                };
        } else if has("GOALS") {
            let filter = get("GOAL_CASE").unwrap_or("all");
            name = format!("goals.{filter}");
            let end = match filter {
                "card" => 1,
                "context" => 2,
                "outcome" => 3,
                "hold" => 5,
                "barrier" => 7,
                "credential" => 8,
                "document_pending" => 9,
                "document_end" => 10,
                _ => 0,
            };
            let number = site
                .rsplit_once('c')
                .and_then(|(_, n)| n.parse::<u32>().ok())
                .unwrap_or(0);
            chosen = match filter {
                "all" => matches!(
                    module,
                    "goal_admission_cases" | "goal_cases" | "declaration_cases" | "delivery_cases"
                ),
                "declaration" => module == "declaration_cases",
                "admission" => module == "goal_admission_cases",
                "outcome" => site == "goal_cases.c003",
                "barrier" => matches!(site, "goal_cases.c006" | "goal_cases.c007"),
                _ => module == "goal_cases" && number == end,
            };
            needed = end > 0
                && (module == "goal_admission_cases" || module == "goal_cases" && number < end);
        } else if has("INFERENCE") {
            let phase = get("INFERENCE_PHASE").unwrap_or("");
            name = if has("SESSION_END") {
                "inference.session-end.selection".into()
            } else if let Some(end) = get("INFERENCE_END") {
                format!("inference.end.{end}")
            } else {
                format!("inference.{}", if phase.is_empty() { "all" } else { phase })
            };
            let core = matches!(
                site,
                "inference_cases.c004" | "inference_cases.c005" | "inference_cases.c006"
            );
            chosen = if let Some(end) = get("INFERENCE_END") {
                site == "inference_cases.c007"
                    && [
                        "lock",
                        "hidden",
                        "pagehide",
                        "reload",
                        "bfcache",
                        "redisplay",
                    ]
                    .iter()
                    .position(|s| *s == end)
                    .is_some_and(|i| slot == format!("p{:03}", i + 1))
            } else {
                match phase {
                    "" => matches!(
                        module,
                        "inference_cases"
                            | "session_end_cases"
                            | "lifecycle_cases"
                            | "lifecycle_repairs"
                    ),
                    "core" => core,
                    "dispatch" => {
                        matches!(
                            module,
                            "session_end_cases" | "lifecycle_cases" | "lifecycle_repairs"
                        ) || matches!(
                            site,
                            "inference_cases.c001"
                                | "inference_cases.c002"
                                | "inference_cases.c003"
                        )
                    }
                    "cutoff" => matches!(site, "inference_cases.c012" | "inference_cases.c013"),
                    "command-intent" => site == "inference_cases.c001",
                    "sent-reads" => site == "inference_cases.c003",
                    "session-end" => {
                        module == "session_end_cases"
                            && get("SESSION_END").is_none_or(|parts| {
                                parts.split(',').any(|part| {
                                    part.strip_prefix('=').map_or_else(
                                        || case["label"].as_str().unwrap().contains(part),
                                        |exact| case["label"] == exact,
                                    )
                                })
                            })
                    }
                    "lifecycle" => matches!(module, "lifecycle_cases" | "lifecycle_repairs"),
                    "lifecycle-core" => module == "lifecycle_cases",
                    "lifecycle-boundaries" => {
                        module == "lifecycle_cases"
                            && matches!(
                                site,
                                "lifecycle_cases.c004"
                                    | "lifecycle_cases.c005"
                                    | "lifecycle_cases.c006"
                                    | "lifecycle_cases.c011"
                            )
                    }
                    "lifecycle-expiry" => site == "lifecycle_cases.c010",
                    "lifecycle-locked" => site == "lifecycle_cases.c013",
                    "lifecycle-repairs" => module == "lifecycle_repairs",
                    _ => false,
                }
            };
            needed = !chosen && (core || site == "inference_cases.c014");
        }
        if chosen {
            selected.push(json!(id));
        } else if needed {
            support.push(json!(id));
        }
        if chosen || needed {
            execution.push(json!(id));
            let scope = match (module, site) {
                ("inference_cases", "inference_cases.c014") => {
                    "inference_cases.no_plaintext".into()
                }
                ("lifecycle_cases", "lifecycle_cases.c013") => {
                    "lifecycle_cases.locked_freeze".into()
                }
                _ => format!("{module}.run"),
            };
            scopes.insert(
                scope,
                if matches!(
                    module,
                    "seed_cases" | "setup_cases" | "binding_cases" | "mode_cases"
                ) {
                    2
                } else {
                    1
                },
            );
        }
    }
    if matches!(
        get("INFERENCE_PHASE"),
        Some("lifecycle-boundaries" | "lifecycle-expiry")
    ) {
        scopes.remove("lifecycle_cases.run");
        scopes.insert("lifecycle_cases.selected".into(), 1);
    }
    if has("GOALS") {
        scopes.insert("goal_cases.run".into(), 1);
    }
    if has("INFERENCE") && get("INFERENCE_PHASE") == Some("lifecycle-repairs") {
        scopes.insert("lifecycle_cases.repair_cases".into(), 1);
    }
    if selected.is_empty() {
        return Err("selection has no executable cases".into());
    }
    Ok(
        json!({"name":name,"selection":selection,"expected_execution":execution,"selected":selected,"support":support,"scenario_scopes":scopes}),
    )
}
