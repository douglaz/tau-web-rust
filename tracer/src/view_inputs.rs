//! Immutable original page views. Receipts contain source references, never page text.
use crate::{completion, history};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
static CAPTURES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static USES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static PRIMARY: Mutex<BTreeMap<&'static str, usize>> = Mutex::new(BTreeMap::new());
static NULL: Value = Value::Null;

#[derive(Clone)]
pub enum Origin {
    Runtime {
        call: u64,
        attempt: usize,
        in_use: bool,
    },
    Observer {
        call: usize,
        attempt: usize,
        slot: &'static str,
    },
    Prior {
        site: &'static str,
        index: usize,
    },
    Direct(&'static str),
}
struct Original {
    value: crate::cdp::OriginalEvaluation,
    id: usize,
    origin: Origin,
}
#[derive(Clone, Default)]
pub struct View {
    original: Option<Arc<Original>>,
}
impl View {
    pub fn empty() -> Self {
        Self::default()
    }
    pub fn id(&self) -> usize {
        self.original.as_ref().map_or(0, |o| o.id)
    }
    pub fn failed(&self, call: u64, attempt: usize) -> bool {
        let result = self["status"] == "failed";
        used("failed", Some(call), Some(attempt), &[self], result, true);
        result
    }
    pub fn ready(&self, call: u64, attempt: usize, in_use: bool) -> bool {
        let state = self["store"].as_str().unwrap_or_default();
        let transient =
            ["starting", "working", ""].contains(&state) || (state == "in-use" && !in_use);
        let result = self["status"] == "ready" && !transient;
        let ok=self.original.as_ref().is_some_and(|o|matches!(o.origin,Origin::Runtime{call:c,attempt:a,in_use:i}if c==call&&a==attempt&&i==in_use));
        used("ready", Some(call), Some(attempt), &[self], result, ok);
        result
    }
    pub fn returned(self, call: u64) -> Self {
        used("returned", Some(call), None, &[&self], true, true);
        self
    }
    pub fn primary(&self, site: &'static str) -> Predicate {
        let expected = match site {
            "main.a097" => self["store"] == "locked" && self["unlock"] == true,
            "main.a004" => {
                self["store"] == "none"
                    && self["create"] == true
                    && self["unlock"] == false
                    && self["lock"] == false
            }
            "main.a014" => self["store"] == "none" && self["create"] == true,
            "main.a093" => self["store"] == "unlocked",
            _ => false,
        };
        let mut counts = PRIMARY.lock().unwrap();
        let n = counts.entry(site).or_default();
        *n += 1;
        let index = used(
            site,
            None,
            Some(*n),
            &[self],
            expected,
            matches!(site, "main.a004" | "main.a014" | "main.a093" | "main.a097"),
        );
        Predicate {
            holds: expected,
            index,
        }
    }
    pub fn completion_text(&self, full: bool) -> Predicate {
        let case = history::active_case_id().unwrap_or_default();
        let ordinal = case
            .rsplit_once(".p")
            .and_then(|(_, n)| n.parse::<usize>().ok());
        let expected_full = ordinal.is_some_and(|n| n % 2 == 1);
        let expected = self["text"].as_str().is_some_and(|t| {
            t.contains(if full {
                "all twelve words re-entered"
            } else {
                "re-entry check skipped"
            })
        });
        let mut counts = PRIMARY.lock().unwrap();
        let n = counts.entry("seed_cases.a022").or_default();
        *n += 1;
        let index = used(
            "seed_cases.a022",
            None,
            Some(*n),
            &[self],
            expected,
            full == expected_full,
        );
        Predicate {
            holds: expected,
            index,
        }
    }
    pub fn persistence(&self, state: &str, says: &str, statement: &str) -> Predicate {
        let mut counts = PRIMARY.lock().unwrap();
        let n = counts.entry("main.a100").or_default();
        *n += 1;
        let expected = match *n {
            1 => (
                "refused",
                "Persistent storage: the browser refused the request.",
            ),
            2 => ("granted", "Persistent storage is granted."),
            _ => ("", ""),
        };
        let original = self["persist"] == state
            && self["persist_text"]
                .as_str()
                .is_some_and(|t| t.contains(says) && t.contains(statement));
        let ok = state == expected.0
            && says == expected.1
            && statement
                == "This is a request, not a guarantee: eviction, device loss or corruption can still lose the local store, so the seed backup and recovery remain necessary.";
        let index = used("main.a100", None, Some(*n), &[self], original, ok);
        Predicate {
            holds: original,
            index,
        }
    }
}
impl std::ops::Deref for View {
    type Target = Value;
    fn deref(&self) -> &Value {
        self.original.as_ref().map_or(&NULL, |o| &o.value)
    }
}
impl std::fmt::Display for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&**self, f)
    }
}
impl std::fmt::Debug for View {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&**self, f)
    }
}
impl serde::Serialize for View {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        (**self).serialize(s)
    }
}
impl PartialEq for View {
    fn eq(&self, other: &Self) -> bool {
        let result = **self == **other;
        used("equal", None, None, &[self, other], result, true);
        result
    }
}
impl Eq for View {}

pub async fn read(
    origin: Origin,
    run: &crate::Run<'_>,
    tab: &crate::Tab,
    expression: &str,
) -> Result<View, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let value = run
        .browser
        .evaluate_original(&tab.session, expression)
        .await?;
    let query_ok = value.within(start, cursor)
        && value.matches_hash(
            &tab.session,
            completion::inventory()["view_query_sha256"]
                .as_str()
                .unwrap_or(""),
        );
    let (kind, site, call, attempt, slot, in_use) = match &origin {
        Origin::Runtime {
            call,
            attempt,
            in_use,
        } => (
            "runtime",
            None,
            Some(*call),
            Some(*attempt),
            None,
            Some(*in_use),
        ),
        Origin::Observer {
            call,
            attempt,
            slot,
        } => (
            "observer",
            None,
            Some(*call as u64),
            Some(*attempt),
            Some(*slot),
            None,
        ),
        Origin::Prior { site, index } => {
            ("prior", Some(*site), Some(*index as u64), None, None, None)
        }
        Origin::Direct(site) => ("direct", Some(*site), None, None, None, None),
    };
    let mut captures = CAPTURES.lock().unwrap();
    let id = captures.len() + 1;
    captures.push(json!({"source":id,"kind":kind,"site":site,"call":call,"attempt":attempt,"slot":slot,"in_use":in_use,"page":history::page_id(&tab.session),"case":history::active_case_id(),"start_ns":start,"end_ns":completion::now(),"start_cursor":cursor,"end_cursor":history::cursor(),"query_ok":query_ok}));
    Ok(View {
        original: Some(Arc::new(Original { value, id, origin })),
    })
}
fn used(
    kind: &str,
    call: Option<u64>,
    attempt: Option<usize>,
    views: &[&View],
    result: bool,
    ok: bool,
) -> usize {
    let mut uses = USES.lock().unwrap();
    let index = uses.len();
    uses.push(json!({"kind":kind,"call":call,"attempt":attempt,"sources":views.iter().map(|v|v.id()).collect::<Vec<_>>(),"result":result,"ok":ok,"at_ns":completion::now(),"history_cursor":history::cursor(),"check_ns":null,"check_cursor":null,"check_instance":null}));
    index
}
#[must_use]
pub struct Predicate {
    holds: bool,
    index: usize,
}
impl Predicate {
    pub fn continues(&self) -> bool {
        self.holds
    }
    pub fn checked(self, binding: &crate::predicate_inputs::Primary) -> bool {
        let (predicate, instance, at, cursor) = binding.coordinates();
        let mut uses = USES.lock().unwrap();
        let row = &mut uses[self.index];
        if row["kind"] != predicate || row["result"] != self.holds || !row["check_ns"].is_null() {
            return false;
        }
        row["check_ns"] = json!(at);
        row["check_cursor"] = json!(cursor);
        row["check_instance"] = json!(instance);
        true
    }
}
pub fn observer_ready(site: &str, call: usize, attempt: usize, view: &View) -> bool {
    let result = match site {
        "main.writer.waiter_unlocked" => view["store"] == "locked",
        "main.persistence.shown" => view["persist"] != "",
        _ => false,
    };
    used(
        "observer",
        Some(call as u64),
        Some(attempt),
        &[view],
        result,
        matches!(
            site,
            "main.writer.waiter_unlocked" | "main.persistence.shown"
        ),
    );
    result
}
pub fn holder_ready(
    call: usize,
    attempt: usize,
    views: &(View, View),
    states: [Option<&str>; 2],
    ready: bool,
) {
    let ok = states == [views.0["store"].as_str(), views.1["store"].as_str()];
    used(
        "observer",
        Some(call as u64),
        Some(attempt),
        &[&views.0, &views.1],
        ready,
        ok,
    );
}
pub fn snapshot() -> Value {
    json!({"captures":*CAPTURES.lock().unwrap(),"uses":*USES.lock().unwrap()})
}
