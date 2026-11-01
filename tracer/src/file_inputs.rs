//! Original encrypted file operands stay private; evidence carries source relationships only.
use super::{completion, history};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

type Bytes = BTreeMap<String, Vec<u8>>;
struct Original {
    files: Bytes,
    id: usize,
    kind: &'static str,
    page: u64,
    parent: Option<usize>,
    site: &'static str,
    dump: Option<Arc<crate::cdp::OriginalEvaluation>>,
}
impl Original {
    fn matches_dump(&self) -> bool {
        if !matches!(self.kind, "browser.dump" | "browser.store") {
            return true;
        }
        let Some(dump) = &self.dump else {
            return false;
        };
        let source = if self.kind == "browser.dump" {
            self.id
        } else {
            self.parent.unwrap_or(0)
        };
        crate::operation_windows::original_dump_matches(source, self.page, dump)
            && dump_bytes(dump).is_ok_and(|files| {
                let expected = if self.kind == "browser.store" {
                    files
                        .into_iter()
                        .filter_map(|(name, bytes)| {
                            Some((name.strip_prefix(super::STORE)?.to_owned(), bytes))
                        })
                        .collect()
                } else {
                    files
                };
                expected == self.files
            })
    }
}
fn dump_bytes(dumped: &Value) -> Result<Bytes, String> {
    use base64::Engine;
    dumped
        .as_object()
        .ok_or("no dump")?
        .iter()
        .map(|(path, b64)| {
            let bytes = super::STANDARD
                .decode(b64.as_str().unwrap_or_default())
                .map_err(|e| format!("{path}: {e}"))?;
            Ok((path.clone(), bytes))
        })
        .collect()
}
#[derive(Clone, Default)]
pub struct Files {
    files: Bytes,
    original: Option<Arc<Original>>,
    control: Option<Arc<Control>>,
    contracts: Option<Arc<Contracts>>,
}
struct Contracts {
    source: usize,
    reader: usize,
    files: Bytes,
    valid: bool,
}
struct Control {
    id: usize,
    files: Bytes,
}
impl Files {
    pub fn new() -> Self {
        Self::default()
    }
    #[cfg(test)]
    fn capture(
        files: Bytes,
        kind: &'static str,
        page: u64,
        parent: Option<usize>,
        ok: bool,
    ) -> Self {
        Self::test_capture_at(files, kind, page, parent, ok, "")
    }
    #[cfg(test)]
    fn test_capture_at(
        files: Bytes,
        kind: &'static str,
        page: u64,
        parent: Option<usize>,
        ok: bool,
        site: &'static str,
    ) -> Self {
        use base64::Engine;
        let dump = matches!(kind, "browser.dump" | "browser.store").then(|| {
            let value = json!(
                files
                    .iter()
                    .map(|(name, bytes)| (
                        if kind == "browser.store" {
                            format!("{}{name}", super::STORE)
                        } else {
                            name.clone()
                        },
                        Value::String(super::STANDARD.encode(bytes))
                    ))
                    .collect::<serde_json::Map<_, _>>()
            );
            Arc::new(crate::cdp::test_dump_original(value))
        });
        let files = Self::capture_at(files, kind, page, parent, ok, site).with_dump(dump);
        if kind == "browser.dump" {
            crate::operation_windows::test_dump_source(files.original.as_ref().unwrap().id, page);
        }
        files
    }
    fn capture_at(
        files: Bytes,
        kind: &'static str,
        page: u64,
        parent: Option<usize>,
        ok: bool,
        site: &'static str,
    ) -> Self {
        let mut captures = CAPTURES.lock().unwrap();
        let id = captures.len() + 1;
        captures.push(json!({"site":site,"source":id,"kind":kind,"page":page,"parent":parent,"ok":ok,"case":history::active_case_id(),"at_ns":completion::now(),"history_cursor":history::cursor()}));
        Self {
            original: Some(Arc::new(Original {
                files: files.clone(),
                id,
                kind,
                page,
                parent,
                site,
                dump: None,
            })),
            files,
            control: None,
            contracts: None,
        }
    }
    fn with_dump(mut self, dump: Option<Arc<crate::cdp::OriginalEvaluation>>) -> Self {
        Arc::get_mut(self.original.as_mut().expect("new file origin"))
            .expect("new unshared file origin")
            .dump = dump;
        self
    }
    pub fn input(&self) -> Value {
        match &self.original {
            Some(source) => {
                json!({"site":source.site,"source":source.id,"kind":source.kind,"page":source.page,"ok":self.files==source.files&&source.matches_dump()})
            }
            None => json!({"site":"","source":null,"kind":"unbound","page":null,"ok":false}),
        }
    }
}
pub const PUT_EXPRESSION: &str = "(async (files) => {\n                        const root = await navigator.storage.getDirectory();\n                        await root.removeEntry('tau-web-store', { recursive: true }).catch(() => {});\n                        const directory = await root.getDirectoryHandle('tau-web-store', { create: true });\n                        for (const [name, b64] of Object.entries(files)) {\n                            const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));\n                            const writable = await (await directory.getFileHandle(name, { create: true })).createWritable();\n                            await writable.write(bytes);\n                            await writable.close();\n                        }\n                        return true;\n                    })(__TAU_FILES__)";
fn put_expression_matches(expression: &str, files: &Files) -> bool {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let Some((prefix, suffix)) = PUT_EXPRESSION.split_once("__TAU_FILES__") else {
        return false;
    };
    let Some(payload) = expression
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(suffix))
    else {
        return false;
    };
    let Ok(Value::Object(payload)) = serde_json::from_str::<Value>(payload) else {
        return false;
    };
    payload.len() == files.len()
        && files.iter().all(|(name, bytes)| {
            payload
                .get(name)
                .and_then(Value::as_str)
                .and_then(|s| STANDARD.decode(s).ok())
                .as_ref()
                == Some(bytes)
        })
}
pub async fn install(run: &crate::Run<'_>, tab: &crate::Tab, files: &Files) -> Result<(), String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let payload: serde_json::Map<String, Value> = files
        .iter()
        .map(|(name, bytes)| (name.clone(), STANDARD.encode(bytes).into()))
        .collect();
    let expression = PUT_EXPRESSION.replace("__TAU_FILES__", &Value::Object(payload).to_string());
    let recipe_ok = hex::encode(
        ring::digest::digest(&ring::digest::SHA256, PUT_EXPRESSION.as_bytes()).as_ref(),
    ) == completion::inventory()["file_put_expression_sha256"]
        .as_str()
        .unwrap_or("");
    put_input(files);
    let put = crate::file_uses::put(
        tab,
        files,
        recipe_ok && put_expression_matches(&expression, files),
    );
    crate::settle_inputs::put(tab, files);
    let result = run.browser.evaluate(&tab.session, &expression).await;
    crate::file_uses::put_finished(put, result.as_ref().is_ok_and(|v| *v == true));
    result.map(|_| ())
}

pub fn contracts_output(before: &Files, mut after: Files, origin: usize, pass: &str) -> Files {
    let valid = crate::auxiliary::contracts_output_matches(origin, before, &after, pass);
    let source = before.original.as_ref().map_or(0, |o| o.id);
    after.contracts = Some(Arc::new(Contracts {
        source,
        reader: origin,
        files: after.files.clone(),
        valid,
    }));
    after
}
pub fn installation(files: &Files) -> Value {
    json!({"empty":files.is_empty(),"control":files.control.as_ref().map(|c|json!({"source":c.id,"ok":c.files==files.files})),"contracts":files.contracts.as_ref().map(|c|json!({"source":c.source,"reader":c.reader,"ok":c.valid&&c.files==files.files}))})
}

impl std::ops::Deref for Files {
    type Target = Bytes;
    fn deref(&self) -> &Bytes {
        &self.files
    }
}
impl std::ops::DerefMut for Files {
    fn deref_mut(&mut self) -> &mut Bytes {
        &mut self.files
    }
}
impl std::fmt::Debug for Files {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.files.fmt(f)
    }
}
impl PartialEq for Files {
    fn eq(&self, other: &Self) -> bool {
        self.files == other.files
    }
}
impl Eq for Files {}
impl FromIterator<(String, Vec<u8>)> for Files {
    fn from_iter<T: IntoIterator<Item = (String, Vec<u8>)>>(iter: T) -> Self {
        Self {
            files: iter.into_iter().collect(),
            original: None,
            control: None,
            contracts: None,
        }
    }
}
impl IntoIterator for Files {
    type Item = (String, Vec<u8>);
    type IntoIter = std::collections::btree_map::IntoIter<String, Vec<u8>>;
    fn into_iter(self) -> Self::IntoIter {
        self.files.into_iter()
    }
}
impl<'a> IntoIterator for &'a Files {
    type Item = (&'a String, &'a Vec<u8>);
    type IntoIter = std::collections::btree_map::Iter<'a, String, Vec<u8>>;
    fn into_iter(self) -> Self::IntoIter {
        self.files.iter()
    }
}
impl<'a> IntoIterator for &'a mut Files {
    type Item = (&'a String, &'a mut Vec<u8>);
    type IntoIter = std::collections::btree_map::IterMut<'a, String, Vec<u8>>;
    fn into_iter(self) -> Self::IntoIter {
        self.files.iter_mut()
    }
}
impl serde::Serialize for Files {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.files.serialize(s)
    }
}

static CAPTURES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static COMPARISONS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static CONTROLS: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static CONTROL_USES: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static PRIMARY: Mutex<Vec<Value>> = Mutex::new(Vec::new());
static SCAN_VALUES: Mutex<Vec<Arc<crate::cdp::OriginalEvaluation>>> = Mutex::new(Vec::new());
pub fn snapshot() -> Value {
    json!(*CAPTURES.lock().unwrap())
}

pub fn comparisons() -> Value {
    json!(*COMPARISONS.lock().unwrap())
}
pub fn controls() -> Value {
    json!({"captures":*CONTROLS.lock().unwrap(),"uses":*CONTROL_USES.lock().unwrap()})
}
pub fn primary_history() -> Value {
    json!(*PRIMARY.lock().unwrap())
}

pub fn refusal_variants(
    baseline: &Files,
    foreign: &Files,
) -> Vec<(&'static str, Files, &'static str, bool)> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let edited = |name: &str, field: &str| {
        let mut files = baseline.clone();
        let mut value: Value = serde_json::from_slice(&files[name]).unwrap_or_default();
        if field == "version" {
            value[field] = json!(2);
        } else {
            let mut bytes = URL_SAFE_NO_PAD
                .decode(value[field].as_str().unwrap_or_default())
                .unwrap_or_default();
            if let Some(first) = bytes.first_mut() {
                *first ^= 1;
            }
            value[field] = URL_SAFE_NO_PAD.encode(bytes).into();
        }
        let bytes = if name == "envelope.json" {
            value.to_string().into_bytes()
        } else {
            crate::reader::record_bytes(&value)
        };
        files.insert(name.into(), bytes);
        files
    };
    let mut foreign_record = baseline.clone();
    foreign_record.insert("1".into(), foreign["1"].clone());
    let mut variants = vec![
        (
            "wrong_passphrase",
            "a wrong passphrase",
            baseline.clone(),
            crate::WRONG_PASSPHRASE,
            true,
        ),
        (
            "salt",
            "a modified envelope: one byte of the salt",
            edited("envelope.json", "salt"),
            crate::PASSPHRASE,
            true,
        ),
        (
            "ciphertext",
            "a modified record: one byte of record 1's ciphertext",
            edited("1", "ciphertext"),
            crate::PASSPHRASE,
            false,
        ),
        (
            "foreign_record",
            "a record from another store, at the same number",
            foreign_record,
            crate::PASSPHRASE,
            false,
        ),
        (
            "version",
            "an envelope of an unknown format: version 2",
            edited("envelope.json", "version"),
            crate::PASSPHRASE,
            false,
        ),
    ];
    let base = baseline.original.as_ref();
    let foreign_source = foreign.original.as_ref();
    let ok = base.is_some_and(|b| {
        b.site == "file.main.dump.013" && b.kind == "browser.store" && b.files == baseline.files
    }) && foreign_source.is_some_and(|f| {
        f.site == "file.main.build.007" && f.kind == "constructor" && f.files == foreign.files
    });
    let mut captures = CONTROLS.lock().unwrap();
    for (kind, _, files, _, _) in &mut variants {
        let id = captures.len() + 1;
        captures.push(json!({"source":id,"kind":kind,"base":base.map(|b|b.id),"foreign":if *kind=="foreign_record"{foreign_source.map(|s|s.id)}else{None},"ok":ok&&refusal_input_matches(kind,baseline,foreign,files),"at_ns":completion::now(),"history_cursor":history::cursor(),"case":history::active_case_id()}));
        files.control = Some(Arc::new(Control {
            id,
            files: files.files.clone(),
        }));
    }
    variants
        .into_iter()
        .map(|(_, label, files, pass, tag)| (label, files, pass, tag))
        .collect()
}

fn refusal_input_matches(kind: &str, base: &Files, foreign: &Files, actual: &Files) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let changed = match kind {
        "wrong_passphrase" => return actual.files == base.files,
        "salt" | "version" => "envelope.json",
        "ciphertext" | "foreign_record" => "1",
        _ => return false,
    };
    if base.len() != actual.len()
        || base
            .iter()
            .any(|(name, bytes)| name != changed && actual.get(name) != Some(bytes))
    {
        return false;
    }
    if kind == "foreign_record" {
        return actual.get("1") == foreign.get("1");
    }
    let Some((before, after)) = base.get(changed).zip(actual.get(changed)) else {
        return false;
    };
    let (Ok(mut before), Ok(mut after)) = (
        serde_json::from_slice::<Value>(before),
        serde_json::from_slice::<Value>(after),
    ) else {
        return false;
    };
    let field = match kind {
        "salt" => "salt",
        "version" => "version",
        _ => "ciphertext",
    };
    let (Some(before_fields), Some(after_fields)) = (before.as_object_mut(), after.as_object_mut())
    else {
        return false;
    };
    let (Some(original), Some(changed_value)) =
        (before_fields.remove(field), after_fields.remove(field))
    else {
        return false;
    };
    if before != after {
        return false;
    }
    if kind == "version" {
        return original == 1 && changed_value == 2;
    }
    let (Some(original), Some(changed_value)) = (original.as_str(), changed_value.as_str()) else {
        return false;
    };
    let (Ok(original), Ok(changed_value)) = (
        URL_SAFE_NO_PAD.decode(original),
        URL_SAFE_NO_PAD.decode(changed_value),
    ) else {
        return false;
    };
    !original.is_empty()
        && original.len() == changed_value.len()
        && original[0] ^ 1 == changed_value[0]
        && original[1..] == changed_value[1..]
}

pub fn constructor_input(site: &str, pass: &str, events: &[Value]) -> bool {
    let words = include_str!("../../tests/vectors/seed-backup-collisions.txt")
        .lines()
        .next()
        .expect("control mnemonic");
    match site {
        "file.main.build.002" => {
            pass == crate::HOST_PASSPHRASE
                && events
                    == [
                        json!({"seed":{"mnemonic":words}}),
                        json!({"command":{"machine":"fixture","command":hex::encode("built on the host")}}),
                    ]
        }
        "file.main.build.007" => {
            pass == crate::PASSPHRASE
                && events
                    == [
                        json!({"seed":{"mnemonic":words}}),
                        json!({"command":{"machine":"fixture","command":hex::encode(crate::COMMAND)}}),
                    ]
        }
        "file.seed_cases.build.001" => {
            let controls: Vec<_> = include_str!("../../tests/vectors/seed-backup-collisions.txt")
                .lines()
                .collect();
            let case = history::active_case_id().unwrap_or_default();
            let slot = case
                .rsplit_once('p')
                .and_then(|(_, n)| n.parse::<usize>().ok())
                .filter(|n| *n > 0);
            slot.is_some_and(|slot| {
                let words = controls[(slot - 1) % controls.len()];
                case.starts_with("seed_cases.c001.")
                    && slot <= 2 * controls.len()
                    && pass
                        == (if slot <= controls.len() {
                            crate::PASSPHRASE
                        } else {
                            crate::SERVED_PASSPHRASE
                        })
                    && events == [json!({"seed":{"mnemonic":words}})]
            })
        }
        "file.seed_cases.build.002" => {
            events.is_empty()
                && match history::active_case_id().as_deref() {
                    Some("seed_cases.c005.p001") => pass == crate::PASSPHRASE,
                    Some("seed_cases.c005.p002") => pass == crate::SERVED_PASSPHRASE,
                    _ => false,
                }
        }
        _ => crate::file_recipes::matches(site, pass, events),
    }
}

pub fn put_input(files: &Files) {
    if let Some(control) = &files.control {
        CONTROL_USES.lock().unwrap().push(json!({"source":control.id,"ok":files.files==control.files,"at_ns":completion::now(),"history_cursor":history::cursor(),"case":history::active_case_id()}));
    }
}

pub fn equal_at(site: &'static str, predicate: &'static str, left: &Files, right: &Files) -> bool {
    equal_primary(site, predicate, left, right).holds
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
        let mut rows = COMPARISONS.lock().unwrap();
        let row = &mut rows[self.index];
        if row["predicate"] != predicate
            || row["result"] != self.holds
            || row["case"] != json!(history::active_case_id())
            || !row["check_ns"].is_null()
        {
            return false;
        }
        row["check_ns"] = json!(at);
        row["check_cursor"] = json!(cursor);
        row["check_instance"] = json!(instance);
        true
    }
}
pub fn equal_primary(
    site: &'static str,
    predicate: &'static str,
    left: &Files,
    right: &Files,
) -> Predicate {
    let result = left.files == right.files;
    let index = comparison(
        site,
        predicate,
        result,
        ComparisonInput {
            left: left.input(),
            right: right.input(),
            name_ok: true,
            controls: [
                left.control.as_ref().map(|c| c.id),
                right.control.as_ref().map(|c| c.id),
            ],
            control_ok: left.control.as_ref().is_none_or(|c| c.files == left.files)
                && right
                    .control
                    .as_ref()
                    .is_none_or(|c| c.files == right.files),
        },
    );
    Predicate {
        holds: result,
        index,
    }
}

struct ComparisonInput {
    left: Value,
    right: Value,
    name_ok: bool,
    controls: [Option<usize>; 2],
    control_ok: bool,
}
fn comparison(
    site: &'static str,
    predicate: &'static str,
    result: bool,
    input: ComparisonInput,
) -> usize {
    let ComparisonInput {
        left,
        right,
        name_ok,
        controls,
        control_ok,
    } = input;
    let at = completion::now();
    let cursor = history::cursor();
    let mut rows = COMPARISONS.lock().unwrap();
    let index = rows.len();
    rows.push(json!({"site":site,"predicate":predicate,"left":left,"right":right,"result":result,"name_ok":name_ok,"controls":controls,"control_ok":control_ok,"case":history::active_case_id(),"at_ns":at,"history_cursor":cursor,"check_ns":if predicate.is_empty(){Some(at)}else{None},"check_cursor":if predicate.is_empty(){Some(cursor)}else{None},"check_instance":if predicate.is_empty(){Some(0)}else{None}}));
    index
}

pub struct Blob {
    bytes: Vec<u8>,
    name: usize,
    input: Value,
    name_ok: bool,
}
pub struct ScanReference {
    value: Arc<crate::cdp::OriginalEvaluation>,
    source: usize,
}
pub struct BlobName {
    raw: String,
    source: usize,
}
static BLOB_SOURCES: Mutex<Vec<Value>> = Mutex::new(Vec::new());

pub async fn scan_reference(
    run: &crate::Run<'_>,
    worker: &crate::Worker,
    secret: &str,
) -> Result<ScanReference, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let body = format!(
        "return await m.test_scan_fixture('service access',new TextEncoder().encode({}));",
        json!(secret)
    );
    let expression = format!(
        "(async()=>{{const m=await import(new URL('./pkg/tau_web.js',self.location.href).href);{body}}})()"
    );
    let value = Arc::new(
        run.browser
            .evaluate_original(&worker.session, &expression)
            .await?,
    );
    let query_ok = value.within(start, cursor) && value.matches(&worker.session, &expression);
    let (identity, page) = history::worker_identity(&worker.session);
    let mut sources = BLOB_SOURCES.lock().unwrap();
    let source = sources.len() + 1;
    SCAN_VALUES.lock().unwrap().push(value.clone());
    sources.push(json!({"source":source,"page":page,"worker":identity,"start_ns":start,"end_ns":completion::now(),"history_cursor":cursor,"case":history::active_case_id(),"ok":query_ok&&history::selected_worker_matches(page,worker),"named":0}));
    Ok(ScanReference { value, source })
}
impl ScanReference {
    pub fn name(&self) -> Result<BlobName, String> {
        use crate::logical_checks::Observe as _;
        let raw = format!(
            "scan-{}",
            self.value
                .as_str()
                .ok_or("scan identity")
                .checked("lifecycle.initial.scan_identity")?
        );
        let mut sources = BLOB_SOURCES.lock().unwrap();
        let row = &mut sources[self.source - 1];
        row["named"] = json!(row["named"].as_u64().unwrap() + 1);
        Ok(BlobName {
            raw,
            source: self.source,
        })
    }
}
pub fn blob_sources() -> Value {
    json!(*BLOB_SOURCES.lock().unwrap())
}

pub fn blob(files: &Files, name: &BlobName) -> Blob {
    let name_ok = SCAN_VALUES
        .lock()
        .unwrap()
        .get(name.source - 1)
        .and_then(|value| value.as_str())
        .is_some_and(|value| name.raw == format!("scan-{value}"));
    Blob {
        bytes: files[&name.raw].clone(),
        name: name.source,
        input: files.input(),
        name_ok,
    }
}
pub fn equal_blob_at(
    site: &'static str,
    predicate: &'static str,
    left: &Blob,
    right: &Blob,
) -> Predicate {
    let result = left.bytes == right.bytes;
    let index = comparison(
        site,
        predicate,
        result,
        ComparisonInput {
            left: left.input.clone(),
            right: right.input.clone(),
            name_ok: left.name_ok && right.name_ok && left.name == right.name,
            controls: [None, None],
            control_ok: true,
        },
    );
    Predicate {
        holds: result,
        index,
    }
}

pub fn checked(predicate: &str, instance: usize) -> (u64, usize) {
    let case = history::active_case_id();
    let at = completion::now();
    let cursor = history::cursor();
    PRIMARY.lock().unwrap().push(json!({"case":case,"id":format!("{predicate}.i{instance:03}"),"at_ns":at,"history_cursor":cursor}));
    (at, cursor)
}

/// One original browser query and its original decoded bytes, before callers can modify them.
pub async fn dump_at(
    run: &super::Run<'_>,
    tab: &super::Tab,
    expression: &str,
    site: &'static str,
) -> Result<Files, String> {
    let start = completion::now();
    let cursor = history::cursor();
    let query = crate::operation_windows::dump_query(tab, expression);
    let dumped = run
        .browser
        .evaluate_original(&tab.session, expression)
        .await?;
    let ok = dumped.within(start, cursor) && dumped.matches(&tab.session, super::DUMP);
    let files = dump_bytes(&dumped)?;
    let files = Files::capture_at(
        files,
        "browser.dump",
        history::page_id(&tab.session),
        None,
        ok,
        site,
    )
    .with_dump(Some(Arc::new(dumped)));
    query.finish(files.original.as_ref().expect("original dump").id);
    Ok(files)
}

pub fn store_files(dumped: &Files) -> Files {
    let original = dumped.original.as_ref();
    let ok = original
        .is_some_and(|s| s.kind == "browser.dump" && s.files == dumped.files && s.matches_dump());
    let files = dumped
        .iter()
        .filter_map(|(path, bytes)| {
            Some((path.strip_prefix(super::STORE)?.to_owned(), bytes.clone()))
        })
        .collect();
    Files::capture_at(
        files,
        "browser.store",
        original.map_or(0, |s| s.page),
        original.map(|s| s.id),
        ok,
        original.map_or("", |s| s.site),
    )
    .with_dump(original.and_then(|s| s.dump.clone()))
}

pub fn constructed_with_input(files: Files, site: &'static str, ok: bool) -> Files {
    Files::capture_at(files.files, "constructor", 0, None, ok, site)
}
#[cfg(test)]
pub fn constructed_at(files: Files, site: &'static str) -> Files {
    constructed_with_input(files, site, true)
}

pub fn validate(report: &Value) -> Result<(), String> {
    validate_shapes(report)?;
    validate_reader_sources(report)?;
    validate_constructors(report)?;
    validate_controls(report)?;
    validate_blob_sources(report)?;
    crate::file_domains::validate(report)
}

fn validate_blob_sources(report: &Value) -> Result<(), String> {
    let error = "original scan reference query/name provenance mismatch";
    let required = report["mode"] == "full"
        || report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .iter()
            .any(|c| c == "lifecycle_cases.c001.p001");
    let sources = report["blob_sources"].as_array().ok_or(error)?;
    if sources.len() != usize::from(required) {
        return Err(error.into());
    }
    let states = crate::reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    let workers = history::worker_states(report);
    for row in sources {
        let cursor = row["history_cursor"].as_u64().ok_or(error)? as usize;
        let state = states.get(cursor).ok_or(error)?;
        let page = *pages
            .get(cursor)
            .and_then(|p| p.get("tracer"))
            .ok_or(error)?;
        let start = row["start_ns"].as_u64().ok_or(error)?;
        let end = row["end_ns"].as_u64().ok_or(error)?;
        if row.as_object().is_none_or(|o| o.len() != 9)
            || row["source"] != 1
            || row["named"] != 1
            || row["ok"] != true
            || row["page"] != page
            || workers[cursor]
                .get(&page)
                .is_none_or(|w| row["worker"] != *w)
            || row["case"] != "lifecycle_cases.c001.p001"
            || state.invocation != 1
            || state.owner.as_ref().is_none_or(|o| {
                o.0 != "lifecycle_cases.run"
                    || o.1 != "inside"
                    || o.2 != "lifecycle_cases.c001.p001"
            })
            || end < start
            || end > report["duration_ns"].as_u64().ok_or(error)?
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn validate_controls(report: &Value) -> Result<(), String> {
    let error = "original cryptographic refusal input/use domain mismatch";
    let selected = if report["mode"] == "full" {
        true
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .iter()
            .any(|c| c == "main.c015.p001")
    };
    let captures = report["file_controls"]["captures"]
        .as_array()
        .ok_or(error)?;
    let uses = report["file_controls"]["uses"].as_array().ok_or(error)?;
    if report["file_controls"]
        .as_object()
        .is_none_or(|o| o.len() != 2)
        || captures.len() != if selected { 5 } else { 0 }
        || uses.len() != captures.len()
    {
        return Err(error.into());
    }
    let files = report["file_captures"].as_array().ok_or(error)?;
    let states = crate::reader_checks::caller_states(report);
    let mut previous = 0;
    for (index, (capture, used)) in captures.iter().zip(uses).enumerate() {
        if capture.as_object().is_none_or(|o| o.len() != 8)
            || used.as_object().is_none_or(|o| o.len() != 5)
            || capture["source"] != index + 1
            || used["source"] != index + 1
            || capture["kind"]
                != [
                    "wrong_passphrase",
                    "salt",
                    "ciphertext",
                    "foreign_record",
                    "version",
                ][index]
            || capture["ok"] != true
            || used["ok"] != true
        {
            return Err(error.into());
        }
        let base = files
            .get(capture["base"].as_u64().filter(|n| *n > 0).ok_or(error)? as usize - 1)
            .ok_or(error)?;
        if base["site"] != "file.main.dump.013"
            || base["kind"] != "browser.store"
            || base["case"] != "main.c015.p001"
            || base["at_ns"].as_u64() > capture["at_ns"].as_u64()
        {
            return Err(error.into());
        }
        if index == 3 {
            let foreign = files
                .get(
                    capture["foreign"]
                        .as_u64()
                        .filter(|n| *n > 0)
                        .ok_or(error)? as usize
                        - 1,
                )
                .ok_or(error)?;
            if foreign["site"] != "file.main.build.007"
                || foreign["kind"] != "constructor"
                || foreign["case"] != "main.c015.p001"
                || foreign["at_ns"].as_u64() > capture["at_ns"].as_u64()
            {
                return Err(error.into());
            }
        } else if !capture["foreign"].is_null() {
            return Err(error.into());
        }
        for value in [capture, used] {
            let at = value["at_ns"].as_u64().ok_or(error)?;
            let state = states
                .get(value["history_cursor"].as_u64().ok_or(error)? as usize)
                .ok_or(error)?;
            if value["case"] != "main.c015.p001"
                || state.invocation != 1
                || state.prepare.is_some()
                || state
                    .owner
                    .as_ref()
                    .is_none_or(|o| o.0 != "main.run" || o.1 != "inside" || o.2 != "main.c015.p001")
                || at > report["duration_ns"].as_u64().ok_or(error)?
            {
                return Err(error.into());
            }
        }
        let at = used["at_ns"].as_u64().ok_or(error)?;
        if at < previous || capture["at_ns"].as_u64().ok_or(error)? > at {
            return Err(error.into());
        }
        previous = at;
    }
    Ok(())
}

fn validate_constructors(report: &Value) -> Result<(), String> {
    let error = "original constructor source invocation/domain mismatch";
    let key = completion::inventory();
    let execution: Vec<_> = if report["mode"] == "full" {
        key["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].clone())
            .collect()
    } else {
        report["plan"]["expected_execution"]
            .as_array()
            .ok_or(error)?
            .clone()
    };
    let readers = super::reader_checks::resolve_callers(report)?;
    let auxiliary = super::auxiliary::constructor_domains(report)?;
    type Owner = (String, String, String, u64);
    let mut expected: BTreeMap<Owner, Vec<String>> = BTreeMap::new();
    for rule in key["file_constructor_sources"].as_array().ok_or(error)? {
        let site = rule[0].as_str().ok_or(error)?;
        let target = rule[2].as_str().ok_or(error)?;
        let mut add = |owner: Owner, n: usize| {
            expected
                .entry(owner)
                .or_default()
                .extend(std::iter::repeat_n(site.to_owned(), n))
        };
        match rule[1].as_str() {
            Some("reader") => {
                for source in readers.iter().filter(|s| s.site == target) {
                    add(
                        (
                            source.owner.0.clone(),
                            source.owner.1.clone(),
                            source.owner.2.clone(),
                            source.invocation,
                        ),
                        1,
                    );
                }
            }
            Some("aux") => {
                for (owner, domains) in &auxiliary {
                    for (invocation, domain) in domains.iter().filter(|(_, d)| {
                        d["caller"].as_str().is_some_and(|s| s.starts_with(target))
                    }) {
                        let _ = domain;
                        add(
                            (
                                owner.0.clone(),
                                owner.1.clone(),
                                owner.2.clone(),
                                *invocation,
                            ),
                            1,
                        );
                    }
                }
            }
            Some("case") => {
                for case in key["cases"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|c| c["site_id"] == target && execution.contains(&c["id"]))
                {
                    let anchor = case["id"].as_str().ok_or(error)?;
                    let (position, anchor) = if rule[3] == "before" {
                        let index = execution.iter().position(|id| id == anchor).ok_or(error)?;
                        (
                            "after",
                            index
                                .checked_sub(1)
                                .map_or("", |i| execution[i].as_str().unwrap()),
                        )
                    } else {
                        (rule[3].as_str().ok_or(error)?, anchor)
                    };
                    add(
                        (
                            format!("{}.run", target.split('.').next().unwrap()),
                            position.into(),
                            anchor.into(),
                            case["invocation"].as_u64().ok_or(error)?,
                        ),
                        rule[4].as_u64().ok_or(error)? as usize,
                    );
                }
            }
            Some("cleanup") => {
                if let Some(case) = key["cases"].as_array().unwrap().iter().rev().find(|c| {
                    c["site_id"].as_str().is_some_and(|s| {
                        s.starts_with(&format!("{}.", target.split('.').next().unwrap()))
                    }) && execution.contains(&c["id"])
                }) {
                    add(
                        (
                            target.into(),
                            "after".into(),
                            case["id"].as_str().unwrap().into(),
                            case["invocation"].as_u64().ok_or(error)?,
                        ),
                        1,
                    );
                }
            }
            _ => return Err(error.into()),
        }
    }
    for (owner, sites) in &mut expected {
        if owner.1 != "inside" {
            continue;
        }
        let case = owner
            .2
            .rsplit_once(".p")
            .map_or(owner.2.as_str(), |(site, _)| site);
        if let Some(order) = key["file_constructor_order"].get(case) {
            let order = order.as_array().ok_or(error)?;
            if sites.iter().any(|site| !order.iter().any(|v| v == site)) {
                return Err(error.into());
            }
            sites.sort_by_key(|site| order.iter().position(|v| v == site).unwrap());
        }
    }
    let states = super::reader_checks::caller_states(report);
    for capture in report["file_captures"]
        .as_array()
        .ok_or(error)?
        .iter()
        .filter(|c| c["kind"] == "constructor")
    {
        let state = states
            .get(capture["history_cursor"].as_u64().ok_or(error)? as usize)
            .ok_or(error)?;
        let owner = state.owner.as_ref().ok_or(error)?;
        let want = expected
            .get_mut(&(
                owner.0.clone(),
                owner.1.clone(),
                owner.2.clone(),
                state.invocation,
            ))
            .filter(|v| !v.is_empty())
            .ok_or(error)?
            .remove(0);
        if capture["site"] != want
            || capture["case"].as_str()
                != if owner.1 == "inside" {
                    Some(owner.2.as_str())
                } else {
                    None
                }
        {
            return Err(error.into());
        }
    }
    if expected.values().any(|v| !v.is_empty()) {
        return Err(error.into());
    }
    Ok(())
}

fn validate_shapes(report: &Value) -> Result<(), String> {
    let error = "original encrypted reader input provenance mismatch";
    let states = super::reader_checks::caller_states(report);
    let captures = report["file_captures"].as_array().ok_or(error)?;
    let events = report["helper_history"].as_array().ok_or(error)?;
    let mut previous = (0, 0);
    for (index, capture) in captures.iter().enumerate() {
        let at = capture["at_ns"].as_u64().ok_or(error)?;
        let cursor = capture["history_cursor"].as_u64().ok_or(error)?;
        let kind = capture["kind"].as_str().ok_or(error)?;
        if capture.as_object().is_none_or(|m| m.len() != 9)
            || capture["source"] != index + 1
            || !capture["site"].is_string()
            || capture["ok"] != true
            || at < previous.0
            || cursor < previous.1
            || cursor as usize > events.len()
            || at > report["duration_ns"].as_u64().ok_or(error)?
        {
            return Err(error.into());
        }
        match kind {
            "browser.dump" => {
                if capture["page"].as_u64().is_none_or(|n| n == 0) || !capture["parent"].is_null() {
                    return Err(error.into());
                }
            }
            "browser.store" => {
                let parent = capture["parent"]
                    .as_u64()
                    .filter(|p| *p > 0 && *p <= index as u64)
                    .ok_or(error)? as usize
                    - 1;
                if captures[parent]["kind"] != "browser.dump"
                    || captures[parent]["page"] != capture["page"]
                    || captures[parent]["site"] != capture["site"]
                {
                    return Err(error.into());
                }
            }
            "constructor" => {
                if capture["page"] != 0 || !capture["parent"].is_null() {
                    return Err(error.into());
                }
            }
            _ => return Err(error.into()),
        }
        previous = (at, cursor);
    }
    for read in report["reader_roots"].as_array().ok_or(error)? {
        let input = &read["file_input"];
        let source = input["source"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= captures.len() as u64)
            .ok_or(error)? as usize
            - 1;
        let original = &captures[source];
        let site = read["site"].as_str().ok_or(error)?;
        let constructor = matches!(
            site,
            "reader.call.hold.legacy_source" | "reader.call.hold.unreachable_source"
        );
        if constructor {
            let cursor = original["history_cursor"].as_u64().ok_or(error)? as usize;
            if original["kind"] != "constructor"
                || original["site"] != "hold.initial"
                || states.get(cursor).is_none_or(|s| {
                    s.invocation != 1
                        || s.owner.as_ref().is_none_or(|o| {
                            o.0 != "hold_cases.run"
                                || o.1 != "after"
                                || o.2.starts_with("hold_cases.")
                        })
                })
                || captures
                    .iter()
                    .filter(|c| c["kind"] == "constructor" && c["site"] == "hold.initial")
                    .count()
                    != 1
            {
                return Err(error.into());
            }
        } else if original["kind"] != "browser.store" {
            return Err(error.into());
        }
        if site == "reader.call.seed.failed_completion_baseline" {
            let cursor = original["history_cursor"].as_u64().ok_or(error)? as usize;
            let owner = states
                .get(cursor)
                .and_then(|s| s.owner.as_ref())
                .ok_or(error)?;
            if original["site"] != "seed.failed_append.baseline"
                || owner.0 != "seed_cases.run"
                || owner.1 != "inside"
                || original["case"] != owner.2
                || read["history_cursor"]
                    .as_u64()
                    .and_then(|n| states.get(n as usize))
                    .and_then(|s| s.owner.as_ref())
                    != Some(owner)
            {
                return Err(error.into());
            }
        }

        if input.as_object().is_none_or(|m| m.len() != 5)
            || input["ok"] != true
            || input["page"] != original["page"]
            || input["kind"] != original["kind"]
            || input["site"] != original["site"]
            || original["at_ns"].as_u64() > read["start_ns"].as_u64()
        {
            return Err(error.into());
        }
    }
    Ok(())
}

fn validate_reader_sources(report: &Value) -> Result<(), String> {
    let sources = super::reader_checks::resolve_callers(report)?;
    let states = super::reader_checks::caller_states(report);
    let pages = history::source_page_states(report)?;
    validate_reader_sources_with(
        report,
        &sources,
        &completion::inventory()["file_read_sources"],
        &states,
        &pages,
    )
}

fn validate_reader_sources_with(
    report: &Value,
    sources: &[super::reader_checks::SourceRoot],
    rules: &Value,
    states: &[super::reader_checks::CallerState],
    pages: &[BTreeMap<String, u64>],
) -> Result<(), String> {
    let error = "original file source checkpoint/page/window mismatch";
    let captures = report["file_captures"].as_array().ok_or(error)?;
    let events = report["helper_history"].as_array().ok_or(error)?;
    let mut used = std::collections::BTreeSet::new();
    let mut occurrences = BTreeMap::new();
    for (read, source) in report["reader_roots"]
        .as_array()
        .ok_or(error)?
        .iter()
        .zip(sources)
    {
        let rule = &rules[&source.site];
        if rule.as_array().is_none_or(|a| !(2..=3).contains(&a.len())) {
            return Err(error.into());
        }
        let site = rule[0].as_str().ok_or(error)?;
        let window = rule[1].as_str().ok_or(error)?;
        let original = &captures[read["file_input"]["source"].as_u64().ok_or(error)? as usize - 1];
        let cursor = original["history_cursor"].as_u64().ok_or(error)? as usize;
        let end = read["history_cursor"].as_u64().ok_or(error)? as usize;
        let state = states.get(cursor).ok_or(error)?;
        if original["site"] != site || cursor > end || state.invocation != source.invocation {
            return Err(error.into());
        }
        if window == "initial" {
            // The hold fixture is built once before its first selected case and reused.
            if original["kind"] != "constructor"
                || state.owner.as_ref().is_none_or(|o| {
                    o.0 != source.owner.0 || o.1 != "after" || o.2.starts_with("hold_cases.")
                })
            {
                return Err(error.into());
            }
            continue;
        }
        let role = if matches!(
            source.owner.0.as_str(),
            "seed_cases.run" | "setup_cases.run" | "binding_cases.run" | "mode_cases.run"
        ) && source.invocation == 2
            || source.site == "reader.call.main.leakage" && source.owner.2 == "main.c022.p001"
        {
            "served"
        } else {
            "tracer"
        };
        let page = if source.prepare.is_some() {
            let mut calls = Vec::new();
            for event in &events[..cursor] {
                match event["event"].as_str() {
                    Some("call_start") => calls.push(event),
                    Some("call_end") => {
                        calls.pop();
                    }
                    _ => {}
                }
            }
            calls
                .last()
                .filter(|e| e["kind"] == "binding.prepare")
                .map(|e| &e["page"])
                .ok_or(error)?
                .as_u64()
                .ok_or(error)?
        } else {
            *pages.get(cursor).and_then(|p| p.get(role)).ok_or(error)?
        };
        if original["page"] != page || state.owner.as_ref() != Some(&source.owner) {
            return Err(error.into());
        }
        let count = occurrences
            .entry((
                source.owner.clone(),
                source.invocation,
                source.site.clone(),
                source.prepare,
            ))
            .or_insert(0usize);
        *count += 1;
        if let Some(anchor) = rule.get(2) {
            let object = anchor.as_object().ok_or(error)?;
            if object.keys().any(|name| {
                name != "before_check"
                    && name != "after_observer"
                    && name != "checks_before_primary"
            }) {
                return Err(error.into());
            }
            if let Some(predicate) = anchor.get("before_check") {
                let predicate = predicate.as_str().ok_or(error)?;
                let checks = anchor
                    .get("checks_before_primary")
                    .map(|v| v.as_array().ok_or(error))
                    .transpose()?
                    .map_or(&[][..], Vec::as_slice);
                crate::file_domains::checkpoint_with_checks(
                    report,
                    original,
                    &source.owner.2,
                    predicate,
                    *count,
                    checks,
                )?;
                let id = format!("{predicate}.i{:03}", *count);
                let check = report["primary_history"]
                    .as_array()
                    .ok_or(error)?
                    .iter()
                    .find(|r| r["case"] == source.owner.2 && r["id"] == id)
                    .ok_or(error)?;
                if read["end_ns"].as_u64() > check["at_ns"].as_u64() {
                    return Err(error.into());
                }
            }
            if let Some(observer) = anchor.get("after_observer") {
                let matches: Vec<_> = report["observer_calls"]
                    .as_array()
                    .ok_or(error)?
                    .iter()
                    .filter(|c| {
                        c["site"] == *observer
                            && c["end_cursor"]
                                .as_u64()
                                .and_then(|n| states.get(n as usize))
                                .is_some_and(|s| {
                                    s.invocation == source.invocation
                                        && s.owner.as_ref() == Some(&source.owner)
                                })
                    })
                    .collect();
                if matches.len() != 1 || matches[0]["end_ns"].as_u64() > original["at_ns"].as_u64()
                {
                    return Err(error.into());
                }
            }
        }
        match window {
            "current" => {
                if cursor != end || !used.insert(original["source"].as_u64().ok_or(error)?) {
                    return Err(error.into());
                }
            }
            "baseline" => {
                if source.site != "reader.call.seed.failed_completion_baseline"
                    || state.prepares_started != 0
                {
                    return Err(error.into());
                }
            }
            "reload" => {
                let mut depth = 0;
                let mut roots = Vec::new();
                for event in &events[cursor..end] {
                    match event["event"].as_str() {
                        Some("call_start") => {
                            if depth == 0 {
                                roots.push(event["kind"].as_str().ok_or(error)?);
                            }
                            depth += 1;
                        }
                        Some("call_end") if depth > 0 => depth -= 1,
                        Some("scenario_start" | "scenario_end" | "case_start" | "case_end") => {
                            return Err(error.into());
                        }
                        _ => {}
                    }
                }
                if depth != 0 || roots != ["runtime.worker", "runtime.submit"] {
                    return Err(error.into());
                }
            }
            _ => return Err(error.into()),
        }
    }
    Ok(())
}

impl From<Bytes> for Files {
    fn from(files: Bytes) -> Self {
        Self {
            files,
            original: None,
            control: None,
            contracts: None,
        }
    }
}
impl From<Files> for Bytes {
    fn from(files: Files) -> Self {
        files.files
    }
}
impl PartialEq<Files> for Bytes {
    fn eq(&self, other: &Files) -> bool {
        *self == other.files
    }
}
impl PartialEq<Bytes> for Files {
    fn eq(&self, other: &Bytes) -> bool {
        self.files == *other
    }
}

#[cfg(test)]
mod contract_output_tests {
    use super::*;
    #[test]
    fn installed_expression_owns_exact_original_payload() {
        let files: Files = [("0".into(), vec![1, 2, 3])].into_iter().collect();
        let expression = PUT_EXPRESSION.replace("__TAU_FILES__", r#"{"0":"AQID"}"#);
        assert!(put_expression_matches(&expression, &files));
        for bad in [
            expression.replace("AQID", "AwIB"),
            expression.replace(r#""0":"#, r#""1":"#),
            expression.replace("return true;", "return false;"),
            PUT_EXPRESSION.replace("__TAU_FILES__", r#"{"0":"AQID","1":"AQID"}"#),
        ] {
            assert!(!put_expression_matches(&bad, &files));
        }
        assert!(put_expression_matches(&expression, &files));
    }

    #[test]
    fn contract_output_is_exact_and_retains_its_private_snapshot() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mut events = vec![json!({"seed":{"mnemonic":words}})];
        events.extend(crate::reader::setup_events(words, &["fixture"]));
        events.push(
            json!({"setup":{"class":{"machine":"fixture","answer":"no","class":"single_purpose"}}}),
        );
        let bytes = crate::reader::build(crate::PASSPHRASE, &events).files;
        let bytes = bytes
            .into_iter()
            .map(|(name, bytes)| (format!("{}{name}", crate::STORE), bytes))
            .collect();
        let dumped = Files::test_capture_at(
            bytes,
            "browser.dump",
            7,
            None,
            true,
            "file.binding_cases.dump.001",
        );
        let original = store_files(&dumped);
        let output = crate::reader::with_contracts(original.clone(), crate::PASSPHRASE).unwrap();
        let origin = installation(&output)["contracts"]["reader"]
            .as_u64()
            .unwrap() as usize;
        assert_eq!(installation(&output)["contracts"]["ok"], true);
        assert!(crate::auxiliary::contracts_output_matches(
            origin,
            &original,
            &output,
            crate::PASSPHRASE
        ));
        for remove in [false, true] {
            let mut bad = output.clone();
            if remove {
                bad.remove(&events.len().to_string());
            } else {
                bad.insert("extra".into(), vec![1]);
            }
            assert_eq!(installation(&bad)["contracts"]["ok"], false);
            assert!(!crate::auxiliary::contracts_output_matches(
                origin,
                &original,
                &bad,
                crate::PASSPHRASE
            ));
        }
        assert!(!crate::auxiliary::contracts_output_matches(
            origin,
            &original,
            &output,
            crate::WRONG_PASSPHRASE
        ));
        assert_eq!(installation(&output)["contracts"]["ok"], true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn refusal_inputs_preserve_each_original_cryptographic_edit() {
        let envelope = json!({"version":1,"salt":"AA"});
        let record = json!({"id":"fixture","type":"event","number":1,"previous":"00","nonce":"AA","ciphertext":"AA"});
        let dumped = Files::test_capture_at(
            BTreeMap::from([
                (
                    format!("{}envelope.json", crate::STORE),
                    envelope.to_string().into_bytes(),
                ),
                (
                    format!("{}1", crate::STORE),
                    crate::reader::record_bytes(&record),
                ),
            ]),
            "browser.dump",
            1,
            None,
            true,
            "file.main.dump.013",
        );
        let base = store_files(&dumped);
        let foreign = Files::test_capture_at(
            BTreeMap::from([("1".into(), vec![7, 8, 9])]),
            "constructor",
            0,
            None,
            true,
            "file.main.build.007",
        );
        let variants = refusal_variants(&base, &foreign);
        let kinds = [
            "wrong_passphrase",
            "salt",
            "ciphertext",
            "foreign_record",
            "version",
        ];
        for (index, (_, files, _, _)) in variants.iter().enumerate() {
            assert!(refusal_input_matches(kinds[index], &base, &foreign, files));
        }
        for kind in kinds.iter().skip(2) {
            assert!(!refusal_input_matches(
                kind,
                &base,
                &foreign,
                &variants[1].1
            ));
        }
        let mut changed = variants[2].1.clone();
        changed.insert("1".into(), base["1"].clone());
        assert!(!refusal_input_matches(
            "ciphertext",
            &base,
            &foreign,
            &changed
        ));
        put_input(&changed);
        assert_eq!(CONTROL_USES.lock().unwrap().last().unwrap()["ok"], false);
        assert_eq!(variants[3].1["1"], foreign["1"]);
        assert!(equal_at("control.replacement", "", &changed, &changed));
        let comparisons = COMPARISONS.lock().unwrap();
        assert_eq!(
            comparisons
                .iter()
                .find(|c| c["site"] == "control.replacement")
                .unwrap()["control_ok"],
            false
        );
    }

    #[test]
    fn fixed_constructor_operands_are_original_inputs() {
        let words = include_str!("../../tests/vectors/seed-backup-collisions.txt")
            .lines()
            .next()
            .unwrap();
        let events = [
            json!({"seed":{"mnemonic":words}}),
            json!({"command":{"machine":"fixture","command":hex::encode(crate::COMMAND)}}),
        ];
        assert!(constructor_input(
            "file.main.build.007",
            crate::PASSPHRASE,
            &events
        ));
        let mut substituted = events.clone();
        substituted[1]["command"]["command"] = json!(hex::encode("other command"));
        assert!(!constructor_input(
            "file.main.build.007",
            crate::PASSPHRASE,
            &substituted
        ));
        assert!(!constructor_input(
            "file.main.build.007",
            crate::HOST_PASSPHRASE,
            &events
        ));
    }
    #[test]
    fn genuine_capture_still_requires_its_original_checkpoint_and_page() {
        let fixture: Value =
            serde_json::from_str(include_str!("../testdata/file-checkpoints.json")).unwrap();
        let base = &fixture["report"];
        let sources = [super::super::reader_checks::SourceRoot {
            invocation: 1,
            site: "reader.call.seed.mismatch_absence".into(),
            owner: (
                "seed_cases.run".into(),
                "inside".into(),
                "seed_cases.c002.p001".into(),
            ),
            role: "only".into(),
            prepare: None,
        }];
        let check = |report: &Value| {
            validate_shapes(report)?;
            validate_reader_sources_with(
                report,
                &sources,
                &fixture["key"]["file_read_sources"],
                &super::super::reader_checks::caller_states(report),
                &history::source_page_states(report)?,
            )
        };
        check(base).unwrap();
        let mut old = base.clone();
        old["reader_roots"][0]["file_input"] = json!({"source":2,"kind":"browser.store","site":"file.seed_cases.dump.003","page":1,"ok":true});
        assert!(check(&old).unwrap_err().contains("checkpoint/page/window"));
        let mut wrong_page = base.clone();
        for capture in wrong_page["file_captures"].as_array_mut().unwrap() {
            capture["page"] = json!(999);
        }
        wrong_page["reader_roots"][0]["file_input"]["page"] = json!(999);
        assert!(
            check(&wrong_page)
                .unwrap_err()
                .contains("checkpoint/page/window")
        );
        check(base).unwrap();
    }
    #[test]
    fn reader_consumes_the_original_browser_bytes_and_origin() {
        let dumped = Files::capture(
            BTreeMap::from([("tau-web-store/0".into(), vec![1, 2, 3])]),
            "browser.dump",
            1,
            None,
            true,
        );
        let original = store_files(&dumped);
        let check = |files: &Files| {
            let captures = snapshot();
            let now = completion::now();
            validate_shapes(
                &json!({"file_captures":captures,"helper_history":history::snapshot(),"reader_roots":[{"site":"reader.call.test","file_input":files.input(),"start_ns":now}],"duration_ns":now}),
            )
        };
        check(&original).unwrap();
        // Altering both the mutable bytes and their later stored copy cannot rewrite
        // the original transport return.
        let mut fabricated = original.clone();
        fabricated.files.insert("0".into(), vec![3, 2, 1]);
        let source = fabricated.original.as_ref().unwrap();
        fabricated.original = Some(Arc::new(Original {
            files: fabricated.files.clone(),
            id: source.id,
            kind: source.kind,
            page: source.page,
            parent: source.parent,
            site: source.site,
            dump: source.dump.clone(),
        }));
        assert_eq!(
            fabricated.files,
            fabricated.original.as_ref().unwrap().files
        );
        assert_eq!(fabricated.input()["ok"], false);
        assert!(check(&fabricated).is_err());
        check(&original).unwrap();
        let mut changed = original.clone();
        changed.insert("0".into(), vec![3, 2, 1]);
        assert_eq!(changed.len(), original.len());
        assert!(
            check(&changed)
                .unwrap_err()
                .contains("reader input provenance")
        );
        check(&original).unwrap();
        let substituted = constructed_at(
            original
                .iter()
                .map(|(n, v)| (n.clone(), v.clone()))
                .collect(),
            "",
        );
        assert_eq!(substituted, original);
        assert!(
            check(&substituted)
                .unwrap_err()
                .contains("reader input provenance")
        );
        check(&original).unwrap();
    }
}
