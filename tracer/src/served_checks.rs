//! Actual mandatory served-check predicates, against source and artifact input domains.
use super::{completion, json};
use serde_json::Value;
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
};
thread_local! { static CALLS: RefCell<Vec<Value>> = const {RefCell::new(Vec::new())}; static ACTIVE: RefCell<Option<usize>> = const { RefCell::new(None) }; }
pub struct Call {
    index: usize,
    previous: Option<usize>,
    directory: PathBuf,
}
thread_local! {static FILES: RefCell<Vec<Vec<PathBuf>>> = const {RefCell::new(Vec::new())};}
pub fn begin(kind: &'static str, directory: &Path) -> Call {
    let input = super::completion::identity::directory(directory).ok();
    let paths = artifact_paths(directory).unwrap_or_default();
    let index = CALLS.with_borrow_mut(|calls| {
        let index = calls.len();
        calls.push(json!({"kind":kind,"input":input,"input_after":null,"start_ns":completion::now(),"end_ns":null,"guards":[]}));
        index
    });
    FILES.with_borrow_mut(|files| files.push(paths));
    let previous = ACTIVE.with_borrow_mut(|active| active.replace(index));
    Call {
        index,
        previous,
        directory: directory.to_owned(),
    }
}
impl Drop for Call {
    fn drop(&mut self) {
        let input = super::completion::identity::directory(&self.directory).ok();
        CALLS.with_borrow_mut(|calls| {
            calls[self.index]["input_after"] = json!(input);
            calls[self.index]["end_ns"] = json!(completion::now());
        });
        ACTIVE.with_borrow_mut(|active| *active = self.previous);
    }
}
pub fn holds(id: &'static str, context: Value, ok: bool) -> bool {
    ACTIVE.with_borrow(|active| {
        if let Some(index) = active {
            CALLS.with_borrow_mut(|calls| {
                calls[*index]["guards"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({"id":id,"context":context,"ok":ok}))
            });
        }
    });
    ok
}
pub fn result<T, E>(id: &'static str, context: Value, result: Result<T, E>) -> Result<T, E> {
    holds(id, context, result.is_ok());
    result
}
pub fn snapshot() -> Value {
    CALLS.with_borrow(|calls| json!(calls))
}
fn guard(id: &str, context: Value) -> Value {
    json!({"id":id,"context":context,"ok":true})
}
fn artifact_paths(dir: &Path) -> Result<Vec<PathBuf>, String> {
    if !std::fs::symlink_metadata(dir)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_dir()
    {
        return Err("nonregular artifact identity input".into());
    }
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            paths.extend(artifact_paths(&entry.path())?);
        } else if kind.is_file() {
            paths.push(entry.path());
        } else {
            return Err("nonregular served-check input".into());
        }
    }
    paths.sort();
    Ok(paths)
}
pub struct AbsenceNeedles(Vec<(String, Vec<u8>)>);
pub fn absence_needles() -> AbsenceNeedles {
    AbsenceNeedles(super::checks::needles())
}
impl AbsenceNeedles {
    pub fn needle_count(&self) -> usize {
        self.0.len()
    }
}
pub fn scan_file(
    needles: &AbsenceNeedles,
    path: &Path,
    file: usize,
) -> Result<Vec<String>, String> {
    let source = ACTIVE.with_borrow(|active| {
        active.is_some_and(|call| {
            FILES.with_borrow(|files| {
                files[call]
                    .get(file)
                    .is_some_and(|expected| expected == path)
            })
        })
    });
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    holds("checks.absence.file_source", json!({"file":file}), source);
    let mut found = Vec::new();
    for (position, (what, needle)) in needles.0.iter().enumerate() {
        if !holds(
            "checks.absence.needle_absent",
            json!({"file":file,"needle":position}),
            !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
        ) {
            found.push(what.clone());
        }
    }
    Ok(found)
}
pub struct Policy(String);
impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
pub fn csp_policy(directory: &Path) -> Result<Policy, String> {
    let path = directory.join("index.html");
    let source = ACTIVE.with_borrow(|active| {
        active.is_some_and(|call| FILES.with_borrow(|files| files[call].contains(&path)))
    });
    let html = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    holds("checks.csp.page_source", json!({}), source);
    super::checks::page_policy(&html).map(Policy)
}
pub fn policy_differences(policy: &Policy) -> Result<(), String> {
    super::checks::policy_differences(&policy.0)
}
fn expected_absence(served: &Path) -> Result<Vec<Value>, String> {
    let mut absence = vec![guard("checks.served.required_files", json!({}))];
    let needles = completion::inventory()["served_check_sources"]["absence_needles"]
        .as_array()
        .ok_or("missing absence needle source domain")?;
    for file in 0..artifact_paths(served)?.len() {
        absence.push(guard("checks.absence.file_source", json!({"file":file})));
        for needle in 0..needles.len() {
            absence.push(guard(
                "checks.absence.needle_absent",
                json!({"file":file,"needle":needle}),
            ));
        }
    }
    absence.push(guard("checks.absence.clear", json!({})));
    Ok(absence)
}
fn expected(served: &Path) -> Result<[Vec<Value>; 2], String> {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("www/index.html");
    let html = std::fs::read_to_string(source).map_err(|e| e.to_string())?;
    if std::fs::read(served.join("index.html")).map_err(|e| e.to_string())? != html.as_bytes() {
        return Err("served page differs from its build source".into());
    }
    let mut csp = vec![guard("checks.served.required_files", json!({}))];
    csp.push(guard("checks.csp.page_source", json!({})));
    // build-web copies this source verbatim. These lexical slots describe its
    // original meta loop; they neither call nor learn from the checked parser.
    let lower = html.to_ascii_lowercase();
    let mut policy = None;
    for (meta, (start, _)) in lower.match_indices("<meta").enumerate() {
        csp.push(guard("checks.csp.meta_closed", json!({"meta":meta})));
        let end = lower[start..]
            .find('>')
            .map(|offset| start + offset)
            .ok_or("unmapped source meta")?;
        let tag = &html[start..end];
        if tag
            .to_ascii_lowercase()
            .contains("http-equiv=\"content-security-policy\"")
        {
            if policy.is_some() {
                return Err("unmapped source policy count".into());
            }
            csp.push(guard("checks.csp.meta_content", json!({"meta":meta})));
            policy = tag
                .split_once("content=\"")
                .and_then(|(_, v)| v.split_once('"'))
                .map(|(v, _)| v);
        }
    }
    let policy = policy.ok_or("unmapped source CSP syntax")?;
    csp.push(guard("checks.csp.single_policy", json!({})));
    csp.push(guard("checks.csp.before_script", json!({})));
    for (directive, _) in policy
        .split(';')
        .filter(|part| !part.trim().is_empty())
        .enumerate()
    {
        csp.push(guard(
            "checks.csp.unique_directive",
            json!({"directive":directive}),
        ));
    }
    csp.push(guard("checks.csp.exact_policy", json!({})));
    Ok([expected_absence(served)?, csp])
}
pub fn validate_preflight(value: &Value, full: bool, served: &Path) -> Result<(), String> {
    if !full {
        return if value["served_checks"] == json!([]) {
            Ok(())
        } else {
            Err("unexpected targeted served checks".into())
        };
    }
    let [absence, csp] = expected(served)?;
    validate_checks(value, served, vec![("absence", absence), ("csp", csp)])
}
pub fn validate_absence(value: &Value, served: &Path) -> Result<(), String> {
    validate_checks(value, served, vec![("absence", expected_absence(served)?)])
}
fn validate_checks(
    value: &Value,
    served: &Path,
    expected: Vec<(&str, Vec<Value>)>,
) -> Result<(), String> {
    let error = "mandatory served-check predicate/input/order mismatch";
    let calls = value["served_checks"].as_array().ok_or(error)?;
    if calls.len() != expected.len() {
        return Err(error.into());
    }
    let input = super::completion::identity::directory(served)?;
    let mut previous = 0;
    for (call, (kind, guards)) in calls.iter().zip(expected) {
        let start = call["start_ns"].as_u64().ok_or(error)?;
        let end = call["end_ns"].as_u64().ok_or(error)?;
        if call.as_object().is_none_or(|o| o.len() != 6)
            || call["kind"] != kind
            || call["input"] != input
            || call["input_after"] != input
            || start < previous
            || start > end
            || value["duration_ns"]
                .as_u64()
                .is_none_or(|duration| end > duration)
            || call["guards"] != json!(guards)
        {
            return Err(error.into());
        }
        previous = end;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn shell(value: &Value, served: &Path) -> bool {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut child=Command::new("python3").arg("-B").arg("-c").arg("import json,sys;sys.path.insert(0,sys.argv[1]);import tracer_history;from pathlib import Path;tracer_history._validate_served_checks(json.load(sys.stdin),True,json.loads(Path(sys.argv[2]).read_text()),sys.argv[3])")
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("scripts"))
            .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("inventory.json")).arg(served)
            .stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(value.to_string().as_bytes())
            .unwrap();
        child.wait().unwrap().success()
    }
    #[test]
    fn mandatory_checks_require_actual_scan_and_nested_policy_predicates() {
        let dir = std::env::temp_dir().join(format!(
            "tau-served-checks-{}-{}",
            std::process::id(),
            hex::encode(crate::fixtures::urandom::<8>())
        ));
        std::fs::create_dir_all(dir.join("pkg")).unwrap();
        for file in crate::checks::SERVED_FILES {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        std::fs::write(
            dir.join("index.html"),
            include_bytes!("../../www/index.html"),
        )
        .unwrap();
        CALLS.with_borrow_mut(Vec::clear);
        FILES.with_borrow_mut(Vec::clear);
        crate::checks::absence(&dir).unwrap();
        crate::checks::csp(&dir).unwrap();
        let value = json!({"duration_ns":completion::now(),"served_checks":snapshot()});
        assert!(validate_preflight(&value, true, &dir).is_ok());
        assert!(shell(&value, &dir));
        for (call, guard) in [(0, 1), (0, 2), (1, 1), (1, 6)] {
            let mut bad = value.clone();
            bad["served_checks"][call]["guards"]
                .as_array_mut()
                .unwrap()
                .remove(guard);
            assert!(validate_preflight(&bad, true, &dir).is_err());
            assert!(!shell(&bad, &dir));
            assert!(validate_preflight(&value, true, &dir).is_ok());
            assert!(shell(&value, &dir));
        }
        let mut bad = value.clone();
        bad["served_checks"].as_array_mut().unwrap().pop();
        assert!(validate_preflight(&bad, true, &dir).is_err());
        assert!(!shell(&bad, &dir));
        // A clean neighbor with the same file count cannot stand for the input
        // whose bytes the gate is supposed to scan.
        let other = dir.with_extension("neighbor");
        std::fs::create_dir_all(other.join("pkg")).unwrap();
        for file in crate::checks::SERVED_FILES {
            std::fs::copy(dir.join(file), other.join(file)).unwrap();
        }
        CALLS.with_borrow_mut(Vec::clear);
        FILES.with_borrow_mut(Vec::clear);
        crate::checks::absence(&other).unwrap();
        crate::checks::csp(&other).unwrap();
        let neighbor = json!({"duration_ns":completion::now(),"served_checks":snapshot()});
        assert!(validate_preflight(&neighbor, true, &dir).is_ok());
        assert!(shell(&neighbor, &dir));
        let original = std::fs::read(dir.join("boot.js")).unwrap();
        std::fs::write(dir.join("boot.js"), b"fixture-root-password-ggw9!").unwrap();
        CALLS.with_borrow_mut(Vec::clear);
        FILES.with_borrow_mut(Vec::clear);
        crate::checks::absence(&other).unwrap();
        crate::checks::csp(&other).unwrap();
        let neighbor = json!({"duration_ns":completion::now(),"served_checks":snapshot()});
        assert!(
            neighbor["served_checks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|call| call["guards"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .all(|guard| guard["ok"] == true))
        );
        assert!(validate_preflight(&neighbor, true, &dir).is_err());
        assert!(!shell(&neighbor, &dir));
        std::fs::write(dir.join("boot.js"), original).unwrap();
        CALLS.with_borrow_mut(Vec::clear);
        FILES.with_borrow_mut(Vec::clear);
        crate::checks::absence(&dir).unwrap();
        crate::checks::csp(&dir).unwrap();
        let restored = json!({"duration_ns":completion::now(),"served_checks":snapshot()});
        assert_eq!(
            restored["served_checks"][0]["input"],
            neighbor["served_checks"][0]["input"]
        );
        assert!(validate_preflight(&restored, true, &dir).is_ok());
        assert!(shell(&restored, &dir));
        std::fs::remove_dir_all(&other).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
