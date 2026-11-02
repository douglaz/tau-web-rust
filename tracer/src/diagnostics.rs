//! Small, direct failure records. Never pass descriptions or returned errors to this module.
use crate::{completion, json};
use serde_json::Value;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

static STORE: Mutex<Option<Store>> = Mutex::new(None);
static BROKEN: AtomicBool = AtomicBool::new(false);
const TOKEN: &str = "_TAU_DIAGNOSTIC_INVOCATION";
const DRIVER: &str = "_TAU_DIAGNOSTIC_DRIVER_PID";
const CAPTURE: &str = "_TAU_DIAGNOSTIC_CAPTURE";

// Descriptor-relative operations never traverse a symlink, including parent components.
// The descriptors also pin the directories across atomic leaf replacements.
pub struct Directory(File);
impl Directory {
    pub fn open(path: &Path, create: bool) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("diagnostic directory must be absolute".into());
        }
        let mut dir = Self(File::open("/").map_err(|_| "diagnostic root unavailable")?);
        for part in path.components() {
            let Component::Normal(part) = part else {
                if part == Component::RootDir {
                    continue;
                }
                return Err("noncanonical diagnostic directory".into());
            };
            let name = CString::new(part.as_encoded_bytes()).map_err(|_| "diagnostic pathname")?;
            if create {
                // SAFETY: name and parent descriptor remain valid for this call.
                let result = unsafe { libc::mkdirat(dir.0.as_raw_fd(), name.as_ptr(), 0o700) };
                if result != 0
                    && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
                {
                    return Err("cannot create diagnostic directory".into());
                }
            }
            // SAFETY: openat returns a new descriptor or -1; no symlink is followed.
            let fd = unsafe {
                libc::openat(
                    dir.0.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("unsafe diagnostic directory".into());
            }
            // SAFETY: the successful openat descriptor is exclusively owned here.
            dir = Self(unsafe { File::from_raw_fd(fd) });
        }
        if dir.0.metadata().map_err(|_| "diagnostic metadata")?.uid() != unsafe { libc::geteuid() }
        {
            return Err("foreign diagnostic directory".into());
        }
        Ok(dir)
    }
    pub fn create(&self, name: &str) -> Result<File, String> {
        let name = CString::new(name).map_err(|_| "diagnostic name")?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("unsafe capture output".into());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn read(&self, name: &str) -> Result<Option<Value>, String> {
        let name = CString::new(name).unwrap();
        // O_NONBLOCK prevents a FIFO from hanging before the regular-file check.
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
                Ok(None)
            } else {
                Err("unsafe diagnostic input".into())
            };
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(|_| "diagnostic metadata")?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.nlink() != 1
            || meta.len() > 8192
        {
            return Err("unsafe diagnostic input".into());
        }
        let mut raw = String::new();
        file.take(8193)
            .read_to_string(&mut raw)
            .map_err(|_| "diagnostic read")?;
        crate::strict_json::parse(&raw)
            .map(Some)
            .map_err(|_| "invalid diagnostic JSON".into())
    }
    pub fn hash(&self, name: &str) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let name = CString::new(name).map_err(|_| "diagnostic name")?;
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("unsafe capture digest input".into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata().map_err(|_| "capture metadata")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
        {
            return Err("unsafe capture digest input".into());
        }
        let mut digest = Sha256::new();
        let mut buffer = [0; 65536];
        loop {
            let count = file.read(&mut buffer).map_err(|_| "capture digest read")?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        Ok(format!("{:x}", digest.finalize()))
    }
    pub fn write(&self, name: &str, value: &Value, first: bool) -> Result<(), String> {
        self.write_inner(name, value, first, true)
    }
    // These existing raw receipt inputs stay local. Their size must not acquire a
    // new admission limit just because diagnostic records are bounded.
    pub fn write_capture(&self, name: &str, value: &Value) -> Result<(), String> {
        assert!(matches!(
            name,
            "identity.json" | "preflight.json" | "exit.json"
        ));
        self.write_inner(name, value, false, false)
    }
    fn write_inner(
        &self,
        name: &str,
        value: &Value,
        first: bool,
        bounded: bool,
    ) -> Result<(), String> {
        let existing = self.read(name)?;
        if first && existing.is_some() {
            return Ok(());
        }
        let temporary = CString::new(format!(".{name}.{}", std::process::id())).unwrap();
        let name = CString::new(name).unwrap();
        let raw = value.to_string();
        if bounded && raw.len() > 8192 {
            return Err("diagnostic record exceeds bound".into());
        }
        let fd = unsafe {
            libc::openat(
                self.0.as_raw_fd(),
                temporary.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("unsafe diagnostic output".into());
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        let result = (|| {
            file.write_all(raw.as_bytes())
                .map_err(|_| "diagnostic write")?;
            file.sync_all().map_err(|_| "diagnostic sync")?;
            // linkat publishes the first failure without ever replacing it.
            let code = unsafe {
                if first {
                    libc::linkat(
                        self.0.as_raw_fd(),
                        temporary.as_ptr(),
                        self.0.as_raw_fd(),
                        name.as_ptr(),
                        0,
                    )
                } else {
                    libc::renameat(
                        self.0.as_raw_fd(),
                        temporary.as_ptr(),
                        self.0.as_raw_fd(),
                        name.as_ptr(),
                    )
                }
            };
            if code != 0 {
                return Err("diagnostic publication failed".into());
            }
            Ok(())
        })();
        unsafe {
            libc::unlinkat(self.0.as_raw_fd(), temporary.as_ptr(), 0);
        }
        result
    }
}
struct Store {
    directory: Directory,
    phase: &'static str,
    status_file: &'static str,
    case: Option<String>,
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target/tracer-evidence")
}
fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn supervisor() -> Result<PathBuf, String> {
    let (token, driver) = match (std::env::var(TOKEN), std::env::var(DRIVER)) {
        (Ok(token), Ok(driver))
            if valid_token(&token)
                && driver.parse::<u32>().ok() == Some(unsafe { libc::getppid() } as u32) =>
        {
            (token, json!(unsafe { libc::getppid() }))
        }
        (Err(std::env::VarError::NotPresent), Err(std::env::VarError::NotPresent)) => {
            (hex::encode(crate::fixtures::urandom::<32>()), Value::Null)
        }
        _ => return Err("foreign diagnostic invocation".into()),
    };
    let parent = Directory::open(&root(), true)?;
    let name = format!("{}-{token}", std::process::id());
    let c_name = CString::new(name.as_str()).unwrap();
    if unsafe { libc::mkdirat(parent.0.as_raw_fd(), c_name.as_ptr(), 0o700) } != 0 {
        return Err("diagnostic capture already exists or is unsafe".into());
    }
    let capture = root().join(name);
    let directory = Directory::open(&capture, false)?;
    directory.write(
        "owner.json",
        &json!({"schema":1,"supervisor":std::process::id(),"driver":driver,"invocation":token}),
        true,
    )?;
    *STORE.lock().unwrap() = Some(Store {
        directory,
        phase: "supervisor",
        status_file: "native-status.json",
        case: None,
    });
    phase("supervisor");
    Ok(capture)
}
pub fn child() -> Result<(), String> {
    let raw = std::env::var(CAPTURE).map_err(|_| "execution requires a diagnostic supervisor")?;
    let path = Path::new(&raw);
    let parent = unsafe { libc::getppid() } as u32;
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid diagnostic capture")?;
    let token = name
        .strip_prefix(&format!("{parent}-"))
        .filter(|s| valid_token(s))
        .ok_or("foreign diagnostic supervisor")?;
    if path.parent() != Some(root().as_path()) {
        return Err("foreign diagnostic capture".into());
    }
    let directory = Directory::open(path, false)?;
    let owner = directory
        .read("owner.json")?
        .ok_or("missing diagnostic owner")?;
    if owner["schema"] != 1 || owner["supervisor"] != parent || owner["invocation"] != token {
        return Err("foreign diagnostic owner".into());
    }
    *STORE.lock().unwrap() = Some(Store {
        directory,
        phase: "execution",
        status_file: "status.json",
        case: None,
    });
    phase("execution");
    Ok(())
}
pub fn configure(command: &mut tokio::process::Command, capture: &Path) {
    command
        .env(CAPTURE, capture)
        .env_remove(TOKEN)
        .env_remove(DRIVER);
}
fn update(f: impl FnOnce(&mut Store) -> Result<(), String>) {
    if let Some(store) = STORE.lock().unwrap().as_mut()
        && f(store).is_err()
    {
        BROKEN.store(true, Ordering::Relaxed);
        eprintln!("diagnostic retention unavailable");
    }
}
impl Store {
    fn invalid_identity(&self) -> Result<(), String> {
        self.failure("execution", "retention", None)?;
        Err("invalid diagnostic identity".into())
    }
    fn status(&self, status: &str) -> Result<(), String> {
        self.directory.write(self.status_file, &json!({"schema":1,"at_ns":completion::now(),"phase":self.phase,"case":self.case,"status":status}), false)
    }
    fn failure(&self, kind: &str, class: &str, instance: Option<&str>) -> Result<(), String> {
        self.directory.write(
            "first-failure.json",
            &self.failure_record(kind, class, instance),
            true,
        )
    }
    fn failure_record(&self, kind: &str, class: &str, instance: Option<&str>) -> Value {
        json!({"schema":1,"at_ns":completion::now(),"phase":self.phase,"case":self.case,"kind":kind,"class":class,"instance":instance})
    }
}
pub fn phase(phase: &'static str) {
    update(|store| {
        store.phase = phase;
        store.status("active")
    });
}
pub fn case(id: &str) {
    update(|store| {
        if !completion::inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == id)
        {
            store.case = None;
            return store.invalid_identity();
        }
        store.case = Some(id.to_owned());
        store.status("active")
    });
}
fn instance_site(instance: &str) -> Option<&str> {
    let (site, occurrence) = instance.rsplit_once(".i")?;
    let count: u64 = occurrence.parse().ok()?;
    (count > 0 && count <= 999999 && instance == format!("{site}.i{count:03}")).then_some(site)
}
pub fn primary(case: &str, instance: &str, reboot: Option<&crate::reboot_evidence::Reboot>) {
    update(|store| {
        let Some(spec) = completion::inventory()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == case)
        else {
            return store.invalid_identity();
        };
        let Some(site) = instance_site(instance) else {
            return store.invalid_identity();
        };
        let known = spec["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == site)
            || spec["optional"]["site"] == site
            || spec["variants"]["sequences"]
                .as_object()
                .is_some_and(|sequences| {
                    sequences
                        .values()
                        .any(|sites| sites.as_array().unwrap().iter().any(|s| s == site))
                });
        // lock_during_command has one false-only check, shared by these two
        // original callers. It cannot appear in the successful completion census.
        let error_only = site == "main.a122" && matches!(case, "main.c017.p001" | "main.c018.p001");
        if !known && !error_only {
            return store.invalid_identity();
        }
        store.case = Some(case.to_owned());
        if (site == "job_cases.a015") != reboot.is_some() {
            return store.invalid_identity();
        }
        if let Some(reboot) = reboot {
            if case != "job_cases.c004.p001" || site != "job_cases.a015" || reboot.holds() {
                return store.invalid_identity();
            }
            let mut value = store.failure_record("primary", "check", Some(instance));
            value["reboot"] = json!(reboot);
            store.directory.write("first-failure.json", &value, true)?;
            // An earlier failure must not suppress this assertion's bounded observations.
            store.directory.write("reboot-failure.json", &value, true)
        } else {
            store.failure("primary", "check", Some(instance))
        }
    });
}
pub fn prerequisite(instance: &str) {
    update(|store| {
        let Some(id) = instance_site(instance) else {
            return store.invalid_identity();
        };
        if !crate::history::expected_prerequisites(completion::inventory()).contains_key(id)
            && completion::inventory()["dynamic_prerequisites"]
                .get(id)
                .is_none()
        {
            return store.invalid_identity();
        }
        store.failure(
            "prerequisite",
            if store.phase == "cleanup" {
                "cleanup"
            } else {
                "prerequisite"
            },
            Some(instance),
        )
    });
}
pub fn error(class: &'static str) {
    update(|store| store.failure("execution", class, None));
}
pub fn cleanup_result(ok: bool) -> bool {
    if !ok {
        error("cleanup");
    }
    ok
}
pub fn terminal(ok: bool) {
    update(|store| store.status(if ok { "succeeded" } else { "failed" }));
}
fn waited_record(status: Option<std::process::ExitStatus>) -> Value {
    use std::os::unix::process::ExitStatusExt;
    json!({"schema":1,"state":if status.is_some() {"waited"} else {"unavailable"},"code":status.and_then(|s|s.code()),"signal":status.and_then(|s|s.signal())})
}
pub fn waited(status: Option<std::process::ExitStatus>) {
    update(|store| {
        store
            .directory
            .write("supervisor.json", &waited_record(status), false)
    });
}
pub fn healthy() -> bool {
    !BROKEN.load(Ordering::Relaxed)
}

pub fn supervision_failed() {
    update(|store| {
        // A missing/failed report after a waited child is a validator outcome, not
        // an observed assertion failure. In particular, death leaves absence explicit.
        if store.directory.read("supervisor.json")?.is_none() {
            store.failure("execution", "setup", None)?;
        }
        Ok(())
    });
}

pub fn execution_error() {
    update(|store| {
        store.failure(
            "execution",
            match store.phase {
                "provenance" | "execution" | "fixtures" | "browser" => "setup",
                "cleanup" => "cleanup",
                "report" => "report",
                _ => "execution",
            },
            None,
        )
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Scratch(PathBuf);
    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "tracer-diagnostics-{}-{}",
                std::process::id(),
                hex::encode(crate::fixtures::urandom::<8>())
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    fn install(scratch: &Scratch, phase: &'static str) {
        BROKEN.store(false, Ordering::Relaxed);
        *STORE.lock().unwrap() = Some(Store {
            directory: Directory::open(&scratch.0, false).unwrap(),
            phase,
            status_file: "status.json",
            case: None,
        });
    }
    fn read(scratch: &Scratch, name: &str) -> Option<Value> {
        Directory::open(&scratch.0, false)
            .unwrap()
            .read(name)
            .unwrap()
    }

    #[test]
    fn observed_boundary_controls() {
        // Process isolation lets these controls use the real global boundaries
        // without mixing diagnostic state with the parallel test harness.
        if std::env::var_os("_TAU_DIAGNOSTIC_TEST").is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "diagnostics::tests::observed_boundary_controls",
                    "--nocapture",
                ])
                .env("_TAU_DIAGNOSTIC_TEST", "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }
        for id in ["main.c017.p001", "main.c018.p001"] {
            let scratch = Scratch::new();
            install(&scratch, "groups");
            case(id);
            let mut check = crate::Case {
                id: id.into(),
                site: "main.c017",
                name: "boundary control".into(),
                failures: Vec::new(),
                assertions: Vec::new(),
                branches: Default::default(),
                start: 0,
                end: 1,
            };
            check.check("main.a122", "SENTINEL description", true);
            check.check("main.a122", "SENTINEL description", false);
            let first = read(&scratch, "first-failure.json").unwrap();
            assert_eq!(first["case"], id);
            assert_eq!(first["instance"], "main.a122.i002");
            assert_eq!(first["kind"], "primary");
            assert_eq!(check.failures.len(), 1);
            assert_eq!(check.assertions[1]["ok"], false);
            assert!(healthy());
            phase("cleanup");
            cleanup_result(false);
            terminal(false);
            assert_eq!(read(&scratch, "first-failure.json"), Some(first));
        }
        {
            let scratch = Scratch::new();
            install(&scratch, "groups");
            let state = json!({"calls":[{"call":2,"state":"unresolved"},{"call":3,"state":"unresolved"}],"terminals":[]});
            let reboot = || {
                crate::reboot_evidence::Reboot::observe(
                    false,
                    crate::reboot_evidence::Job::observe(2, &json!({"state":"ended"}), &state),
                    crate::reboot_evidence::Job::observe(3, &json!({"state":"missing"}), &state),
                    crate::reboot_evidence::Fixture {
                        setup_ms: 31001,
                        boundary_alive: true,
                        boundary_stopped: true,
                        record_present: true,
                        exit_present: false,
                        record_boot_matches: true,
                        after_alive: false,
                        after_exit_present: false,
                        record_boot_preserved: true,
                        missing_record_absent: true,
                    },
                )
            };
            let mut check = crate::Case::new(
                "job_cases.c004",
                "reboot keeps records; ended and missing calls stay unresolved (CNF-55)",
            );
            check.check("job_cases.a015", "SENTINEL description", reboot());
            let first = read(&scratch, "first-failure.json").unwrap();
            assert_eq!(first["instance"], "job_cases.a015.i001");
            assert_eq!(first["reboot"]["checks"]["boot_changed"], false);
            assert_eq!(first["reboot"]["running"]["collection"], "ended");
            assert!(first.to_string().len() < 8192);
            assert!(!first.to_string().contains("SENTINEL"));
            phase("cleanup");
            cleanup_result(false);
            terminal(false);
            primary("main.c001.p001", "main.a001.i001", None);
            assert_eq!(read(&scratch, "first-failure.json"), Some(first.clone()));
            assert_eq!(read(&scratch, "reboot-failure.json"), Some(first));
            let later = Scratch::new();
            install(&later, "groups");
            primary("main.c001.p001", "main.a001.i001", None);
            let earlier = read(&later, "first-failure.json");
            primary(
                "job_cases.c004.p001",
                "job_cases.a015.i001",
                Some(&reboot()),
            );
            assert_eq!(read(&later, "first-failure.json"), earlier);
            let record = read(&later, "reboot-failure.json").unwrap();
            assert_eq!(record["case"], "job_cases.c004.p001");
            assert_eq!(record["instance"], "job_cases.a015.i001");
            assert_eq!(record["reboot"]["checks"]["boot_changed"], false);
        }
        for (id, instance, prerequisite) in [
            ("SENTINEL", "main.a122.i001", false),
            ("main.c001.p001", "main.a122.i001", false),
            ("main.c017.p001", "main.a122.i000", false),
            ("main.c017.p001", "main.a122.i01", false),
            ("main.c017.p001", "SENTINEL", false),
            ("main.c017.p001", "SENTINEL.i001", true),
            ("main.c017.p001", "runtime.worker.ready.i000", true),
        ] {
            let scratch = Scratch::new();
            install(&scratch, "groups");
            case(id);
            if prerequisite {
                super::prerequisite(instance);
            } else {
                primary(id, instance, None);
            }
            let first = read(&scratch, "first-failure.json").unwrap();
            assert_eq!(first["class"], "retention");
            assert_eq!(first["kind"], "execution");
            assert!(first["instance"].is_null());
            assert!(!first.to_string().contains("SENTINEL"));
            assert!(!healthy());
            // A bad identity never poisons STORE or replaces the first event.
            error("cleanup");
            assert_eq!(read(&scratch, "first-failure.json"), Some(first));
        }
        {
            let scratch = Scratch::new();
            install(&scratch, "groups");
            case("main.c001.p001");
            assert!(!completion::prerequisite("runtime.worker.ready", false));
            let first = read(&scratch, "first-failure.json").unwrap();
            assert_eq!(first["kind"], "prerequisite");
            assert_eq!(first["instance"], "runtime.worker.ready.i001");
        }
        for earlier in [false, true] {
            use std::future::Future;
            use std::task::{Context, Waker};
            let scratch = Scratch::new();
            install(&scratch, "cleanup");
            case("main.c001.p001");
            if earlier {
                primary("main.c001.p001", "main.a001.i001", None);
            }
            let before = read(&scratch, "first-failure.json");
            let mut cleanup = Box::pin(async {
                let first = std::future::ready(false).await;
                cleanup_result(first);
                std::future::pending::<()>().await;
            });
            assert!(
                cleanup
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending()
            );
            let first = read(&scratch, "first-failure.json").unwrap();
            if earlier {
                assert_eq!(Some(first.clone()), before);
            } else {
                assert_eq!(first["class"], "cleanup");
            }
            drop(cleanup);
            assert_eq!(read(&scratch, "first-failure.json"), Some(first));
        }
        struct Log {
            fail_flush: bool,
        }
        impl Write for Log {
            fn write(&mut self, raw: &[u8]) -> std::io::Result<usize> {
                Ok(raw.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                if self.fail_flush {
                    Err(std::io::Error::other("SENTINEL"))
                } else {
                    Ok(())
                }
            }
        }
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .status()
            .unwrap();
        for problem in [
            "capture_flush",
            "forwarding",
            "log_digest",
            "preflight_digest",
            "capture_receipt",
            "missing_report",
        ] {
            for earlier in [false, true] {
                let scratch = Scratch::new();
                install(&scratch, "execution");
                case("main.c001.p001");
                if earlier {
                    primary("main.c001.p001", "main.a001.i001", None);
                }
                let before = read(&scratch, "first-failure.json");
                waited(Some(status));
                let directory = Directory::open(&scratch.0, false).unwrap();
                if problem != "log_digest" {
                    directory.create("execution.log").unwrap();
                }
                if problem != "preflight_digest" {
                    directory
                        .write_capture("preflight.json", &json!({}))
                        .unwrap();
                }
                if problem == "capture_receipt" {
                    std::fs::create_dir(scratch.0.join("exit.json")).unwrap();
                }
                let result = completion::finish_capture(
                    &mut Log {
                        fail_flush: problem == "capture_flush",
                    },
                    &mut Log {
                        fail_flush: problem == "forwarding",
                    },
                    &directory,
                    status,
                );
                assert_eq!(
                    result.is_ok(),
                    matches!(problem, "missing_report" | "forwarding")
                );
                if problem == "forwarding" {
                    assert!(result.unwrap());
                }
                supervision_failed();
                terminal(false);
                let first = read(&scratch, "first-failure.json");
                if earlier || problem == "missing_report" {
                    assert_eq!(first, before);
                } else {
                    let first = first.unwrap();
                    assert_eq!(first["kind"], "execution");
                    assert!(first["instance"].is_null());
                    assert_eq!(first["phase"], "execution");
                    assert_eq!(
                        first["class"],
                        if problem.ends_with("digest") {
                            "capture_digest"
                        } else {
                            problem
                        }
                    );
                    assert!(!first.to_string().contains("SENTINEL"));
                }
                assert_eq!(
                    read(&scratch, "supervisor.json"),
                    Some(waited_record(Some(status)))
                );
            }
        }
        *STORE.lock().unwrap() = None;
    }
    #[test]
    fn first_observation_survives_cleanup_and_status_changes() {
        let scratch = Scratch::new();
        let mut store = Store {
            directory: Directory::open(&scratch.0, false).unwrap(),
            phase: "groups",
            status_file: "status.json",
            case: Some("main.c001.p001".into()),
        };
        store
            .failure("primary", "check", Some("main.a001.i001"))
            .unwrap();
        let first = store.directory.read("first-failure.json").unwrap().unwrap();
        store.phase = "cleanup";
        store.failure("execution", "cleanup", None).unwrap();
        store.status("failed").unwrap();
        assert_eq!(
            store.directory.read("first-failure.json").unwrap().unwrap(),
            first
        );
        assert_eq!(
            store.directory.read("status.json").unwrap().unwrap()["phase"],
            "cleanup"
        );
        assert_eq!(first["instance"], "main.a001.i001");
        assert!(first.get("description").is_none());
    }
    #[test]
    fn prerequisite_and_early_error_are_distinct_without_an_assertion() {
        for (kind, class, instance) in [
            (
                "prerequisite",
                "prerequisite",
                Some("runtime.worker.ready.i003"),
            ),
            ("execution", "setup", None),
            ("execution", "cleanup", None),
        ] {
            let scratch = Scratch::new();
            let store = Store {
                directory: Directory::open(&scratch.0, false).unwrap(),
                phase: "browser",
                status_file: "status.json",
                case: None,
            };
            store.failure(kind, class, instance).unwrap();
            let value = store.directory.read("first-failure.json").unwrap().unwrap();
            assert_eq!(value["kind"], kind);
            assert_eq!(value["class"], class);
            assert_eq!(value["instance"], json!(instance));
            assert!(value["case"].is_null());
        }
    }
    #[test]
    fn directory_leaf_and_fifo_are_never_followed() {
        let scratch = Scratch::new();
        let real = scratch.0.join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("secret"), "SENTINEL").unwrap();
        symlink(&real, scratch.0.join("link")).unwrap();
        assert!(Directory::open(&scratch.0.join("link/child"), true).is_err());
        assert!(!real.join("child").exists());
        symlink(real.join("secret"), real.join("status.json")).unwrap();
        let directory = Directory::open(&real, false).unwrap();
        assert!(directory.write("status.json", &json!({}), false).is_err());
        assert!(directory.read("status.json").is_err());
        assert_eq!(
            std::fs::read_to_string(real.join("secret")).unwrap(),
            "SENTINEL"
        );
        let fifo = CString::new(real.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(directory.read("fifo").is_err());
        assert!(directory.create("status.json").is_err());
    }
    #[test]
    fn raw_receipts_keep_their_size_contract_while_diagnostics_are_bounded() {
        let scratch = Scratch::new();
        let directory = Directory::open(&scratch.0, false).unwrap();
        let large = json!({"local_only":"x".repeat(65536)});
        directory.write_capture("preflight.json", &large).unwrap();
        assert!(directory.write("status.json", &large, false).is_err());
        assert_eq!(
            directory.hash("preflight.json").unwrap(),
            completion::identity::digest(large.to_string().as_bytes())
        );
    }
    #[test]
    fn waited_signal_is_an_actual_abnormal_exit() {
        use std::os::unix::process::ExitStatusExt;
        let status = std::process::Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(status.code(), None);
        assert_eq!(status.signal(), Some(libc::SIGTERM));
        let scratch = Scratch::new();
        let store = Store {
            directory: Directory::open(&scratch.0, false).unwrap(),
            phase: "groups",
            status_file: "status.json",
            case: Some("main.c001.p001".into()),
        };
        store.status("active").unwrap();
        store
            .directory
            .write("supervisor.json", &waited_record(Some(status)), false)
            .unwrap();
        assert!(
            store
                .directory
                .read("first-failure.json")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.directory.read("supervisor.json").unwrap().unwrap()["signal"],
            libc::SIGTERM
        );
    }
}
