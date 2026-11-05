use super::*;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

const ID: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn poc_none_preserves_recorded_wire_bytes() {
    // Digests of the pre-elevation launch/read arguments, including the original scripts.
    let launch = launch_with_elevation(
        ID,
        "machine with 'quotes' and 日本語",
        b"printf '%s\\n' 'quoted'; exit 7",
        Elevation::None,
    );
    assert_eq!(
        hex::encode(Sha256::digest(launch.as_bytes())),
        "9a74ddeb5cd367c3bc322ce3f4490cc0a50e92dd48b5ca101ca955e7c165ce0e"
    );
    assert_eq!(
        hex::encode(Sha256::digest(
            collect_with_elevation(ID, Elevation::None).as_bytes()
        )),
        "1e9733fb35a217458499f18479e272ae5317ef6bbf3690a88eb4367bfb46bf74"
    );
}

#[test]
fn poc_full_wrapper_size_and_reconciliation() {
    for elevation in [Elevation::None, Elevation::SudoNoninteractive] {
        let machine = "quoted ' machine";
        let base = launch_size_with_elevation(machine, b"", elevation);
        let command = vec![b'x'; (MAX_LAUNCH_BYTES - base) / 5];
        let bytes = launch_with_elevation(ID, machine, &command, elevation).into_bytes();
        assert_eq!(
            bytes.len(),
            launch_size_with_elevation(machine, &command, elevation)
        );
        assert!(launch_fits(bytes.len()));
        let mut longer = command.clone();
        longer.push(b'x');
        assert!(!launch_fits(launch_size_with_elevation(
            machine, &longer, elevation
        )));
        let entry = crate::harness::Entry {
            machine: machine.into(),
            command,
            provenance: None,
        };
        assert!(launch_reconciles(ID, &entry, elevation, &bytes));
        let substituted = match elevation {
            Elevation::None => Elevation::SudoNoninteractive,
            Elevation::SudoNoninteractive => Elevation::None,
        };
        assert!(!launch_reconciles(ID, &entry, substituted, &bytes));
        let mut changed = entry;
        changed.command.push(b'!');
        assert!(!launch_reconciles(ID, &changed, elevation, &bytes));
    }
}

fn scratch_root(
    explicit: Option<std::ffi::OsString>,
    fallback: impl FnOnce() -> PathBuf,
) -> PathBuf {
    explicit.map(PathBuf::from).unwrap_or_else(fallback)
}

#[test]
fn poc_temp_root_fallback_without_external_writes() {
    let owned = std::env::temp_dir();
    assert_eq!(scratch_root(None, || owned.clone()), owned);
    assert_eq!(
        scratch_root(Some(owned.clone().into_os_string()), || panic!(
            "fallback called with TMPDIR"
        )),
        owned
    );
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(refuse: bool) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = scratch_root(std::env::var_os("TMPDIR"), std::env::temp_dir).join(format!(
            "tau-web-poc-jobs-{}-{}-'quoted'",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        let sudo = path.join("sudo");
        std::fs::write(
            &sudo,
            if refuse {
                "#!/bin/sh\nprintf '%s\\n' called >> \"$TAU_TEST_ROUTE\"\nexit 1\n"
            } else {
                "#!/bin/sh\nprintf '%s\\n' called >> \"$TAU_TEST_ROUTE\"\n[ \"$1\" = -n ] || exit 98\nshift\nexec \"$@\"\n"
            },
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(sudo, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(path)
    }

    fn script(&self, script: &str) -> String {
        script.replace(
            DIRECTORY,
            &quote(&self.0.join("jobs").display().to_string()),
        )
    }

    fn run(&self, script: &str) -> Output {
        let path = format!(
            "{}:{}",
            self.0.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        Command::new("sh")
            .args(["-c", script])
            .env("PATH", path)
            .env("TAU_TEST_ROUTE", self.0.join("route"))
            .output()
            .unwrap()
    }

    fn calls(&self) -> usize {
        std::fs::read_to_string(self.0.join("route"))
            .unwrap()
            .lines()
            .count()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

fn record(output: Output) -> Record {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: Record = serde_json::from_slice(&output.stdout).unwrap();
    record.validate().unwrap();
    record
}

#[test]
fn poc_sudo_route_quotes_complete_launch_and_collect_scripts() {
    let scratch = Scratch::new(false);
    let machine = "machine '日本語'";
    let command = b"printf '%s\\n' \"a 'quoted' value\"; printf err >&2; exit 7";
    // Transform only the test script, before applying shell quoting to the whole argument.
    let launch = elevated(
        scratch.script(&launch(ID, machine, command)),
        Elevation::SudoNoninteractive,
    );
    let launched = record(scratch.run(&launch));
    assert_eq!(launched.classify(machine), State::Finished);
    if let Record::Present {
        machine: received_machine,
        command: received,
        stdout,
        stderr,
        exit_status,
        ..
    } = &launched
    {
        assert_eq!(*received_machine, hex::encode(machine));
        assert_eq!(*received, hex::encode(command));
        assert_eq!(*stdout, hex::encode("a 'quoted' value\n"));
        assert_eq!(*stderr, hex::encode("err"));
        assert_eq!(*exit_status, Some(7));
    } else {
        panic!("expected complete job record");
    }
    let read = elevated(scratch.script(&collect(ID)), Elevation::SudoNoninteractive);
    assert_eq!(record(scratch.run(&read)), launched);
    assert_eq!(scratch.calls(), 2);
}

#[test]
fn poc_sudo_refusal_never_downgrades_or_becomes_missing() {
    let scratch = Scratch::new(true);
    for script in [launch(ID, "machine", b"exit 0"), collect(ID)] {
        let wrapped = elevated(scratch.script(&script), Elevation::SudoNoninteractive);
        let output = scratch.run(&wrapped);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        let delivered = ReadDelivery {
            stdout: output.stdout,
            stderr: output.stderr,
            status: output.status.code().map(|n| n as u32),
            closed: true,
        };
        let why = delivered.record().unwrap_err();
        assert!(why.contains("sudo -n elevation"), "{why}");
        assert!(!scratch.0.join("jobs").exists());
    }
    assert_eq!(scratch.calls(), 2);
}

#[test]
fn poc_sudo_runner_survives_launch_wrapper_exit() {
    let scratch = Scratch::new(false);
    let script = scratch
        .script(&launch(ID, "machine", b"sleep 0.5; printf kept; exit 0"))
        .replace("wait_job=true", "wait_job=false");
    let wrapped = elevated(script, Elevation::SudoNoninteractive);
    let running = record(scratch.run(&wrapped));
    assert_eq!(running.classify("machine"), State::Running);
    assert!(!scratch.0.join("jobs").join(ID).join("exit").exists());
    let read = elevated(scratch.script(&collect(ID)), Elevation::SudoNoninteractive);
    let finished = record(scratch.run(&read));
    assert_eq!(finished.classify("machine"), State::Finished);
    if let Record::Present { stdout, .. } = finished {
        assert_eq!(stdout, hex::encode("kept"));
    }
}
