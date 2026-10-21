//! Real fixture processes, with fixed machine paths mapped into one owned directory.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct Job {
    pub command: Vec<u8>,
    pub pid: u32,
    pub group: ProcessIdentity,
    start: u64,
    pub ended: Option<Instant>,
}

pub struct Machine {
    pub root: PathBuf,
    jobs: Mutex<Observations>,
}

#[derive(Default)]
struct Observations {
    current: BTreeMap<String, Job>,
    launches: Vec<(String, Job)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    start: u64,
}

impl ProcessIdentity {
    pub fn current(pid: u32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let start = stat
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(19)?
            .parse()
            .ok()?;
        Some(Self { pid, start })
    }

    fn matches(self) -> bool {
        Self::current(self.pid) == Some(self)
    }
}

pub fn kill_group(group: ProcessIdentity) {
    if !group.matches() {
        return;
    }
    // A group is only signalled while its original leader still has this identity.
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", group.pid)).unwrap_or_default();
    if stat
        .rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().nth(2))
        != Some(group.pid.to_string().as_str())
    {
        return;
    }
    let _ = Command::new("kill")
        .args(["-KILL", "--", &format!("-{}", group.pid)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn recorded_identity(text: &str) -> Option<ProcessIdentity> {
    let mut fields = text.split_whitespace();
    Some(ProcessIdentity {
        pid: fields.next()?.parse().ok()?,
        start: fields.next()?.parse().ok()?,
    })
}

pub fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|s| {
            s.rsplit_once(") ")
                .map(|(_, rest)| !rest.starts_with(['Z', 'X']))
        })
        .unwrap_or(false)
}

fn shell_quote(path: &str) -> String {
    format!("'{}'", path.replace('\'', "'\\''"))
}

impl Machine {
    pub fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "tau-web-fixture-{}-{}",
            std::process::id(),
            hex::encode(super::fixtures::urandom::<8>())
        ));
        std::fs::create_dir(&root).expect("new fixture directory");
        std::fs::create_dir(root.join("jobs")).expect("fixture jobs");
        std::fs::write(
            root.join("boot"),
            hex::encode(super::fixtures::urandom::<16>()),
        )
        .expect("fixture boot");
        Self {
            root,
            jobs: Mutex::default(),
        }
    }

    pub fn map(&self, bytes: &[u8]) -> String {
        String::from_utf8(bytes.to_vec())
            .expect("wrapper text")
            .replace(
                tau_web::jobs::DIRECTORY,
                &shell_quote(self.root.join("jobs").to_str().expect("path")),
            )
            .replace(
                tau_web::jobs::BOOT_ID,
                &shell_quote(self.root.join("boot").to_str().expect("path")),
            )
    }

    pub fn path(&self, id: &str, file: &str) -> PathBuf {
        assert!(tau_web::jobs::valid_id(id));
        self.root.join("jobs").join(id).join(file)
    }

    /// Sample the fixture's own filesystem and process table, independently of reports.
    pub fn observe(&self) -> BTreeMap<String, Job> {
        let mut observations = self.jobs.lock().expect("jobs lock");
        let Observations {
            current: jobs,
            launches,
        } = &mut *observations;
        for entry in std::fs::read_dir(self.root.join("jobs"))
            .expect("jobs directory")
            .flatten()
        {
            let id = entry.file_name().to_string_lossy().into_owned();
            if !tau_web::jobs::valid_id(&id) {
                continue;
            }
            let d = entry.path();
            if !d.join("ready").is_file() {
                continue;
            }
            if let (Ok(pid), Ok(runner)) = (
                std::fs::read_to_string(d.join("pid")),
                std::fs::read_to_string(d.join("runner")),
            ) && let (Ok(pid), Ok(runner)) = (
                recorded_identity(&pid).ok_or(()),
                recorded_identity(&runner).ok_or(()),
            ) && jobs
                .get(&id)
                .is_none_or(|job| job.pid != pid.pid || job.start != pid.start)
            {
                let job = Job {
                    command: std::fs::read(d.join("command")).expect("command"),
                    pid: pid.pid,
                    start: pid.start,
                    group: runner,
                    ended: None,
                };
                launches.push((id.clone(), job.clone()));
                jobs.insert(id.clone(), job);
            }
            if let Some(job) = jobs.get_mut(&id)
                && job.ended.is_none()
                && (d.join("exit").exists()
                    || !ProcessIdentity {
                        pid: job.pid,
                        start: job.start,
                    }
                    .matches()
                    || !alive(job.pid))
            {
                job.ended = Some(Instant::now());
                if let Some((_, launch)) = launches
                    .iter_mut()
                    .find(|(of, j)| of == &id && j.pid == job.pid)
                {
                    launch.ended = job.ended;
                }
            }
        }
        jobs.clone()
    }

    pub fn launches(&self) -> Vec<(String, Job)> {
        self.observe();
        self.jobs.lock().expect("jobs lock").launches.clone()
    }

    pub fn cleanup(&self) {
        if self.root.exists() {
            for (_, job) in self.launches() {
                kill_group(job.group);
            }
            std::fs::remove_dir_all(&self.root).expect("remove exact fixture directory");
        }
    }

    pub fn reboot(&self) {
        for (_, job) in self.launches() {
            kill_group(job.group);
        }
        std::fs::write(
            self.root.join("boot"),
            hex::encode(super::fixtures::urandom::<16>()),
        )
        .expect("new boot");
        self.observe();
    }
}

impl Drop for Machine {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// A channel or connection ending kills exactly the exec's process group.
pub struct ExecGroup(pub ProcessIdentity);
impl ExecGroup {
    pub fn new(pid: u32) -> Self {
        Self(ProcessIdentity::current(pid).expect("new exec identity"))
    }
}
impl Drop for ExecGroup {
    fn drop(&mut self) {
        kill_group(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::time::Duration;
    use tau_web::jobs::{self, Record, State};

    fn shell() -> String {
        std::env::var("JOB_TEST_SHELL").unwrap_or_else(|_| "sh".into())
    }

    fn start(machine: &Machine, text: &str) -> (tokio::process::Child, ExecGroup) {
        let shell = shell();
        let text = machine
            .map(text.as_bytes())
            .replace("sh -c ", &format!("{shell} -c "))
            .replace("exec sh ", &format!("exec {shell} "));
        let child = tokio::process::Command::new(&shell)
            .args(["-c", &text])
            .current_dir(&machine.root)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let guard = ExecGroup::new(child.id().unwrap());
        (child, guard)
    }

    async fn result(child: tokio::process::Child) -> Record {
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .expect("wrapper did not return promptly")
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
        serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{e}: {:?}", output))
    }

    fn replace_once(text: &str, from: &str, to: &str) -> String {
        assert_eq!(text.matches(from).count(), 1, "scratch anchor: {from}");
        text.replace(from, to)
    }

    #[tokio::test]
    async fn runner_rechecks_pid_after_fast_command_is_reaped() {
        let machine = Machine::new();
        let id = "a".repeat(48);
        let original = include_str!("../../src/jobs/runner.sh");
        // The interpreter cannot publish pid until the runner has entered the gap.
        let runner = replace_once(
            original,
            "    d=$1\n",
            "    d=$1\n    while [ ! -f \"$d/pid-gap\" ]; do sleep 0.01; done\n    sleep 0.05\n",
        );
        let runner = replace_once(
            &runner,
            "while [ ! -f \"$d/pid\" ]; do\n",
            "while [ ! -f \"$d/pid\" ]; do\n    : > \"$d/pid-gap\"\n    sleep 0.2\n    while kill -0 \"$command_pid\" 2>/dev/null; do sleep 0.01; done\n",
        );
        let launch = replace_once(
            &jobs::launch(&id, "fixture", b"exit 7"),
            &shell_quote(original),
            &shell_quote(&runner),
        );
        let (child, _guard) = start(&machine, &launch);
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        let (read, _read_guard) = start(&machine, &jobs::collect(&id));
        let record = result(read).await;
        let ready = machine.path(&id, "ready").is_file();
        let exit = std::fs::read_to_string(machine.path(&id, "exit")).ok();
        println!(
            "runner gap: wrapper={}, ready={ready}, exit={exit:?}, record={record:?}",
            output.status
        );
        assert!(machine.path(&id, "pid-gap").is_file());
        assert!(
            ready,
            "runner lost ready after the command published pid and ended"
        );
        assert_eq!(exit.as_deref(), Some("7\n"));
        assert!(output.status.success());
        assert_eq!(record.classify("fixture"), State::Finished);
        assert!(matches!(
            record,
            Record::Present {
                exit_status: Some(7),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn launch_rechecks_ready_after_fast_runner_is_reaped() {
        let machine = Machine::new();
        let id = "b".repeat(48);
        // The runner cannot start until the launch has entered its ready gap.
        let launch = replace_once(
            &jobs::launch(&id, "fixture", b"exit 7"),
            "umask 077\nd=$1\n",
            "umask 077\nd=$1\nwhile [ ! -f \"$d/ready-gap\" ]; do sleep 0.01; done\nsleep 0.05\n",
        );
        let launch = replace_once(
            &launch,
            "while [ ! -f \"$d/ready\" ]; do\n",
            "while [ ! -f \"$d/ready\" ]; do\n    : > \"$d/ready-gap\"\n    sleep 0.2\n    while kill -0 \"$launcher\" 2>/dev/null; do sleep 0.01; done\n",
        );
        let (child, _guard) = start(&machine, &launch);
        let output = tokio::time::timeout(Duration::from_secs(5), child.wait_with_output())
            .await
            .unwrap()
            .unwrap();
        println!(
            "launch gap: wrapper={}, stdout={:?}",
            output.status,
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(machine.path(&id, "ready-gap").is_file());
        assert!(
            output.status.success(),
            "launch lost the ready file: {output:?}"
        );
        let record: Record = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(record.classify("fixture"), State::Finished);
        assert!(matches!(
            record,
            Record::Present {
                exit_status: Some(7),
                ..
            }
        ));
    }

    async fn launched(machine: &Machine, id: &str) -> Job {
        for _ in 0..300 {
            if let Some(job) = machine.observe().get(id) {
                return job.clone();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no job launch: {id}");
    }

    // Keep detached children owned even when their original session leader has ended.
    struct OwnedProcess(ProcessIdentity);

    impl Drop for OwnedProcess {
        fn drop(&mut self) {
            if self.0.matches() {
                assert!(
                    Command::new("kill")
                        .args(["-KILL", "--", &self.0.pid.to_string()])
                        .status()
                        .unwrap()
                        .success()
                );
            }
        }
    }

    async fn end_owned_process(process: OwnedProcess) {
        let identity = process.0;
        drop(process);
        for _ in 0..300 {
            if !identity.matches() || !alive(identity.pid) {
                println!(
                    "ended owned child: pid={} start={}",
                    identity.pid, identity.start
                );
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("owned child still running: {identity:?}");
    }

    #[tokio::test]
    async fn only_statuses_through_128_finish_and_signals_have_no_exit_code() {
        let machine = Machine::new();
        for (i, command, expected) in [
            (1, "echo before; kill -KILL $$; echo after", None),
            (2, "echo before; kill -TERM $$; echo after", None),
            (3, "exit 129", None),
            (4, "exit 137", None),
            (5, "exit 255", None),
            (6, "exit 0", Some(0)),
            (7, "exit 128", Some(128)),
            (8, "exec sleep 0", Some(0)),
            (9, "sh -c 'kill -KILL $$'", None),
        ] {
            let id = format!("{i:048x}");
            let (child, _guard) =
                start(&machine, &jobs::launch(&id, "fixture", command.as_bytes()));
            let record = result(child).await;
            assert_eq!(
                record.classify("fixture"),
                if expected.is_some() {
                    State::Finished
                } else {
                    State::Ended
                },
                "{command}: {record:?}"
            );
            assert!(
                matches!(record, Record::Present { exit_status, .. } if exit_status == expected)
            );
            assert_eq!(
                machine.path(&id, "exit").exists(),
                expected.is_some(),
                "{command}"
            );
            let (read, _guard) = start(&machine, &jobs::collect(&id));
            assert_eq!(result(read).await, record);
        }
    }

    #[tokio::test]
    async fn command_variables_are_private_and_d_clobber_leaves_no_stray_status() {
        let machine = Machine::new();
        std::fs::create_dir(machine.root.join("x")).unwrap();
        for (i, command) in [
            "d=/nonexistent; exit 0",
            "for d in x; do :; done; exit 0",
            "printf '%s' \"${d-unset}\"; d=x; exit 0",
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("{:048x}", i + 1);
            let (child, _guard) =
                start(&machine, &jobs::launch(&id, "fixture", command.as_bytes()));
            let record = result(child).await;
            assert!(
                matches!(record, Record::Present { exit_status: Some(0), ref stdout, .. }
                if stdout == &hex::encode(if i == 2 { "unset" } else { "" })),
                "{command}: {record:?}"
            );
            assert!(!machine.path(&id, "status").exists());
            assert!(!machine.root.join("x/status").exists());
        }
    }

    #[tokio::test]
    async fn previous_143_status_cannot_turn_sigterm_into_an_exit_code() {
        let machine = Machine::new();
        let id = "1".repeat(48);
        let (child, _guard) = start(
            &machine,
            &jobs::launch(&id, "fixture", b"sh -c 'exit 143'; sleep 30"),
        );
        let job = launched(&machine, &id).await;
        let mut sleeping = None;
        for _ in 0..300 {
            let children =
                std::fs::read_to_string(format!("/proc/{}/task/{}/children", job.pid, job.pid))
                    .unwrap_or_default();
            sleeping = std::iter::once(job.pid.to_string())
                .chain(children.split_whitespace().map(str::to_owned))
                .find_map(|pid| {
                    if std::fs::read_to_string(format!("/proc/{pid}/comm"))
                        .is_ok_and(|comm| comm.trim() == "sleep")
                    {
                        ProcessIdentity::current(pid.parse().unwrap()).map(OwnedProcess)
                    } else {
                        None
                    }
                });
            if sleeping.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let sleeping = sleeping.expect("command never reached sleep");
        assert!(job.group.matches());
        assert!(
            Command::new("kill")
                .args(["-TERM", &job.pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        let record = result(child).await;
        end_owned_process(sleeping).await;
        assert_eq!(record.classify("fixture"), State::Ended);
        assert!(matches!(
            record,
            Record::Present {
                exit_status: None,
                ..
            }
        ));
        assert!(!machine.path(&id, "exit").exists());
    }

    #[tokio::test]
    async fn externally_killed_command_leaves_living_runner_no_exit_code() {
        let machine = Machine::new();
        let id = "1".repeat(48);
        let (child, _guard) = start(
            &machine,
            &jobs::launch(&id, "fixture", b"echo before; sleep 1; echo after"),
        );
        let job = launched(&machine, &id).await;
        assert!(job.group.matches());
        assert!(
            Command::new("kill")
                .args(["-KILL", &job.pid.to_string()])
                .status()
                .unwrap()
                .success()
        );
        let record = result(child).await;
        assert_eq!(record.classify("fixture"), State::Ended);
        assert!(matches!(
            record,
            Record::Present {
                exit_status: None,
                ..
            }
        ));
        assert!(!machine.path(&id, "exit").exists());
    }

    fn crafted(machine: &Machine, id: &str) {
        std::fs::create_dir(machine.path(id, "")).unwrap();
        for (name, bytes) in [
            ("machine", "fixture"),
            ("command", "exit 0"),
            ("stdout", ""),
            ("stderr", ""),
            ("ready", ""),
            ("pid", "0 0\n"),
            ("runner", "0 0\n"),
        ] {
            std::fs::write(machine.path(id, name), bytes).unwrap();
        }
        std::fs::copy(machine.root.join("boot"), machine.path(id, "boot")).unwrap();
    }

    async fn failed_read(machine: &Machine, id: &str, file: &str) {
        let (read, _guard) = start(machine, &jobs::collect(id));
        let output = read.wait_with_output().await.unwrap();
        assert!(!output.status.success(), "{file}: {output:?}");
        assert!(
            output.stdout.is_empty(),
            "failed read printed fields: {output:?}"
        );
        let mut delivered = jobs::ReadDelivery {
            stdout: output.stdout,
            status: Some(output.status.code().unwrap() as u32),
            closed: true,
            ..Default::default()
        };
        delivered.extended_data(&output.stderr);
        let why = delivered.record().unwrap_err();
        assert!(
            why.contains(machine.path(id, file).to_str().unwrap()),
            "{why}"
        );
    }

    #[tokio::test]
    async fn missing_record_files_fail_instead_of_fabricating_fields() {
        let machine = Machine::new();
        for (i, file) in [
            "stdout", "machine", "command", "boot", "stderr", "pid", "runner",
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("{:048x}", i + 1);
            crafted(&machine, &id);
            std::fs::write(machine.path(&id, "exit"), "0\n").unwrap();
            let path = machine.path(&id, file);
            let bytes = std::fs::read(&path).unwrap();
            std::fs::remove_file(&path).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::create_dir(&path).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::remove_dir(&path).unwrap();
            std::os::unix::fs::symlink("missing-target", &path).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::remove_file(&path).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    }

    #[tokio::test]
    async fn invalid_scalar_files_fail_without_malformed_output() {
        let machine = Machine::new();
        for (i, (file, value)) in [
            ("pid", ""),
            ("pid", "12"),
            ("pid", "12 nope\n"),
            ("runner", ""),
            ("exit", ""),
            ("exit", "256\n"),
            ("exit", "0\n1\n"),
            ("boot", "bad\"boot\n"),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("{:048x}", i + 1);
            crafted(&machine, &id);
            std::fs::write(machine.path(&id, "exit"), "0\n").unwrap();
            std::fs::write(machine.path(&id, file), value).unwrap();
            failed_read(&machine, &id, file).await;
        }
    }

    #[tokio::test]
    async fn nul_bytes_in_scalars_fail_instead_of_being_discarded() {
        let machine = Machine::new();
        for (i, (file, value)) in [
            ("exit", b"1\x002\n".as_slice()),
            ("pid", b"1\x002 0\n".as_slice()),
            ("runner", b"1\x002 0\n".as_slice()),
            ("boot", b"old\x00boot\n".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let id = format!("{:048x}", i + 1);
            crafted(&machine, &id);
            std::fs::write(machine.path(&id, "exit"), "0\n").unwrap();
            std::fs::write(machine.path(&id, file), value).unwrap();
            failed_read(&machine, &id, file).await;
        }
        let id = "f".repeat(48);
        crafted(&machine, &id);
        std::fs::write(machine.root.join("boot"), b"old\x00boot\n").unwrap();
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        let output = read.wait_with_output().await.unwrap();
        assert!(!output.status.success(), "current boot: {output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains(machine.root.join("boot").to_str().unwrap())
        );
    }

    #[tokio::test]
    async fn scalar_records_accept_only_exact_ascii_forms() {
        let machine = Machine::new();
        let id = "a".repeat(48);
        crafted(&machine, &id);
        for suffix in ["", "\n"] {
            for file in ["pid", "runner"] {
                std::fs::write(machine.path(&id, file), format!("0 0{suffix}")).unwrap();
            }
            std::fs::write(machine.path(&id, "boot"), format!("old-boot{suffix}")).unwrap();
            std::fs::write(machine.path(&id, "exit"), format!("128{suffix}")).unwrap();
            let (read, _guard) = start(&machine, &jobs::collect(&id));
            assert!(matches!(
                result(read).await,
                Record::Present {
                    exit_status: Some(128),
                    ..
                }
            ));
        }
        for (file, value) in [
            ("pid", "0  0\n"),
            ("pid", " 0 0\n"),
            ("runner", "0 0 \n"),
            ("exit", "12\r\n"),
            ("exit", "12\n\n"),
            ("boot", "old\tboot\n"),
        ] {
            let original = std::fs::read(machine.path(&id, file)).unwrap();
            std::fs::write(machine.path(&id, file), value).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::write(machine.path(&id, file), original).unwrap();
        }
    }

    #[tokio::test]
    async fn exit_file_above_128_fails_the_read() {
        let machine = Machine::new();
        let id = "a".repeat(48);
        crafted(&machine, &id);
        std::fs::write(machine.path(&id, "exit"), "137\n").unwrap();
        failed_read(&machine, &id, "exit").await;
    }

    #[tokio::test]
    async fn incomplete_record_present_unreadable_files_fail_instead_of_null() {
        let machine = Machine::new();
        let id = "a".repeat(48);
        std::fs::create_dir(machine.path(&id, "")).unwrap();
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        assert_eq!(
            result(read).await,
            Record::Incomplete {
                machine: None,
                command: None
            }
        );
        for file in ["machine", "command"] {
            std::fs::create_dir(machine.path(&id, file)).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::remove_dir(machine.path(&id, file)).unwrap();
            std::os::unix::fs::symlink("missing-target", machine.path(&id, file)).unwrap();
            failed_read(&machine, &id, file).await;
            std::fs::remove_file(machine.path(&id, file)).unwrap();
        }
    }

    #[tokio::test]
    async fn exit_record_precedes_even_a_live_runner_identity() {
        let machine = Machine::new();
        let id = "2".repeat(48);
        crafted(&machine, &id);
        let process = ProcessIdentity::current(std::process::id()).unwrap();
        std::fs::write(
            machine.path(&id, "runner"),
            format!("{} {}\n", process.pid, process.start),
        )
        .unwrap();
        std::fs::write(machine.path(&id, "exit"), "0\n").unwrap();
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        assert_eq!(result(read).await.classify("fixture"), State::Finished);
    }

    #[tokio::test]
    async fn recycled_command_and_runner_pids_are_not_alive() {
        let machine = Machine::new();
        let process = ProcessIdentity::current(std::process::id()).unwrap();
        for (i, file) in [(3, "pid"), (4, "runner")] {
            let id = format!("{i:048x}");
            crafted(&machine, &id);
            std::fs::write(machine.path(&id, "pid"), "1 0\n").unwrap();
            std::fs::write(
                machine.path(&id, file),
                format!("{} {}\n", process.pid, process.start + 1),
            )
            .unwrap();
            let (read, _guard) = start(&machine, &jobs::collect(&id));
            let record = result(read).await;
            assert_eq!(record.classify("fixture"), State::Ended, "{file}");
            assert!(matches!(
                record,
                Record::Present {
                    alive: false,
                    exit_status: None,
                    ..
                }
            ));
        }
    }

    #[test]
    fn stale_group_identity_cannot_kill_an_unrelated_leader() {
        let mut child = Command::new("sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let process = ProcessIdentity::current(child.id()).unwrap();
        kill_group(ProcessIdentity {
            start: process.start + 1,
            ..process
        });
        assert!(alive(child.id()));
        kill_group(process);
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn wrapper_survives_drop_waits_once_and_refuses_existing_id() {
        let machine = Machine::new();
        let id = "a".repeat(48);
        let text = jobs::launch(&id, "fixture", b"sleep 2; echo out; echo err >&2; exit 7");
        let (mut child, guard) = start(&machine, &text);
        let job = launched(&machine, &id).await;
        assert_ne!(job.group, guard.0, "job must be detached from exec");
        drop(guard);
        let _ = child.wait().await;
        assert!(alive(job.pid), "command must survive killed exec group");
        let before = Instant::now();
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        let record = result(read).await;
        assert!(
            before.elapsed() >= Duration::from_millis(1200),
            "collection did not wait"
        );
        assert_eq!(record.classify("fixture"), State::Finished);
        assert!(
            matches!(record, Record::Present { exit_status: Some(7), ref stdout, ref stderr, .. } if stdout == &hex::encode("out\n") && stderr == &hex::encode("err\n"))
        );
        assert!(machine.observe()[&id].ended.is_some());
        let files = std::fs::read_dir(machine.path(&id, ""))
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                assert_eq!(
                    std::fs::metadata(&p).unwrap().permissions().mode() & 0o077,
                    0
                );
                (p.clone(), std::fs::read(p).unwrap())
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            std::fs::metadata(machine.path(&id, ""))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let (repeat, _guard) = start(&machine, &text);
        let output = repeat.wait_with_output().await.unwrap();
        assert!(!output.status.success(), "existing job id must be refused");
        let mut delivered = jobs::ReadDelivery {
            stdout: output.stdout,
            status: Some(output.status.code().unwrap() as u32),
            closed: true,
            ..Default::default()
        };
        delivered.extended_data(&output.stderr);
        let why = delivered.record().unwrap_err();
        assert!(
            why.contains("refusing existing or unavailable job directory"),
            "{why}"
        );
        for (p, bytes) in files {
            assert_eq!(std::fs::read(p).unwrap(), bytes);
        }
        assert_eq!(machine.observe().len(), 1);
    }

    #[tokio::test]
    async fn wrapper_returns_before_background_stdout_holder_ends() {
        let machine = Machine::new();
        let id = "b".repeat(48);
        let (child, _guard) = start(
            &machine,
            &jobs::launch(
                &id,
                "fixture",
                b"sleep 12 & printf '%s\n' \"$!\" > holder-pid; echo hi",
            ),
        );
        launched(&machine, &id).await;
        let mut holder = None;
        for _ in 0..300 {
            if let Ok(pid) = std::fs::read_to_string(machine.root.join("holder-pid"))
                && let Ok(pid) = pid.trim().parse()
                && let Some(identity) = ProcessIdentity::current(pid)
            {
                holder = Some(OwnedProcess(identity));
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let holder = holder.expect("background holder identity");
        let now = Instant::now();
        let record = result(child).await;
        let elapsed = now.elapsed();
        end_owned_process(holder).await;
        assert!(elapsed < Duration::from_secs(3));
        assert!(
            matches!(record, Record::Present { exit_status: Some(0), ref stdout, .. } if stdout == &hex::encode("hi\n"))
        );
    }

    #[tokio::test]
    async fn partial_launch_preserves_received_bytes_without_claiming_an_end_or_launching() {
        let machine = Machine::new();
        let id = "e".repeat(48);
        std::fs::create_dir(machine.path(&id, "")).unwrap();
        std::fs::write(machine.path(&id, "command"), b"truncated").unwrap();
        std::fs::write(machine.path(&id, "machine"), b"fixture").unwrap();
        let (child, _guard) = start(&machine, &jobs::collect(&id));
        let record = result(child).await;
        assert_eq!(
            record,
            Record::Incomplete {
                machine: Some(hex::encode("fixture")),
                command: Some(hex::encode("truncated"))
            }
        );
        assert_eq!(record.classify("fixture"), State::Incomplete);
        let report = jobs::Evidence {
            call: 1,
            job: id,
            record,
        }
        .report(2, "fixture", &hex::encode("original"));
        assert!(matches!(
            report.comparison,
            jobs::Comparison::Finding { .. }
        ));
        assert!(report.exit_status.is_none());
        assert!(machine.launches().is_empty());
    }

    #[tokio::test]
    async fn wrapper_reads_old_boot_live_pid_and_same_boot_gone_pid_as_ended_and_missing_as_missing()
     {
        let machine = Machine::new();
        let id = "c".repeat(48);
        let (mut child, guard) = start(&machine, &jobs::launch(&id, "fixture", b"sleep 30"));
        let job = launched(&machine, &id).await;
        // A live PID is deliberately retained across the simulated boot identity change.
        std::fs::write(machine.root.join("boot"), "new-boot").unwrap();
        assert!(alive(job.pid));
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        assert_eq!(result(read).await.classify("fixture"), State::Ended);
        kill_group(job.group);
        let boot = std::fs::read(machine.path(&id, "boot")).unwrap();
        std::fs::write(machine.root.join("boot"), boot).unwrap();
        let (read, _guard) = start(&machine, &jobs::collect(&id));
        assert_eq!(result(read).await.classify("fixture"), State::Ended);
        assert!(!machine.path(&id, "exit").exists());
        let (read, _guard) = start(&machine, &jobs::collect(&"d".repeat(48)));
        assert_eq!(result(read).await.classify("fixture"), State::Missing);
        drop(guard);
        let _ = child.wait().await;
    }

    #[tokio::test]
    async fn independent_store_job_ids_launch_and_read_their_own_records() {
        use tau_web::credential::LocalPassphrase;
        use tau_web::dispatch::Approval;
        use tau_web::harness::{Entry, Journal};
        use tau_web::store::{MemoryStorage, Pbkdf2, create};
        let machine = Machine::new();
        let mut ids = Vec::new();
        for command in ["echo first", "echo second"] {
            let mut store = create(
                MemoryStorage::default(),
                &Pbkdf2,
                LocalPassphrase::new(b"correct horse battery staple".to_vec()),
            )
            .await
            .unwrap();
            let call = store
                .append(
                    &Entry {
                        provenance: None,
                        machine: "fixture".into(),
                        command: command.as_bytes().to_vec(),
                    },
                    &Approval::HarnessPin {
                        machine: "fixture".into(),
                        fingerprint: "SHA256:test".into(),
                    },
                )
                .await
                .unwrap();
            assert_eq!(call, 1);
            let id = store.intent(call).await.unwrap().job.unwrap();
            let (child, _guard) =
                start(&machine, &jobs::launch(&id, "fixture", command.as_bytes()));
            let record = result(child).await;
            assert!(
                matches!(record, Record::Present { ref stdout, .. } if stdout == &hex::encode(format!("{}\n", command.strip_prefix("echo ").unwrap())))
            );
            let (read, _guard) = start(&machine, &jobs::collect(&id));
            assert_eq!(result(read).await, record);
            ids.push(id);
        }
        assert_ne!(ids[0], ids[1]);
        assert_eq!(machine.observe().len(), 2);
    }
}
