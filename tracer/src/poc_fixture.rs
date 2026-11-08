//! Loopback fixtures for the independent durable-page browser checks.
use crate::{fixtures, json};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime};

pub async fn run() -> Result<(), String> {
    let seen = fixtures::Observed::default();
    let tls = fixtures::tls();
    let inference =
        crate::aggregator::Aggregator::start(tls.acceptor.clone(), tls.cert.clone()).await;
    let sshd = fixtures::sshd(seen.clone()).await;
    let relay = fixtures::relay(seen.clone(), tls.acceptor, vec![], false).await;
    let size = |n| tau_web::jobs::launch(&"0".repeat(48), "machine-a", &vec![b'x'; n]).len();
    let (mut low, mut high) = (0, tau_web::jobs::MAX_LAUNCH_BYTES);
    while low + 1 < high {
        let middle = (low + high) / 2;
        if size(middle) <= tau_web::jobs::MAX_LAUNCH_BYTES {
            low = middle;
        } else {
            high = middle;
        }
    }
    let largest = low;
    println!(
        "{}",
        json!({"relay":relay.url,"port":sshd.port,"spki":tls.spki_sha256,"host_key":crate::keys::ed25519(&crate::keys::HOST_KEY_PINNED).public_key().to_openssh().expect("public host key"),
        "pin":tau_web::testonly::PINS[0].1,"largest":largest,"directory":sshd.machine.root,"inference":format!("{}/completion",inference.origin),"relay_spacing_ms":fixtures::Limits::bundle().min_spacing.as_millis()})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines() {
            if send.send(line).is_err() {
                break;
            }
        }
    });
    while let Some(line) = receive.recv().await {
        let value: Value =
            serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if value["stop"] == true {
            break;
        }
        let result = if let Some(config) = value.get("inference") {
            let mut state = inference.state.lock().unwrap();
            if let Some(key) = config["key"].as_str()
                && !state.keys.iter().any(|k| k.value == key)
            {
                state.keys.push(crate::aggregator::Key {
                    id: "byo-fixture".into(),
                    value: key.into(),
                    cap: None,
                    expires: None,
                    spent: 0,
                    revoked: false,
                });
            }
            if let Some(commands) = config["commands"].as_array() {
                state.script.clear();
                for (n, command) in commands.iter().enumerate() {
                    let (name, arguments) = if let Some(command) = command.as_str() {
                        ("exec", json!({"machine":"machine-a","command":command}))
                    } else {
                        ("done", json!({"machine":"machine-a"}))
                    };
                    state
                        .script
                        .push_back(json!({"id":format!("loopback-call-{n}"),"type":"function",
                        "function":{"name":name,"arguments":arguments.to_string()}}));
                }
            }
            state.hold_completion = config["hold"] == true;
            json!({"inference_configured":true})
        } else if value["provisioning"] == true {
            use std::os::unix::fs::PermissionsExt;
            std::fs::write(sshd.machine.root.join("provisioning"), "fixture")
                .map_err(|e| e.to_string())?;
            std::fs::create_dir(sshd.machine.root.join("bin")).map_err(|e| e.to_string())?;
            let shim = sshd.machine.root.join("bin/sudo");
            std::fs::write(
                &shim,
                "#!/bin/sh\n[ \"$1\" = -n ] || exit 1\nshift\nexec \"$@\"\n",
            )
            .map_err(|e| e.to_string())?;
            std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
            *relay.fixture_port.lock().unwrap() = Some(sshd.port);
            json!({"provisioning":true})
        } else if let Some(wrong) = value["wrong_host_key"].as_bool() {
            sshd.present_other
                .store(wrong, std::sync::atomic::Ordering::SeqCst);
            json!({"changed":true})
        } else if let Some(keys) = value.get("keys") {
            std::fs::write(
                sshd.machine.root.join("authorized_keys"),
                keys["authorized_keys"].as_str().ok_or("SSH public key")?,
            )
            .map_err(|e| e.to_string())?;
            relay.passes.lock().unwrap().push(fixtures::Pass {
                key: hex::decode(keys["relay_pubkey"].as_str().ok_or("relay public key")?)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "relay key length")?,
                hosts: if sshd.machine.root.join("provisioning").is_file() {
                    vec!["192.0.2.10".into()]
                } else {
                    vec!["127.0.0.1".into()]
                },
                expires: SystemTime::now() + Duration::from_secs(3600),
            });
            json!({"installed":true})
        } else if let Some(output) = value["output"].as_str() {
            let name = if value["second"] == true {
                "second-output"
            } else {
                "ordinary-output"
            };
            std::fs::write(sshd.machine.root.join(name), output).map_err(|e| e.to_string())?;
            json!({"command":format!("cat '{}/{}'", sshd.machine.root.display(), name)})
        } else if value["release"] == true {
            std::fs::write(sshd.machine.root.join("continue"), "ready")
                .map_err(|e| e.to_string())?;
            json!({"released":true})
        } else if value["verify"] == true {
            std::fs::write(sshd.machine.root.join("verified"), "ready")
                .map_err(|e| e.to_string())?;
            json!({"verified":true})
        } else {
            let launches = sshd
                .machine
                .launches()
                .into_iter()
                .map(|(id, job)| json!({"job":id,"command":String::from_utf8_lossy(&job.command)}))
                .collect::<Vec<_>>();
            let observed = seen.lock().unwrap();
            let inference_requests = inference
                .requests
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.starts_with(b"POST /completion "))
                .count();
            json!({"launches":launches,"inference_requests":inference_requests,"ssh_connections":observed.ssh_connections,"ssh_ends":observed.ssh_ends.len(),"execs":observed.ssh_exec.iter().map(|e|String::from_utf8_lossy(e).into_owned()).collect::<Vec<_>>(),"contacts":observed.relay_accepted,"authentication":observed.ssh_auth,"wire_errors":observed.relay_wire_errors,"binary_sizes":observed.relay_binary_sizes})
        };
        println!("{result}");
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    if !sshd.cleanup_at(None).await {
        return Err("fixture connections did not end".into());
    }
    sshd.machine.cleanup();
    Ok(())
}
