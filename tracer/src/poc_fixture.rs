//! Loopback fixtures for the independent durable-page browser checks.
use crate::{fixtures, json};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::time::{Duration, SystemTime};

pub async fn run() -> Result<(), String> {
    let seen = fixtures::Observed::default();
    let tls = fixtures::tls();
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
        json!({"relay":relay.url,"port":sshd.port,"spki":tls.spki_sha256,
        "pin":tau_web::testonly::PINS[0].1,"largest":largest,"directory":sshd.machine.root})
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
        let result = if let Some(keys) = value.get("keys") {
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
                hosts: vec!["127.0.0.1".into()],
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
            json!({"launches":launches,"execs":observed.ssh_exec.iter().map(|e|String::from_utf8_lossy(e).into_owned()).collect::<Vec<_>>(),"contacts":observed.relay_accepted,"authentication":observed.ssh_auth,"wire_errors":observed.relay_wire_errors,"binary_sizes":observed.relay_binary_sizes})
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
