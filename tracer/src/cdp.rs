//! Headless Chrome over the DevTools protocol: one browser the tracer starts and stops, one page,
//! and the dedicated workers it starts, each a flattened session on one socket.

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;

pub struct Browser {
    child: tokio::process::Child,
    profile: PathBuf,
    send: mpsc::UnboundedSender<String>,
    pending: Pending,
    next: Mutex<u64>,
    /// Every event, in arrival order, with its `sessionId`.
    pub events: Arc<Mutex<Vec<Value>>>,
}

impl Browser {
    /// Starts `chrome` headless with a fresh profile at `profile`, which must not exist, accepting
    /// the one test certificate whose key hashes to `spki_sha256`. The policy is never bypassed:
    /// no `--disable-web-security`, no `Page.setBypassCSP`.
    pub async fn launch(
        chrome: &str,
        profile: PathBuf,
        spki_sha256: &str,
    ) -> Result<Browser, String> {
        std::fs::create_dir(&profile).map_err(|e| format!("{}: {e}", profile.display()))?;
        let spawned = tokio::process::Command::new(chrome)
            .args([
                "--headless=new",
                "--no-sandbox",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=0",
                &format!("--user-data-dir={}", profile.display()),
                &format!("--ignore-certificate-errors-spki-list={spki_sha256}"),
                "about:blank",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn();
        let child = match spawned {
            Ok(child) => child,
            Err(e) => {
                remove_profile(&profile);
                return Err(format!("starting Chrome ({chrome}): {e}"));
            }
        };
        let mut browser = Browser {
            child,
            profile,
            send: mpsc::unbounded_channel().0,
            pending: Arc::default(),
            next: Mutex::new(0),
            events: Arc::default(),
        };
        match browser.connect().await {
            Ok(()) => Ok(browser),
            Err(e) => {
                browser.close().await;
                Err(e)
            }
        }
    }

    /// Opens the DevTools socket Chrome announces in its profile, and routes what arrives on it:
    /// replies to their callers, events to `events`.
    async fn connect(&mut self) -> Result<(), String> {
        let mut browser_url = None;
        for _ in 0..300 {
            if let Ok(port_file) = std::fs::read_to_string(self.profile.join("DevToolsActivePort"))
            {
                let mut lines = port_file.lines();
                if let (Some(port), Some(path)) = (lines.next(), lines.next()) {
                    browser_url = Some(format!("ws://127.0.0.1:{port}{path}"));
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let browser_url = browser_url.ok_or("Chrome wrote no DevToolsActivePort in 30 s")?;
        let (socket, _) = tokio_tungstenite::connect_async(&browser_url)
            .await
            .map_err(|e| format!("DevTools socket: {e}"))?;
        let (mut write, mut read) = socket.split();
        let (send, mut outgoing) = mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(text) = outgoing.recv().await {
                if write.send(Message::text(text)).await.is_err() {
                    break;
                }
            }
        });
        let (pending, events) = (self.pending.clone(), self.events.clone());
        tokio::spawn(async move {
            while let Some(Ok(Message::Text(text))) = read.next().await {
                let Ok(message) = serde_json::from_str::<Value>(&text) else {
                    continue;
                };
                match message["id"].as_u64() {
                    Some(id) => {
                        if let Some(reply) = pending.lock().expect("pending lock").remove(&id) {
                            let _ = reply.send(message);
                        }
                    }
                    None => events.lock().expect("events lock").push(message),
                }
            }
        });
        self.send = send;
        Ok(())
    }

    /// One command, on the browser (`session` `None`) or on a page or worker session.
    pub async fn call(
        &self,
        session: Option<&str>,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let id = {
            let mut next = self.next.lock().expect("id lock");
            *next += 1;
            *next
        };
        let mut message = json!({ "id": id, "method": method, "params": params });
        if let Some(session) = session {
            message["sessionId"] = session.into();
        }
        let (reply, response) = oneshot::channel();
        self.pending.lock().expect("pending lock").insert(id, reply);
        self.send
            .send(message.to_string())
            .map_err(|_| "the DevTools socket closed".to_string())?;
        let response = tokio::time::timeout(Duration::from_secs(120), response)
            .await
            .map_err(|_| format!("{method}: no reply in 120 s"))?
            .map_err(|_| format!("{method}: the DevTools socket closed"))?;
        match response.get("error") {
            Some(error) => Err(format!("{method}: {error}")),
            None => Ok(response["result"].clone()),
        }
    }

    /// Evaluates `expression` in a session, awaiting a promise, and returns its JSON value. A
    /// thrown or rejected value is the error.
    pub async fn evaluate(&self, session: &str, expression: &str) -> Result<Value, String> {
        let result = self
            .call(
                Some(session),
                "Runtime.evaluate",
                json!({ "expression": expression, "awaitPromise": true, "returnByValue": true }),
            )
            .await?;
        match result.get("exceptionDetails") {
            Some(details) => Err(details["exception"]["description"]
                .as_str()
                .or(details["exception"]["value"].as_str())
                .unwrap_or(&details.to_string())
                .to_string()),
            None => Ok(result["result"]["value"].clone()),
        }
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().expect("events lock").len()
    }

    /// Closes the browser, kills the process it started if it has not exited, and deletes the
    /// profile it was given, by that exact path.
    pub async fn close(mut self) {
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            self.call(None, "Browser.close", json!({})),
        )
        .await;
        if tokio::time::timeout(Duration::from_secs(10), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
        remove_profile(&self.profile);
    }
}

fn remove_profile(profile: &Path) {
    if let Err(e) = std::fs::remove_dir_all(profile) {
        eprintln!(
            "could not delete the Chrome profile {}: {e}",
            profile.display()
        );
    }
}
