//! Authenticated read-only scan loading. No enrollment or lifetime writer lives here.
use super::*;
use crate::scan::{Required, ScanMaterial};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    nonce: String,
    ciphertext: String,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

impl<S: Storage> Store<S> {
    /// Synthetic producer for isolated fixture stores only. These bytes establish no production
    /// enrollment, reservation, counted encryption, causal lifetime or finalization evidence.
    #[cfg(any(test, feature = "tracer"))]
    pub async fn synthetic_scan_fixture(
        &mut self,
        name: String,
        value: Zeroizing<Vec<u8>>,
    ) -> Result<String, String> {
        if value.len() < 16 || !self.scans.identities().is_empty() {
            return Err(
                "fixture requires a fresh reference inventory and a value of at least 16 bytes"
                    .into(),
            );
        }
        use hmac::Mac;
        let key = Zeroizing::new(random::<32>()?);
        let mut mac = <hmac::Hmac<Sha256> as hmac::KeyInit>::new_from_slice(&key[..])
            .map_err(|_| "fixture HMAC")?;
        mac.update(&Sha256::digest(&value));
        let material = ScanMaterial {
            key: *key,
            reference: mac.finalize().into_bytes().into(),
            length: value.len() as u64,
        };
        let plaintext =
            Zeroizing::new(serde_json::to_vec(&material).map_err(|_| "fixture material")?);
        let identity = hex::encode(random::<24>()?);
        let nonce = random::<12>()?;
        let aad = format!("tau-web/local/v1/{}/scan/{identity}", self.id);
        let ciphertext = cipher(&self.key.0)
            .encrypt(
                &nonce.into(),
                Payload {
                    msg: &plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| "fixture encryption")?;
        let bytes = serde_json::to_vec(&Blob {
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        })
        .map_err(|_| "fixture envelope")?;
        self.storage
            .write(&format!("scan-{identity}"), &bytes)
            .await?;
        self.load_scan_references(vec![Required {
            identity: identity.clone(),
            name,
        }])
        .await?;
        Ok(identity)
    }
    /// Identified required inventory comes from the placement protocol, never blob discovery.
    pub async fn load_scan_references(&mut self, inventory: Vec<Required>) -> Result<(), String> {
        self.scans.clear();
        self.scans.inventory(inventory)?;
        self.reload_scan_references().await
    }

    pub async fn reload_scan_references(&mut self) -> Result<(), String> {
        self.scans.clear();
        let mut authenticated = Vec::new();
        for identity in self.scans.identities() {
            let bytes = self
                .storage
                .read(&format!("scan-{identity}"))
                .await
                .map_err(|_| "required scan material unavailable")?;
            let blob: Blob = serde_json::from_slice(&bytes).map_err(|_| "invalid scan envelope")?;
            if serde_json::to_vec(&blob).map_err(|_| "scan envelope encoding")? != bytes {
                return Err("noncanonical scan envelope".into());
            }
            let nonce = decode::<12>("scan nonce", &blob.nonce)?;
            let ciphertext = URL_SAFE_NO_PAD
                .decode(&blob.ciphertext)
                .map_err(|_| "invalid scan ciphertext")?;
            if URL_SAFE_NO_PAD.encode(&ciphertext) != blob.ciphertext {
                return Err("noncanonical scan ciphertext".into());
            }
            let aad = format!("tau-web/local/v1/{}/scan/{identity}", self.id);
            let plaintext = Zeroizing::new(
                cipher(&self.key.0)
                    .decrypt(
                        &nonce.into(),
                        Payload {
                            msg: &ciphertext,
                            aad: aad.as_bytes(),
                        },
                    )
                    .map_err(|_| "scan authentication failed")?,
            );
            authenticated.push((identity, ScanMaterial::parse(&plaintext)?));
        }
        for (identity, material) in authenticated {
            self.scans.install(identity, material)?;
        }
        let ready = self.scans.ready();
        #[cfg(target_arch = "wasm32")]
        crate::harness::inference::authority_changed();
        ready
    }

    /// An entitled consumer may reload the original authenticated material after working-copy
    /// clearing. A failed load never changes the required inventory into an empty ready set.
    pub async fn ensure_scan_references(&mut self) -> Result<(), String> {
        if self.scan_readiness().is_err() {
            self.reload_scan_references().await?;
        }
        Ok(())
    }

    pub fn clear_scan_working_copies(&mut self) {
        self.scans.clear();
    }
    pub fn scan_revision(&self) -> u64 {
        self.scans.revision()
    }
    pub fn scan_readiness(&self) -> Result<(), String> {
        self.scans.ready()
    }
    pub(crate) fn scan_output(&self, chunks: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.scans.scan(chunks)
    }

    /// Protect nested copies, including legacy hex evidence. Marker substitution is not
    /// intrinsic occurrence custody or completed protected finalization.
    pub fn protect_output(&self, value: &Value) -> Result<Value, String> {
        fn protect<S: Storage>(store: &Store<S>, value: &Value) -> Result<Value, String> {
            Ok(match value {
                Value::String(text) => {
                    let raw = if !text.is_empty()
                        && text.len().is_multiple_of(2)
                        && text
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        let bytes = Zeroizing::new(hex::decode(text).map_err(|_| "output hex")?);
                        hex::encode(
                            crate::redaction::Redacted::for_store(store, &bytes, &[])?.as_bytes(),
                        )
                    } else {
                        text.clone()
                    };
                    let safe = crate::redaction::Redacted::for_store(store, raw.as_bytes(), &[])?;
                    String::from_utf8_lossy(safe.as_bytes()).into_owned().into()
                }
                Value::Array(values) => values
                    .iter()
                    .map(|v| protect(store, v))
                    .collect::<Result<Vec<_>, _>>()?
                    .into(),
                Value::Object(values) => {
                    // Legacy job reports carry both decoded output and the exact raw record.
                    // Derive the released text from scanned raw bytes, before lossy decoding.
                    let mut values = values.clone();
                    if let Some(record) = values.get("record").cloned() {
                        for field in ["stdout", "stderr"] {
                            if let Some(encoded) = record.get(field).and_then(Value::as_str) {
                                let bytes = Zeroizing::new(
                                    hex::decode(encoded).map_err(|_| "job output hex")?,
                                );
                                let safe =
                                    crate::redaction::Redacted::for_store(store, &bytes, &[])?;
                                values["record"][field] = hex::encode(safe.as_bytes()).into();
                                if values.contains_key(field) {
                                    values[field] = String::from_utf8_lossy(safe.as_bytes())
                                        .into_owned()
                                        .into();
                                }
                            }
                        }
                    }
                    let mut result = serde_json::Map::new();
                    for (key, value) in &values {
                        let safe =
                            crate::redaction::Redacted::for_store(store, key.as_bytes(), &[])?;
                        let key = String::from_utf8_lossy(safe.as_bytes()).into_owned();
                        if result.insert(key, protect(store, value)?).is_some() {
                            return Err("output key collision after protection".into());
                        }
                    }
                    Value::Object(result)
                }
                _ => value.clone(),
            })
        }
        self.scan_readiness()?;
        protect(self, value)
    }

    /// Final command release preserves committed evidence while removing stale action authority.
    pub(crate) fn protect_command_results(&self, value: &Value) -> Result<Value, String> {
        let mut safe = self.protect_output(value)?;
        self.current_command_results(&mut safe);
        Ok(safe)
    }

    /// Called after final encoding as well as scanning. Once a result is historical, its
    /// identities and outcome stay intelligible without requiring ordinary authority.
    pub(crate) fn current_command_results(&self, value: &mut Value) -> bool {
        let mut changed = false;
        if let Some(call) = value.get("call").and_then(Value::as_u64)
            && (value["historical"] != true
                || value["actionable"] != false
                || value.get("done").is_some())
            && let Some(session) = self
                .dispatch
                .calls
                .get(&call)
                .and_then(|call| call.intent.provenance.as_ref())
                .and_then(|p| p.session.as_deref())
            && let Err(why) = self.check_session_authority(session, self.session_pair(session))
        {
            crate::jobs::historical(value, &why);
            changed = true;
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    changed |= self.current_command_results(value);
                }
            }
            Value::Object(values) => {
                for value in values.values_mut() {
                    changed |= self.current_command_results(value);
                }
            }
            _ => {}
        }
        changed
    }

    pub(crate) fn protect_job_report(
        &self,
        mut report: crate::jobs::Report,
    ) -> Result<crate::jobs::Report, String> {
        if let crate::jobs::Record::Present { stdout, stderr, .. } = &mut report.evidence.record {
            for (encoded, decoded) in [(stdout, &mut report.stdout), (stderr, &mut report.stderr)] {
                let raw = Zeroizing::new(hex::decode(&*encoded).map_err(|_| "job output hex")?);
                let safe = crate::redaction::Redacted::for_store(self, &raw, &[])?;
                *encoded = hex::encode(safe.as_bytes());
                *decoded = String::from_utf8_lossy(safe.as_bytes()).into_owned();
            }
        }
        let value =
            self.protect_output(&serde_json::to_value(report).map_err(|_| "job report encoding")?)?;
        serde_json::from_value(value).map_err(|_| "job report protection".into())
    }

    pub(crate) fn protect_job_evidence(
        &self,
        evidence: &crate::jobs::Evidence,
    ) -> Result<crate::jobs::Evidence, String> {
        let mut evidence = evidence.clone();
        if let crate::jobs::Record::Present { stdout, stderr, .. } = &mut evidence.record {
            for field in [stdout, stderr] {
                let bytes = Zeroizing::new(hex::decode(&*field).map_err(|_| "job output hex")?);
                let safe = crate::redaction::Redacted::for_store(self, &bytes, &[])?;
                *field = hex::encode(safe.as_bytes());
            }
        }
        Ok(evidence)
    }
}
