//! Authenticated read-only scan loading. No enrollment or lifetime writer lives here.
use super::*;
use crate::scan::{Required, ScanMaterial};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Blob {
    nonce: String,
    ciphertext: String,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;

#[derive(Default)]
struct OutputCache {
    bytes: BTreeMap<sha2::digest::Output<Sha256>, Zeroizing<Vec<u8>>>,
    echoes: Vec<crate::poc::inference::EchoCache>,
}

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
                .map_err(|_| crate::poc::wait::SCAN_REQUIRED)?;
            let blob: Blob =
                serde_json::from_slice(&bytes).map_err(|_| crate::poc::wait::SCAN_ENVELOPE)?;
            if serde_json::to_vec(&blob).map_err(|_| crate::poc::wait::SCAN_ENCODING)? != bytes {
                return Err(crate::poc::wait::SCAN_NONCANONICAL.into());
            }
            let nonce = decode::<12>(crate::poc::wait::SCAN_NONCE_FIELD, &blob.nonce)?;
            let ciphertext = URL_SAFE_NO_PAD
                .decode(&blob.ciphertext)
                .map_err(|_| crate::poc::wait::SCAN_CIPHERTEXT)?;
            if URL_SAFE_NO_PAD.encode(&ciphertext) != blob.ciphertext {
                return Err(crate::poc::wait::SCAN_NONCANONICAL_CIPHER.into());
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
                    .map_err(|_| crate::poc::wait::SCAN_AUTH)?,
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
    /// Remember only scan fingerprints, without extending the usable credential's lifetime.
    /// Keep prior generations until this store drops so late machine evidence remains protected.
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn remember_poc_credential(&mut self, key: &[u8]) {
        let next = crate::poc::inference::EchoFilter::new(&[key]);
        if let Some(combined) = self.poc_credential_filters.first_mut() {
            combined.merge(next);
        } else {
            self.poc_credential_filters.push(next);
        }
    }

    pub(crate) fn scan_decoded(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::poc::inference::work::charge(self.scans.work_cost(bytes.len()))?;
        self.scans.scan(&[bytes])
    }

    pub(crate) fn protect_decoded(&self, value: &Value) -> Result<Value, String> {
        let Value::String(text) = value else {
            return Ok(value.clone());
        };
        let mut raw = Zeroizing::new(text.as_bytes().to_vec());
        let hexadecimal = !text.is_empty()
            && text.len().is_multiple_of(2)
            && text.bytes().all(|b| b.is_ascii_hexdigit());
        if hexadecimal {
            raw = Zeroizing::new(hex::decode(text).map_err(|_| crate::poc::wait::OUTPUT_HEX)?);
        }
        let safe = crate::redaction::Redacted::decoded(self, &raw)?;
        if hexadecimal {
            if safe.as_bytes() == raw.as_slice() {
                Ok(value.clone())
            } else {
                Ok(hex::encode(safe.as_bytes()).into())
            }
        } else {
            Ok(String::from_utf8_lossy(safe.as_bytes()).into_owned().into())
        }
    }

    pub(crate) fn scan_output(&self, chunks: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.scan_output_cached(chunks, &mut Vec::new())
    }

    pub(crate) fn scan_output_cached(
        &self,
        chunks: &[&[u8]],
        cache: &mut Vec<crate::poc::inference::EchoCache>,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        crate::poc::inference::work::scope(|| {
            let size = chunks.iter().map(|c| c.len()).sum::<usize>();
            crate::poc::inference::work::charge(self.scans.work_cost(size))?;
            let mut safe = self.scans.scan(chunks)?;
            cache.resize_with(
                self.poc_credential_filters.len() + self.provider_filters.len(),
                Default::default,
            );
            for (filter, cache) in self
                .poc_credential_filters
                .iter()
                .chain(&self.provider_filters)
                .zip(cache)
            {
                safe = filter.protect_bytes_cached(&safe, cache)?;
            }
            Ok(safe)
        })
    }

    pub(crate) fn poc_output_is_safe(&self, bytes: &[u8]) -> Result<bool, String> {
        for filter in self
            .poc_credential_filters
            .iter()
            .chain(&self.provider_filters)
        {
            if filter.protect_bytes(bytes)?.as_slice() != bytes {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Protect nested copies, including legacy hex evidence. Marker substitution is not
    /// intrinsic occurrence custody or completed protected finalization.
    pub fn protect_output(&self, value: &Value) -> Result<Value, String> {
        fn bytes<S: Storage>(
            store: &Store<S>,
            raw: &[u8],
            cache: &mut OutputCache,
        ) -> Result<Zeroizing<Vec<u8>>, String> {
            crate::poc::inference::work::charge(raw.len().saturating_mul(2))?;
            let digest = Sha256::digest(raw);
            if let Some(safe) = cache.bytes.get(&digest) {
                return Ok(safe.clone());
            }
            let safe = Zeroizing::new(
                crate::redaction::Redacted::for_store_cached(store, raw, &[], &mut cache.echoes)?
                    .as_bytes()
                    .to_vec(),
            );
            cache.bytes.insert(digest, safe.clone());
            Ok(safe)
        }
        fn protect<S: Storage>(
            store: &Store<S>,
            value: &Value,
            cache: &mut OutputCache,
        ) -> Result<Value, String> {
            crate::poc::inference::work::charge(128)?;
            Ok(match value {
                Value::String(text) => {
                    let raw = if !text.is_empty()
                        && text.len().is_multiple_of(2)
                        && text
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    {
                        let raw = Zeroizing::new(
                            hex::decode(text).map_err(|_| crate::poc::wait::OUTPUT_HEX)?,
                        );
                        hex::encode(bytes(store, &raw, cache)?.as_slice())
                    } else {
                        text.clone()
                    };
                    let safe = bytes(store, raw.as_bytes(), cache)?;
                    String::from_utf8_lossy(&safe).into_owned().into()
                }
                Value::Array(values) => values
                    .iter()
                    .map(|v| protect(store, v, cache))
                    .collect::<Result<Vec<_>, _>>()?
                    .into(),
                Value::Object(values) => {
                    // Legacy job reports carry both decoded output and the exact raw record.
                    // Derive the released text from scanned raw bytes, before lossy decoding.
                    let mut values = values.clone();
                    if let Some(record) = values.get("record").cloned() {
                        for field in ["stdout", "stderr"] {
                            if let Some(encoded) = record.get(field).and_then(Value::as_str) {
                                let raw = Zeroizing::new(
                                    hex::decode(encoded)
                                        .map_err(|_| crate::poc::wait::JOB_OUTPUT_HEX)?,
                                );
                                let safe = bytes(store, &raw, cache)?;
                                values["record"][field] = hex::encode(safe.as_slice()).into();
                                if values.contains_key(field) {
                                    values[field] =
                                        String::from_utf8_lossy(&safe).into_owned().into();
                                }
                            }
                        }
                    }
                    let mut result = serde_json::Map::new();
                    for (key, value) in &values {
                        let safe = bytes(store, key.as_bytes(), cache)?;
                        let key = String::from_utf8_lossy(&safe).into_owned();
                        if result.insert(key, protect(store, value, cache)?).is_some() {
                            return Err(crate::poc::wait::OUTPUT_COLLISION.into());
                        }
                    }
                    Value::Object(result)
                }
                _ => value.clone(),
            })
        }
        crate::poc::inference::work::scope(|| {
            self.scan_readiness()?;
            crate::poc::inference::work::value(value, 0)?;
            protect(self, value, &mut OutputCache::default())
        })
    }

    /// Check every supported final envelope before a terminal changes collection authority.
    /// Use the original journal bytes and immutable privilege route, exactly as transmission does.
    pub(crate) fn preflight_job_release(&self, report: &crate::jobs::Report) -> Result<(), String> {
        let intent = &self
            .dispatch
            .calls
            .get(&report.evidence.call)
            .ok_or("job release intent missing")?
            .intent;
        let command = hex::decode(&intent.command).map_err(|_| "job release command hex")?;
        let elevation = self
            .poc_target(&intent.machine)
            .map_or(crate::jobs::Elevation::None, |target| target.elevation);
        let host_key = match &intent.approval {
            Some(crate::dispatch::Approval::HarnessPin { fingerprint, .. }) => fingerprint.clone(),
            _ => String::new(),
        };
        let done = crate::harness::Done {
            seq: intent.call,
            sent: crate::jobs::launch_with_elevation(
                intent
                    .job
                    .as_deref()
                    .ok_or("job release identity missing")?,
                &intent.machine,
                &command,
                elevation,
            )
            .into_bytes(),
            recorded: crate::harness::Entry {
                machine: intent.machine.clone(),
                command,
                provenance: intent.provenance.clone(),
            },
            stdout: report.stdout.as_bytes().to_vec(),
            stderr: report.stderr.as_bytes().to_vec(),
            exit_status: report.exit_status.ok_or("job release exit missing")?,
            terminal: report.number.ok_or("job release number missing")?,
            host_key,
            evidence: report.clone(),
        };
        // Each is an alternative synchronous release, not an aggregate array on the wire.
        // protect_output inherits an enclosing work scope; no remaining budget is reset here.
        for value in crate::harness::release_forms(&done) {
            self.protect_output(&value)?;
        }
        if self.poc.values().any(|task| {
            task.pending
                .as_ref()
                .is_some_and(|pending| pending.call == intent.call)
        }) {
            // A task releases each terminal independently of the bounded history view.
            let mut result =
                serde_json::to_value(report).map_err(|_| crate::poc::wait::RESULT_ENCODING)?;
            self.protect_output(&json!({"command_result":result}))?;
            crate::jobs::historical(&mut result, "stale result after suspension");
            self.protect_output(&json!({"command_result":result}))?;
        }
        Ok(())
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

    /// Bound validation and the initial decoded report allocation in the same scope as
    /// protection. This scope is synchronous and inherits any caller's remaining capacity.
    pub(crate) fn job_report(
        &self,
        evidence: &crate::jobs::Evidence,
        number: Option<u64>,
        machine: &str,
        command: &str,
    ) -> Result<crate::jobs::Report, String> {
        crate::poc::inference::work::scope(|| {
            if let crate::jobs::Record::Present {
                machine,
                command,
                boot,
                current_boot,
                stdout,
                stderr,
                ..
            } = &evidence.record
            {
                for field in [machine, command, boot, current_boot, stdout, stderr] {
                    crate::poc::inference::work::charge(field.len().saturating_mul(16))?;
                }
            }
            if let crate::jobs::Record::Incomplete { machine, command } = &evidence.record {
                for field in machine.iter().chain(command.iter()) {
                    crate::poc::inference::work::charge(field.len().saturating_mul(16))?;
                }
            }
            crate::poc::inference::work::charge(evidence.job.len().saturating_mul(16))?;
            evidence.record.validate()?;
            let mut report = evidence.report(number.unwrap_or(0), machine, command);
            report.number = number;
            self.protect_job_report(report)
        })
    }

    pub(crate) fn protect_job_report(
        &self,
        mut report: crate::jobs::Report,
    ) -> Result<crate::jobs::Report, String> {
        crate::poc::inference::work::scope(|| {
            // Reports duplicate the same output as raw hex and lossy text. Protect the full
            // bytes once, then derive both copies; scan every other field independently.
            let output = if let crate::jobs::Record::Present { stdout, stderr, .. } =
                &mut report.evidence.record
            {
                Some([std::mem::take(stdout), std::mem::take(stderr)])
            } else {
                None
            };
            report.stdout.clear();
            report.stderr.clear();
            let value = self.protect_output(
                &serde_json::to_value(report).map_err(|_| "job report encoding")?,
            )?;
            let mut report: crate::jobs::Report =
                serde_json::from_value(value).map_err(|_| "job report protection")?;
            if let Some(output) = output
                && let crate::jobs::Record::Present { stdout, stderr, .. } =
                    &mut report.evidence.record
            {
                let mut cache = Vec::new();
                for (raw, encoded, decoded) in [
                    (&output[0], stdout, &mut report.stdout),
                    (&output[1], stderr, &mut report.stderr),
                ] {
                    crate::poc::inference::work::charge(raw.len().saturating_mul(4))?;
                    let bytes = Zeroizing::new(
                        hex::decode(raw).map_err(|_| crate::poc::wait::JOB_OUTPUT_HEX)?,
                    );
                    let safe = crate::redaction::Redacted::for_store_cached(
                        self,
                        &bytes,
                        &[],
                        &mut cache,
                    )?;
                    *encoded = hex::encode(safe.as_bytes());
                    *decoded = String::from_utf8_lossy(safe.as_bytes()).into_owned();
                    // Encoding or lossy decoding can itself create another credential's
                    // spelling. Refuse rather than corrupt the hex or release that junction.
                    if crate::redaction::Redacted::for_store_cached(
                        self,
                        encoded.as_bytes(),
                        &[],
                        &mut cache,
                    )?
                    .as_bytes()
                        != encoded.as_bytes()
                        || (decoded.as_bytes() != safe.as_bytes()
                            && crate::redaction::Redacted::for_store_cached(
                                self,
                                decoded.as_bytes(),
                                &[],
                                &mut cache,
                            )?
                            .as_bytes()
                                != decoded.as_bytes())
                    {
                        return Err(crate::poc::wait::PROTECTED_UNAVAILABLE.into());
                    }
                }
            }
            Ok(report)
        })
    }
}
