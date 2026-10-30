//! Read-only consumers of identified placed-secret references (SEC-5 row 23).
//! Inventory is supplied by the owning placement protocol; a blob alone arms nothing.

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Required {
    pub identity: String,
    pub name: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ScanMaterial {
    pub key: [u8; 32],
    pub reference: [u8; 32],
    pub length: u64,
}

impl Drop for ScanMaterial {
    fn drop(&mut self) {
        self.key.zeroize();
        self.reference.zeroize();
        self.length.zeroize();
    }
}
impl ZeroizeOnDrop for ScanMaterial {}

impl ScanMaterial {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: Self = serde_json::from_slice(bytes).map_err(|_| "invalid scan material")?;
        if value.length < 16
            || usize::try_from(value.length).is_err()
            || serde_json::to_vec(&value).map_err(|_| "scan material encoding")? != bytes
        {
            return Err("noncanonical or unsupported scan material".into());
        }
        Ok(value)
    }

    fn matches(&self, bytes: &[u8]) -> bool {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).expect("HMAC key length");
        mac.update(&Sha256::digest(bytes));
        mac.verify_slice(&self.reference).is_ok()
    }
}

#[derive(Default)]
pub(crate) struct References {
    required: BTreeMap<String, String>,
    material: std::cell::RefCell<BTreeMap<String, ScanMaterial>>,
    revision: std::cell::Cell<u64>,
    invalid_inventory: bool,
}

impl References {
    /// Replace inventory only from the owning protocol, never from machine output or blobs.
    pub(crate) fn inventory(&mut self, inventory: Vec<Required>) -> Result<(), String> {
        self.invalid_inventory = true;
        let mut required = BTreeMap::new();
        for entry in inventory {
            if !crate::jobs::valid_id(&entry.identity)
                || entry.name.is_empty()
                || entry.name.chars().any(char::is_control)
                || required.insert(entry.identity, entry.name).is_some()
            {
                return Err("invalid or duplicate required scan identity".into());
            }
        }
        self.clear();
        self.required = required;
        self.invalid_inventory = false;
        Ok(())
    }

    pub(crate) fn identities(&self) -> Vec<String> {
        self.required.keys().cloned().collect()
    }

    pub(crate) fn install(&mut self, id: String, material: ScanMaterial) -> Result<(), String> {
        if !self.required.contains_key(&id) || self.material.borrow().contains_key(&id) {
            return Err("scan identity is not awaiting material".into());
        }
        self.material.get_mut().insert(id, material);
        self.revision.set(
            self.revision
                .get()
                .checked_add(1)
                .expect("scan revision exhausted"),
        );
        Ok(())
    }

    pub(crate) fn clear(&self) {
        self.material.borrow_mut().clear();
        self.revision.set(
            self.revision
                .get()
                .checked_add(1)
                .expect("scan revision exhausted"),
        );
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision.get()
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub(crate) fn working_material_bytes(&self, id: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.material
            .borrow()
            .get(id)
            .map(|m| Zeroizing::new(serde_json::to_vec(m).expect("material serializes")))
    }

    pub(crate) fn ready(&self) -> Result<(), String> {
        if self.invalid_inventory || self.required.len() != self.material.borrow().len() {
            return Err("required scan material unavailable; output withheld".into());
        }
        Ok(())
    }

    /// No chunk is released early. Concatenation preserves raw windows crossing deliveries.
    pub(crate) fn scan(&self, chunks: &[&[u8]]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.ready()?;
        let bytes = Zeroizing::new(chunks.concat());
        let mut ranges = Vec::new();
        let material_set = self.material.borrow();
        for (identity, material) in material_set.iter() {
            let length = usize::try_from(material.length).map_err(|_| "scan length")?;
            for (start, window) in bytes.windows(length).enumerate() {
                if material.matches(window) {
                    ranges.push((start, start + length, identity));
                }
            }
        }
        ranges.sort_unstable();
        let mut output = Zeroizing::new(Vec::new());
        let mut cursor = 0;
        let mut i = 0;
        while i < ranges.len() {
            let (start, mut end, _) = ranges[i];
            let mut names = std::collections::BTreeSet::new();
            names.insert(self.required[ranges[i].2].as_str());
            i += 1;
            while i < ranges.len() && ranges[i].0 < end {
                end = end.max(ranges[i].1);
                names.insert(self.required[ranges[i].2].as_str());
                i += 1;
            }
            output.extend_from_slice(&bytes[cursor..start]);
            for name in names {
                output.extend_from_slice(format!("<redacted secret: {name}>").as_bytes());
            }
            cursor = end;
        }
        output.extend_from_slice(&bytes[cursor..]);
        // Names/markers and their junctions are also untrusted output.
        for material in material_set.values() {
            if output
                .windows(material.length as usize)
                .any(|w| material.matches(w))
            {
                return Err("scan marker contains protected material; output withheld".into());
            }
        }
        Ok(output)
    }
}
