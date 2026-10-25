//! Live bindings and their durable exposure ledger. Replay restores the ledger alone.

use crate::allocation::Identity;
use crate::credential::{Credential, SshClientKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::any::Any;

/// Inspection and transport read the same credential collection. The row comes from the
/// credential's type, so inspection also reveals an accidentally supplied operator seed.
pub(crate) trait Given {
    fn row(&self) -> u8;
    fn value(&self) -> &dyn Any;
    fn response_bytes(&self) -> Option<&[u8]>;
}

impl<T: Credential + 'static> Given for T {
    fn row(&self) -> u8 {
        T::ROW
    }
    fn value(&self) -> &dyn Any {
        self
    }
    fn response_bytes(&self) -> Option<&[u8]> {
        let value = self.value();
        macro_rules! bytes {
            ($($ty:ty),*) => { $(
                if let Some(key) = value.downcast_ref::<$ty>() {
                    return Some(&key.0);
                }
            )* };
        }
        bytes!(
            SshClientKey,
            crate::credential::AttestSenderKey,
            crate::credential::AttestRecipientKey,
            crate::credential::RelayKey,
            crate::credential::PostHarnessCredential,
            crate::credential::DataKey,
            crate::credential::WrappingKey,
            crate::credential::LocalPassphrase,
            crate::credential::InferenceAccountCredential,
            crate::credential::SessionInferenceKey
        );
        value
            .downcast_ref::<crate::seed::Seed>()
            .map(|seed| seed.bytes())
    }
}

pub(crate) struct Holding {
    pub machine: String,
    pub credential: Box<dyn Given>,
}

pub struct Session {
    pub identity: String,
    pub bound_set: Vec<String>,
    pub(crate) given: std::cell::RefCell<Vec<Holding>>,
}

impl Session {
    pub(crate) fn new(identity: String, machine: String, key: SshClientKey) -> Self {
        Self {
            identity,
            bound_set: vec![machine.clone()],
            given: std::cell::RefCell::new(vec![Holding {
                machine,
                credential: Box::new(key),
            }]),
        }
    }

    pub fn client_key(&self, machine: &str) -> Option<std::cell::Ref<'_, SshClientKey>> {
        std::cell::Ref::filter_map(self.given.borrow(), |given| {
            given
                .iter()
                .find(|h| h.machine == machine)?
                .credential
                .value()
                .downcast_ref()
        })
        .ok()
    }

    pub fn inspect(&self) -> Value {
        json!({"identity":self.identity,"bound_set":self.bound_set,
            "given":self.given.borrow().iter().map(|h| json!({"row":h.credential.row(),"machine":if h.machine.is_empty() {Value::Null} else {json!(h.machine)}})).collect::<Vec<_>>()})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundMachine {
    pub machine: String,
    pub identity: Identity,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exposure {
    pub session: String,
    pub bound_set: Vec<BoundMachine>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub accepted_modes: Vec<crate::modes::Mode>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Unbound,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionRefusal {
    pub machine: String,
    pub reason: Reason,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionRefusal {
    NoEntry,
    Unbound,
    Journal(String),
}
