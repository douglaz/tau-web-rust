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
}

impl<T: Credential + 'static> Given for T {
    fn row(&self) -> u8 {
        T::ROW
    }
    fn value(&self) -> &dyn Any {
        self
    }
}

pub(crate) struct Holding {
    pub machine: String,
    pub credential: Box<dyn Given>,
}

pub struct Session {
    pub identity: String,
    pub bound_set: Vec<String>,
    pub(crate) given: Vec<Holding>,
}

impl Session {
    pub(crate) fn new(identity: String, machine: String, key: SshClientKey) -> Self {
        Self {
            identity,
            bound_set: vec![machine.clone()],
            given: vec![Holding {
                machine,
                credential: Box::new(key),
            }],
        }
    }

    pub fn client_key(&self, machine: &str) -> Option<&SshClientKey> {
        self.given
            .iter()
            .find(|holding| holding.machine == machine)?
            .credential
            .value()
            .downcast_ref()
    }

    pub fn inspect(&self) -> Value {
        json!({"identity":self.identity,"bound_set":self.bound_set,
            "given":self.given.iter().map(|h| json!({"row":h.credential.row(),"machine":h.machine})).collect::<Vec<_>>()})
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
