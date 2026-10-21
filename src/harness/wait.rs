//! Worker-local dispatch results and stoppable unresolved-command waits. Nothing is replayed.

use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::future::Future;
use std::rc::Rc;
use tokio::sync::Notify;

#[derive(Default)]
pub(super) struct ResultCell {
    result: RefCell<Option<Value>>,
    ready: Notify,
}

impl ResultCell {
    pub async fn get(&self) -> Value {
        loop {
            let ready = self.ready.notified();
            if let Some(result) = self.result.borrow().as_ref() {
                return result.clone();
            }
            ready.await;
        }
    }

    fn finish(&self, result: Value) {
        *self.result.borrow_mut() = Some(result);
        self.ready.notify_waiters();
    }
}

thread_local! {
    static RESULTS: RefCell<BTreeMap<u64, Rc<ResultCell>>> = RefCell::default();
    static WAITS: RefCell<Vec<(String, std::rc::Weak<Stop>)>> = RefCell::default();
}

pub(super) fn result(call: u64) -> Option<Rc<ResultCell>> {
    RESULTS.with(|results| results.borrow().get(&call).cloned())
}

pub(super) struct DispatchResult {
    call: u64,
    cell: Rc<ResultCell>,
}

impl DispatchResult {
    /// Called in the same poll as intent append returns, before any further await.
    pub fn new(call: u64) -> Self {
        let cell = Rc::new(ResultCell::default());
        RESULTS.with(|results| results.borrow_mut().insert(call, cell.clone()));
        Self { call, cell }
    }

    pub fn finish(self, result: Value) {
        self.cell.finish(result);
    }
}

impl Drop for DispatchResult {
    fn drop(&mut self) {
        RESULTS.with(|results| results.borrow_mut().remove(&self.call));
        if self.cell.result.borrow().is_none() {
            self.cell.finish(json!({"unresolved":true,"call":self.call,
                "why":"own dispatch ended without a record","not_read":true}));
        }
    }
}

#[derive(Default)]
pub struct Stop {
    stopped: Cell<bool>,
    ready: Notify,
}

impl Stop {
    pub fn new(machine: &str) -> Rc<Self> {
        let stop = Rc::new(Self::default());
        WAITS.with(|waits| {
            let mut waits = waits.borrow_mut();
            waits.retain(|(_, stop)| stop.strong_count() != 0);
            waits.push((machine.into(), Rc::downgrade(&stop)));
        });
        stop
    }

    pub fn stopped(&self) -> bool {
        self.stopped.get()
    }

    pub async fn until<T>(&self, work: impl Future<Output = T>) -> Option<T> {
        // Dropping a stopped wait also unregisters its notification futures.
        super::write::until(self.notified(), work).await
    }

    pub(crate) async fn notified(&self) {
        let ready = self.ready.notified();
        if !self.stopped() {
            ready.await;
        }
    }
}

/// Stop only unresolved-command waits already registered for this machine.
pub fn stop_waits(machine: &str) -> usize {
    WAITS.with(|waits| {
        waits
            .borrow()
            .iter()
            .filter_map(|(name, stop)| (name == machine).then(|| stop.upgrade()).flatten())
            .filter(|stop| {
                let changed = !stop.stopped.replace(true);
                stop.ready.notify_waiters();
                changed
            })
            .count()
    })
}
