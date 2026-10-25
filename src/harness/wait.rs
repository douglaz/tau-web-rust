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
    static WAITS: RefCell<Vec<(Option<String>, std::rc::Weak<Stop>)>> = RefCell::default();
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
    sockets: RefCell<BTreeMap<u64, web_sys::WebSocket>>,
    next_socket: Cell<u64>,
}

pub(super) struct SocketRegistration {
    stop: Rc<Stop>,
    id: u64,
}

impl Drop for SocketRegistration {
    fn drop(&mut self) {
        self.stop.sockets.borrow_mut().remove(&self.id);
    }
}

impl Stop {
    pub fn new(machine: &str) -> Rc<Self> {
        Self::register(Some(machine))
    }

    /// Dispatch and collection stop at session end, independently of held-request stops.
    pub(super) fn collection() -> Rc<Self> {
        Self::register(None)
    }

    fn register(machine: Option<&str>) -> Rc<Self> {
        let stop = Rc::new(Self::default());
        WAITS.with(|waits| {
            let mut waits = waits.borrow_mut();
            waits.retain(|(_, stop)| stop.strong_count() != 0);
            waits.push((machine.map(str::to_owned), Rc::downgrade(&stop)));
        });
        stop
    }

    pub(super) fn socket(self: &Rc<Self>, socket: web_sys::WebSocket) -> SocketRegistration {
        let id = self.next_socket.get();
        self.next_socket.set(id + 1);
        if self.stopped() {
            let _ = socket.close();
        }
        self.sockets.borrow_mut().insert(id, socket);
        SocketRegistration {
            stop: self.clone(),
            id,
        }
    }

    fn fire(&self) -> bool {
        let changed = !self.stopped.replace(true);
        self.ready.notify_waiters();
        for socket in self.sockets.borrow().values() {
            let _ = socket.close();
        }
        changed
    }

    pub fn stopped(&self) -> bool {
        self.stopped.get() || super::inference::ending()
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

/// Session end stops every registered wait before acquiring the store writer.
pub(super) fn stop_all() {
    WAITS.with(|waits| {
        for (_, stop) in waits.borrow().iter() {
            if let Some(stop) = stop.upgrade() {
                stop.fire();
            }
        }
    });
}

/// Stop only unresolved-command waits already registered for this machine.
pub fn stop_waits(machine: &str) -> usize {
    WAITS.with(|waits| {
        waits
            .borrow()
            .iter()
            .filter_map(|(name, stop)| {
                (name.as_deref() == Some(machine))
                    .then(|| stop.upgrade())
                    .flatten()
            })
            .filter(|stop| stop.fire())
            .count()
    })
}
