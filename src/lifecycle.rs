//! One worker-owned lifecycle fence. Ordinary hide does not change authority.
use std::cell::{Cell, RefCell};
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Running,
    Suspended,
    Ended,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ExecutionIdentity([u8; 16]);

pub struct Authority {
    incarnation: ExecutionIdentity,
    page_incarnation: RefCell<Option<String>>,
    identity_sealed: Cell<bool>,
    generation: Cell<u64>,
    phase: Cell<Phase>,
}
impl Default for Authority {
    fn default() -> Self {
        let mut incarnation = [0; 16];
        getrandom::fill(&mut incarnation).expect("execution incarnation randomness");
        Self {
            incarnation: ExecutionIdentity(incarnation),
            page_incarnation: RefCell::new(None),
            identity_sealed: Cell::new(false),
            generation: Cell::new(0),
            phase: Cell::new(Phase::Running),
        }
    }
}

#[derive(Clone)]
pub struct Continuation {
    owner: Rc<Authority>,
    incarnation: ExecutionIdentity,
    generation: u64,
    clock_verification: bool,
}

impl Authority {
    #[cfg(any(target_arch = "wasm32", test))]
    pub(crate) fn identify(&self, identity: String) -> Result<(), String> {
        if self.identity_sealed.get()
            || self.page_incarnation.borrow().is_some()
            || identity.len() != 36
            || !identity.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err("execution identity is invalid or already fixed".into());
        }
        *self.page_incarnation.borrow_mut() = Some(identity);
        Ok(())
    }
    pub(crate) fn seal_identity(&self) {
        self.identity_sealed.set(true);
    }
    pub(crate) fn references(&self) -> Vec<String> {
        let mut references = vec![hex::encode(self.incarnation.0)];
        references.extend(self.page_incarnation.borrow().iter().cloned());
        references
    }
    pub fn state(&self) -> &'static str {
        match self.phase.get() {
            Phase::Running => "running",
            Phase::Suspended => "reconciling",
            Phase::Ended => "ended",
        }
    }
    pub fn generation(&self) -> u64 {
        self.generation.get()
    }
    pub fn ordinary(&self) -> Result<(), String> {
        match self.phase.get() {
            Phase::Running => Ok(()),
            Phase::Suspended => Err(crate::poc::wait::SUSPENSION.into()),
            Phase::Ended => Err(crate::poc::wait::SESSIONS_ENDED.into()),
        }
    }
    pub fn verification(&self) -> bool {
        self.phase.get() != Phase::Ended
    }
    pub fn suspend(&self) {
        if self.verification() {
            self.generation.set(
                self.generation
                    .get()
                    .checked_add(1)
                    .expect("lifecycle generation exhausted"),
            );
            self.phase.set(Phase::Suspended);
        }
    }
    pub fn revalidated(&self) -> Result<(), String> {
        if !self.verification() {
            return Err(crate::poc::wait::SESSIONS_ENDED.into());
        }
        self.phase.set(Phase::Running);
        Ok(())
    }
    pub fn end(&self) {
        self.generation.set(
            self.generation
                .get()
                .checked_add(1)
                .expect("lifecycle generation exhausted"),
        );
        self.phase.set(Phase::Ended);
    }
    pub fn continuation(self: &Rc<Self>) -> Result<Continuation, String> {
        self.ordinary()?;
        Ok(Continuation {
            owner: self.clone(),
            incarnation: self.incarnation,
            generation: self.generation.get(),
            clock_verification: false,
        })
    }
    pub(crate) fn clock_continuation(self: &Rc<Self>) -> Result<Continuation, String> {
        if !self.verification() {
            return Err(crate::poc::wait::SESSIONS_ENDED.into());
        }
        Ok(Continuation {
            owner: self.clone(),
            incarnation: self.incarnation,
            generation: self.generation.get(),
            clock_verification: true,
        })
    }
}

impl Continuation {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn is_clock_verification(&self) -> bool {
        self.clock_verification
    }
    pub fn check(&self) -> Result<(), String> {
        if self.incarnation != self.owner.incarnation {
            return Err("stale execution incarnation".into());
        }
        if self.clock_verification {
            if !self.owner.verification() {
                return Err(crate::poc::wait::SESSIONS_ENDED.into());
            }
        } else {
            self.owner.ordinary()?;
        }
        if self.generation != self.owner.generation.get() {
            return Err("stale continuation; reconciliation required".into());
        }
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
thread_local! { static OWNER: Rc<Authority> = Rc::default(); }
pub(crate) fn owner() -> Rc<Authority> {
    #[cfg(target_arch = "wasm32")]
    {
        OWNER.with(Rc::clone)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        Rc::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poc_execution_identity_is_fixed_before_store_authority() {
        let a = Authority::default();
        let id = "11223344-5566-7788-99aa-bbccddeeff00";
        a.identify(id.into()).unwrap();
        assert!(a.references().iter().any(|r| r == id));
        assert!(a.identify(id.into()).is_err());
        let b = Authority::default();
        b.seal_identity();
        assert!(b.identify(id.into()).is_err());
        assert_ne!(a.references()[0], b.references()[0]);
    }
    #[test]
    fn suspended_continuation_never_revives_and_end_is_irreversible() {
        let a = Rc::new(Authority::default());
        let old = a.continuation().unwrap();
        a.suspend();
        assert!(old.check().is_err());
        assert!(a.verification());
        a.revalidated().unwrap();
        assert!(old.check().is_err());
        assert!(a.continuation().unwrap().check().is_ok());
        a.end();
        assert!(!a.verification());
        assert!(a.revalidated().is_err());
        a.suspend();
        assert!(a.ordinary().is_err());
    }
}
