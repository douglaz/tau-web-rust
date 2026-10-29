//! One worker-owned lifecycle fence. Ordinary hide does not change authority.
use std::cell::Cell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Running,
    Suspended,
    Ended,
}

pub struct Authority {
    generation: Cell<u64>,
    phase: Cell<Phase>,
}
impl Default for Authority {
    fn default() -> Self {
        Self {
            generation: Cell::new(0),
            phase: Cell::new(Phase::Running),
        }
    }
}

#[derive(Clone)]
pub struct Continuation {
    owner: Rc<Authority>,
    generation: u64,
    clock_verification: bool,
}

impl Authority {
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
            Phase::Suspended => {
                Err("reconciliation or verification required after suspension".into())
            }
            Phase::Ended => Err("sessions ended".into()),
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
            return Err("sessions ended".into());
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
            generation: self.generation.get(),
            clock_verification: false,
        })
    }
    pub(crate) fn clock_continuation(self: &Rc<Self>) -> Result<Continuation, String> {
        if !self.verification() {
            return Err("sessions ended".into());
        }
        Ok(Continuation {
            owner: self.clone(),
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
        if self.clock_verification {
            if !self.owner.verification() {
                return Err("sessions ended".into());
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
