//! Current session, reference and original-limit admission under the Store owner.
use super::*;
use crate::clock::{Observation, Pair};
use crate::inference_limits::{Confirmed, Limits};

impl<S: Storage> Store<S> {
    #[cfg(target_arch = "wasm32")]
    pub(crate) fn clock_verification_authority(
        &self,
        session: &str,
    ) -> Result<(crate::lifecycle::Continuation, Rc<Session>), String> {
        if self.inference.ended || !self.authority.verification() {
            return Err("sessions ended".into());
        }
        let live = self
            .sessions
            .iter()
            .find(|s| s.identity == session && !s.ended.get())
            .ok_or("no live clock-verification session")?;
        if !self.inference.limits.borrow().contains_key(session) {
            return Err("no issuer clock profile".into());
        }
        Ok((self.authority.clock_continuation()?, live.clone()))
    }
    /// Explicitly synthetic confirmed sessions; never compiled into the served build.
    #[cfg(any(test, feature = "tracer"))]
    pub fn synthetic_confirm_limits(&mut self, issuer_seconds: u64) -> Result<(), String> {
        let pair = current_pair(issuer_seconds);
        for session in self
            .sessions
            .iter()
            .map(|s| s.identity.clone())
            .collect::<Vec<_>>()
        {
            if self.inference.limits.borrow().contains_key(&session) {
                continue;
            }
            let confirmed = Confirmed {
                session: session.clone(),
                account_record: self.inference.account_record.ok_or("no fixture account")?,
                choice_generation: format!("synthetic-{session}"),
                profile: "inference-profile-fixture-v1".into(),
                cap_hundredths: 10,
                unit: "account units".into(),
                lifetime_seconds: 900,
            };
            let rate = crate::clock::Rate {
                numerator: 1,
                denominator: 1,
            };
            self.consume_confirmed_limits(
                confirmed,
                Observation {
                    sent: pair,
                    received: pair,
                    earliest: issuer_seconds,
                    latest: issuer_seconds,
                    minimum: rate,
                    maximum: rate,
                },
            )?;
        }
        Ok(())
    }
    /// Shared consumer seam. Confirmation construction and issuer profile admission are callers'
    /// responsibilities; replay never constructs this memory-only authority.
    pub fn consume_confirmed_limits(
        &mut self,
        confirmed: Confirmed,
        observation: Observation,
    ) -> Result<(), String> {
        if !cfg!(any(test, feature = "tracer")) {
            return Err("missing reviewed issuer profile".into());
        }
        self.authority.ordinary()?;
        if observation.minimum.numerator != observation.minimum.denominator
            || observation.maximum.numerator != observation.maximum.denominator
            || self.inference_choice_used(&confirmed.choice_generation)
            || confirmed.profile != "inference-profile-fixture-v1"
            || confirmed.unit != "account units"
            || self
                .inference
                .limits
                .borrow()
                .values()
                .any(|l| l.confirmed.choice_generation == confirmed.choice_generation)
        {
            return Err("unsupported profile/unit or reused choice generation".into());
        }
        if self.inference.account_record != Some(confirmed.account_record)
            || !self
                .sessions
                .iter()
                .any(|s| s.identity == confirmed.session)
            || self
                .inference
                .limits
                .borrow()
                .contains_key(&confirmed.session)
            || self.mint_attempted(&confirmed.session)
        {
            return Err("confirmed session/account differs or limits already consumed".into());
        }
        let session = confirmed.session.clone();
        self.inference
            .limits
            .borrow_mut()
            .insert(session, Limits::new(confirmed, observation)?);
        Ok(())
    }

    pub fn suspend_clocks(&self) {
        for limits in self.inference.limits.borrow_mut().values_mut() {
            limits.clock.suspend();
        }
    }

    pub fn check_session_authority(&self, session: &str, now: Pair) -> Result<(), String> {
        if self.inference.ended {
            return Err("sessions ended".into());
        }
        let live = self
            .sessions
            .iter()
            .find(|s| s.identity == session)
            .ok_or("no live session")?;
        if live.ended.get() {
            return Err("session ended".into());
        }
        if let Some(limits) = self.inference.limits.borrow_mut().get_mut(session) {
            let result = limits.check(now);
            if limits.ended.is_some() {
                #[cfg(target_arch = "wasm32")]
                if let Some(id) = self.session_revocation(session) {
                    crate::harness::inference::schedule_revocation(id);
                }
                live.ended.set(true);
                live.given.borrow_mut().clear();
                if !self.has_live_sessions() {
                    self.scans.clear();
                }
                #[cfg(target_arch = "wasm32")]
                crate::harness::goals::end_session(session);
            }
            result?;
        }
        self.authority.ordinary()?;
        self.scan_readiness()?;
        Ok(())
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) fn check_report_sessions(&self, report: &Value) -> Result<(), String> {
        if let Some(views) = report["sessions"].as_array() {
            for view in views {
                if view["session_state"] != "ended"
                    && view["inference_limits"]["state"] != "clock-withheld"
                    && let Some(identity) = view["identity"].as_str()
                {
                    self.check_session_authority(identity, current_pair(0))?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn has_live_sessions(&self) -> bool {
        self.sessions.iter().any(|session| !session.ended.get())
    }

    pub fn check_current_session(&self, session: &Session) -> Result<(), String> {
        if !self
            .sessions
            .iter()
            .any(|s| std::ptr::eq(s.as_ref(), session) && s.bound_set == session.bound_set)
        {
            return Err("stale session binding".into());
        }
        self.check_session_authority(&session.identity, self.session_pair(&session.identity))
    }

    pub(crate) fn session_pair(&self, session: &str) -> Pair {
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(limits) = self.inference.limits.borrow().get(session) {
            return limits.clock.last_pair();
        }
        let _ = session;
        current_pair(0)
    }

    pub fn limit_state(&self, session: &str) -> Value {
        self.inference.limits.borrow().get(session).map_or(Value::Null, |l| {
            json!({"confirmed":l.confirmed,"original_origin":l.origin,"original_expiry":l.expires,
                "observed_spend":l.spent.text(),
                "state":l.ended.as_deref().unwrap_or(if l.clock.is_valid() { "running" } else { "clock-withheld" })})
        })
    }
}

pub(crate) fn current_pair(fallback_seconds: u64) -> Pair {
    #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
    if let Some(pair) = SAMPLE.with(std::cell::Cell::get) {
        return pair;
    }
    #[cfg(target_arch = "wasm32")]
    {
        let global = js_sys::global();
        let monotonic = js_sys::Reflect::get(&global, &"performance".into())
            .ok()
            .and_then(|p| {
                js_sys::Reflect::get(&p, &"now".into()).ok().and_then(|f| {
                    use wasm_bindgen::JsCast;
                    f.dyn_into::<js_sys::Function>()
                        .ok()?
                        .call0(&p)
                        .ok()?
                        .as_f64()
                })
            });
        let ticks = |n: f64| -> Option<u64> {
            let value = n * 1000.;
            (value.is_finite() && value >= 0. && value < u64::MAX as f64)
                .then(|| value.floor() as u64)
        };
        let _ = fallback_seconds;
        Pair {
            monotonic: monotonic.and_then(ticks).unwrap_or(u64::MAX),
            wall: ticks(js_sys::Date::now()).unwrap_or(u64::MAX),
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        fallback_seconds.checked_mul(crate::clock::TICKS).map_or(
            Pair {
                monotonic: u64::MAX,
                wall: u64::MAX,
            },
            |ticks| Pair {
                monotonic: ticks,
                wall: ticks,
            },
        )
    }
}

#[cfg(all(feature = "tracer", target_arch = "wasm32"))]
thread_local! { static SAMPLE: std::cell::Cell<Option<Pair>> = const { std::cell::Cell::new(None) }; }
#[cfg(all(feature = "tracer", target_arch = "wasm32"))]
pub(crate) fn synthetic_clock_pair(pair: Option<Pair>) {
    SAMPLE.set(pair);
}

#[cfg(any(test, feature = "tracer"))]
impl<S: Storage> Store<S> {
    pub fn synthetic_session_transition(
        &self,
        session: &str,
        transition: &str,
    ) -> Result<(), String> {
        {
            let mut limits = self.inference.limits.borrow_mut();
            let limits = limits.get_mut(session).ok_or("no synthetic limits")?;
            match transition {
                "ended" => limits.ended = Some("session ended".into()),
                "exhausted" => limits
                    .spent
                    .add(&crate::inference_limits::Decimal::parse(&limits.cap())?),
                "uncertain" => limits.clock.suspend(),
                _ => return Err("synthetic transition".into()),
            }
        }
        let _ = self.check_session_authority(session, self.session_pair(session));
        Ok(())
    }
}
