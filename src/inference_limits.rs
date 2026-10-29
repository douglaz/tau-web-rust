//! Immutable procured-session limits and exact observed accounting, consumed by lifecycle.
use crate::clock::{Clock, MAX_UTC, Observation, Pair};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Confirmed {
    pub session: String,
    pub account_record: u64,
    pub choice_generation: String,
    pub profile: String,
    pub cap_hundredths: u64,
    pub unit: String,
    pub lifetime_seconds: u64,
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::clock::{Rate, TICKS};
    fn pair(seconds: u64) -> Pair {
        Pair {
            monotonic: seconds * TICKS,
            wall: seconds * TICKS,
        }
    }
    fn observation(seconds: u64) -> Observation {
        let rate = Rate {
            numerator: 1,
            denominator: 1,
        };
        Observation {
            sent: pair(seconds),
            received: pair(seconds),
            earliest: seconds,
            latest: seconds,
            minimum: rate,
            maximum: rate,
        }
    }
    fn limits() -> Limits {
        Limits::new(
            Confirmed {
                session: "synthetic-session".into(),
                account_record: 1,
                choice_generation: "synthetic-choice".into(),
                profile: "inference-profile-fixture-v1".into(),
                cap_hundredths: 10,
                unit: "account units".into(),
                lifetime_seconds: 900,
            },
            observation(100),
        )
        .unwrap()
    }
    #[test]
    fn original_limits_expiry_equality_and_uncertain_repair_do_not_reset() {
        for (now, eligible) in [(999, true), (1000, false), (1001, false)] {
            let mut l = limits();
            assert_eq!(l.authorize_mint(pair(100)).unwrap(), ("0.10".into(), 1000));
            let original = l.confirmed.clone();
            l.spent
                .add(&Decimal::parse("0.000000123456789012345678901234567890").unwrap());
            let spent = l.spent.clone();
            l.clock.suspend();
            assert!(l.check(pair(200)).is_err());
            l.clock.repair(observation(201)).unwrap();
            assert_eq!(l.confirmed, original);
            assert_eq!(l.expires, Some(1000));
            assert_eq!(l.spent, spent);
            assert_eq!(l.check(pair(now)).is_ok(), eligible);
            if !eligible {
                l.clock.repair(observation(now + 1)).unwrap();
                assert!(
                    l.check(pair(now + 1)).is_err(),
                    "clock repair cannot revive end"
                );
            }
            assert!(
                l.authorize_mint(pair(now)).is_err(),
                "one original origin only"
            );
        }
    }
    #[test]
    fn finer_precision_and_many_concurrent_charges_share_one_exact_cap() {
        let mut l = limits();
        l.authorize_mint(pair(100)).unwrap();
        l.spent
            .add(&Decimal::parse("0.099999999999999999999999999999999999").unwrap());
        assert!(l.check(pair(101)).is_ok());
        l.spent
            .add(&Decimal::parse("0.000000000000000000000000000000000001").unwrap());
        assert_eq!(l.spent.text(), "0.1");
        assert_eq!(l.check(pair(102)), Err("session cap exhausted".into()));
        let mut sum = Decimal::default();
        for _ in 0..10 {
            sum.add(&Decimal::parse("1e-2").unwrap());
        }
        assert_eq!(sum, Decimal::parse("0.10").unwrap());
        for bad in ["-1", "NaN", "1e1000000", ".1", "1.", "", "+1"] {
            assert!(Decimal::parse(bad).is_err());
        }
    }
    #[test]
    fn checked_origin_lifetime_and_utc_bounds() {
        let mut l = limits();
        l.clock = Clock::new(observation(MAX_UTC - 899)).unwrap();
        assert!(l.authorize_mint(pair(MAX_UTC - 899)).is_err());
        let mut l = limits();
        l.clock = Clock::new(observation(MAX_UTC - 900)).unwrap();
        assert_eq!(l.authorize_mint(pair(MAX_UTC - 900)).unwrap().1, MAX_UTC);
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    pub confirmed: Confirmed,
    pub clock: Clock,
    pub origin: Option<u64>,
    pub expires: Option<u64>,
    pub ended: Option<String>,
    pub spent: Decimal,
    pub evidence: Option<OriginEvidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginEvidence {
    pub confirmed: Confirmed,
    pub origin: u64,
    pub authorized_at: Pair,
    pub clock: Observation,
}

/// Arbitrary precision nonnegative decimal; no binary float enters accounting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decimal {
    digits: Vec<u8>,
    scale: usize,
}
impl Decimal {
    pub fn is_zero(&self) -> bool {
        self.digits.is_empty()
    }
    pub fn text(&self) -> String {
        let mut digits: String = self.digits.iter().map(|n| char::from(b'0' + n)).collect();
        while digits.len() <= self.scale {
            digits.insert(0, '0');
        }
        if self.scale > 0 {
            digits.insert(digits.len() - self.scale, '.');
        }
        if digits.is_empty() {
            digits.push('0');
        }
        digits
    }
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut parts = text.split(['e', 'E']);
        let mantissa = parts.next().ok_or("invalid spend")?;
        let exponent: i32 = parts
            .next()
            .map(str::parse)
            .transpose()
            .map_err(|_| "invalid spend exponent")?
            .unwrap_or(0);
        if parts.next().is_some() {
            return Err("invalid spend".into());
        }
        let mut fraction = None;
        let mut digits = Vec::new();
        for b in mantissa.bytes() {
            if b == b'.' && fraction.is_none() {
                fraction = Some(0usize);
            } else if b.is_ascii_digit() {
                digits.push(b - b'0');
                if let Some(n) = &mut fraction {
                    *n += 1;
                }
            } else {
                return Err("invalid nonnegative spend".into());
            }
        }
        if digits.is_empty() || mantissa.starts_with('.') || mantissa.ends_with('.') {
            return Err("invalid spend".into());
        }
        let scale =
            i64::try_from(fraction.unwrap_or(0)).map_err(|_| "spend scale")? - i64::from(exponent);
        // Bound resource use, refusing unsupported evidence rather than rounding it.
        if scale.unsigned_abs() > 10000 {
            return Err("unsupported spend precision".into());
        }
        if scale < 0 {
            digits.extend(std::iter::repeat_n(0, (-scale) as usize));
        }
        let mut value = Self {
            digits,
            scale: scale.max(0) as usize,
        };
        value.normalize();
        Ok(value)
    }
    fn normalize(&mut self) {
        while self.scale > 0 && self.digits.last() == Some(&0) {
            self.digits.pop();
            self.scale -= 1;
        }
        let first = self
            .digits
            .iter()
            .position(|n| *n != 0)
            .unwrap_or(self.digits.len());
        self.digits.drain(..first);
    }
    fn aligned(&self, scale: usize) -> Vec<u8> {
        let mut digits = self.digits.clone();
        digits.extend(std::iter::repeat_n(0, scale - self.scale));
        digits
    }
    pub fn add(&mut self, other: &Self) {
        let scale = self.scale.max(other.scale);
        let mut a = self.aligned(scale);
        a.reverse();
        let mut b = other.aligned(scale);
        b.reverse();
        let mut result = Vec::new();
        let mut carry = 0;
        for i in 0..a.len().max(b.len()) {
            let n = a.get(i).copied().unwrap_or(0) + b.get(i).copied().unwrap_or(0) + carry;
            result.push(n % 10);
            carry = n / 10;
        }
        if carry > 0 {
            result.push(carry);
        }
        result.reverse();
        *self = Self {
            digits: result,
            scale,
        };
        self.normalize();
    }
    pub fn at_least(&self, other: &Self) -> bool {
        let scale = self.scale.max(other.scale);
        let strip = |v: Vec<u8>| {
            let i = v.iter().position(|n| *n != 0).unwrap_or(v.len());
            v[i..].to_vec()
        };
        let a = strip(self.aligned(scale));
        let b = strip(other.aligned(scale));
        a.len() > b.len() || (a.len() == b.len() && a >= b)
    }
}

impl OriginEvidence {
    pub fn validate(
        &self,
        session: &str,
        account_record: u64,
        cap: &str,
        expires: u64,
    ) -> Result<(), String> {
        let limits = Limits::new(self.confirmed.clone(), self.clock.clone())?;
        let mut clock = Clock::new(self.clock.clone())?;
        let (lower, upper) = clock.interval(self.authorized_at)?;
        if self.confirmed.session != session
            || self.confirmed.account_record != account_record
            || self.origin != lower
            || limits.cap() != cap
            || upper >= expires
            || self.origin.checked_add(self.confirmed.lifetime_seconds) != Some(expires)
            || expires > MAX_UTC
        {
            return Err("mint clock/confirmation evidence differs from original limits".into());
        }
        Ok(())
    }
}

impl Limits {
    pub fn new(confirmed: Confirmed, observation: Observation) -> Result<Self, String> {
        if confirmed.session.is_empty()
            || confirmed.choice_generation.is_empty()
            || confirmed.profile.is_empty()
            || confirmed.unit.is_empty()
            || !(1..=10000).contains(&confirmed.cap_hundredths)
            || !(60..=86400).contains(&confirmed.lifetime_seconds)
            || !confirmed.lifetime_seconds.is_multiple_of(60)
        {
            return Err("unsupported confirmed limits".into());
        }
        Ok(Self {
            confirmed,
            clock: Clock::new(observation)?,
            origin: None,
            expires: None,
            ended: None,
            spent: Decimal::default(),
            evidence: None,
        })
    }
    pub fn cap(&self) -> String {
        format!(
            "{}.{:02}",
            self.confirmed.cap_hundredths / 100,
            self.confirmed.cap_hundredths % 100
        )
    }
    pub fn authorize_mint(&mut self, now: Pair) -> Result<(String, u64), String> {
        self.check(now)?;
        if self.origin.is_some() {
            return Err("original mint limits already fixed".into());
        }
        let (origin, upper) = self.clock.interval(now)?;
        let expires = origin
            .checked_add(self.confirmed.lifetime_seconds)
            .filter(|v| *v <= MAX_UTC)
            .ok_or("original expiry out of range")?;
        if upper >= expires {
            return Err("original lifetime consumed before intent".into());
        }
        self.origin = Some(origin);
        self.expires = Some(expires);
        self.evidence = Some(OriginEvidence {
            confirmed: self.confirmed.clone(),
            origin,
            authorized_at: now,
            clock: self.clock.observation(),
        });
        Ok((self.cap(), expires))
    }
    pub fn check(&mut self, now: Pair) -> Result<(), String> {
        if let Some(why) = &self.ended {
            return Err(why.clone());
        }
        if self.spent.at_least(&Decimal::parse(&self.cap())?) {
            self.ended = Some("session cap exhausted".into());
            return Err("session cap exhausted".into());
        }
        let (_, upper) = self.clock.interval(now)?;
        if self.expires.is_some_and(|expiry| upper >= expiry) {
            self.ended = Some("session expired".into());
            return Err("session expired".into());
        }
        Ok(())
    }
}
