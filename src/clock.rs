//! ARC-31a's issuer interval. Every calculation starts at the authenticated anchor.
use serde::{Deserialize, Serialize};

pub const TICKS: u64 = 1_000_000;
pub const MAX_UTC: u64 = 253_402_300_799;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pair {
    pub monotonic: u64,
    pub wall: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    pub numerator: u64,
    pub denominator: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub sent: Pair,
    pub received: Pair,
    pub earliest: u64,
    pub latest: u64,
    pub minimum: Rate,
    pub maximum: Rate,
}

#[derive(Clone, Debug)]
pub struct Clock {
    anchor: Observation,
    last: Pair,
    valid: bool,
}

fn discrepancy(a: Pair, b: Pair) -> bool {
    let wall = i128::from(b.wall) - i128::from(a.wall);
    let mono = i128::from(b.monotonic) - i128::from(a.monotonic);
    (wall - mono).abs() > i128::from(5 * TICKS) || mono < 0
}

impl Clock {
    pub(crate) fn observation(&self) -> Observation {
        self.anchor.clone()
    }
    pub fn is_valid(&self) -> bool {
        self.valid
    }
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) fn last_pair(&self) -> Pair {
        self.last
    }
    pub fn new(anchor: Observation) -> Result<Self, String> {
        let Observation {
            sent,
            received,
            earliest,
            latest,
            minimum,
            maximum,
        } = &anchor;
        if sent.monotonic == u64::MAX
            || received.monotonic == u64::MAX
            || sent.wall == u64::MAX
            || received.wall == u64::MAX
            || sent.monotonic > received.monotonic
            || earliest > latest
            || *earliest == 0
            || *latest > MAX_UTC
            || minimum.numerator == 0
            || minimum.denominator == 0
            || maximum.numerator == 0
            || maximum.denominator == 0
            || u128::from(minimum.numerator) * u128::from(maximum.denominator)
                > u128::from(maximum.numerator) * u128::from(minimum.denominator)
            || discrepancy(*sent, *received)
        {
            return Err("invalid issuer clock evidence".into());
        }
        Ok(Self {
            last: *received,
            anchor,
            valid: true,
        })
    }

    pub fn suspend(&mut self) {
        self.valid = false;
    }

    pub fn interval(&mut self, pair: Pair) -> Result<(u64, u64), String> {
        if !self.valid
            || pair.monotonic == u64::MAX
            || pair.wall == u64::MAX
            || discrepancy(self.anchor.received, pair)
            || discrepancy(self.last, pair)
        {
            self.valid = false;
            return Err("clock uncertain; verification required".into());
        }
        let result = (|| {
            fn bound(time: u64, elapsed: u64, rate: Rate, ceil: bool) -> Option<u64> {
                let denominator = u128::from(rate.denominator).checked_mul(u128::from(TICKS))?;
                let numerator = u128::from(time)
                    .checked_mul(denominator)?
                    .checked_add(u128::from(elapsed).checked_mul(u128::from(rate.numerator))?)?;
                let value = (numerator / denominator)
                    .checked_add(u128::from(ceil && numerator % denominator != 0))?;
                let value = u64::try_from(value).ok()?;
                (value > 0 && value <= MAX_UTC).then_some(value)
            }
            Some((
                bound(
                    self.anchor.earliest,
                    pair.monotonic.checked_sub(self.anchor.received.monotonic)?,
                    self.anchor.minimum,
                    false,
                )?,
                bound(
                    self.anchor.latest,
                    pair.monotonic.checked_sub(self.anchor.sent.monotonic)?,
                    self.anchor.maximum,
                    true,
                )?,
            ))
        })();
        match result {
            Some((l, u)) if l <= u => {
                self.last = pair;
                Ok((l, u))
            }
            _ => {
                self.valid = false;
                Err("clock evidence out of range".into())
            }
        }
    }

    pub fn repair(&mut self, observation: Observation) -> Result<(), String> {
        let mut fresh = match Self::new(observation.clone()) {
            Ok(fresh) => fresh,
            Err(why) => {
                self.valid = false;
                return Err(why);
            }
        };
        if observation.received.monotonic < self.last.monotonic {
            if self.valid {
                let mut previous = self.clone();
                if let (Ok(old), Ok(new)) =
                    (previous.interval(self.last), fresh.interval(self.last))
                    && (new.0 > old.1 || old.0 > new.1)
                {
                    self.valid = false;
                    return Err("contradictory issuer clock observations".into());
                }
            }
            return Err("superseded issuer clock observation".into());
        }
        let new = fresh.interval(observation.received)?;
        if self.valid
            && let Ok(old) = self.interval(observation.received)
            && (new.0 > old.1 || old.0 > new.1)
        {
            self.valid = false;
            return Err("contradictory issuer clock observations".into());
        }
        *self = fresh;
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    fn pair(m: u64, wall_offset: i64) -> Pair {
        Pair {
            monotonic: m * TICKS,
            wall: (1000_i64 + m as i64 + wall_offset) as u64 * TICKS,
        }
    }
    fn clock() -> Clock {
        Clock::new(Observation {
            sent: pair(0, 0),
            received: pair(2, 0),
            earliest: 100,
            latest: 100,
            minimum: Rate {
                numerator: 1,
                denominator: 2,
            },
            maximum: Rate {
                numerator: 3,
                denominator: 2,
            },
        })
        .unwrap()
    }
    #[test]
    fn exact_outward_rounding_and_old_wide_observations() {
        let mut c = clock();
        assert_eq!(c.interval(pair(3, 0)).unwrap(), (100, 105));
        assert_eq!(c.interval(pair(20, 0)).unwrap(), (109, 130));
        assert_eq!(c.interval(pair(20, 0)).unwrap(), (109, 130));
    }
    #[test]
    fn independent_anchor_and_previous_pair_checks_both_directions() {
        for sign in [-1, 1] {
            let mut c = clock();
            assert!(c.interval(pair(20, sign * 5)).is_ok());
            assert!(c.interval(pair(21, sign * 6)).is_err(), "anchor baseline");
            let mut c = clock();
            assert!(c.interval(pair(20, -sign * 5)).is_ok());
            assert!(
                c.interval(pair(21, sign)).is_err(),
                "previous pair independently"
            );
            let mut c = clock();
            assert!(c.interval(pair(20, -sign * 5)).is_ok());
            assert!(c.interval(pair(21, 0)).is_ok(), "equality five is eligible");
        }
    }
    #[test]
    fn suspension_repair_rollback_overflow_and_contradictions() {
        let mut c = clock();
        c.suspend();
        assert!(c.interval(pair(3, 0)).is_err());
        let fresh = clock().anchor;
        c.repair(fresh.clone()).unwrap();
        assert!(c.interval(pair(3, 0)).is_ok());
        let mut bad = fresh;
        bad.earliest = 500;
        bad.latest = 500;
        bad.sent = pair(4, 0);
        bad.received = pair(5, 0);
        assert!(c.repair(bad).is_err());
        assert!(clock().interval(pair(1, 0)).is_err());
        let mut c = clock();
        c.anchor.latest = MAX_UTC;
        assert!(c.interval(pair(3, 0)).is_err());
    }
    #[test]
    fn reordered_verification_never_replaces_newer_or_accepts_contradiction() {
        let original = clock().observation();
        let mut latest = original.clone();
        latest.sent = pair(10, 0);
        latest.received = pair(11, 0);
        latest.earliest = 105;
        latest.latest = 110;
        let mut c = Clock::new(latest.clone()).unwrap();
        c.interval(pair(12, 0)).unwrap();
        assert!(
            c.repair(original.clone())
                .unwrap_err()
                .contains("superseded")
        );
        assert!(c.is_valid());
        assert_eq!(c.observation(), latest);
        let mut contradictory = original;
        contradictory.earliest = 500;
        contradictory.latest = 500;
        assert!(
            c.repair(contradictory)
                .unwrap_err()
                .contains("contradictory")
        );
        assert!(!c.is_valid());
        assert_eq!(c.observation(), latest);
    }
}
