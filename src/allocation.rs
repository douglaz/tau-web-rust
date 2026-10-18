//! Allocation (`STA-22`, `STA-22b`): the allocation metadata the journal owns, and the one core
//! every allocation event goes through. Per role family — machines, passes, handoffs — a
//! monotonic counter issues the next unused index; an issued index stays consumed, and an entry
//! that failed or was destroyed is a tombstone, never revived and never issued again. Indices run
//! from 0 through 2^31−1 with no wraparound (credential format v1, "Seed and child keys": "a
//! failed reserved allocation remains consumed").
//!
//! Pure and synchronous, on every target: no I/O, no seed and no key material. The seed is known
//! by its identifier alone. The local store (`src/store.rs`) journals each event before it is
//! applied (`STA-3`) and replays the journal through this core; the companion comparison
//! (`comparison`, a host test) drives the same core with the allocation witness file's traces.
//!
//! An imported seed keeps the listed identities and refuses every allocation, in every family,
//! until a Replace (`STA-22b`). A generated seed needs its `STA-23` ceremony record first. Restore
//! is an ordinary event here; the durable import path that would journal one is twr-ggw.27's.

use crate::seed::{MAX_INDEX, VERSION};
use serde::{Deserialize, Serialize};

#[cfg(all(test, not(target_arch = "wasm32")))]
mod comparison;

/// A role family, each with its own counter. Roles 0–2 share the machine index; role 3 takes
/// a pass index and role 4 a handoff index (`STA-22`, credential format v1's role table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    Machines,
    Passes,
    Handoffs,
}

impl Family {
    pub const ALL: [Family; 3] = [Family::Machines, Family::Passes, Family::Handoffs];
}

/// One allocated identity: seed identifier, derivation version, family and index. Every
/// reservation records the version and the seed it derives under (`STA-22a`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub seed: String,
    pub derivation_version: u32,
    pub family: Family,
    pub index: u32,
}

/// An entry's status. `Failed` and `Destroyed` are `STA-22b`'s tombstones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Reserved,
    Created,
    Failed,
    Destroyed,
}

/// An allocated entry: its identity and its status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub identity: Identity,
    pub status: Status,
}

/// The next unused index of each family. 2^31 is a family with no index left.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NextUnused {
    pub machines: u32,
    pub passes: u32,
    pub handoffs: u32,
}

impl NextUnused {
    pub fn get(&self, family: Family) -> u32 {
        match family {
            Family::Machines => self.machines,
            Family::Passes => self.passes,
            Family::Handoffs => self.handoffs,
        }
    }

    fn get_mut(&mut self, family: Family) -> &mut u32 {
        match family {
            Family::Machines => &mut self.machines,
            Family::Passes => &mut self.passes,
            Family::Handoffs => &mut self.handoffs,
        }
    }
}

/// `STA-22b`'s allocation metadata: the seed identifier, the derivation version, the next unused
/// index of each family, the allocated entries oldest first, the seed-backup ceremony record,
/// and whether the seed was imported with no Replace since. It changes only through [`apply`],
/// and its export is itself.
///
/// [`apply`]: Metadata::apply
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    seed: String,
    derivation_version: u32,
    next_unused: NextUnused,
    entries: Vec<Entry>,
    restored_from_import: bool,
    seed_backup: Option<Completion>,
}

/// The recorded completion of the seed-backup ceremony (`STA-23`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Completion {
    FullReentry,
    Skipped,
}

/// An allocation event, as the store journals it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Event {
    /// A completion for the named seed, applied after its durable append (`STA-23`).
    SeedBackup {
        seed: String,
        completion: Completion,
    },
    /// A family's next unused index, reserved before any external effect (`STA-22b`).
    Reserve(Identity),
    /// The adapter's observations of a reserved or created identity.
    Created(Identity),
    Failed(Identity),
    Destroyed(Identity),
    /// Imported metadata, including its ceremony record (`STA-22b`, `STA-17`'s Restore).
    Restore(Metadata),
    /// A freshly generated seed, by its identifier (`STA-17`'s Replace).
    Replace {
        seed: String,
    },
}

/// Why an event was not applied. A refused event changes nothing.
#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    /// `STA-22b`: every imported seed "MUST NOT allocate new ones".
    Restored,
    /// The current seed has no journaled ceremony record (`STA-22b`).
    BackupMissing,
    /// A ceremony completion names another seed.
    WrongSeed,
    /// The family has issued 2^31−1 and allocates nothing more: indices never wrap.
    Exhausted(Family),
    /// `STA-22a`: "Unknown versions are refused".
    UnknownVersion(u32),
    /// A reservation that is not the family's next unused index under the current seed: a
    /// recorded identity, a skipped index or another seed's.
    NotNext(Identity),
    /// An observation the metadata cannot apply: `created` or `failed` for an identity that is
    /// not reserved, `destroyed` for one that is not created.
    Inapplicable(Identity),
    /// A Replace to the current seed or one an entry already names: it would issue a recorded
    /// identity again.
    NotFresh,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Refusal::Restored => write!(f, "a restored seed allocates nothing until a Replace"),
            Refusal::BackupMissing => {
                write!(f, "the seed-backup ceremony is not recorded for this seed")
            }
            Refusal::WrongSeed => write!(f, "the seed-backup completion names another seed"),
            Refusal::Exhausted(family) => write!(f, "the {family:?} family has no index left"),
            Refusal::UnknownVersion(version) => write!(f, "unknown derivation version {version}"),
            Refusal::NotNext(identity) => write!(
                f,
                "{:?} {} is not the next unused index under this seed",
                identity.family, identity.index
            ),
            Refusal::Inapplicable(identity) => write!(
                f,
                "the observation does not apply to {:?} {}",
                identity.family, identity.index
            ),
            Refusal::NotFresh => write!(f, "a Replace needs a freshly generated seed"),
        }
    }
}

impl Metadata {
    /// The metadata of a freshly generated seed: nothing allocated.
    pub fn new(seed: String) -> Metadata {
        Metadata {
            seed,
            derivation_version: VERSION,
            next_unused: NextUnused::default(),
            entries: Vec::new(),
            restored_from_import: false,
            seed_backup: None,
        }
    }

    pub fn seed(&self) -> &str {
        &self.seed
    }

    pub fn derivation_version(&self) -> u32 {
        self.derivation_version
    }

    pub fn next_unused(&self) -> NextUnused {
        self.next_unused
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn restored_from_import(&self) -> bool {
        self.restored_from_import
    }

    pub fn seed_backup(&self) -> Option<Completion> {
        self.seed_backup
    }

    /// The export: the whole metadata (`STA-22b`). The sheet's export time and journal sequence
    /// are twr-ggw.27's.
    pub fn export(&self) -> Metadata {
        self.clone()
    }

    /// The identity a reservation of `family` would take now, changing nothing: the caller
    /// journals `Event::Reserve` with it, then applies it.
    pub fn issue(&self, family: Family) -> Result<Identity, Refusal> {
        if self.restored_from_import {
            return Err(Refusal::Restored);
        }
        if self.seed_backup.is_none() {
            return Err(Refusal::BackupMissing);
        }
        let index = self.next_unused.get(family);
        if index > MAX_INDEX {
            return Err(Refusal::Exhausted(family));
        }
        Ok(Identity {
            seed: self.seed.clone(),
            derivation_version: self.derivation_version,
            family,
            index,
        })
    }

    /// Applies `event` wholly, or refuses it and changes nothing.
    pub fn apply(&mut self, event: &Event) -> Result<(), Refusal> {
        match event {
            Event::SeedBackup { seed, completion } => {
                if *seed != self.seed {
                    return Err(Refusal::WrongSeed);
                }
                self.seed_backup = Some(*completion);
            }
            Event::Reserve(identity) => {
                if identity.derivation_version != VERSION {
                    return Err(Refusal::UnknownVersion(identity.derivation_version));
                }
                if *identity != self.issue(identity.family)? {
                    return Err(Refusal::NotNext(identity.clone()));
                }
                *self.next_unused.get_mut(identity.family) = identity.index + 1;
                self.entries.push(Entry {
                    identity: identity.clone(),
                    status: Status::Reserved,
                });
            }
            Event::Created(identity) => {
                self.observe(identity, Status::Reserved, Status::Created)?
            }
            Event::Failed(identity) => self.observe(identity, Status::Reserved, Status::Failed)?,
            Event::Destroyed(identity) => {
                self.observe(identity, Status::Created, Status::Destroyed)?
            }
            Event::Restore(export) => {
                let mut versions = std::iter::once(export.derivation_version)
                    .chain(export.entries.iter().map(|e| e.identity.derivation_version));
                if let Some(version) = versions.find(|v| *v != VERSION) {
                    return Err(Refusal::UnknownVersion(version));
                }
                *self = Metadata {
                    restored_from_import: true,
                    ..export.clone()
                };
            }
            Event::Replace { seed } => {
                if *seed == self.seed || self.entries.iter().any(|e| e.identity.seed == *seed) {
                    return Err(Refusal::NotFresh);
                }
                // The fresh seed has derived nothing, so each family starts at 0 under it; the
                // old entries are retained (`STA-22b`), under the old seed's identifier.
                self.seed = seed.clone();
                self.next_unused = NextUnused::default();
                self.restored_from_import = false;
                self.seed_backup = None;
            }
        }
        Ok(())
    }

    /// Moves the entry with exactly this identity from `from` to `to`.
    fn observe(&mut self, identity: &Identity, from: Status, to: Status) -> Result<(), Refusal> {
        match self.entries.iter_mut().find(|e| e.identity == *identity) {
            Some(entry) if entry.status == from => {
                entry.status = to;
                Ok(())
            }
            _ => Err(Refusal::Inapplicable(identity.clone())),
        }
    }
}

/// The core's own tests: `STA-22b`'s counters, tombstones, exhaustion and restriction. The store's
/// journaling of it is tested in `src/store.rs`, and the companion comparison in `comparison`.
#[cfg(all(test, not(target_arch = "wasm32")))]
pub(crate) mod tests {
    use super::*;
    use crate::seed::Seed;

    fn recorded(seed: String) -> Metadata {
        let mut core = Metadata::new(seed.clone());
        core.apply(&Event::SeedBackup {
            seed,
            completion: Completion::FullReentry,
        })
        .unwrap();
        core
    }

    #[test]
    fn each_family_needs_its_current_seeds_ceremony_record() {
        let mut core = Metadata::new("s".into());
        let before = core.clone();
        for family in Family::ALL {
            assert_eq!(core.issue(family), Err(Refusal::BackupMissing));
            assert_eq!(
                core.apply(&Event::Reserve(Identity {
                    seed: "s".into(),
                    derivation_version: VERSION,
                    family,
                    index: 0,
                })),
                Err(Refusal::BackupMissing)
            );
            assert_eq!(core, before);
        }
        assert_eq!(
            core.apply(&Event::SeedBackup {
                seed: "other".into(),
                completion: Completion::Skipped,
            }),
            Err(Refusal::WrongSeed)
        );
        assert_eq!(core, before);
        for completion in [Completion::FullReentry, Completion::Skipped] {
            core.apply(&Event::SeedBackup {
                seed: "s".into(),
                completion,
            })
            .unwrap();
            assert_eq!(core.seed_backup(), Some(completion));
            for family in Family::ALL {
                reserve(&mut core, family).unwrap();
            }
        }
    }

    #[test]
    fn restore_copies_the_record_and_every_import_refuses_allocation() {
        for completion in [
            None,
            Some(Completion::FullReentry),
            Some(Completion::Skipped),
        ] {
            let mut original = Metadata::new("s".into());
            if let Some(completion) = completion {
                original
                    .apply(&Event::SeedBackup {
                        seed: "s".into(),
                        completion,
                    })
                    .unwrap();
            }
            let export = original.export();
            let mut core = Metadata::new("other".into());
            core.apply(&Event::Restore(export)).unwrap();
            assert_eq!(core.seed_backup(), completion);
            for family in Family::ALL {
                assert_eq!(reserve(&mut core, family), Err(Refusal::Restored));
            }
            // A completion can be recorded after Restore, but cannot lift the import bar.
            core.apply(&Event::SeedBackup {
                seed: "s".into(),
                completion: Completion::Skipped,
            })
            .unwrap();
            for family in Family::ALL {
                assert_eq!(reserve(&mut core, family), Err(Refusal::Restored));
            }
        }
    }

    #[test]
    fn replace_clears_the_record_and_generation_is_never_gated() {
        for completion in [
            None,
            Some(Completion::FullReentry),
            Some(Completion::Skipped),
        ] {
            let mut core = Metadata::new("s".into());
            if let Some(completion) = completion {
                core.apply(&Event::SeedBackup {
                    seed: "s".into(),
                    completion,
                })
                .unwrap();
            }
            core.apply(&Event::Replace {
                seed: "fresh".into(),
            })
            .unwrap();
            assert_eq!(core.seed_backup(), None);
            for family in Family::ALL {
                assert_eq!(reserve(&mut core, family), Err(Refusal::BackupMissing));
            }
            core.apply(&Event::SeedBackup {
                seed: "fresh".into(),
                completion: Completion::Skipped,
            })
            .unwrap();
            for family in Family::ALL {
                assert_eq!(reserve(&mut core, family).unwrap().index, 0);
            }
        }
    }

    /// The public keys of every role at `identity`: roles 0–2 for a machine, 3 for a pass, 4 for
    /// a handoff.
    pub(crate) fn keys(seed: &Seed, identity: &Identity) -> Vec<[u8; 32]> {
        let (v, i) = (identity.derivation_version, identity.index);
        match identity.family {
            Family::Machines => vec![
                seed.ssh_client_key(v, i).unwrap().public_key(),
                seed.attest_sender_key(v, i).unwrap().public_key(),
                seed.attest_recipient_key(v, i).unwrap().public_key(),
            ],
            Family::Passes => vec![seed.relay_key(v, i).unwrap().public_key()],
            Family::Handoffs => vec![seed.post_harness_credential(v, i).unwrap().public_key()],
        }
    }

    fn reserve(core: &mut Metadata, family: Family) -> Result<Identity, Refusal> {
        let identity = core.issue(family)?;
        core.apply(&Event::Reserve(identity.clone()))?;
        Ok(identity)
    }

    fn status(core: &Metadata, identity: &Identity) -> Option<Status> {
        core.entries()
            .iter()
            .find(|e| e.identity == *identity)
            .map(|e| e.status)
    }

    #[test]
    fn each_family_has_its_own_monotonic_counter() {
        let mut core = recorded("s".into());
        for expected in 0..3 {
            assert_eq!(
                reserve(&mut core, Family::Machines).unwrap().index,
                expected
            );
        }
        assert_eq!(reserve(&mut core, Family::Passes).unwrap().index, 0);
        assert_eq!(reserve(&mut core, Family::Handoffs).unwrap().index, 0);
        assert_eq!(reserve(&mut core, Family::Passes).unwrap().index, 1);
        assert_eq!(
            core.next_unused(),
            NextUnused {
                machines: 3,
                passes: 2,
                handoffs: 1
            }
        );
        assert_eq!(core.entries().len(), 6);
        assert!(core.entries().iter().all(|e| e.status == Status::Reserved
            && e.identity.seed == "s"
            && e.identity.derivation_version == VERSION));
    }

    /// `CNF-72`: no event puts a second machine at a recorded identity. A reservation must be
    /// exactly the next unused index, and an observation never revives a tombstone.
    #[test]
    fn a_recorded_identity_is_never_reserved_or_revived() {
        let mut core = recorded("s".into());
        let first = reserve(&mut core, Family::Machines).unwrap();
        let before = core.clone();
        for crafted in [
            first.clone(),
            Identity {
                index: 2,
                ..first.clone()
            },
            Identity {
                seed: "other".into(),
                index: 1,
                ..first.clone()
            },
        ] {
            assert_eq!(
                core.apply(&Event::Reserve(crafted.clone())),
                Err(Refusal::NotNext(crafted))
            );
            assert_eq!(core, before);
        }
        // Created once; a second creation changes nothing.
        core.apply(&Event::Created(first.clone())).unwrap();
        let created = core.clone();
        assert!(core.apply(&Event::Created(first.clone())).is_err());
        assert!(core.apply(&Event::Failed(first.clone())).is_err());
        assert_eq!(core, created);
        // Destroyed: a tombstone. Neither observation revives it.
        core.apply(&Event::Destroyed(first.clone())).unwrap();
        let destroyed = core.clone();
        for event in [
            Event::Created(first.clone()),
            Event::Failed(first.clone()),
            Event::Destroyed(first.clone()),
        ] {
            assert_eq!(
                core.apply(&event),
                Err(Refusal::Inapplicable(first.clone()))
            );
            assert_eq!(core, destroyed);
        }
        // A failed reservation: a tombstone that no creation revives.
        let second = reserve(&mut core, Family::Machines).unwrap();
        core.apply(&Event::Failed(second.clone())).unwrap();
        let failed = core.clone();
        assert!(core.apply(&Event::Created(second.clone())).is_err());
        assert!(core.apply(&Event::Destroyed(second.clone())).is_err());
        assert_eq!(core, failed);
        assert_eq!(status(&core, &second), Some(Status::Failed));
        // An observation of an identity never reserved changes nothing.
        let never = Identity {
            index: 9,
            ..first.clone()
        };
        assert!(core.apply(&Event::Created(never)).is_err());
        assert_eq!(core, failed);
    }

    /// `STA-22b`: a failed or destroyed allocation keeps its index for ever.
    #[test]
    fn a_tombstoned_index_is_never_issued_again() {
        let mut core = recorded("s".into());
        let failed = reserve(&mut core, Family::Machines).unwrap();
        core.apply(&Event::Failed(failed.clone())).unwrap();
        let destroyed = reserve(&mut core, Family::Machines).unwrap();
        core.apply(&Event::Created(destroyed.clone())).unwrap();
        core.apply(&Event::Destroyed(destroyed.clone())).unwrap();
        let next = reserve(&mut core, Family::Machines).unwrap();
        assert_eq!((failed.index, destroyed.index, next.index), (0, 1, 2));
        assert_eq!(core.issue(Family::Machines).unwrap().index, 3);
    }

    #[test]
    fn a_family_at_2_to_the_31_minus_1_issues_it_then_refuses_and_never_wraps() {
        let mut core = recorded("s".into());
        core.next_unused.passes = MAX_INDEX;
        assert_eq!(reserve(&mut core, Family::Passes).unwrap().index, MAX_INDEX);
        assert_eq!(core.next_unused().passes, 1 << 31);
        let exhausted = core.clone();
        assert_eq!(
            reserve(&mut core, Family::Passes),
            Err(Refusal::Exhausted(Family::Passes))
        );
        let past = Identity {
            seed: "s".into(),
            derivation_version: VERSION,
            family: Family::Passes,
            index: 1 << 31,
        };
        assert!(core.apply(&Event::Reserve(past)).is_err());
        let wrapped = Identity {
            seed: "s".into(),
            derivation_version: VERSION,
            family: Family::Passes,
            index: 0,
        };
        assert!(core.apply(&Event::Reserve(wrapped)).is_err());
        assert_eq!(core, exhausted);
        assert_eq!(reserve(&mut core, Family::Machines).unwrap().index, 0);
    }

    #[test]
    fn an_unknown_derivation_version_is_refused() {
        let mut core = recorded("s".into());
        let mut identity = core.issue(Family::Handoffs).unwrap();
        identity.derivation_version = 2;
        assert_eq!(
            core.apply(&Event::Reserve(identity)),
            Err(Refusal::UnknownVersion(2))
        );
        let mut export = core.export();
        export.derivation_version = 2;
        assert_eq!(
            core.apply(&Event::Restore(export)),
            Err(Refusal::UnknownVersion(2))
        );
        assert_eq!(core, recorded("s".into()));
    }

    /// Criterion 3 on the core (`STA-22b`, `STA-17`'s Restore): the seed's mnemonic imported after
    /// the store is gone, with the core's own export. Durable import is twr-ggw.27's.
    #[test]
    fn a_seed_imported_after_loss_restores_the_listed_identities_and_allocates_none() {
        let seed = Seed::generate().unwrap();
        let mut core = recorded(seed.id());
        let machine = reserve(&mut core, Family::Machines).unwrap();
        let failed = reserve(&mut core, Family::Machines).unwrap();
        let pass = reserve(&mut core, Family::Passes).unwrap();
        let handoff = reserve(&mut core, Family::Handoffs).unwrap();
        core.apply(&Event::Created(machine.clone())).unwrap();
        core.apply(&Event::Failed(failed.clone())).unwrap();
        core.apply(&Event::Created(pass.clone())).unwrap();
        let export = core.export();
        let listed = |seed: &Seed| -> Vec<_> {
            export
                .entries()
                .iter()
                .map(|e| keys(seed, &e.identity))
                .collect()
        };
        let before = listed(&seed);
        let phrase = seed.phrase();
        // The journal is lost: from here on, only the mnemonic and the export are used.

        let imported = Seed::import(&phrase).unwrap();
        let mut restored = Metadata::new(imported.id());
        restored.apply(&Event::Restore(export.clone())).unwrap();
        assert_eq!(restored.seed(), imported.id());
        assert_eq!(
            restored.entries(),
            export.entries(),
            "every listed identity"
        );
        assert_eq!(status(&restored, &machine), Some(Status::Created));
        assert_eq!(status(&restored, &failed), Some(Status::Failed));
        assert_eq!(status(&restored, &handoff), Some(Status::Reserved));
        assert_eq!(
            listed(&imported),
            before,
            "each listed identity's keys re-derive"
        );
        assert!(restored.restored_from_import());
        let refused_everywhere = |core: &mut Metadata| {
            let before = core.clone();
            for family in Family::ALL {
                assert_eq!(core.issue(family), Err(Refusal::Restored), "{family:?}");
                let next = Identity {
                    seed: core.seed().into(),
                    derivation_version: VERSION,
                    family,
                    index: core.next_unused().get(family),
                };
                assert_eq!(core.apply(&Event::Reserve(next)), Err(Refusal::Restored));
            }
            assert_eq!(*core, before);
        };
        refused_everywhere(&mut restored);
        // Observations and exports leave the restriction in place.
        restored.apply(&Event::Created(handoff.clone())).unwrap();
        restored.apply(&Event::Destroyed(machine.clone())).unwrap();
        let again = restored.export();
        assert!(again.restored_from_import());
        refused_everywhere(&mut restored);
        restored.apply(&Event::Restore(again)).unwrap();
        refused_everywhere(&mut restored);

        // Only Replace with a fresh seed allocates again, and the old entries are retained.
        let old = restored.entries().to_vec();
        assert_eq!(
            restored.apply(&Event::Replace {
                seed: imported.id()
            }),
            Err(Refusal::NotFresh)
        );
        refused_everywhere(&mut restored);
        let fresh = Seed::generate().unwrap();
        restored
            .apply(&Event::Replace { seed: fresh.id() })
            .unwrap();
        assert!(!restored.restored_from_import());
        assert_eq!(restored.entries(), old);
        restored
            .apply(&Event::SeedBackup {
                seed: fresh.id(),
                completion: Completion::FullReentry,
            })
            .unwrap();
        for family in Family::ALL {
            let identity = reserve(&mut restored, family).unwrap();
            assert_eq!((identity.seed.as_str(), identity.index), (&*fresh.id(), 0));
        }
    }
}
