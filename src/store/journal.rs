//! The session journal version is independent of the local encryption envelope.
use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Journal<E> {
    pub journal_version: u64,
    pub event: E,
}

pub(super) fn journal<E>(event: E) -> Journal<E> {
    Journal {
        journal_version: 2,
        event,
    }
}

const UNCHANGED: &str = "Data was left unchanged. Clearing site data permanently deletes the store, including its seed record.";

pub(super) fn refusal(why: String) -> String {
    if why.contains(UNCHANGED) {
        why
    } else {
        format!("{why}. {UNCHANGED}")
    }
}

// Only inspect the version here. The typed closed wrapper and event decoder below establish
// validity; this probe supplies distinct diagnostics without retaining plaintext values.
struct Version(Option<u64>);
impl<'de> Deserialize<'de> for Version {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Probe;
        impl<'de> serde::de::Visitor<'de> for Probe {
            type Value = Version;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("journal object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Version, A::Error> {
                let mut event_seen = false;
                let mut version = None;
                while let Some(mut key) = map.next_key::<String>()? {
                    let is_version = key == "journal_version";
                    let is_event = key == "event";
                    key.zeroize();
                    if is_version {
                        if version.is_some() {
                            return Err(serde::de::Error::custom("duplicate journal member"));
                        }
                        version = Some(map.next_value::<u64>()?);
                    } else {
                        if is_event && std::mem::replace(&mut event_seen, true) {
                            return Err(serde::de::Error::custom("duplicate journal member"));
                        }
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(Version(version))
            }
        }
        d.deserialize_map(Probe)
    }
}

// Typed event fields may contain maps or arbitrary structured evidence. Check decoded member
// uniqueness there too, without creating a generic value that could discard duplicates.
struct Unique;
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> serde::de::Visitor<'de> for Read {
            type Value = Unique;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("journal value")
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Unique, E> {
                Ok(Unique)
            }
            fn visit_string<E: serde::de::Error>(self, mut text: String) -> Result<Unique, E> {
                text.zeroize();
                Ok(Unique)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Unique, A::Error> {
                while seq.next_element::<Unique>()?.is_some() {}
                Ok(Unique)
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Unique, A::Error> {
                struct Keys(std::collections::BTreeSet<String>);
                impl Drop for Keys {
                    fn drop(&mut self) {
                        while let Some(mut key) = self.0.pop_first() {
                            key.zeroize();
                        }
                    }
                }
                let mut keys = Keys(Default::default());
                while let Some(mut key) = map.next_key::<String>()? {
                    if keys.0.contains(&key) {
                        key.zeroize();
                        return Err(serde::de::Error::custom("duplicate journal member"));
                    }
                    keys.0.insert(key);
                    map.next_value::<Unique>()?;
                }
                Ok(Unique)
            }
        }
        d.deserialize_any(Read)
    }
}

pub(super) fn decode(bytes: &[u8]) -> Result<Event, String> {
    let version: Version = serde_json::from_slice(bytes)
        .map_err(|_| format!("journal decoding failed. {UNCHANGED}"))?;
    match version.0 {
        None | Some(1) => return Err(format!("unsupported earlier journal format. {UNCHANGED}")),
        Some(2) => (),
        Some(_) => return Err(format!("unknown journal version. {UNCHANGED}")),
    }
    let _: Unique = serde_json::from_slice(bytes)
        .map_err(|_| format!("journal decoding failed. {UNCHANGED}"))?;
    let wrapper: Journal<Event> = serde_json::from_slice(bytes)
        .map_err(|_| format!("journal decoding failed. {UNCHANGED}"))?;
    Ok(wrapper.event)
}
