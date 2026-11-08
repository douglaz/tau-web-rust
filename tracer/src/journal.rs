//! Independent closed format-2 plaintext decoding, including duplicate object members.
use serde::de::{Error, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Read;
        impl<'de> Visitor<'de> for Read {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("JSON value")
            }
            fn visit_bool<E: Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E: Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: Error>(self, v: f64) -> Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(n.into()))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: Error>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: Error>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_unit<E: Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(values.into()))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom("duplicate member"));
                    }
                    let Strict(value) = map.next_value()?;
                    values.insert(key, value);
                }
                Ok(Strict(values.into()))
            }
        }
        d.deserialize_any(Read)
    }
}

pub fn event(bytes: &[u8]) -> Result<Value, String> {
    let Strict(wrapper) = serde_json::from_slice(bytes).map_err(|_| "journal decoding failed")?;
    let object = wrapper
        .as_object()
        .ok_or("journal wrapper is not an object")?;
    if object.len() != 2
        || object.get("journal_version") != Some(&Value::from(2))
        || !object.contains_key("event")
    {
        return Err("journal requires the closed version-2 wrapper".into());
    }
    Ok(wrapper["event"].clone())
}

pub fn wrap(event: &Value) -> Value {
    serde_json::json!({"journal_version":2,"event":event})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poc_reader_v2_wrapper_is_closed_and_rejects_nested_duplicate_members() {
        let inner = serde_json::json!({"command":{"machine":"fixture","command":"74727565"}});
        assert_eq!(
            event(&wrap(&inner).to_string().into_bytes()).unwrap(),
            inner
        );
        for bytes in [
            br#"{"command":{"machine":"fixture","command":"74727565"}}"#.as_slice(),
            br#"{"journal_version":1,"event":{}}"#,
            br#"{"journal_version":73,"event":{}}"#,
            br#"{"journal_version":2}"#,
            br#"{"journal_version":2,"event":{},"extra":true}"#,
            br#"{"journal_version":2,"journal_version":2,"event":{}}"#,
            br#"{"journal_version":2,"event":{},"event":{}}"#,
            br#"{"journal_version":2,"event":{"end":{"session":"a","session":"b","reason":"explicit"}}}"#,
        ] {
            assert!(event(bytes).is_err());
        }
    }
}
