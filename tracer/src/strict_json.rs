//! Evidence preserves every object member; duplicate fields are a refusal.
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use std::fmt;

struct Evidence(Value);
impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> Visitor<'de> for Object {
            type Value = Evidence;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unambiguous evidence JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Evidence, E> {
                Ok(Evidence(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Evidence, E> {
                Ok(Evidence(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Evidence, E> {
                Ok(Evidence(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Evidence, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| Evidence(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite evidence number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Evidence, E> {
                Ok(Evidence(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Evidence, E> {
                Ok(Evidence(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Evidence, E> {
                Ok(Evidence(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Evidence, A::Error> {
                let mut values = Vec::new();
                while let Some(Evidence(v)) = seq.next_element()? {
                    values.push(v);
                }
                Ok(Evidence(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Evidence, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, Evidence(value))) = map.next_entry::<String, Evidence>()? {
                    if values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate evidence field"));
                    }
                }
                Ok(Evidence(Value::Object(values)))
            }
        }
        decoder.deserialize_any(Object)
    }
}

pub fn parse(raw: &str) -> Result<Value, String> {
    let mut decoder = serde_json::Deserializer::from_str(raw);
    let Evidence(value) = Evidence::deserialize(&mut decoder)
        .map_err(|_| "invalid or duplicate evidence JSON field")?;
    decoder.end().map_err(|_| "trailing evidence JSON")?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    #[test]
    fn duplicate_nested_success_and_identity_fields_refuse() {
        for raw in [
            r#"{"guards":[{"ok":false,"ok":true}]}"#,
            r#"{"source":"wrong","source":"current"}"#,
            r#"{"nested":{"id":1,"id":2}}"#,
        ] {
            assert!(super::parse(raw).is_err());
        }
        assert!(super::parse(r#"{"guards":[{"ok":true}],"source":"current"}"#).is_ok());
    }
}
