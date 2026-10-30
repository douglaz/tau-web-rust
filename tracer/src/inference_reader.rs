//! Independent parsing of inference records; no production record types are used.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
fn object<'a>(
    v: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let o = v.as_object().ok_or("inference body is not an object")?;
    if required.iter().any(|k| !o.contains_key(*k))
        || o.keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
    {
        return Err("inference members differ".into());
    }
    Ok(o)
}
fn text(v: &Value, k: &str) -> Result<(), String> {
    if v[k].as_str().is_none_or(str::is_empty) {
        Err("inference text missing".into())
    } else {
        Ok(())
    }
}
fn number(v: &Value, k: &str) -> Result<(), String> {
    if v[k].as_u64().is_none() {
        Err("inference integer missing".into())
    } else {
        Ok(())
    }
}

fn mint_evidence(body: &Value) -> Result<(), String> {
    let Some(e) = body.get("evidence") else {
        return Ok(());
    };
    object(e, &["confirmed", "origin", "authorized_at", "clock"], &[])?;
    let c = &e["confirmed"];
    object(
        c,
        &[
            "session",
            "account_record",
            "choice_generation",
            "profile",
            "cap_hundredths",
            "unit",
            "lifetime_seconds",
        ],
        &[],
    )?;
    for k in ["session", "choice_generation", "profile", "unit"] {
        text(c, k)?;
    }
    for k in ["account_record", "cap_hundredths", "lifetime_seconds"] {
        number(c, k)?;
    }
    let cap = c["cap_hundredths"].as_u64().ok_or("cap integer")?;
    let lifetime = c["lifetime_seconds"].as_u64().ok_or("lifetime integer")?;
    let expiry = body["expires"].as_u64().ok_or("expiry")?;
    let origin = e["origin"].as_u64().ok_or("origin")?;
    if !(1..=10000).contains(&cap)
        || !(60..=86400).contains(&lifetime)
        || !lifetime.is_multiple_of(60)
        || c["session"] != body["session"]
        || c["unit"] != "account units"
        || expiry > 253402300799
        || body["cap"] != format!("{}.{:02}", cap / 100, cap % 100)
        || origin.checked_add(lifetime) != Some(expiry)
    {
        return Err("original mint bounds differ".into());
    }
    let clock = &e["clock"];
    object(
        clock,
        &[
            "sent", "received", "earliest", "latest", "minimum", "maximum",
        ],
        &[],
    )?;
    fn pair(v: &Value) -> Result<(u64, u64), String> {
        object(v, &["monotonic", "wall"], &[])?;
        Ok((
            v["monotonic"]
                .as_u64()
                .filter(|n| *n != u64::MAX)
                .ok_or("monotonic")?,
            v["wall"]
                .as_u64()
                .filter(|n| *n != u64::MAX)
                .ok_or("wall")?,
        ))
    }
    let (m0, w0) = pair(&clock["sent"])?;
    let (m1, w1) = pair(&clock["received"])?;
    let (m, w) = pair(&e["authorized_at"])?;
    for (base_m, base_w, next_m, next_w) in [(m0, w0, m1, w1), (m1, w1, m, w)] {
        if next_m < base_m
            || ((i128::from(next_w) - i128::from(base_w))
                - (i128::from(next_m) - i128::from(base_m)))
            .abs()
                > 5_000_000
        {
            return Err("invalid original clock pair".into());
        }
    }
    let a = clock["earliest"].as_u64().ok_or("earliest")?;
    let b = clock["latest"].as_u64().ok_or("latest")?;
    fn rate(v: &Value) -> Result<(u128, u128), String> {
        object(v, &["numerator", "denominator"], &[])?;
        let n = v["numerator"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("rate numerator")?;
        let d = v["denominator"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("rate denominator")?;
        Ok((u128::from(n), u128::from(d)))
    }
    let (min_n, min_d) = rate(&clock["minimum"])?;
    let (max_n, max_d) = rate(&clock["maximum"])?;
    fn bound(t: u64, elapsed: u64, n: u128, d: u128, ceil: bool) -> Option<u128> {
        let d = d.checked_mul(1_000_000)?;
        let n = u128::from(t)
            .checked_mul(d)?
            .checked_add(n.checked_mul(u128::from(elapsed))?)?;
        (n / d).checked_add(u128::from(ceil && n % d != 0))
    }
    if a == 0
        || a > b
        || b > 253402300799
        || min_n * max_d > max_n * min_d
        || bound(
            a,
            m.checked_sub(m1).ok_or("negative elapsed")?,
            min_n,
            min_d,
            false,
        ) != Some(u128::from(origin))
        || bound(
            b,
            m.checked_sub(m0).ok_or("negative elapsed")?,
            max_n,
            max_d,
            true,
        )
        .is_none_or(|upper| upper >= u128::from(expiry))
    {
        return Err("original interval does not authorize mint".into());
    }
    Ok(())
}
pub fn shape(n: u64, event: &Value) -> Result<(), String> {
    let (kind, body) = event
        .as_object()
        .filter(|o| o.len() == 1)
        .ok_or("invalid inference event")?
        .iter()
        .next()
        .unwrap();
    match kind.as_str() {
        "inference_account" => {
            object(body, &["credential"], &[])?;
            text(body, "credential")?;
        }
        "inference_intent" => {
            let (k, b) = body
                .as_object()
                .filter(|o| o.len() == 1)
                .ok_or("invalid inference intent")?
                .iter()
                .next()
                .unwrap();
            let fields: &[&str] = match k.as_str() {
                "account_read" => &["call", "session"],
                "clock_read" => &["call", "session", "sent"],
                "mint" => &["call", "session", "cap", "expires"],
                "completion" => &[
                    "call",
                    "session",
                    "key_id",
                    "model",
                    "requested_provider",
                    "zdr",
                ],
                "revoke" => &["call", "key_id"],
                _ => return Err("unknown inference call kind".into()),
            };
            object(b, fields, if k == "mint" { &["evidence"] } else { &[] })?;
            if k == "mint" {
                mint_evidence(b)?;
            }
            number(b, "call")?;
            if b["call"] != n {
                return Err("inference identity differs from record number".into());
            }
            for field in fields {
                match *field {
                    "call" | "expires" => number(b, field)?,
                    "sent" => {
                        object(&b["sent"], &["monotonic", "wall"], &[])?;
                        number(&b["sent"], "monotonic")?;
                        number(&b["sent"], "wall")?;
                    }
                    "zdr" => {
                        if b["zdr"] != true {
                            return Err("retention request missing".into());
                        }
                    }
                    _ => text(b, field)?,
                }
            }
        }
        "inference_terminal" => {
            let o = object(
                body,
                &["call", "status"],
                &[
                    "issuer_time",
                    "clock_received",
                    "clock_sent",
                    "unit",
                    "charge_refusal",
                    "automatic_top_up",
                    "key_id",
                    "cap",
                    "expires",
                    "model",
                    "requested_provider",
                    "reported_provider",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                    "spend",
                    "request_id",
                ],
            )?;
            number(body, "call")?;
            number(body, "status")?;
            if !body["status"]
                .as_u64()
                .is_some_and(|s| (100..=599).contains(&s))
            {
                return Err("invalid inference status".into());
            }
            for field in o
                .keys()
                .map(String::as_str)
                .filter(|k| !["call", "status"].contains(k))
            {
                match field {
                    "charge_refusal" => {
                        if !matches!(
                            body[field].as_str(),
                            Some("account_balance" | "key_cap_exhausted" | "key_expired")
                        ) {
                            return Err("invalid charge refusal".into());
                        }
                    }
                    "automatic_top_up" => {
                        if !body[field].is_boolean() {
                            return Err("invalid top-up setting".into());
                        }
                    }
                    "clock_sent" | "clock_received" => {
                        object(&body[field], &["monotonic", "wall"], &[])?;
                        number(&body[field], "monotonic")?;
                        number(&body[field], "wall")?;
                    }
                    "issuer_time" | "expires" | "prompt_tokens" | "completion_tokens"
                    | "total_tokens" => number(body, field)?,
                    "spend" => {
                        text(body, field)?;
                        if !serde_json::from_str::<Value>(body[field].as_str().unwrap())
                            .is_ok_and(|v| v.is_number())
                        {
                            return Err("invalid spend".into());
                        }
                    }
                    _ => text(body, field)?,
                }
            }
        }
        _ => return Err("unknown inference record".into()),
    }
    Ok(())
}
#[derive(Default)]
pub struct History {
    account: bool,
    account_record: Option<u64>,
    sessions: BTreeSet<String>,
    intents: BTreeMap<u64, Value>,
    terminals: BTreeMap<u64, Value>,
    revokes: BTreeSet<String>,
}
impl History {
    pub fn apply(&mut self, n: u64, event: &Value) -> Result<(), String> {
        if let Some(e) = event.get("exposure") {
            self.sessions
                .insert(e["session"].as_str().ok_or("invalid exposure")?.into());
        }
        if let Some(a) = event.get("inference_account") {
            shape(n, event)?;
            if self.account
                || a["credential"]
                    .as_str()
                    .unwrap()
                    .bytes()
                    .any(|c| !(33..=126).contains(&c))
            {
                return Err("invalid account credential record".into());
            }
            self.account = true;
            self.account_record = Some(n);
        }
        if let Some(intent) = event.get("inference_intent") {
            shape(n, event)?;
            if !self.account {
                return Err("inference has no account credential".into());
            }
            let (k, b) = intent.as_object().unwrap().iter().next().unwrap();
            if let Some(session) = b.get("session")
                && !self.sessions.contains(session.as_str().unwrap())
            {
                return Err("inference names no exposure".into());
            }
            match k.as_str() {
                "mint" => {
                    if let Some(e) = b.get("evidence")
                        && e["confirmed"]["account_record"].as_u64() != self.account_record
                    {
                        return Err("mint account generation differs".into());
                    }
                    if self
                        .intents
                        .values()
                        .any(|i| i.get("mint").is_some_and(|i| i["session"] == b["session"]))
                    {
                        return Err("second session mint".into());
                    }
                    if !self
                        .intents
                        .iter()
                        .rev()
                        .find(|(_, i)| {
                            i.get("account_read")
                                .is_some_and(|r| r["session"] == b["session"])
                        })
                        .and_then(|(id, _)| self.terminals.get(id))
                        .is_some_and(|t| {
                            t["automatic_top_up"] == false
                                && t["status"]
                                    .as_u64()
                                    .is_some_and(|s| (200..300).contains(&s))
                        })
                    {
                        return Err("mint has no top-up-off read".into());
                    }
                    if b["cap"]
                        .as_str()
                        .unwrap()
                        .parse::<f64>()
                        .ok()
                        .is_none_or(|v| !v.is_finite() || v <= 0.)
                        || b["expires"] == 0
                    {
                        return Err("invalid mint bounds".into());
                    }
                }
                "completion" => {
                    if !self.terminals.iter().any(|(id, t)| {
                        t["key_id"] == b["key_id"]
                            && self.intents[id]["mint"]["session"] == b["session"]
                    }) {
                        return Err("completion has no minted key".into());
                    }
                }
                "revoke" => {
                    let id = b["key_id"].as_str().unwrap();
                    if !self.terminals.values().any(|t| t["key_id"] == id)
                        || !self.revokes.insert(id.into())
                    {
                        return Err("invalid or repeated revoke".into());
                    }
                }
                _ => {}
            }
            self.intents.insert(n, intent.clone());
        }
        if let Some(t) = event.get("inference_terminal") {
            shape(n, event)?;
            let call = t["call"].as_u64().unwrap();
            let intent = self
                .intents
                .get(&call)
                .ok_or("inference terminal has no intent")?;
            if self.terminals.contains_key(&call) {
                return Err("second inference terminal".into());
            }
            let (kind, b) = intent.as_object().unwrap().iter().next().unwrap();
            let allowed: &[&str] = match kind.as_str() {
                "account_read" => &["automatic_top_up"],
                "mint" => &["key_id", "cap", "expires", "unit"],
                "clock_read" => &["issuer_time", "clock_received", "clock_sent"],
                "completion" => &[
                    "charge_refusal",
                    "model",
                    "requested_provider",
                    "reported_provider",
                    "prompt_tokens",
                    "completion_tokens",
                    "total_tokens",
                    "spend",
                    "request_id",
                ],
                _ => &[],
            };
            if t.as_object().unwrap().keys().any(|k| {
                !["call", "status"].contains(&k.as_str()) && !allowed.contains(&k.as_str())
            }) {
                return Err("terminal fields belong to another inference kind".into());
            }
            // Discrepant issuer facts remain history; replay supplies no usable credential.
            if kind == "completion"
                && (t["model"] != b["model"] || t["requested_provider"] != b["requested_provider"])
            {
                return Err("completion selection differs".into());
            }
            self.terminals.insert(call, t.clone());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn records() -> Vec<Value> {
        vec![
            json!({"inference_account":{"credential":"account-private"}}),
            json!({"exposure":{"session":"s"}}),
            json!({"inference_intent":{"account_read":{"call":2,"session":"s"}}}),
            json!({"inference_terminal":{"call":2,"status":200,"automatic_top_up":false}}),
            json!({"inference_intent":{"mint":{"call":4,"session":"s","cap":"0.10","expires":900}}}),
            json!({"inference_terminal":{"call":4,"status":200,"key_id":"k","cap":"0.10","expires":900}}),
            json!({"inference_intent":{"completion":{"call":6,"session":"s","key_id":"k","model":"fixture-model","requested_provider":"fixture-provider","zdr":true}}}),
            json!({"inference_terminal":{"call":6,"status":200,"model":"fixture-model","requested_provider":"fixture-provider","reported_provider":"Fixture Provider","spend":"0.12345678901234567890","request_id":"gen-fixture","total_tokens":8}}),
            json!({"inference_intent":{"revoke":{"call":8,"key_id":"k"}}}),
            json!({"inference_terminal":{"call":8,"status":200}}),
        ]
    }
    fn read(r: &[Value]) -> Result<(), String> {
        let mut h = History::default();
        for (n, e) in r.iter().enumerate() {
            h.apply(n as u64, e)?;
        }
        Ok(())
    }
    #[test]
    fn independent_reader_requires_the_latest_top_up_read_of_the_mint_session() {
        let mut r = records()[..4].to_vec();
        r.push(json!({"exposure":{"session":"other"}}));
        r.push(json!({"inference_intent":{"account_read":{"call":5,"session":"other"}}}));
        r.push(json!({"inference_terminal":{"call":5,"status":200,"automatic_top_up":true}}));
        r.push(json!({"inference_intent":{"mint":{"call":7,"session":"other","cap":"0.10","expires":900}}}));
        assert!(read(&r).unwrap_err().contains("top-up-off"));
        r[5]["inference_intent"]["account_read"]["session"] = "s".into();
        r[7]["inference_intent"]["mint"]["session"] = "s".into();
        assert!(read(&r).unwrap_err().contains("top-up-off"));
        r[6]["inference_terminal"]["automatic_top_up"] = false.into();
        read(&r).unwrap();
    }
    #[test]
    fn independent_inference_shapes_and_references_refuse_malformed_records() {
        let r = records();
        read(&r).unwrap();
        for n in [0, 2, 3, 4, 5, 6, 7, 8, 9] {
            let mut bad = r.clone();
            let b = bad[n].as_object_mut().unwrap().values_mut().next().unwrap();
            let b = if n == 2 || n == 4 || n == 6 || n == 8 {
                b.as_object_mut().unwrap().values_mut().next().unwrap()
            } else {
                b
            };
            b["extra"] = true.into();
            assert!(read(&bad).is_err(), "extra member at {n}");
        }
        let mut bad = r.clone();
        bad[6]["inference_intent"]["completion"]["session"] = "missing".into();
        assert!(read(&bad).is_err());
        let mut bad = r.clone();
        bad[7]["inference_terminal"]["call"] = 55.into();
        assert!(read(&bad).is_err());
        let mut bad = r.clone();
        bad.push(r[9].clone());
        assert!(read(&bad).is_err());
        let mut bad = r;
        bad[7]["inference_terminal"]["model"] = "other".into();
        assert!(read(&bad).is_err());
    }
}
