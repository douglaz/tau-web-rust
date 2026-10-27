//! Operator delivery messages carry no measurements, classifications or replacement results.
use crate::delivery::Measurements;
use crate::worker::local;
use serde::Deserialize;
use serde_json::{Value, json};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Check {
        session: String,
        machine: String,
    },
    Application {
        session: String,
        machine: String,
        name: String,
    },
    AcceptFinding {
        session: String,
        machine: String,
    },
    WaiveFinding {
        session: String,
        machine: String,
    },
}
#[wasm_bindgen]
pub async fn delivery_request(request: String) -> String {
    let stop = super::Stop::collection();
    let result: Result<(), String> = async {
        if !serde_json::from_str::<Value>(&request).is_ok_and(|v| v.is_object()) {
            return Err("delivery request schema".into());
        }
        let request: Request =
            serde_json::from_str(&request).map_err(|_| "delivery request schema")?;
        let (session, machine) = match &request {
            Request::Check { session, machine }
            | Request::Application {
                session, machine, ..
            }
            | Request::AcceptFinding { session, machine }
            | Request::WaiveFinding { session, machine } => (session, machine),
        };
        let local = local();
        let authority = {
            let mut guard = stop.until(local.lock()).await.ok_or("sessions ended")?;
            if stop.stopped() {
                return Err("sessions ended".into());
            }
            if let Some(why) = guard.dispatch_refusal() {
                return Err(why.into());
            }
            guard
                .store()
                .ok_or("locked")?
                .delivery_authority(session, machine)?
        };
        match request {
            Request::Check { session, .. } => {
                // No live observer exists yet. Only tracer may supply typed fixture facts,
                // and missing evidence remains missing in the ordinary served build.
                let measurements = stop
                    .until(measurements(&session, &authority))
                    .await
                    .ok_or("sessions ended")??;
                #[cfg(feature = "tracer")]
                stop.until(crate::testonly::session_point("delivery_writer"))
                    .await
                    .ok_or("sessions ended")?;
                super::write::unless_stopped(
                    local.lock(),
                    stop.notified(),
                    || stop.stopped(),
                    async |mut guard| {
                        if let Some(why) = guard.dispatch_refusal() {
                            return Err(why.into());
                        }
                        guard
                            .store()
                            .ok_or("locked")?
                            .delivery_check(&session, authority, measurements)
                            .await
                    },
                )
                .await
                .ok_or("sessions ended")?
            }
            Request::Application {
                session,
                machine,
                name,
            } => super::write::unless_stopped(
                local.lock(),
                stop.notified(),
                || stop.stopped(),
                async |mut guard| {
                    if let Some(why) = guard.dispatch_refusal() {
                        return Err(why.into());
                    }
                    guard
                        .store()
                        .ok_or("locked")?
                        .record_application(&session, &machine, name)
                        .await
                },
            )
            .await
            .ok_or("sessions ended")?,
            Request::AcceptFinding { .. } | Request::WaiveFinding { .. } => {
                let mut guard = stop.until(local.lock()).await.ok_or("sessions ended")?;
                guard.store().ok_or("locked")?.refuse_finding_acceptance()
            }
        }
    }
    .await;
    if stop.stopped() {
        return json!({"state":"stopped","error":"sessions ended"}).to_string();
    }
    let local = local();
    let Some(guard) = stop.until(local.lock()).await else {
        return json!({"state":"stopped","error":"sessions ended"}).to_string();
    };
    if stop.stopped() {
        return json!({"state":"stopped","error":"sessions ended"}).to_string();
    }
    guard
        .report(result.as_ref().err().map(String::as_str))
        .to_string()
}
async fn measurements(
    session: &str,
    authority: &crate::store::delivery::Authority,
) -> Result<Measurements, String> {
    #[cfg(feature = "tracer")]
    {
        crate::testonly::session_point("delivery_read").await;
        if let Some((s, a, m)) = FIXTURE.with_borrow_mut(Option::take) {
            if s != session || a != *authority {
                return Err("stale fixture delivery authority".into());
            }
            return Ok(m);
        }
    }
    let _ = (session, authority);
    Ok(Measurements::missing())
}
#[cfg(feature = "tracer")]
thread_local! {
    static FIXTURE: std::cell::RefCell<Option<(String,crate::store::delivery::Authority,Measurements)>> = const {std::cell::RefCell::new(None)};
}
#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_delivery_fixture(
    session: String,
    machine: String,
    measurements: String,
) -> Result<(), JsValue> {
    let value: Value =
        serde_json::from_str(&measurements).map_err(|_| "fixture measurement schema")?;
    let m: Measurements =
        serde_json::from_str(&measurements).map_err(|_| "fixture measurement schema")?;
    if serde_json::to_value(&m).map_err(|_| "fixture measurement schema")? != value {
        return Err("fixture measurement shape".into());
    }
    let local = local();
    let mut guard = local.lock().await;
    let authority = guard
        .store()
        .ok_or("locked")?
        .delivery_authority(&session, &machine)
        .map_err(JsValue::from)?;
    FIXTURE.with_borrow_mut(|v| *v = Some((session, authority, m)));
    Ok(())
}
#[cfg(feature = "tracer")]
#[wasm_bindgen]
pub async fn test_delivery_state(record: String) -> Result<(), JsValue> {
    let record: crate::store::delivery::Record =
        serde_json::from_str(&record).map_err(|_| "fixture state schema")?;
    if !matches!(
        record,
        crate::store::delivery::Record::FindingsUnknown { .. }
            | crate::store::delivery::Record::SubsequentPlacement { .. }
    ) {
        return Err("fixture state only".into());
    }
    local()
        .lock()
        .await
        .store()
        .ok_or("locked")?
        .fixture_delivery_record(record)
        .await
        .map_err(JsValue::from)
}
