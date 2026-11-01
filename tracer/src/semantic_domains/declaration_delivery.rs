//! Source-derived, secret-free input domains, captured before actual validation.
//! This planner does not call any shape checker, actual History or completion recorder.
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn alias<'a>(v: &Value, choices: &'a [&'a str]) -> &'a str {
    v.as_str()
        .and_then(|s| choices.iter().copied().find(|c| *c == s))
        .unwrap_or("unknown")
}
fn list(v: &Value, element: impl Fn(&Value) -> Value) -> Value {
    json!({"unspecified":v == "unspecified", "items":v.as_array().map(|a| a.iter().map(element).collect::<Vec<_>>()).unwrap_or_default()})
}
fn host(v: &Value) -> Value {
    json!({"kind":match v.as_str() {Some("any")=>"any",Some(s) if s.contains('/')=>"network",Some(_)=>"hostname",None=>"unknown"}})
}
pub fn declaration(v: &Value, multi: bool) -> Value {
    json!({
        "multi":multi,
        "inbound":list(&v["listeners"]["inbound"], |_| json!({})),
        "outbound":list(&v["listeners"]["outbound"], |row| json!({"host":host(&row["host"])})),
        "services":list(&v["services"], |row| json!({"scope":alias(&row["scope"]["kind"], &["system","user"])})),
        "permitted":list(&v["key_material"]["permitted"], |_| json!({})),
        "credentials":{
            "none":v["default_credentials"] == "none",
            "unspecified":v["default_credentials"] == "unspecified",
            "items":v["default_credentials"].as_array().map(|a| a.iter().map(|_|json!({})).collect::<Vec<_>>()).unwrap_or_default()
        }
    })
}
pub fn declaration_shape(v: &Value) -> Value {
    json!({"kind":alias(&v["proposal"]["kind"], &["declaration","tighten_class"]), "declaration":declaration(&v["proposal"]["declaration"], false)})
}
/// Its own state is projected from raw earlier records, never the actual checked History.
#[derive(Default)]
pub struct DeclarationInputs {
    previous_declarations: BTreeMap<String, Value>,
    previous_classes: BTreeMap<String, bool>,
}
impl DeclarationInputs {
    pub fn event(&mut self, event: &Value) -> Value {
        let setup = &event["setup"];
        let requirements = setup.get("requirements");
        let p = &setup["requirements"]["proposal"];
        let machine = p["machine"].as_str().unwrap_or("");
        let previous = self.previous_declarations.get(machine);
        let multi = self.previous_classes.get(machine).copied().unwrap_or(false);
        let domain = json!({
            "approval":setup["approval"]["entries"].is_array(),
            "class":setup.get("class").is_some(),
            "requirements":requirements.is_some(),
            "kind":alias(&p["kind"], &["declaration","tighten_class"]),
            "prior_declaration":previous.is_some(),
            "declaration":if p["kind"] == "declaration" {declaration(&p["declaration"],multi)} else {declaration(previous.unwrap_or(&Value::Null),true)}
        });
        if requirements.is_some() && p["kind"] == "declaration" {
            self.previous_declarations
                .insert(machine.to_owned(), p["declaration"].clone());
        }
        if let Some(c) = setup.get("class") {
            self.previous_classes.insert(
                c["machine"].as_str().unwrap_or("").to_owned(),
                c["class"] == "multi_tenant",
            );
        }
        if requirements.is_some() && p["kind"] == "tighten_class" {
            self.previous_classes.insert(machine.to_owned(), true);
        }
        domain
    }
}
pub fn delivery(v: &Value) -> Value {
    let c = &v["check"];
    let r = &c["result"];
    let measurements:Vec<_>=["inbound","outbound","services","spendable","permitted","required","credentials","fixed_default_credentials","sshd_posture"].into_iter().map(|field| json!({
        "field":field,
        "read":alias(&c["measurements"][field]["read"], &["missing","failed","value"]),
        "type":if ["spendable","fixed_default_credentials","sshd_posture"].contains(&field) {"bool"} else {"array"}
    })).collect();
    let rows = |v: &Value| {
        v.as_array().map(|a| a.iter().map(|row|json!({"field":alias(&row["field"], &["version","inbound","outbound","services","spendable","permitted","drift_checks","required","default_credentials","fixed_default_credentials","sshd_posture"])})).collect::<Vec<_>>()).unwrap_or_default()
    };
    let notes = r["notes"]
        .as_array()
        .map(|a| a.iter().map(|_| json!({})).collect::<Vec<_>>())
        .unwrap_or_default();
    json!({
        "kind":alias(&v["kind"], &["check","application","findings_unknown","subsequent_placement"]),
        "declaration":declaration(&c["authority"]["declaration"], c["authority"]["class"]=="multi_tenant"),
        "measurements":measurements,
        "fields":rows(&r["fields"]),
        "findings":rows(&r["findings"]),
        "notes":notes
    })
}
pub fn delivery_history(event: &Value) -> Value {
    json!({"class":event.pointer("/setup/class").is_some(),"requirements_proposal":event.pointer("/setup/requirements/proposal").is_some(),"delivery":event.get("delivery").is_some(),"kind":alias(&event["delivery"]["kind"], &["check","application","findings_unknown","subsequent_placement"]),"shape":delivery(&event["delivery"])})
}
