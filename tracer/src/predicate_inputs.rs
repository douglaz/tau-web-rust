//! Assertion consumption is available only while the original primary check is recorded.
use crate::{file_inputs, json, state_inputs};
pub struct Primary {
    site: &'static str,
    instance: usize,
    at: u64,
    cursor: usize,
}
impl Primary {
    pub fn coordinates(&self) -> (&str, usize, u64, usize) {
        (self.site, self.instance, self.at, self.cursor)
    }
}
impl crate::Case {
    pub(crate) fn check(
        &mut self,
        site: &'static str,
        what: &str,
        holds: impl Into<state_inputs::Predicate>,
    ) {
        let occurrence = self.assertions.iter().filter(|a| a["site"] == site).count() + 1;
        let (at, cursor) = file_inputs::checked(site, occurrence);
        let binding = Primary {
            site,
            instance: occurrence,
            at,
            cursor,
        };
        let holds = holds.into().checked(&binding);
        let instance = format!("{site}.i{occurrence:03}");
        if !holds {
            crate::diagnostics::primary(&self.id, &instance);
        }
        self.assertions
            .push(json!({"id":instance,"site":site,"ok":holds}));
        println!("   [{}] {what}", if holds { "ok" } else { "FAILED" });
        if !holds {
            self.failures.push(what.to_string());
        }
    }
}
