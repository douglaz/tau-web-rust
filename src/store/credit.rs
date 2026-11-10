//! Private credit custody and non-secret credit history in the existing journal.
use super::*;
use crate::credential::InferenceAccountCredential;
use crate::poc::credit::{AccountRecord, CAP, Invoice, Mint, Payment, identifier};

pub(crate) struct CreditAccount {
    pub credit_id: InferenceAccountCredential,
    pub default_key: InferenceAccountCredential,
}
#[derive(Default)]
pub(crate) struct State {
    pub account: Option<CreditAccount>,
    pub invoices: Vec<Invoice>,
    pub mints: Vec<Mint>,
    pub sessions: std::collections::BTreeSet<String>,
    /// Rebuilt only by a successful current read, never by replay.
    pub balance: Option<f64>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub(crate) enum Record {
    Invoice(Invoice),
    Status {
        id: String,
        status: String,
        outcome: Payment,
        balance: Option<f64>,
    },
    Abandoned {
        id: String,
    },
    MintName(Mint),
    MintId {
        name: String,
        issuer_id: String,
        returned_cap: f64,
        returned_expiry: String,
    },
}
impl<S: Storage> Store<S> {
    #[cfg(all(feature = "tracer", target_arch = "wasm32"))]
    pub(crate) async fn test_credit_append_probe(&mut self, value: String) -> Result<(), String> {
        self.commit(&Event::Command {
            machine: "fixture".into(),
            command: value,
        })
        .await
        .map(|_| ())
    }
    pub(crate) async fn credit_pause_mint_failure(
        &mut self,
        session: &str,
        why: &str,
    ) -> Result<(), String> {
        self.credit_ready()?;
        self.credit_authority(session)?;
        let tasks: Vec<_> = self
            .poc
            .values()
            .filter(|task| {
                task.start_session == session
                    && task.pending.is_none()
                    && task.proposal.is_none()
                    && !task.verifying
                    && matches!(
                        task.status,
                        super::poc::Status::Running
                            | super::poc::Status::Waiting
                            | super::poc::Status::Verifying
                    )
            })
            .cloned()
            .collect();
        for task in tasks {
            self.poc_change(
                &task.id,
                task.revision,
                super::poc::Change::Pause(why.into()),
            )
            .await?;
        }
        Ok(())
    }
    pub(crate) fn credit_filter_handle(
        &self,
    ) -> Rc<std::cell::RefCell<Vec<crate::poc::inference::EchoFilter>>> {
        self.poc_credential_filters.clone()
    }
    pub(crate) fn credit_ready(&self) -> Result<(), String> {
        self.authority.ordinary()?;
        if self.failed.is_some() || self.next >= u64::from(u32::MAX) {
            return Err("Credit store write hold; unlock again before continuing.".into());
        }
        Ok(())
    }
    pub(crate) fn credit_authority(&self, session: &str) -> Result<(), String> {
        self.check_session_authority(session, self.session_pair(session))
    }
    pub(crate) fn credit_account(&self) -> Option<&CreditAccount> {
        self.credit.account.as_ref()
    }
    pub(crate) fn credit_session(&self, session: &str) -> bool {
        self.credit.sessions.contains(session)
    }
    pub(crate) fn credit_invoice(&self) -> Option<&Invoice> {
        self.credit.invoices.last()
    }
    pub(crate) fn credit_mints(&self, session: &str) -> Vec<Mint> {
        self.credit
            .mints
            .iter()
            .filter(|m| m.session == session)
            .cloned()
            .collect()
    }
    pub(crate) fn credit_balance(&mut self, value: Option<f64>) {
        self.credit.balance = value.filter(|n| n.is_finite() && *n >= 0.0 && *n <= 1e12);
    }
    pub(crate) fn credit_can_start(&self) -> bool {
        self.failed.is_none() && self.credit.balance.is_some_and(|n| n > 0.0)
    }
    pub(crate) fn credit_view(&self) -> Value {
        #[cfg(target_arch = "wasm32")]
        let selected = crate::poc::credit::browser::selected();
        #[cfg(not(target_arch = "wasm32"))]
        let selected = false;
        json!({"selected":selected,"account":self.credit.account.is_some(), "balance":self.credit.balance,
            "balance_text":self.credit.balance.map(crate::poc::credit::display_balance),
            "can_start":self.credit_can_start(), "invoices":self.credit.invoices,
            "disclosure":crate::poc::credit::DISCLOSURE})
    }
    pub(crate) async fn credit_install(&mut self, account: &AccountRecord) -> Result<(), String> {
        self.credit_ready()?;
        #[cfg(target_arch = "wasm32")]
        if crate::poc::inference::response_pending() {
            return Err(
                "Credit configuration refused: command response pending; retry after it completes."
                    .into(),
            );
        }
        account.validate()?;
        self.poc_configuration_ready()?;
        self.poc_configuration_key(account.credit_id.0.as_bytes())?;
        self.poc_configuration_key(account.default_key.0.as_bytes())?;
        if self.credit.account.is_some() {
            return Err("Credit account already recorded.".into());
        }
        let event = Event::PocCreditAccount(AccountRecord {
            credit_id: crate::poc::credit::SecretText(Zeroizing::new(
                account.credit_id.0.to_string(),
            )),
            default_key: crate::poc::credit::SecretText(Zeroizing::new(
                account.default_key.0.to_string(),
            )),
        });
        self.commit(&event).await?;
        // No await or external effect separates committed custody from filter installation.
        self.replay_credit_account(account)
    }
    pub(super) fn replay_credit_account(&mut self, account: &AccountRecord) -> Result<(), String> {
        account.validate()?;
        if self.credit.account.is_some() {
            return Err("Second credit account refused.".into());
        }
        let id = account.credit_id.0.as_bytes();
        let key = account.default_key.0.as_bytes();
        self.credit.account = Some(CreditAccount {
            credit_id: InferenceAccountCredential::new(id.to_vec()),
            default_key: InferenceAccountCredential::new(key.to_vec()),
        });
        self.remember_poc_credential(id);
        self.remember_poc_credential(key);
        Ok(())
    }
    fn credit_validate(&self, record: &Record) -> Result<(), String> {
        if self.credit.account.is_none() {
            return Err("Credit account required.".into());
        }
        match record {
            Record::Invoice(invoice) => {
                if self.credit.invoices.iter().any(|i| i.id == invoice.id)
                    || self.credit_invoice().is_some_and(|i| {
                        !matches!(
                            i.outcome,
                            Payment::Paid | Payment::ExpiredUnpaid | Payment::Abandoned
                        )
                    })
                    || !identifier(&invoice.id)
                    || invoice.outcome != Payment::Pending
                    || invoice.last_status != "New"
                {
                    return Err("An unresolved credit invoice prevents another invoice.".into());
                }
                let checked = crate::poc::credit::Invoice::from_response(
                    201,
                    &json!({"invoice_id":invoice.id,"lightning_invoice":invoice.bolt11,"amount":invoice.amount_sat,"currency":"SATS","expires_at":invoice.expires_at}),
                    invoice.amount_sat,
                    invoice.baseline,
                )?;
                if checked != *invoice {
                    return Err(crate::poc::credit::INVOICE_INVALID.into());
                }
            }
            Record::Status {
                id,
                status,
                balance,
                outcome,
            } => {
                if self
                    .credit_invoice()
                    .is_none_or(|i| i.id != *id || (i.resolved() && i.outcome != *outcome))
                    || status.len() > 128
                    || balance.is_some_and(|n| !n.is_finite() || !(0.0..=1e12).contains(&n))
                {
                    return Err("Credit status record refused.".into());
                }
            }
            Record::Abandoned { id } => {
                if self.credit_invoice().is_none_or(|i| {
                    i.id != *id
                        || matches!(
                            i.outcome,
                            Payment::Paid | Payment::ExpiredUnpaid | Payment::Abandoned
                        )
                }) {
                    return Err("Invoice abandonment refused.".into());
                }
            }
            Record::MintName(mint) => {
                if !self.credit_session(&mint.session)
                    || self.ended_sessions.contains(&mint.session)
                    || mint.name.len() != 25
                    || !identifier(&mint.name)
                    || self.credit.mints.iter().any(|m| m.name == mint.name)
                    || mint.requested_cap != CAP
                    || mint.requested_expiry == 0
                    || mint.issuer_id.is_some()
                    || mint.returned_cap.is_some()
                    || mint.returned_expiry.is_some()
                {
                    return Err(crate::poc::credit::MINT_FAILED.into());
                }
            }
            Record::MintId {
                name,
                issuer_id,
                returned_cap,
                returned_expiry,
            } => {
                let mint = self
                    .credit
                    .mints
                    .iter()
                    .find(|m| m.name == *name)
                    .ok_or(crate::poc::credit::MINT_FAILED)?;
                if mint.issuer_id.is_some()
                    || !identifier(issuer_id)
                    || *returned_cap != CAP
                    || !crate::poc::credit::expiry_matches(mint.requested_expiry, returned_expiry)
                {
                    return Err(crate::poc::credit::MINT_FAILED.into());
                }
            }
        }
        Ok(())
    }
    pub(super) fn replay_credit(&mut self, record: &Record) -> Result<(), String> {
        self.credit_validate(record)?;
        match record {
            Record::Invoice(invoice) => self.credit.invoices.push(invoice.clone()),
            Record::Status {
                status, outcome, ..
            } => {
                let invoice = self.credit.invoices.last_mut().expect("validated invoice");
                if !invoice.resolved() {
                    invoice.last_status = status.clone();
                    invoice.outcome = *outcome;
                }
            }
            Record::Abandoned { .. } => {
                let invoice = self.credit.invoices.last_mut().expect("validated invoice");
                invoice.outcome = Payment::Abandoned;
                invoice.last_status = "abandoned".into();
            }
            Record::MintName(mint) => self.credit.mints.push(mint.clone()),
            Record::MintId {
                name,
                issuer_id,
                returned_cap,
                returned_expiry,
            } => {
                let mint = self
                    .credit
                    .mints
                    .iter_mut()
                    .find(|m| m.name == *name)
                    .expect("validated mint");
                mint.issuer_id = Some(issuer_id.clone());
                mint.returned_cap = Some(*returned_cap);
                mint.returned_expiry = Some(returned_expiry.clone());
            }
        }
        Ok(())
    }
    pub(crate) async fn credit_commit(&mut self, record: Record) -> Result<(), String> {
        self.credit_ready()?;
        self.credit_validate(&record)?;
        let value = serde_json::to_value(&record).map_err(|_| "Credit record encoding refused.")?;
        if !crate::poc::inference::safe(self, &value, &[]) {
            return Err(crate::poc::wait::JOURNAL_REFUSED.into());
        }
        self.commit(&Event::PocCredit(record.clone())).await?;
        self.replay_credit(&record)?;
        if let Record::Status { balance, .. } = record {
            self.credit_balance(balance);
        }
        Ok(())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests;
