//! Host-only fixture adapter. Mutations are reconcile-before-retry (`STA-5`): no mutation
//! response confirms anything. Only the fixture status contract reports an observed effect.

use super::*;
use crate::store::{OperationError, Storage, Store};

#[derive(Default)]
pub struct Vendor {
    pub received: Vec<OperationIntent>,
    pub pause_before_send: bool,
    pub response: Option<Vec<u8>>,
}

impl Vendor {
    pub const RETRY_SAFETY: &str = "reconcile-before-retry";

    pub async fn run<S: Storage>(
        &mut self,
        store: &mut Store<S>,
        caller: Option<&str>,
        request: &Request,
    ) -> Result<u64, OperationError> {
        self.run_response(store, caller, request)
            .await
            .map(|(call, _)| call)
    }

    pub async fn run_response<S: Storage>(
        &mut self,
        store: &mut Store<S>,
        caller: Option<&str>,
        request: &Request,
    ) -> Result<(u64, Option<crate::redaction::Redacted>), OperationError> {
        store
            .check_bound_operation(caller, request)
            .map_err(OperationError::Policy)?;
        store
            .check_operation(request)
            .map_err(OperationError::Policy)?;
        let intent = store.operation(request).await?;
        let call = intent.call;
        if self.pause_before_send {
            std::future::pending::<()>().await;
        }
        self.received.push(intent);
        // A lost response has no record. The intent remains unresolved.
        let output = match &self.response {
            Some(body) => Some(
                store
                    .operation_response(call, body, &["/root_password"])
                    .await
                    .map_err(OperationError::Storage)?,
            ),
            None => None,
        };
        Ok((call, output))
    }

    pub async fn status<S: Storage>(
        &mut self,
        store: &mut Store<S>,
        caller: Option<&str>,
        request: &Request,
        operation: Operation,
        reports: Reports,
    ) -> Result<Vec<u64>, OperationError> {
        store
            .check_bound_operation(caller, request)
            .map_err(OperationError::Policy)?;
        let resource = store
            .dispatch()
            .check_request(request)
            .map_err(OperationError::Policy)?;
        assert_eq!(request.operation, Operation::Read);
        let observation = store.dispatch().observation(resource, operation, reports);
        self.run(store, caller, request).await?;
        store
            .operation_observation(observation)
            .await
            .map_err(OperationError::Storage)
    }
}

/// Arbitrary-byte stand-in, journaled against a fixture typed call; enables no untyped call.
pub async fn injected_response<S: Storage>(
    store: &mut Store<S>,
    call: u64,
    body: &[u8],
) -> Result<crate::redaction::Redacted, String> {
    store.operation_response(call, body, &[]).await
}

pub const ROOT_PASSWORD: &str = "fixture-root-password-ggw9!";
