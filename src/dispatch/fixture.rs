//! Host-only fixture adapter. Mutations are reconcile-before-retry (`STA-5`): no mutation
//! response confirms anything. Only the fixture status contract reports an observed effect.

use super::*;
use crate::store::{OperationError, Storage, Store};

#[derive(Default)]
pub struct Vendor {
    pub received: Vec<OperationIntent>,
    pub pause_before_send: bool,
}

impl Vendor {
    pub const RETRY_SAFETY: &str = "reconcile-before-retry";

    pub async fn run<S: Storage>(
        &mut self,
        store: &mut Store<S>,
        request: &Request,
    ) -> Result<u64, OperationError> {
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
        Ok(call)
    }

    pub async fn status<S: Storage>(
        &mut self,
        store: &mut Store<S>,
        request: &Request,
        operation: Operation,
        reports: Reports,
    ) -> Result<Vec<u64>, OperationError> {
        let resource = store
            .dispatch()
            .check_request(request)
            .map_err(OperationError::Policy)?;
        assert_eq!(request.operation, Operation::Read);
        let observation = store.dispatch().observation(resource, operation, reports);
        self.run(store, request).await?;
        store
            .operation_observation(observation)
            .await
            .map_err(OperationError::Storage)
    }
}
