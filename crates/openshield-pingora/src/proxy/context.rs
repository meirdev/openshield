use openshield_core::{Intervention, Transaction};

use super::metrics::ACTIVE_CONNECTIONS;

pub struct RequestCtx {
    pub tx: Transaction,
    /// Block decision from a request-body phase, rendered in `fail_to_proxy`.
    pub pending_block: Option<Intervention>,
}

impl Drop for RequestCtx {
    fn drop(&mut self) {
        ACTIVE_CONNECTIONS.dec();
    }
}
