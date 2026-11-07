#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the browser transport is not compiled on the host"
    )
)]
pub mod inference;
#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the provider adapter is driven by the dedicated browser worker"
    )
)]
pub mod provisioning;
pub mod run;
pub mod targets;
#[cfg(target_arch = "wasm32")]
pub(crate) mod web;

pub(crate) mod wait;
