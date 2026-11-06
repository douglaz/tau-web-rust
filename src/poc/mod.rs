#[cfg_attr(
    not(target_arch = "wasm32"),
    allow(
        dead_code,
        reason = "the browser transport is not compiled on the host"
    )
)]
pub mod inference;
pub mod run;
pub mod targets;
#[cfg(target_arch = "wasm32")]
pub(crate) mod web;

pub(crate) mod wait;
