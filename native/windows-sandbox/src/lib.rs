//! Standalone Windows sandbox primitives. No Codex runtime or CLI dependency.
//! Experimental: the production entry point stays disabled pending native validation.
pub mod policy_masks;
pub mod protocol;
pub const NATIVE_VALIDATED: bool = false;
#[cfg(windows)]
pub mod acl;
#[cfg(windows)]
pub mod admission;
#[cfg(windows)]
pub mod broker;
#[cfg(windows)]
pub mod desktop;
#[cfg(windows)]
pub mod network;
#[cfg(windows)]
mod proc_thread_attr;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod setup;
#[cfg(windows)]
pub mod token;
#[cfg(windows)]
mod token_user;
#[cfg(windows)]
pub mod winutil;

#[cfg(any(windows, test))]
#[path = "network/firewall_scope.rs"]
mod firewall_scope;
