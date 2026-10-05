//! Standalone Windows sandbox primitives. No Codex runtime or CLI dependency.
//! Experimental: the production entry point stays disabled pending native validation.
#[cfg(all(
    feature = "lab-minimal-load-comparison",
    any(feature = "lab-loader-trace", feature = "lab-loader-probe", feature = "lab-sechost-breakpoints")
))]
compile_error!("minimal load comparison cannot be combined with advanced diagnostic features");
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
#[cfg(all(windows, feature = "lab-loader-trace"))]
mod loader_trace;
#[cfg(windows)]
pub mod network;
#[cfg(windows)]
mod proc_thread_attr;
#[cfg(windows)]
pub mod process;
#[cfg(all(windows, feature = "lab-sechost-breakpoints"))]
mod sechost_breakpoints;
#[cfg(windows)]
pub mod setup;
#[cfg(all(windows, not(feature = "lab-minimal-load-comparison")))]
mod startup_diagnostics;
#[cfg(windows)]
pub mod token;
#[cfg(windows)]
mod token_user;
#[cfg(windows)]
pub mod winutil;

#[cfg(any(windows, test))]
#[path = "network/firewall_scope.rs"]
mod firewall_scope;
