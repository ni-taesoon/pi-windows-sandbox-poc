//! Offline policy extracted from the pinned Apache-2.0 Windows sandbox sources.
//! Installation is a privileged SETUP action, never part of ordinary execution.
//! It does not prove enforcement: Windows adversarial tests remain mandatory.
mod firewall;
mod wfp;

use anyhow::{ensure, Result};

pub(crate) fn install_offline_protection(sid: &str) -> Result<usize> {
    ensure!(
        sid == crate::setup::local_offline_account_sid()?,
        "refusing non-product account"
    );
    // The fixed local SAM identity is re-read; no account-name lookup is used.
    ensure!(sid.starts_with("S-1-5-21-"), "expected a local account SID");
    let mut log = std::io::sink();
    firewall::ensure_offline_network_blocks(sid, &mut log)?;
    // WFP failure propagates; caller must never activate the account on error.
    wfp::install_wfp_filters_for_sid(sid)
}

/// Read-only configuration preflight; does not substitute for traffic tests.
pub fn verify_offline_protection(sid: &str) -> Result<()> {
    ensure!(
        sid == crate::setup::local_offline_account_sid()?,
        "non-product account"
    );
    firewall::verify_offline_network_blocks(sid)?;
    wfp::verify_wfp_filters_for_sid(sid)
}

/// Read-only collision check, intended before fresh disposable-lab setup.
pub fn require_product_namespace_absent() -> Result<()> {
    firewall::require_namespace_absent()?;
    wfp::require_namespace_absent()
}
