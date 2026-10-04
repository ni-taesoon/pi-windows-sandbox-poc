//! Offline policy extracted from the pinned Apache-2.0 Windows sandbox sources.
//! Installation is a privileged SETUP action, never part of ordinary execution.
//! It does not prove enforcement: Windows adversarial tests remain mandatory.
mod firewall;
mod wfp;

use anyhow::{ensure, Result};

pub(crate) fn install_offline_protection(account: &str, sid: &str) -> Result<usize> {
    ensure!(
        account == format!(".\\{}", crate::setup::OFFLINE_ACCOUNT),
        "refusing non-product account"
    );
    // The SID comes from LookupAccountNameW after creating our disabled account.
    ensure!(sid.starts_with("S-1-5-21-"), "expected a local account SID");
    let mut log = std::io::sink();
    firewall::ensure_offline_network_blocks(sid, &mut log)?;
    // WFP failure propagates; caller must never activate the account on error.
    wfp::install_wfp_filters_for_account(account)
}
