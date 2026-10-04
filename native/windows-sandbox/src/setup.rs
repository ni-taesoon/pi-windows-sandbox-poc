//! Explicit, elevated-only setup plus read-only broker logon.
//! Production CLI admission remains gated pending Windows runtime validation.
//! Fresh-only provisioning owns account creation, firewall/WFP, protected DPAPI
//! credential storage, activation, token validation and disable rollback.

mod accounts;
pub(crate) mod dpapi;
pub(crate) mod no_reparse_dir;
mod store;

use anyhow::{bail, Result};
use std::ffi::OsStr;
use std::fmt;
use std::os::windows::ffi::OsStrExt;

pub const OFFLINE_ACCOUNT: &str = "PiSandboxOffline";

/// A preparation result is deliberately NOT serializable or Debug: it carries
/// credential material. Machine-scope DPAPI is not an access-control boundary;
/// the broker credential store must have a verified protected DACL.
pub struct PreparedOfflineAccount {
    pub username: String,
    pub sid: String,
    pub installed_wfp_filter_count: usize,
    pub(crate) encrypted_password: Vec<u8>,
}

/// Run only from an independently launched, authorized elevated setup process.
/// Creates a new disabled account; refuses to adopt/reset an existing identity.
/// On any error after creation, the account remains disabled. No setup marker or
/// launch-ready claim is emitted, and no password is persisted or logged.
///
/// This primitive is source-complete but is intentionally not exposed by the
/// shipped command-line execution path until Windows validation is complete.
pub fn prepare_disabled_offline_account() -> Result<PreparedOfflineAccount> {
    accounts::require_elevated()?;
    let password = accounts::random_password()?;
    let encrypted_password = dpapi::protect(password.as_bytes())?;
    accounts::create_disabled_account(OFFLINE_ACCOUNT, &password)?;
    let local_account = format!(".\\{}", OFFLINE_ACCOUNT);
    let sid = accounts::account_sid_string(&local_account)?;
    let installed_wfp_filter_count =
        crate::network::install_offline_protection(&local_account, &sid)?;
    Ok(PreparedOfflineAccount {
        username: OFFLINE_ACCOUNT.to_owned(),
        sid,
        installed_wfp_filter_count,
        encrypted_password,
    })
}

/// A setup result alone is never a launch capability.
pub fn require_validated_activation() -> Result<()> {
    bail!("PI_NATIVE_NOT_VALIDATED: native account activation, credential store and execution have not been runtime-validated on Windows")
}

pub(crate) fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SetupErrorCode {
    HelperFirewallComInitFailed,
    HelperFirewallPolicyAccessFailed,
    HelperFirewallPolicyIneffective,
    HelperFirewallRuleCreateOrAddFailed,
    HelperFirewallRuleVerifyFailed,
}
#[derive(Debug)]
pub(crate) struct SetupFailure {
    pub code: SetupErrorCode,
    message: String,
}
impl SetupFailure {
    pub fn new(code: SetupErrorCode, message: String) -> Self {
        Self { code, message }
    }
}
impl fmt::Display for SetupFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}
impl std::error::Error for SetupFailure {}

/// Explicit elevated provisioning transaction. The store path must be a new
/// local directory under an existing parent; no reparse component is traversed.
/// A protected credential record is flushed before activation. Errors after
/// activation trigger an owned-SID-checked disable rollback and report failure.
/// This library API remains behind the production CLI validation gate.
pub fn provision_offline_account(
    store_path: &std::path::Path,
    broker_owner_sid: &str,
) -> Result<()> {
    accounts::require_elevated()?;
    let store = store::NewStore::create(store_path, broker_owner_sid)?;
    let prepared = prepare_disabled_offline_account()?;
    let mut record = store::Record {
        version: 1,
        ready: false,
        account: prepared.username,
        account_sid: prepared.sid.clone(),
        owner_sid: broker_owner_sid.to_owned(),
        password_dpapi: prepared.encrypted_password,
    };
    let mut credential_file = store.write(&record)?;
    let validation = (|| -> Result<()> {
        accounts::set_disabled(&prepared.sid, false)?;
        let plain = zeroize::Zeroizing::new(dpapi::unprotect(&record.password_dpapi)?);
        let password = std::str::from_utf8(&plain)?;
        let token = accounts::logon(password, &prepared.sid)?;
        drop(token);
        store::commit(&mut credential_file, &mut record)?;
        Ok(())
    })();
    if let Err(error) = validation {
        return match accounts::set_disabled(&prepared.sid, true) {
            Ok(()) => Err(error.context("provisioning failed; account disabled")),
            Err(rollback) => Err(anyhow::anyhow!(
                "provisioning failed: {error}; DISABLE ROLLBACK FAILED: {rollback}"
            )),
        };
    }
    Ok(())
}

/// Read-only broker logon seam. The protected store is authenticated by its
/// handle security descriptor, owner, product record, then token SID and groups.
/// It never provisions, repairs, enables accounts, or modifies firewall policy.
pub fn logon_offline_account(
    store_path: &std::path::Path,
    broker_owner_sid: &str,
) -> Result<crate::process::Handle> {
    let record = store::read(store_path, broker_owner_sid)?;
    anyhow::ensure!(
        record.ready,
        "account provisioning has not committed readiness"
    );
    let plain = zeroize::Zeroizing::new(dpapi::unprotect(&record.password_dpapi)?);
    let password = std::str::from_utf8(&plain)?;
    accounts::logon(password, &record.account_sid)
}

/// Explicit elevated shutdown/recovery action scoped to the protected record.
/// It does not remove persistent protections or delete credentials/accounts.
pub fn disable_offline_account(store_path: &std::path::Path, broker_owner_sid: &str) -> Result<()> {
    accounts::require_elevated()?;
    let record = store::read(store_path, broker_owner_sid)?;
    accounts::set_disabled(&record.account_sid, true)
}

/// Validated broker identity; callers cannot construct one from an arbitrary token.
pub struct OfflineIdentity {
    token: crate::process::Handle,
    sid: String,
}
impl OfflineIdentity {
    pub fn token(&self) -> &crate::process::Handle {
        &self.token
    }
    pub fn sid(&self) -> &str {
        &self.sid
    }
}
pub fn logon_offline_identity(
    store_path: &std::path::Path,
    broker_owner_sid: &str,
) -> Result<OfflineIdentity> {
    let record = store::read(store_path, broker_owner_sid)?;
    anyhow::ensure!(
        record.ready,
        "account provisioning has not committed readiness"
    );
    let plain = zeroize::Zeroizing::new(dpapi::unprotect(&record.password_dpapi)?);
    let password = std::str::from_utf8(&plain)?;
    let token = accounts::logon(password, &record.account_sid)?;
    Ok(OfflineIdentity {
        token,
        sid: record.account_sid,
    })
}

pub mod launch;
