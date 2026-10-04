//! Explicit, elevated-only setup plus read-only broker logon.
//! Production CLI admission remains gated pending Windows runtime validation.
//! Fresh-only provisioning owns account creation, firewall/WFP, protected DPAPI
//! credential storage, activation, token validation and disable rollback.

mod accounts;
pub(crate) mod dpapi;
pub(crate) mod no_reparse_dir;
mod store;

use anyhow::{bail, Context, Result};
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
    ownership: accounts::FreshAccount,
}

/// Run only from an independently launched, authorized elevated setup process.
/// Creates a new disabled account; refuses to adopt/reset an existing identity.
/// Failure recovery is same-SID/creation-marker bound; inability to verify it is
/// reported explicitly, never treated as proof that the account is disabled. No setup marker or
/// launch-ready claim is emitted, and no password is persisted or logged.
///
/// This primitive is source-complete but is intentionally not exposed by the
/// shipped command-line execution path until Windows validation is complete.
pub fn prepare_disabled_offline_account() -> Result<PreparedOfflineAccount> {
    let mut prepared = create_fresh_disabled_identity()?;
    let installed = crate::network::install_offline_protection(&prepared.sid).and_then(|count| {
        crate::network::verify_offline_protection(&prepared.sid)?;
        Ok(count)
    });
    match installed {
        Ok(count)=>{ prepared.installed_wfp_filter_count=count; Ok(prepared) },
        Err(error)=>match prepared.ownership.rollback() {
            Ok(())=>Err(error.context("phase=prepare-offline-protection; owned account disable verified")),
            Err(recovery)=>Err(anyhow::anyhow!("phase=prepare-offline-protection: {error:#}; DISABLE ROLLBACK FAILED: {recovery:#}")),
        }
    }
}
fn create_fresh_disabled_identity() -> Result<PreparedOfflineAccount> {
    accounts::require_elevated()?;
    let password = accounts::random_password()?;
    let encrypted_password =
        dpapi::protect(password.as_bytes()).context("phase=protect-generated-password")?;
    let ownership = accounts::create_disabled_account(OFFLINE_ACCOUNT, &password)
        .context("phase=create-fresh-disabled-account")?;
    Ok(PreparedOfflineAccount {
        username: OFFLINE_ACCOUNT.to_owned(),
        sid: ownership.sid.clone(),
        installed_wfp_filter_count: 0,
        encrypted_password,
        ownership,
    })
}

/// Read-only fixed local SAM SID. Does not resolve a domain or adopt an account.
pub fn local_offline_account_sid() -> Result<String> {
    Ok(accounts::local_account_state()?.sid)
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
    let store = store::NewStore::create(store_path, broker_owner_sid)
        .context("phase=create-protected-store")?;
    let PreparedOfflineAccount {
        username,
        sid,
        encrypted_password,
        mut ownership,
        ..
    } = create_fresh_disabled_identity()?;
    let mut record = store::Record {
        version: 1,
        ready: false,
        account: username,
        account_sid: sid.clone(),
        owner_sid: broker_owner_sid.to_owned(),
        password_dpapi: encrypted_password,
    };
    let validation = (|| -> Result<()> {
        // Flush an authenticated ready:false record before network work. If that
        // write itself fails, the still-owned in-memory guard is the authority.
        let mut credential_file = store
            .write(&record)
            .context("phase=flush-disabled-account-store")?;
        crate::network::install_offline_protection(&sid)
            .context("phase=install-offline-protection")?;
        crate::network::verify_offline_protection(&sid)
            .context("phase=verify-offline-protection-before-activation")?;
        accounts::set_disabled(&sid, false).context("phase=activate-owned-account")?;
        let plain = zeroize::Zeroizing::new(dpapi::unprotect(&record.password_dpapi)?);
        let password = std::str::from_utf8(&plain)?;
        let token = accounts::logon(password, &sid).context("phase=validate-dedicated-logon")?;
        drop(token);
        store::commit(&mut credential_file, &mut record).context("phase=commit-ready-store")?;
        Ok(())
    })();
    match validation {
        Ok(()) => {
            ownership.disarm();
            Ok(())
        }
        Err(error) => {
            match ownership.rollback() {
                Ok(()) => Err(error
                    .context("provisioning failed; owned account disabled and read-back verified")),
                Err(recovery) => Err(anyhow::anyhow!(
                    "provisioning failed: {error:#}; DISABLE ROLLBACK FAILED: {recovery:#}"
                )),
            }
        }
    }
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
