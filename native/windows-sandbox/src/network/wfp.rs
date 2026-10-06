// Derived from OpenAI Codex (Apache-2.0).
// Source: codex-rs/windows-sandbox-rs/src/wfp.rs
// Pinned revision: a956835d020762cb2b570053af06f643a11c0ecc
// Modified for Pi: standalone modules and product-owned identity; see repository-root third_party/codex/PROVENANCE.md.

mod filter_specs;

use crate::setup::to_wide;
use anyhow::Result;
use std::ffi::OsStr;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Foundation::FWP_E_ALREADY_EXISTS;
use windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_PROVIDER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_SUBLAYER_NOT_FOUND;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionAbort0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionCommit0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_USER_ID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTRL_MATCH_FILTER;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SECURITY_DESCRIPTOR_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0;
use windows_sys::Win32::Security::Authorization::BuildSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::Authorization::{TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W};
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::Threading::INFINITE;

use filter_specs::ConditionSpec;
use filter_specs::FilterSpec;
use filter_specs::FILTER_SPECS;

const SESSION_NAME: &str = "Pi Windows Sandbox WFP";
const PROVIDER_NAME: &str = "Pi Windows Sandbox WFP";
const PROVIDER_DESCRIPTION: &str = "Persistent WFP provider for Pi Windows sandbox filters";
const SUBLAYER_NAME: &str = "Pi Windows Sandbox WFP";
const SUBLAYER_DESCRIPTION: &str = "Persistent WFP sublayer for Pi Windows sandbox filters";

// WFP identifies persistent providers, sublayers, and filters by stable GUIDs.
// These values are Pi-owned identities, distinct from upstream; do not regenerate unless we
// intentionally want to orphan old objects and create a new WFP namespace.
const PROVIDER_KEY: GUID = GUID::from_u128(0xfdf5f7962e035500b81b83e9e8b69f8d);
const SUBLAYER_KEY: GUID = GUID::from_u128(0xa112309bf79e58a7bf97348979bad2fb);

/// Installs the persistent Pi WFP filters for the validated local account SID.
///
/// This is intended to run from the already-elevated setup helper. Callers
/// may continue ordinary setup after an error, but must restore these filters
/// before re-enabling accounts left disabled by interrupted cleanup.
pub fn install_wfp_filters_for_sid(sid: &str) -> Result<usize> {
    // Reject malformed compiled scope and an unowned SID before opening a
    // write transaction. A future spec must never create a global block.
    for spec in FILTER_SPECS {
        validate_user_scope(spec.conditions)?;
    }
    let user_condition = UserMatchCondition::for_sid(sid)?;
    let engine = Engine::open(INFINITE)?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(engine.handle)?;
    ensure_sublayer(engine.handle)?;

    let mut installed_filter_count = 0;
    for spec in FILTER_SPECS {
        delete_filter_if_present(engine.handle, &spec.key)?;
        add_filter(engine.handle, spec, &user_condition)?;
        installed_filter_count += 1;
    }

    transaction.commit()?;
    Ok(installed_filter_count)
}

/// Compiled policy metadata only; neither installs nor inspects OS state.
pub(super) fn expected_filter_count() -> usize {
    FILTER_SPECS.len()
}

pub(crate) fn remove_wfp_filters() -> Result<()> {
    // Leave time for other cleanup if a WFP policy writer holds the transaction lock.
    let engine = Engine::open(/*transaction_wait_timeout_ms*/ 1_000)?;
    let mut transaction = engine.begin_transaction()?;
    for spec in FILTER_SPECS {
        delete_filter_if_present(engine.handle, &spec.key)?;
    }
    for (result, operation, missing) in [
        (
            unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &SUBLAYER_KEY) },
            "FwpmSubLayerDeleteByKey0",
            FWP_E_SUBLAYER_NOT_FOUND as u32,
        ),
        (
            unsafe { FwpmProviderDeleteByKey0(engine.handle, &PROVIDER_KEY) },
            "FwpmProviderDeleteByKey0",
            FWP_E_PROVIDER_NOT_FOUND as u32,
        ),
    ] {
        ensure_success_or(result, operation, &[missing, FWP_E_NOT_FOUND as u32])?;
    }
    transaction.commit()
}

/// Owns an open WFP engine handle and closes it on drop.
struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open(transaction_wait_timeout_ms: u32) -> Result<Self> {
        let session_name = to_wide(OsStr::new(SESSION_NAME));
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: session_name.as_ptr() as *mut _,
            description: null_mut(),
        };
        session.txnWaitTimeoutInMSec = transaction_wait_timeout_ms;

        let mut handle = HANDLE::default();
        let result = unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut handle,
            )
        };
        ensure_success(result, "FwpmEngineOpen0")?;
        Ok(Self { handle })
    }

    fn begin_transaction(&self) -> Result<Transaction<'_>> {
        let result = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        ensure_success(result, "FwpmTransactionBegin0")?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

/// Aborts an open WFP transaction unless it was explicitly committed.
struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl Transaction<'_> {
    fn commit(&mut self) -> Result<()> {
        let result = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        ensure_success(result, "FwpmTransactionCommit0")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

/// Builds the ALE_USER_ID condition blob that scopes filters to one account.
struct UserMatchCondition {
    security_descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

impl UserMatchCondition {
    fn for_sid(sid: &str) -> Result<Self> {
        // Keep direct callers subject to the same fixed-local-account check as
        // network::install_offline_protection; never accept an alias/group SID.
        anyhow::ensure!(
            !sid.is_empty() && sid.starts_with("S-1-5-21-"),
            "expected a nonempty local account SID"
        );
        anyhow::ensure!(
            sid == crate::setup::local_offline_account_sid()?,
            "refusing non-product WFP account"
        );
        let account_sid = crate::token::LocalSid::from_string(sid)?;
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FWP_ACTRL_MATCH_FILTER,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: 0,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_USER,
                ptstrName: account_sid.as_ptr().cast(),
            },
        };

        let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut security_descriptor_len = 0;
        let result = unsafe {
            BuildSecurityDescriptorW(
                null(),
                null(),
                1,
                &access,
                0,
                null(),
                null_mut(),
                &mut security_descriptor_len,
                &mut security_descriptor,
            )
        };
        ensure_success(result, "BuildSecurityDescriptorW")?;

        let condition = Self {
            security_descriptor,
            blob: FWP_BYTE_BLOB {
                size: security_descriptor_len,
                data: security_descriptor as *mut u8,
            },
        };
        anyhow::ensure!(
            !condition.blob.data.is_null() && condition.blob.size > 0,
            "empty WFP account security descriptor"
        );
        Ok(condition)
    }
}

impl Drop for UserMatchCondition {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor as HLOCAL);
            }
        }
    }
}

/// Ensures the persistent Pi WFP provider exists.
fn ensure_provider(engine: HANDLE) -> Result<()> {
    let provider_name = to_wide(OsStr::new(PROVIDER_NAME));
    let provider_description = to_wide(OsStr::new(PROVIDER_DESCRIPTION));
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: provider_name.as_ptr() as *mut _,
            description: provider_description.as_ptr() as *mut _,
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: null_mut(),
    };

    let result = unsafe { FwpmProviderAdd0(engine, &provider, null_mut()) };
    ensure_success_or(result, "FwpmProviderAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Ensures the persistent Pi sublayer exists under the Pi provider.
fn ensure_sublayer(engine: HANDLE) -> Result<()> {
    let sublayer_name = to_wide(OsStr::new(SUBLAYER_NAME));
    let sublayer_description = to_wide(OsStr::new(SUBLAYER_DESCRIPTION));
    let provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: sublayer_name.as_ptr() as *mut _,
            description: sublayer_description.as_ptr() as *mut _,
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        weight: 0x8000,
    };

    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    ensure_success_or(result, "FwpmSubLayerAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Adds one blocking WFP filter from the static filter spec list.
fn add_filter(
    engine: HANDLE,
    spec: &FilterSpec,
    user_condition: &UserMatchCondition,
) -> Result<()> {
    let filter_name = to_wide(OsStr::new(spec.name));
    let filter_description = to_wide(OsStr::new(spec.description));
    let mut filter_conditions = build_conditions(spec.conditions, user_condition)?;
    let provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: spec.key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: filter_name.as_ptr() as *mut _,
            description: filter_description.as_ptr() as *mut _,
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        layerKey: spec.layer_key,
        subLayerKey: SUBLAYER_KEY,
        weight: empty_value(),
        numFilterConditions: filter_conditions.len() as u32,
        filterCondition: filter_conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: zero_guid(),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };

    let mut filter_id = 0_u64;
    let result = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
    ensure_success(result, &format!("FwpmFilterAdd0({})", spec.name))
}

/// Converts our compact condition specs into WFP filter conditions.
fn build_conditions(
    specs: &[ConditionSpec],
    user_condition: &UserMatchCondition,
) -> Result<Vec<FWPM_FILTER_CONDITION0>> {
    validate_user_scope(specs)?;
    Ok(specs
        .iter()
        .map(|spec| match spec {
            ConditionSpec::User => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: &user_condition.blob as *const _ as *mut _,
                    },
                },
            },
            ConditionSpec::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                },
            },
            ConditionSpec::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
        })
        .collect())
}

/// Exactly one account condition is mandatory even for port/protocol filters.
/// This pure guard rejects empty, account-free, or ambiguous duplicated scope.
fn validate_user_scope(specs: &[ConditionSpec]) -> Result<()> {
    anyhow::ensure!(
        specs
            .iter()
            .filter(|condition| matches!(condition, ConditionSpec::User))
            .count()
            == 1,
        "WFP filter requires exactly one owned-account user condition"
    );
    Ok(())
}

/// Deletes an old copy of a filter before re-adding it.
fn delete_filter_if_present(engine: HANDLE, key: &GUID) -> Result<()> {
    let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
    ensure_success_or(
        result,
        "FwpmFilterDeleteByKey0",
        &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
    )
}

fn ensure_success(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(result, operation, &[])
}

fn ensure_success_or(result: u32, operation: &str, allowed: &[u32]) -> Result<()> {
    if result == 0 || allowed.contains(&result) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{operation} failed: {}",
            format_error_code(result)
        ))
    }
}

fn format_error_code(result: u32) -> String {
    format!("0x{result:08X}")
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: null_mut(),
    }
}

fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { zeroed() },
    }
}

fn zero_guid() -> GUID {
    GUID::from_u128(0)
}

#[cfg(test)]
mod tests {
    use super::{validate_user_scope, ConditionSpec};
    use super::FILTER_SPECS;

    use std::collections::BTreeSet;

    #[test]
    fn filter_keys_are_unique() {
        let keys = FILTER_SPECS
            .iter()
            .map(|spec| {
                (
                    spec.key.data1,
                    spec.key.data2,
                    spec.key.data3,
                    spec.key.data4,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), FILTER_SPECS.len());
    }

    #[test]
    fn filter_names_are_unique() {
        let names = FILTER_SPECS
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), FILTER_SPECS.len());
    }

    #[test]
    fn every_filter_has_exactly_one_account_condition() {
        for spec in FILTER_SPECS {
            validate_user_scope(spec.conditions).unwrap();
        }
        assert!(validate_user_scope(&[]).is_err());
        assert!(validate_user_scope(&[ConditionSpec::Protocol(6)]).is_err());
        assert!(validate_user_scope(&[ConditionSpec::RemotePort(53)]).is_err());
        assert!(validate_user_scope(&[ConditionSpec::User, ConditionSpec::User]).is_err());
        assert!(validate_user_scope(&[ConditionSpec::User]).is_ok());
    }

    #[test]
    fn compiled_filter_count_matches_lab_feature() {
        assert_eq!(
            FILTER_SPECS.len(),
            if cfg!(feature = "lab-python-policy-repair-comparison") { 14 } else { 12 }
        );
    }
}

/// Fresh lab provisioning must not adopt or replace an existing product namespace.
pub fn require_namespace_absent() -> Result<()> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    let engine = Engine::open(1000)?;
    unsafe {
        let mut provider = null_mut();
        let code = FwpmProviderGetByKey0(engine.handle, &PROVIDER_KEY, &mut provider);
        if !provider.is_null() {
            FwpmFreeMemory0((&mut provider as *mut *mut FWPM_PROVIDER0).cast());
        }
        anyhow::ensure!(
            code == FWP_E_PROVIDER_NOT_FOUND as u32,
            "existing or unreadable Pi WFP provider: {code}"
        );
        let mut sublayer = null_mut();
        let code = FwpmSubLayerGetByKey0(engine.handle, &SUBLAYER_KEY, &mut sublayer);
        if !sublayer.is_null() {
            FwpmFreeMemory0((&mut sublayer as *mut *mut FWPM_SUBLAYER0).cast());
        }
        anyhow::ensure!(
            code == FWP_E_SUBLAYER_NOT_FOUND as u32,
            "existing or unreadable Pi WFP sublayer: {code}"
        );
        for spec in FILTER_SPECS {
            let mut filter = null_mut();
            let code = FwpmFilterGetByKey0(engine.handle, &spec.key, &mut filter);
            if !filter.is_null() {
                FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast());
            }
            anyhow::ensure!(
                code == FWP_E_FILTER_NOT_FOUND as u32,
                "existing or unreadable Pi WFP filter: {code}"
            );
        }
    }
    Ok(())
}

fn same_guid(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

/// Strict read-only inspection of installed filters against compiled specifications.
/// Exact descriptor equality is intentionally conservative (normalization may refuse).
pub fn verify_wfp_filters_for_sid(sid: &str) -> Result<()> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    let user = UserMatchCondition::for_sid(sid)?;
    let engine = Engine::open(1000)?;
    for spec in FILTER_SPECS {
        validate_user_scope(spec.conditions)?;
        unsafe {
            let mut raw = null_mut();
            ensure_success(
                FwpmFilterGetByKey0(engine.handle, &spec.key, &mut raw),
                "read WFP filter",
            )?;
            let checked = (|| -> Result<()> {
                anyhow::ensure!(!raw.is_null(), "null WFP filter");
                let f = &*raw;
                anyhow::ensure!(
                    same_guid(&f.filterKey, &spec.key)
                        && same_guid(&f.layerKey, &spec.layer_key)
                        && same_guid(&f.subLayerKey, &SUBLAYER_KEY)
                        && !f.providerKey.is_null()
                        && same_guid(&*f.providerKey, &PROVIDER_KEY),
                    "WFP filter identity mismatch"
                );
                anyhow::ensure!(
                    f.flags == FWPM_FILTER_FLAG_PERSISTENT
                        && f.action.r#type == FWP_ACTION_BLOCK
                        && f.numFilterConditions as usize == spec.conditions.len()
                        && !f.filterCondition.is_null(),
                    "WFP filter scope mismatch"
                );
                let expected = build_conditions(spec.conditions, &user)?;
                for (actual, expected) in
                    std::slice::from_raw_parts(f.filterCondition, f.numFilterConditions as usize)
                        .iter()
                        .zip(&expected)
                {
                    anyhow::ensure!(
                        same_guid(&actual.fieldKey, &expected.fieldKey)
                            && actual.matchType == expected.matchType
                            && actual.conditionValue.r#type == expected.conditionValue.r#type,
                        "WFP condition mismatch"
                    );
                    let a = actual.conditionValue.Anonymous;
                    let e = expected.conditionValue.Anonymous;
                    let matches = match actual.conditionValue.r#type {
                        FWP_UINT8 => a.uint8 == e.uint8,
                        FWP_UINT16 => a.uint16 == e.uint16,
                        FWP_SECURITY_DESCRIPTOR_TYPE => {
                            !a.sd.is_null()
                                && !(*a.sd).data.is_null()
                                && (*a.sd).size == (*e.sd).size
                                && std::slice::from_raw_parts((*a.sd).data, (*a.sd).size as usize)
                                    == std::slice::from_raw_parts(
                                        (*e.sd).data,
                                        (*e.sd).size as usize,
                                    )
                        }
                        _ => false,
                    };
                    anyhow::ensure!(matches, "WFP condition value mismatch");
                }
                Ok(())
            })();
            FwpmFreeMemory0((&mut raw as *mut *mut FWPM_FILTER0).cast());
            checked?;
        }
    }
    Ok(())
}
