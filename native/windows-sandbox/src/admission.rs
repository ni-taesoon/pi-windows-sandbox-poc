//! Experimental trusted-broker composition, not a public IPC authorization endpoint.
//! Per-account ACLs are serialized by a global product lease; per-run capability
//! ACEs constrain write access. Existing account ACEs fail closed for explicit recovery.
use crate::{
    desktop::PrivateDesktop,
    process::{run_restricted, Handle},
    protocol::{RunRequest, RunResult},
    setup::no_reparse_dir as nr,
    token, winutil,
};
use anyhow::{ensure, Context, Result};
use std::{
    ffi::c_void,
    fs::File,
    os::windows::io::{AsHandle, AsRawHandle, OwnedHandle},
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HANDLE, HLOCAL},
    Security::Authorization::*,
    Security::*,
    Storage::FileSystem::*,
};

struct Target {
    handle: OwnedHandle,
    path: PathBuf,
    mode: ACCESS_MODE,
    mask: u32,
}
/// A trusted admission owns target pins/guards, the restricted token and desktop.
/// Dropping without launching intentionally retains restrictive ACEs. The broker
/// should run/finish each admitted launch, then record cleanup errors for repair.
pub struct AdmittedLaunch {
    request: RunRequest,
    targets: Vec<Target>,
    _pins: Vec<OwnedHandle>,
    _guards: Vec<OwnedHandle>,
    account_sid: token::LocalSid,
    capability: token::LocalSid,
    capability_string: String,
    _account_lease: Option<Handle>,
    restricted: Handle,
    desktop: PrivateDesktop,
}
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE; // Never share deletion.
const ACCESS: u32 = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES | FILE_READ_DATA;
const WRITE_ALLOW: u32 = FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
// Avoid READ_CONTROL/SYNCHRONIZE carried by FILE_GENERIC_WRITE in a deny ACE.
const WRITE_DENY: u32 = crate::policy_masks::WRITE_DENY;

fn edit_acl(target: &Target, sid: *mut c_void, mode: ACCESS_MODE, mask: u32) -> Result<()> {
    unsafe {
        let mut sd = null_mut();
        let mut dacl = null_mut();
        let status = GetSecurityInfo(
            target.handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        ensure!(status == 0, "read target ACL failed: {status}");
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: mask,
            grfAccessMode: mode,
            grfInheritance: 3,
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
            },
        };
        let mut updated = null_mut();
        let status = SetEntriesInAclW(1, &entry, dacl, &mut updated);
        if status != 0 {
            LocalFree(sd as HLOCAL);
            anyhow::bail!("build target ACL failed: {status}");
        }
        let status = SetSecurityInfo(
            target.handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            updated,
            null(),
        );
        LocalFree(updated as HLOCAL);
        LocalFree(sd as HLOCAL);
        ensure!(
            status == 0,
            "write target ACL failed for {}: {status}",
            target.path.display()
        );
        Ok(())
    }
}
fn already_has_sid(target: &Target, sid: *mut c_void) -> Result<bool> {
    unsafe {
        let mut sd = null_mut();
        let mut dacl = null_mut();
        let status = GetSecurityInfo(
            target.handle.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut sd,
        );
        ensure!(status == 0, "inspect launch SID ACL failed");
        let result = (|| -> Result<bool> {
            ensure!(
                !dacl.is_null() && IsValidAcl(dacl) != 0,
                "null/invalid DACL unsupported"
            );
            for i in 0..(*dacl).AceCount {
                let mut ace: *mut c_void = null_mut();
                ensure!(GetAce(dacl, i as u32, &mut ace) != 0, "invalid ACE");
                let h = &*(ace as *const ACE_HEADER);
                // Unknown/object/callback ACEs are refused instead of assuming safe inheritance.
                ensure!(
                    h.AceType == 0 || h.AceType == 1,
                    "complex ACE not supported by experimental admission"
                );
                let a = &*(ace as *const ACCESS_ALLOWED_ACE);
                if EqualSid(std::ptr::addr_of!(a.SidStart).cast_mut().cast(), sid) != 0 {
                    return Ok(true);
                }
            }
            Ok(false)
        })();
        LocalFree(sd as HLOCAL);
        result
    }
}
fn enumerate(
    path: &Path,
    mode: ACCESS_MODE,
    mask: u32,
    targets: &mut Vec<Target>,
    pins: &mut Vec<OwnedHandle>,
    guards: &mut Vec<OwnedHandle>,
) -> Result<()> {
    nr::validate_local_directory_path(path)?;
    ensure!(
        path.parent().is_some() && path.file_name().is_some(),
        "filesystem roots are not admissible"
    );
    ensure!(path.components().count() <= 128, "policy tree too deep");
    // Pin every ancestor so pathname enumeration cannot be redirected by renames.
    for ancestor in path.parent().unwrap().ancestors() {
        pins.push(nr::open_directory_no_reparse(
            ancestor,
            FILE_TRAVERSE,
            SHARE,
            nr::DirectoryOpenDisposition::OpenExisting,
        )?);
    }
    let parent = nr::open_directory_no_reparse(
        path.parent().unwrap(),
        FILE_TRAVERSE,
        SHARE,
        nr::DirectoryOpenDisposition::OpenExisting,
    )?;
    let mut leaf = winutil::to_wide(path.file_name().unwrap());
    let handle = nr::open_no_reparse(
        parent.as_raw_handle() as HANDLE,
        &mut leaf,
        ACCESS,
        SHARE,
        1,
        0,
        null(),
    )?;
    pins.push(parent);
    let metadata = File::from(handle.try_clone()?).metadata()?;
    if metadata.is_file() {
        let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(
            unsafe {
                GetFileInformationByHandle(handle.as_raw_handle() as HANDLE, &mut information)
            } != 0,
            "cannot inspect file hardlinks"
        );
        ensure!(
            information.nNumberOfLinks == 1,
            "hardlinked policy targets unsupported"
        );
    }
    ensure!(
        targets.len() < 10_000,
        "policy tree too large for bounded admission"
    );
    if metadata.is_dir() {
        // A guard prevents converting a pinned empty directory into a reparse point.
        // Snapshot names before guard creation. Do not skip user-controlled names.
        let children = std::fs::read_dir(path)?.collect::<std::io::Result<Vec<_>>>()?;
        for child in children {
            enumerate(&child.path(), mode, mask, targets, pins, guards)?;
        }
    }
    ensure!(
        targets.len() < 10_000,
        "policy tree too large for bounded admission"
    );
    targets.push(Target {
        handle,
        path: path.to_owned(),
        mode,
        mask,
    });
    Ok(())
}
impl AdmittedLaunch {
    /// Broker composition using the protected-store logon identity.
    /// # Safety
    /// Same trusted policy/authorization/network and fresh-logon preconditions as prepare.
    pub unsafe fn from_identity(
        identity: &crate::setup::OfflineIdentity,
        request: RunRequest,
    ) -> Result<Self> {
        Self::prepare(identity.token(), identity.sid(), request)
    }

    /// Compose policy ACLs, strict restricted token and private desktop.
    /// Exact existing local paths only; globs, absent paths, network paths and reparses
    /// fail closed. Bound: 10,000 objects, 128 path components. Complex ACEs rejected.
    /// # Safety
    /// Caller must authenticate this policy/digest/request, serialize policy admission,
    /// verify the fresh base logon belongs to its provisioned PiSandboxOffline account,
    /// ensure the account's WFP/firewall rules are installed and effective, and authorize
    /// ACL changes on every specified path. The base logon MUST NOT have run untrusted
    /// code already. The broker and policy files must be outside all writable roots.
    /// Admission does not turn an untrusted JSON request into trusted authority.
    pub unsafe fn prepare(
        base: &Handle,
        expected_account_sid: &str,
        request: RunRequest,
    ) -> Result<Self> {
        let current = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let owner = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(current.raw())?)
            .map_err(anyhow::Error::msg)?;
        Self::prepare_impl(
            base,
            expected_account_sid,
            request,
            Some(acquire_account_lease(&owner)?),
        )
    }
    pub(crate) unsafe fn prepare_under_lease(
        base: &Handle,
        expected_account_sid: &str,
        request: RunRequest,
        _lease: &Handle,
    ) -> Result<Self> {
        Self::prepare_impl(base, expected_account_sid, request, None)
    }
    unsafe fn prepare_impl(
        base: &Handle,
        expected_account_sid: &str,
        request: RunRequest,
        account_lease: Option<Handle>,
    ) -> Result<Self> {
        request.validate()?;
        let actual = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(base.raw())?)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            actual == expected_account_sid,
            "base logon account mismatch"
        );
        let current = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let current_sid =
            winutil::string_from_sid_bytes(&token::get_user_sid_bytes(current.raw())?)
                .map_err(anyhow::Error::msg)?;
        ensure!(
            actual != current_sid,
            "same-user sandbox fallback forbidden"
        );
        let account_sid = token::LocalSid::from_string(&actual)?;
        let mut random = [0u8; 16];
        ensure!(
            Cryptography::BCryptGenRandom(
                null_mut(),
                random.as_mut_ptr(),
                16,
                Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG
            ) >= 0,
            "capability RNG failed"
        );
        let parts: Vec<_> = random
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();
        let capability_string = format!(
            "S-1-5-21-{}-{}-{}-{}",
            parts[0], parts[1], parts[2], parts[3]
        );
        let cap = token::LocalSid::from_string(&capability_string)?;
        let restricted = Handle::from_raw(token::create_strict_write_token_from(
            base.raw(),
            &[cap.as_ptr()],
        )?)?;
        let desktop = PrivateDesktop::for_token_with_cap(base.raw(), Some(&capability_string))?;
        let (mut targets, mut pins, mut guards) = (Vec::new(), Vec::new(), Vec::new());
        // Explicit denies first; they also cover protected-inheritance existing descendants
        // through direct ACEs on pinned objects, and future descendants by inheritance.
        for path in &request.policy.deny_read {
            enumerate(
                Path::new(path),
                DENY_ACCESS,
                FILE_GENERIC_READ | WRITE_DENY,
                &mut targets,
                &mut pins,
                &mut guards,
            )?;
        }
        for path in &request.policy.deny_write {
            enumerate(
                Path::new(path),
                DENY_ACCESS,
                WRITE_DENY,
                &mut targets,
                &mut pins,
                &mut guards,
            )?;
        }
        for path in &request.policy.writable_roots {
            enumerate(
                Path::new(path),
                GRANT_ACCESS,
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | WRITE_ALLOW,
                &mut targets,
                &mut pins,
                &mut guards,
            )?;
        }
        // Create guards only after every overlapping subtree has been enumerated, so
        // our own delete-on-close guard cannot conflict with a later target pin.
        let mut guarded = std::collections::HashSet::new();
        for target in &targets {
            if File::from(target.handle.try_clone()?).metadata()?.is_dir() {
                let mut info: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
                ensure!(
                    GetFileInformationByHandle(target.handle.as_raw_handle() as HANDLE, &mut info)
                        != 0,
                    "directory identity unavailable"
                );
                if guarded.insert((
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                )) {
                    guards.push(nr::create_directory_guard(target.handle.as_handle())?);
                    // Reject a path converted to a reparse before the guard existed.
                    let pin = nr::open_directory_no_reparse(
                        &target.path,
                        FILE_TRAVERSE,
                        SHARE,
                        nr::DirectoryOpenDisposition::OpenExisting,
                    )?;
                    let mut current: BY_HANDLE_FILE_INFORMATION = std::mem::zeroed();
                    ensure!(
                        GetFileInformationByHandle(pin.as_raw_handle() as HANDLE, &mut current)
                            != 0,
                        "guarded directory identity unavailable"
                    );
                    ensure!(
                        (
                            info.dwVolumeSerialNumber,
                            info.nFileIndexHigh,
                            info.nFileIndexLow
                        ) == (
                            current.dwVolumeSerialNumber,
                            current.nFileIndexHigh,
                            current.nFileIndexLow
                        ),
                        "policy target changed during admission"
                    );
                    pins.push(pin);
                }
            }
        }
        // All objects must be inspected before edits; no pre-existing ACE for this fresh logon.
        for target in &targets {
            ensure!(
                !already_has_sid(target, account_sid.as_ptr())?,
                "account SID already has policy ACL; clean account ACL required"
            );
        }
        for (index, target) in targets.iter().enumerate() {
            let applied = edit_acl(target, account_sid.as_ptr(), target.mode, target.mask)
                .and_then(|()| {
                    if target.mode == GRANT_ACCESS {
                        edit_acl(target, cap.as_ptr(), target.mode, target.mask)
                    } else {
                        Ok(())
                    }
                });
            if let Err(error) = applied {
                let mut rollback_failed = false;
                for previous in targets[..=index].iter().rev() {
                    rollback_failed |=
                        edit_acl(previous, account_sid.as_ptr(), REVOKE_ACCESS, 0).is_err();
                    rollback_failed |= edit_acl(previous, cap.as_ptr(), REVOKE_ACCESS, 0).is_err();
                }
                anyhow::bail!(
                    "policy admission failed: {error}; rollback_failed={rollback_failed}"
                );
            }
        }
        Ok(Self {
            request,
            targets,
            _pins: pins,
            _guards: guards,
            account_sid,
            capability: cap,
            capability_string,
            _account_lease: account_lease,
            restricted,
            desktop,
        })
    }
    /// Launch and revoke per-account/capability policy ACEs only after process-tree death is verified.
    /// On execution/cleanup error, per-account/capability ACEs remain for explicit broker recovery;
    /// this deliberately preserves read denies if any descendant's death is uncertain.
    pub fn run(self) -> Result<RunResult> {
        let result =
            unsafe { run_restricted(self.restricted.raw(), self.desktop.name(), &self.request) }
                .context(
                    "launch failed; per-account/capability ACLs retained until verified cleanup",
                )?;
        self.finish_after_verified_cleanup(result)
    }
    pub(crate) fn helper_payload(&self, parent_wait_handle: u64) -> crate::broker::HelperPayload {
        crate::broker::HelperPayload {
            parent_wait_handle,
            request: self.request.clone(),
            capability_sid: self.capability_string.clone(),
            private_desktop: self.desktop.name().to_owned(),
        }
    }
    /// The caller must have independently verified the outer helper job is empty.
    pub(crate) fn finish_after_verified_cleanup(self, result: RunResult) -> Result<RunResult> {
        ensure!(result.cleanup_verified, "unverified cleanup; ACLs retained");
        let mut failures = Vec::new();
        for target in self.targets.iter().rev() {
            if let Err(e) = edit_acl(target, self.account_sid.as_ptr(), REVOKE_ACCESS, 0) {
                failures.push(e.to_string());
            }
            if let Err(e) = edit_acl(target, self.capability.as_ptr(), REVOKE_ACCESS, 0) {
                failures.push(e.to_string());
            }
        }
        ensure!(
            failures.is_empty(),
            "job dead but ACL cleanup incomplete: {}",
            failures.join("; ")
        );
        Ok(result)
    }
}

pub(crate) fn acquire_account_lease(owner_sid: &str) -> Result<Handle> {
    use windows_sys::Win32::{
        Foundation::{GetLastError, ERROR_ALREADY_EXISTS},
        System::Threading::CreateMutexW,
    };
    unsafe {
        let mut descriptor = null_mut();
        let sddl = winutil::to_wide(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid})"));
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut()
            ) != 0,
            "account lease ACL invalid"
        );
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = CreateMutexW(
            &attributes,
            1,
            winutil::to_wide("Global\\PiSandboxOffline-Policy-956ec6e84e794dc69a289d46baf8d4e7")
                .as_ptr(),
        );
        let existed = GetLastError() == ERROR_ALREADY_EXISTS;
        LocalFree(descriptor as HLOCAL);
        let handle = Handle::from_raw(handle)?;
        ensure!(
            !existed,
            "another account policy lease is active or namespace is occupied"
        );
        Ok(handle)
    }
}
