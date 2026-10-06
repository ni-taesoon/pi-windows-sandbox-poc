//! Fixed synthetic fixtures for the default-off Codex-policy comparison.
//!
//! The broker calls this only after admission, while its authenticated helper is
//! still suspended. Its ancestor/leaf pins and directory guards must remain live.
//! There is no caller-selected path, ACL inventory, rollback, or retained target
//! handle. Failure leaves the disposable lab for explicit disposal.
#![cfg(windows)]

use super::VerifiedCodexIdentity;
use crate::{acl, process::Handle, setup::no_reparse_dir as nr, token, winutil};
use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    ffi::c_void,
    fs::OpenOptions,
    io::{Read, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsHandle, AsRawHandle, OwnedHandle},
    },
    path::Path,
    ptr::null_mut,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, HANDLE, HLOCAL},
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
};

const OWNER_CONTROL_BYTES: &[u8] = b"CODEX_PRIVATE_OWNER_CONTROL\n";
const PROTECTED_FILE_BYTES: &[u8] = b"CODEX_PROTECTED_FILE\n";
const MODIFY: u32 = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
// Exact generic-mapped mask of acl::add_deny_write_ace, deliberately preserving
// the pinned Codex implementation, including its shared standard-access bits.
const DENY_WRITE: u32 = FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;
const OBJECT_INHERIT: u8 = 0x01;
const CONTAINER_INHERIT: u8 = 0x02;
const INHERIT_ONLY: u8 = 0x08;
const INHERITED: u8 = 0x10;
const NORMAL_FLAGS: u8 = OBJECT_INHERIT | CONTAINER_INHERIT | INHERIT_ONLY | INHERITED;
const ALLOW: u8 = 0;
const DENY: u8 = 1;
const SHARE: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE; // Never share deletion.

#[derive(Clone, Copy)]
enum Target {
    OutsidePrivate,
    Work,
    OwnerControl,
    ProtectedFile,
    ProtectedDirectory,
    RenamedFile,
    RenamedDirectory,
}

impl Target {
    fn path(self) -> &'static Path {
        Path::new(match self {
            Self::OutsidePrivate => r"C:\PiSandboxLab\fixtures\outside-private",
            Self::Work => r"C:\PiSandboxLab\work",
            Self::OwnerControl => r"C:\PiSandboxLab\fixtures\outside-private\owner-control.txt",
            Self::ProtectedFile => r"C:\PiSandboxLab\work\codex-protected-file.txt",
            Self::ProtectedDirectory => r"C:\PiSandboxLab\work\codex-protected-dir",
            Self::RenamedFile => r"C:\PiSandboxLab\work\codex-protected-file-renamed.txt",
            Self::RenamedDirectory => r"C:\PiSandboxLab\work\codex-protected-dir-renamed",
        })
    }

    fn role(self) -> &'static str {
        match self {
            Self::OutsidePrivate => "OUTSIDE_PRIVATE_DIR",
            Self::Work => "WORK_DIR",
            Self::OwnerControl => "PRIVATE_OWNER_CONTROL",
            Self::ProtectedFile => "CODEX_PROTECTED_FILE",
            Self::ProtectedDirectory => "CODEX_PROTECTED_DIR",
            Self::RenamedFile => "CODEX_PROTECTED_FILE_RENAMED",
            Self::RenamedDirectory => "CODEX_PROTECTED_DIR_RENAMED",
        }
    }
}

struct Roles {
    owner: Vec<u8>,
    account: Vec<u8>,
    capability: Vec<u8>,
    logon: Vec<u8>,
    system: Vec<u8>,
    administrators: Vec<u8>,
    users: Vec<u8>,
    everyone: Vec<u8>,
    capability_sid: token::LocalSid,
}

impl Roles {
    fn verified(identity: &VerifiedCodexIdentity) -> Result<Self> {
        let parse = |text: &str| -> Result<Vec<u8>> {
            // Do not place caller identity strings in errors or receipts.
            let sid = token::LocalSid::from_string(text)
                .map_err(|_| anyhow::anyhow!("invalid verified fixture identity"))?;
            unsafe { copy_sid(sid.as_ptr()) }
        };
        let owner = parse(&identity.owner_sid)?;
        let account = parse(&identity.account_sid)?;
        let capability = parse(&identity.capability_sid)?;
        let logon = parse(&identity.actual_logon_sid)?;
        ensure!(
            identity.actual_logon_sid.starts_with("S-1-5-5-")
                && owner != account && owner != capability && owner != logon
                && account != capability && account != logon && capability != logon,
            "fixture identity roles must be distinct and use the actual helper logon"
        );
        let system = parse("S-1-5-18")?;
        let administrators = parse("S-1-5-32-544")?;
        let users = parse("S-1-5-32-545")?;
        let everyone = parse("S-1-1-0")?;
        for role in [&account, &capability, &logon] {
            ensure!(
                ![&system, &administrators, &users, &everyone].contains(&role),
                "fixture sandbox identity must not alias a well-known role"
            );
        }
        let current = unsafe {
            Handle::from_raw(token::get_current_token_for_restriction()?)?
        };
        let actual_owner = unsafe { token::get_user_sid_bytes(current.raw())? };
        ensure!(actual_owner == owner, "fixture caller is not the verified owner");
        let capability_sid = token::LocalSid::from_string(&identity.capability_sid)
            .map_err(|_| anyhow::anyhow!("invalid verified fixture capability"))?;
        Ok(Self { owner, account, capability, logon, system, administrators, users,
            everyone, capability_sid })
    }

    fn role(&self, sid: &[u8]) -> &'static str {
        if sid == self.owner { "OWNER" }
        else if sid == self.account { "ACCOUNT" }
        else if sid == self.capability { "CAPABILITY" }
        else if sid == self.logon { "ACTUAL_LOGON" }
        else if sid == self.system { "SYSTEM" }
        else if sid == self.administrators { "ADMINISTRATORS" }
        else if sid == self.users { "BUILTIN_USERS" }
        else if sid == self.everyone { "EVERYONE" }
        else { "OTHER" }
    }

    fn trusted_owner(&self, sid: &[u8]) -> bool {
        sid == self.owner || sid == self.system || sid == self.administrators
    }
}

#[derive(Clone)]
struct Ace {
    kind: u8,
    flags: u8,
    mask: u32,
    sid: Vec<u8>,
}

struct Snapshot {
    owner: Vec<u8>,
    protected: bool,
    aces: Vec<Ace>,
}

// This only releases API-allocated memory. No destructor restores or edits ACLs.
struct SecurityDescriptor(*mut c_void);
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0 as HLOCAL); }
        }
    }
}

unsafe fn copy_sid(sid: *mut c_void) -> Result<Vec<u8>> {
    ensure!(!sid.is_null() && IsValidSid(sid) != 0, "invalid fixture ACL trustee");
    let length = GetLengthSid(sid) as usize;
    ensure!((8..=68).contains(&length), "fixture ACL trustee length out of bounds");
    Ok(std::slice::from_raw_parts(sid.cast::<u8>(), length).to_vec())
}

fn snapshot(handle: HANDLE) -> Result<Snapshot> {
    unsafe {
        let mut raw_sd = null_mut();
        let mut dacl = null_mut();
        let mut owner = null_mut();
        let status = GetSecurityInfo(handle, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner, null_mut(), &mut dacl, null_mut(), &mut raw_sd);
        let sd = SecurityDescriptor(raw_sd);
        ensure!(status == 0, "read fixed fixture security failed: {status}");
        ensure!(!sd.0.is_null() && IsValidSecurityDescriptor(sd.0) != 0,
            "invalid fixture security descriptor");
        let mut control = 0;
        let mut revision = 0;
        ensure!(GetSecurityDescriptorControl(sd.0, &mut control, &mut revision) != 0,
            "read fixture DACL protection failed");
        ensure!(control & SE_DACL_PRESENT != 0 && !dacl.is_null()
            && IsValidAcl(dacl) != 0, "fixture requires a present non-null valid DACL");
        ensure!((*dacl).AceCount <= 64
            && (std::mem::size_of::<ACL>()..=16_384).contains(&((*dacl).AclSize as usize)),
            "fixture DACL exceeds inspection bounds");
        let start = dacl as usize;
        let end = start.checked_add((*dacl).AclSize as usize)
            .context("fixture ACL address overflow")?;
        let mapping = GENERIC_MAPPING { GenericRead: FILE_GENERIC_READ,
            GenericWrite: FILE_GENERIC_WRITE, GenericExecute: FILE_GENERIC_EXECUTE,
            GenericAll: FILE_ALL_ACCESS };
        let mut aces = Vec::new();
        for index in 0..(*dacl).AceCount {
            let mut raw = null_mut();
            ensure!(GetAce(dacl, index as u32, &mut raw) != 0,
                "read fixture ACE failed");
            let address = raw as usize;
            ensure!(address >= start && address.checked_add(16).is_some_and(|n| n <= end),
                "fixture ACE header outside ACL bounds");
            let header = &*raw.cast::<ACE_HEADER>();
            ensure!((header.AceType == ALLOW || header.AceType == DENY)
                && header.AceFlags & !NORMAL_FLAGS == 0
                && header.AceSize >= 16
                && address.checked_add(header.AceSize as usize).is_some_and(|n| n <= end),
                "unsupported fixture ACE type, flags, or size");
            let entry = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            let sid = std::ptr::addr_of!(entry.SidStart).cast_mut().cast::<u8>();
            let sid_length = 8 + usize::from(*sid.add(1)) * 4;
            ensure!(sid_length <= 68 && header.AceSize as usize == 8 + sid_length,
                "fixture ACE SID outside ACE bounds");
            let mut mask = entry.Mask;
            MapGenericMask(&mut mask, &mapping);
            aces.push(Ace { kind: header.AceType, flags: header.AceFlags,
                mask, sid: copy_sid(sid.cast())? });
        }
        Ok(Snapshot { owner: copy_sid(owner)?, protected: control & SE_DACL_PROTECTED != 0,
            aces })
    }
}

#[derive(Clone, Copy)]
enum Scope { Object, ChildFile, ChildDirectory }

fn applies(ace: &Ace, scope: Scope) -> bool {
    match scope {
        Scope::Object => ace.flags & INHERIT_ONLY == 0,
        Scope::ChildFile => ace.flags & OBJECT_INHERIT != 0,
        Scope::ChildDirectory => ace.flags & CONTAINER_INHERIT != 0,
    }
}

fn coverage(snapshot: &Snapshot, sid: &[u8], kind: u8, scope: Scope,
    inherited_only: bool) -> u32 {
    snapshot.aces.iter().filter(|a| a.sid == sid && a.kind == kind
        && (!inherited_only || a.flags & INHERITED != 0) && applies(a, scope))
        .fold(0, |mask, ace| mask | ace.mask)
}

fn verify_private(snapshot: &Snapshot, roles: &Roles) -> Result<()> {
    ensure!(snapshot.protected && roles.trusted_owner(&snapshot.owner),
        "outside-private must have a protected DACL and trusted owner");
    for ace in &snapshot.aces {
        ensure!(ace.kind == ALLOW && roles.trusted_owner(&ace.sid)
            && ace.mask == FILE_ALL_ACCESS && ace.flags & INHERITED == 0,
            "outside-private must contain only explicit owner/SYSTEM/Administrators full allows");
    }
    for sid in [&roles.owner, &roles.system, &roles.administrators] {
        for scope in [Scope::Object, Scope::ChildFile, Scope::ChildDirectory] {
            ensure!(coverage(snapshot, sid, ALLOW, scope, false) == FILE_ALL_ACCESS,
                "outside-private needs applicable and inheritable trusted full control");
        }
    }
    Ok(())
}

fn grants_delete_child_to(ace: &Ace, sids: &[&[u8]]) -> bool {
    ace.kind == ALLOW && ace.mask & FILE_DELETE_CHILD != 0
        && sids.iter().any(|sid| ace.sid.as_slice() == *sid)
}

fn verify_no_delete_child(snapshot: &Snapshot, roles: &Roles) -> Result<()> {
    for ace in &snapshot.aces {
        ensure!(!grants_delete_child_to(ace, &[
            &roles.account, &roles.capability, &roles.everyone, &roles.logon]),
            "alternate account/capability/Everyone/logon FILE_DELETE_CHILD grant refused");
    }
    Ok(())
}

fn verify_grants(snapshot: &Snapshot, roles: &Roles, directory: bool,
    require_inherited: bool) -> Result<()> {
    ensure!(roles.trusted_owner(&snapshot.owner), "untrusted fixed fixture owner");
    verify_no_delete_child(snapshot, roles)?;
    for ace in &snapshot.aces {
        ensure!(roles.role(&ace.sid) != "OTHER", "unexpected fixed fixture trustee");
        if ace.kind == ALLOW && (ace.sid == roles.account || ace.sid == roles.capability) {
            ensure!(ace.mask & !MODIFY == 0, "unexpected sandbox grant rights");
        }
    }
    for sid in [&roles.account, &roles.capability] {
        for scope in [Scope::Object, Scope::ChildFile, Scope::ChildDirectory] {
            if !directory && !matches!(scope, Scope::Object) { continue; }
            ensure!(coverage(snapshot, sid, ALLOW, scope, require_inherited) == MODIFY,
                "missing admitted account/capability grant coverage");
        }
    }
    Ok(())
}

fn verify_protected(snapshot: &Snapshot, roles: &Roles, directory: bool) -> Result<()> {
    verify_grants(snapshot, roles, directory, true)?;
    verify_capability_deny(snapshot, &roles.capability, directory)
}

fn verify_capability_deny(snapshot: &Snapshot, capability: &[u8], directory: bool) -> Result<()> {
    // Windows may split a generic/inheritable ACE into effective and
    // inherit-only entries. Compare mapped rights and coverage, not raw layout.
    for ace in snapshot.aces.iter().filter(|a| a.kind == DENY) {
        ensure!(ace.sid == capability && ace.mask == DENY_WRITE
            && ace.flags & INHERITED == 0,
            "protected fixture deny must be exact, explicit, and capability-only");
    }
    for scope in [Scope::Object, Scope::ChildFile, Scope::ChildDirectory] {
        if !directory && !matches!(scope, Scope::Object) { continue; }
        ensure!(coverage(snapshot, capability, DENY, scope, false) == DENY_WRITE,
            "protected fixture lacks applicable/inheritable capability deny");
    }
    // Require explicit denies before all applicable allows, rather than assume
    // that an arbitrary ACL ordering implements the expected access check.
    let mut saw_allow = false;
    for ace in &snapshot.aces {
        if ace.kind == ALLOW { saw_allow = true; }
        if ace.kind == DENY { ensure!(!saw_allow, "noncanonical protected fixture deny"); }
    }
    Ok(())
}

fn normalized(target: Target, snapshot: &Snapshot, roles: &Roles) -> Value {
    json!({
        "target": target.role(), "ownerRole": roles.role(&snapshot.owner),
        "daclProtected": snapshot.protected,
        "aces": snapshot.aces.iter().enumerate().map(|(index, a)| json!({
            "index": index, "type": if a.kind == ALLOW { "ALLOW" } else { "DENY" },
            "trusteeRole": roles.role(&a.sid), "flags": a.flags,
            "mask": a.mask, "maskHex": format!("0x{:08x}", a.mask),
            "effective": a.flags & INHERIT_ONLY == 0,
            "objectInherit": a.flags & OBJECT_INHERIT != 0,
            "containerInherit": a.flags & CONTAINER_INHERIT != 0,
            "inherited": a.flags & INHERITED != 0,
            "fileDeleteChild": a.mask & FILE_DELETE_CHILD != 0
        })).collect::<Vec<_>>()
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FileIdentity { volume: u32, high: u32, low: u32 }

impl FileIdentity {
    fn receipt(self, target: Target) -> Value {
        json!({"target": target.role(), "identity": {
            "volumeSerialNumber": self.volume, "fileIndexHigh": self.high,
            "fileIndexLow": self.low
        }})
    }
}

fn shape(handle: HANDLE, directory: bool, length: Option<usize>) -> Result<FileIdentity> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(handle, &mut info) } != 0,
        "query fixed fixture identity failed");
    ensure!(info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
        && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory,
        "fixed fixture has a reparse point or wrong object type");
    if !directory {
        ensure!(info.nNumberOfLinks == 1, "fixed fixture file must have exactly one link");
    }
    if let Some(expected) = length {
        let actual = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        ensure!(actual == expected as u64, "fixed fixture content length changed");
    }
    Ok(FileIdentity { volume: info.dwVolumeSerialNumber, high: info.nFileIndexHigh,
        low: info.nFileIndexLow })
}

fn pin_directory(target: Target) -> Result<OwnedHandle> {
    let pin = nr::open_directory_no_reparse(target.path(),
        READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE, SHARE,
        nr::DirectoryOpenDisposition::OpenExisting)
        .with_context(|| format!("pin {}", target.role()))?;
    shape(pin.as_raw_handle() as HANDLE, true, None)?;
    Ok(pin)
}

fn absent(target: Target) -> Result<()> {
    // symlink_metadata does not silently treat a dangling reparse point as absent.
    match std::fs::symlink_metadata(target.path()) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect fresh {}", target.role())),
        Ok(_) => anyhow::bail!("fixed {} must be absent", target.role()),
    }
}

fn create_and_readback(target: Target, bytes: &[u8]) -> Result<FileIdentity> {
    // CREATE_NEW plus share_mode(0): never overwrite a prior fixture, and finish
    // the exclusive write/flush before a distinct read-only open verifies it.
    let mut writer = OpenOptions::new().write(true).create_new(true)
        .access_mode(FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES)
        .share_mode(0).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(target.path()).with_context(|| format!("create fresh {}", target.role()))?;
    let initial = shape(writer.as_raw_handle() as HANDLE, false, Some(0))?;
    writer.write_all(bytes).context("write fixed fixture bytes")?;
    writer.sync_all().context("sync fixed fixture bytes")?;
    ensure!(shape(writer.as_raw_handle() as HANDLE, false, Some(bytes.len()))? == initial,
        "fixed fixture identity changed during exclusive write");
    drop(writer);
    let mut reader = OpenOptions::new().read(true).share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(target.path())
        .with_context(|| format!("independently read {}", target.role()))?;
    ensure!(shape(reader.as_raw_handle() as HANDLE, false, Some(bytes.len()))? == initial,
        "fixed fixture identity changed before independent readback");
    let mut observed = vec![0; bytes.len()];
    reader.read_exact(&mut observed).context("read fixed fixture bytes")?;
    let mut tail = [0u8; 1];
    ensure!(observed == bytes && reader.read(&mut tail)? == 0,
        "fixed fixture independent content readback mismatch");
    ensure!(shape(reader.as_raw_handle() as HANDLE, false, Some(bytes.len()))? == initial,
        "fixed fixture shape changed after readback");
    Ok(initial)
}

fn empty_protected_directory() -> Result<()> {
    ensure!(std::fs::read_dir(Target::ProtectedDirectory.path())?.next().transpose()?.is_none(),
        "protected directory must be empty for removal probe");
    Ok(())
}

/// Create only the fixed controls using the broker's post-admission proof.
/// All target handles are closed before this returns and before helper resume.
/// The caller durably persists the role-normalized receipt before resuming.
pub fn prepare(identity: &VerifiedCodexIdentity) -> Result<Value> {
    let roles = Roles::verified(identity)?;
    let receipt = {
        let private = pin_directory(Target::OutsidePrivate)?;
        let work = pin_directory(Target::Work)?;
        let private_before = snapshot(private.as_raw_handle() as HANDLE)?;
        verify_private(&private_before, &roles)?;
        let work_before = snapshot(work.as_raw_handle() as HANDLE)?;
        verify_grants(&work_before, &roles, true, false)?;
        ensure!(work_before.aces.iter().all(|a| a.kind == ALLOW),
            "work parent must not supply an alternate deny control");
        for target in [Target::OwnerControl, Target::ProtectedFile,
            Target::ProtectedDirectory, Target::RenamedFile, Target::RenamedDirectory] {
            absent(target)?;
        }
        let owner_control_identity = create_and_readback(Target::OwnerControl, OWNER_CONTROL_BYTES)?;
        let expected_file = create_and_readback(Target::ProtectedFile, PROTECTED_FILE_BYTES)?;
        let file = OpenOptions::new().access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_DATA)
            .share_mode(SHARE).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(Target::ProtectedFile.path()).context("pin protected file")?;
        ensure!(shape(file.as_raw_handle() as HANDLE, false, Some(PROTECTED_FILE_BYTES.len()))?
            == expected_file, "protected file changed before deny");
        // CreateDirectoryW fails if the fixed directory already exists.
        ensure!(unsafe { CreateDirectoryW(winutil::to_wide(Target::ProtectedDirectory.path()).as_ptr(),
            std::ptr::null()) } != 0, "create fresh protected directory failed: {}",
            std::io::Error::last_os_error());
        let directory = pin_directory(Target::ProtectedDirectory)?;
        let directory_identity = shape(directory.as_raw_handle() as HANDLE, true, None)?;
        empty_protected_directory()?;
        let guard = nr::create_directory_guard(directory.as_handle())?;
        let post_guard = pin_directory(Target::ProtectedDirectory)?;
        ensure!(shape(post_guard.as_raw_handle() as HANDLE, true, None)? == directory_identity,
            "protected directory changed while installing reparse guard");
        for (target, handle, is_directory) in [
            (Target::ProtectedFile, file.as_raw_handle() as HANDLE, false),
            (Target::ProtectedDirectory, directory.as_raw_handle() as HANDLE, true),
        ] {
            let before = snapshot(handle)?;
            verify_grants(&before, &roles, is_directory, true)?;
            ensure!(before.aces.iter().all(|a| a.kind == ALLOW),
                "fresh protected target already has a deny");
            ensure!(unsafe { acl::add_deny_write_ace(target.path(), roles.capability_sid.as_ptr())? },
                "fresh capability deny was not added");
        }
        let file_after = snapshot(file.as_raw_handle() as HANDLE)?;
        let directory_after = snapshot(directory.as_raw_handle() as HANDLE)?;
        verify_protected(&file_after, &roles, false)?;
        verify_protected(&directory_after, &roles, true)?;
        ensure!(shape(file.as_raw_handle() as HANDLE, false, Some(PROTECTED_FILE_BYTES.len()))?
            == expected_file, "protected file changed after deny");
        // The temporary no-reparse guard must not make RemoveDirectory fail for
        // non-emptiness. Its delete-on-close cleanup finishes before observation.
        drop(guard);
        let final_directory = pin_directory(Target::ProtectedDirectory)?;
        ensure!(shape(final_directory.as_raw_handle() as HANDLE, true, None)? == directory_identity,
            "protected directory changed after guard release");
        empty_protected_directory()?;
        let private_after = snapshot(private.as_raw_handle() as HANDLE)?;
        verify_private(&private_after, &roles)?;
        let work_after = snapshot(work.as_raw_handle() as HANDLE)?;
        verify_grants(&work_after, &roles, true, false)?;
        absent(Target::RenamedFile)?;
        absent(Target::RenamedDirectory)?;
        json!({
            "schemaVersion": 1,
            "fixtureProfile": "FIXED_CODEX_POLICY_SYNTHETIC_V1",
            "ownerControlWriteReadVerified": true,
            "ownerMatchesAuthenticatedBroker": true,
            "capabilityMatchesAdmittedLaunch": true,
            "actualLogonMatchesAuthenticatedSuspendedHelper": true,
            "sandboxIdentityRolesDistinct": true,
            "privateLeafProtectedOwnerSystemAdministratorsOnly": true,
            "lateTargetsCreatedAfterAdmission": true,
            "protectedTargetsVerified": true,
            "protectedDirectoryEmpty": true,
            "renameCounterpartsAbsent": true,
            "parentDeleteChildBypassAbsent": true,
            "denyTrusteeRole": "CAPABILITY",
            "denyMappedMask": DENY_WRITE,
            "denyMappedMaskHex": format!("0x{DENY_WRITE:08x}"),
            "readSemantics": "PINNED_WRITE_RESTRICTED_CAPABILITY_ONLY_DENY",
            "targets": [
                expected_file.receipt(Target::ProtectedFile),
                directory_identity.receipt(Target::ProtectedDirectory),
                owner_control_identity.receipt(Target::OwnerControl)
            ],
            "outsidePrivateAcl": normalized(Target::OutsidePrivate, &private_after, &roles),
            "workParentAcl": normalized(Target::Work, &work_after, &roles),
            "protectedFileAcl": normalized(Target::ProtectedFile, &file_after, &roles),
            "protectedDirectoryAcl": normalized(Target::ProtectedDirectory, &directory_after, &roles)
        })
    }; // All file/directory/guard handles are released here, on both success/error.
    let mut receipt = receipt;
    receipt["targetHandlesReleased"] = Value::Bool(true);
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure normalized-ACL checks only. These tests make no Windows API calls,
    // open no filesystem objects, and do not construct or mutate tokens/ACLs.
    fn ace(kind: u8, flags: u8, mask: u32, role: u8) -> Ace {
        Ace { kind, flags, mask, sid: vec![role] }
    }

    fn snapshot_with(aces: Vec<Ace>) -> Snapshot {
        Snapshot { owner: vec![0], protected: false, aces }
    }

    #[test]
    fn accepts_windows_split_effective_and_inherit_only_deny() {
        let snapshot = snapshot_with(vec![
            ace(DENY, 0, DENY_WRITE, 1),
            ace(DENY, OBJECT_INHERIT | CONTAINER_INHERIT | INHERIT_ONLY, DENY_WRITE, 1),
            ace(ALLOW, OBJECT_INHERIT | CONTAINER_INHERIT | INHERITED, MODIFY, 2),
        ]);
        assert!(verify_capability_deny(&snapshot, &[1], true).is_ok());
        assert_eq!(DENY_WRITE, 0x0013_0156);
        assert_eq!(MODIFY, 0x0013_01bf);
    }

    #[test]
    fn directory_requires_effective_file_and_directory_deny_coverage() {
        for flags in [0, OBJECT_INHERIT, CONTAINER_INHERIT,
            OBJECT_INHERIT | CONTAINER_INHERIT | INHERIT_ONLY] {
            let snapshot = snapshot_with(vec![ace(DENY, flags, DENY_WRITE, 1)]);
            assert!(verify_capability_deny(&snapshot, &[1], true).is_err());
        }
        let file = snapshot_with(vec![ace(DENY, 0, DENY_WRITE, 1)]);
        assert!(verify_capability_deny(&file, &[1], false).is_ok());
    }

    #[test]
    fn refuses_wrong_deny_trustee_mask_inheritance_and_order() {
        let invalid = [
            vec![ace(DENY, 3, DENY_WRITE, 2)],
            vec![ace(DENY, 3, DENY_WRITE | FILE_READ_DATA, 1)],
            vec![ace(DENY, 3, DENY_WRITE & !DELETE, 1)],
            vec![ace(DENY, 3 | INHERITED, DENY_WRITE, 1)],
            vec![ace(ALLOW, INHERITED, MODIFY, 2), ace(DENY, 3, DENY_WRITE, 1)],
        ];
        for aces in invalid {
            assert!(verify_capability_deny(&snapshot_with(aces), &[1], true).is_err());
        }
    }

    #[test]
    fn inherited_grant_coverage_does_not_count_explicit_or_inherit_only_grants() {
        let explicit = snapshot_with(vec![ace(ALLOW, 3, MODIFY, 1)]);
        assert_eq!(coverage(&explicit, &[1], ALLOW, Scope::Object, true), 0);
        let child_only = snapshot_with(vec![ace(ALLOW, 3 | INHERITED | INHERIT_ONLY, MODIFY, 1)]);
        assert_eq!(coverage(&child_only, &[1], ALLOW, Scope::Object, true), 0);
        assert_eq!(coverage(&child_only, &[1], ALLOW, Scope::ChildFile, true), MODIFY);
        assert_eq!(coverage(&child_only, &[1], ALLOW, Scope::ChildDirectory, true), MODIFY);
    }

    #[test]
    fn refuses_any_restricted_role_delete_child_allow_including_child_only() {
        let roles: &[&[u8]] = &[&[1], &[2], &[3], &[4]];
        for role in 1..=4 {
            for flags in [0, INHERITED, 3 | INHERIT_ONLY, 3 | INHERITED | INHERIT_ONLY] {
                assert!(grants_delete_child_to(&ace(ALLOW, flags, FILE_DELETE_CHILD, role), roles));
            }
            assert!(!grants_delete_child_to(&ace(ALLOW, 3, MODIFY, role), roles));
            assert!(!grants_delete_child_to(&ace(DENY, 3, DENY_WRITE, role), roles));
        }
        assert!(!grants_delete_child_to(&ace(ALLOW, 3, FILE_ALL_ACCESS, 9), roles));
    }
}
