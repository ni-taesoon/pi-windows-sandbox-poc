// Derived from OpenAI Codex (Apache-2.0).
// Sources: codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs
//          codex-rs/windows-sandbox-rs/src/winutil.rs
// Revision: a956835d020762cb2b570053af06f643a11c0ecc
// Pi changes: fresh-only disabled account, no existing-account password reset,
// BCrypt entropy, zeroized temporary passwords, no Codex identities or state.
use super::to_wide;
use anyhow::{ensure, Context, Result};
use std::{
    ffi::OsStr,
    ptr::{null, null_mut},
};
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetApiBufferFree, NetApiBufferSize, NetUserAdd, NetUserGetInfo,
    UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1, USER_INFO_23, USER_PRIV_USER,
};
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use zeroize::Zeroizing;

pub(super) fn require_elevated() -> Result<()> {
    let mut token = 0;
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "OpenProcessToken failed: {}",
        std::io::Error::last_os_error()
    );
    let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
    let mut returned = 0;
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of_val(&elevation) as u32,
            &mut returned,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        CloseHandle(token);
    }
    ensure!(ok != 0, "GetTokenInformation failed: {error}");
    ensure!(
        elevation.TokenIsElevated != 0,
        "explicit elevated setup required"
    );
    Ok(())
}

pub(super) fn random_password() -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    ensure!(status >= 0, "BCryptGenRandom failed: {status}");
    // Fixed complexity prefix plus 256 bits of cryptographic entropy.
    let mut password = Zeroizing::new(String::from("Pi!aA9-"));
    use std::fmt::Write;
    for byte in bytes.iter() {
        write!(&mut *password, "{byte:02x}")?;
    }
    Ok(password)
}

pub(super) fn create_disabled_account(name: &str, password: &str) -> Result<FreshAccount> {
    ensure!(
        name == super::OFFLINE_ACCOUNT,
        "refusing non-product account"
    );
    let name_w = to_wide(OsStr::new(name));
    let password_w = Zeroizing::new(to_wide(OsStr::new(password)));
    let mut nonce = [0u8; 16];
    ensure!(
        unsafe {
            BCryptGenRandom(
                null_mut(),
                nonce.as_mut_ptr(),
                16,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } >= 0,
        "ownership marker RNG failed"
    );
    let marker = format!(
        "Pi fresh disabled account:{}",
        nonce.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let comment = to_wide(&marker);
    let info = USER_INFO_1 {
        usri1_name: name_w.as_ptr() as *mut u16,
        usri1_password: password_w.as_ptr() as *mut u16,
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: null_mut(),
        usri1_comment: comment.as_ptr() as *mut u16,
        usri1_flags: UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_ACCOUNTDISABLE,
        usri1_script_path: null_mut(),
    };
    let status = unsafe { NetUserAdd(null(), 1, &info as *const _ as *const u8, null_mut()) };
    // Existing accounts are NOT adopted, reset, enabled, or assigned privileges.
    ensure!(
        status == NERR_Success,
        "fresh account creation failed ({status}); existing identities are never adopted"
    );
    // NetUserAdd accepted UF_ACCOUNTDISABLE. Until local SAM returns the
    // matching creation marker/SID, do not mutate by name or claim recovery.
    let state = match local_account_state() {
        Ok(state) => state,
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::json!({"type":"setup-account-state","phase":"capture-created-identity-failed","account":super::OFFLINE_ACCOUNT,"creationAccepted":true,"disabledFlagRequested":true,"sid":null,"disabled":null,"recovery":"not-attempted-without-owned-identity"})
            );
            return Err(error.context("phase=capture-created-identity; NetUserAdd succeeded with disabled flag requested; identity/state unverified; no name-only recovery"));
        }
    };
    ensure!(
        state.marker == marker,
        "phase=capture-created-identity; ownership marker mismatch; no mutation authorized"
    );
    let mut owned = FreshAccount {
        sid: state.sid.clone(),
        marker,
        armed: true,
    };
    if state.flags & UF_ACCOUNTDISABLE == 0 {
        let recovery = owned.rollback();
        anyhow::bail!("phase=capture-created-identity; newly created account unexpectedly enabled; rollback={recovery:?}");
    }
    state.log("fresh-disabled-created");
    Ok(owned)
}

pub(super) struct LocalAccountState {
    pub sid: String,
    pub flags: u32,
    marker: String,
}
impl LocalAccountState {
    pub fn log(&self, phase: &str) {
        eprintln!(
            "{}",
            serde_json::json!({"type":"setup-account-state","phase":phase,"account":super::OFFLINE_ACCOUNT,"sid":self.sid,"disabled":self.flags & UF_ACCOUNTDISABLE != 0,"flags":self.flags})
        );
    }
}
struct NetBuffer(*mut u8);
impl Drop for NetBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                NetApiBufferFree(self.0.cast());
            }
        }
    }
}
fn offset_in_buffer(base: usize, size: usize, pointer: usize, length: usize) -> Result<usize> {
    let offset = pointer
        .checked_sub(base)
        .context("SAM pointer before buffer")?;
    ensure!(
        offset <= size && length <= size - offset,
        "SAM field outside buffer"
    );
    Ok(offset)
}
unsafe fn sam_string(base: *mut u8, size: usize, value: *mut u16) -> Result<String> {
    let offset = offset_in_buffer(base as usize, size, value as usize, 2)?;
    ensure!((value as usize) % 2 == 0, "unaligned SAM string");
    let units = std::slice::from_raw_parts(value, (size - offset) / 2);
    let end = units
        .iter()
        .position(|v| *v == 0)
        .context("unterminated SAM string")?;
    Ok(String::from_utf16(&units[..end])?)
}
/// NULL server explicitly selects the local SAM; no '.\\name' lookup ambiguity.
pub(super) fn local_account_state() -> Result<LocalAccountState> {
    unsafe {
        let mut raw = null_mut();
        let status = NetUserGetInfo(
            null(),
            to_wide(super::OFFLINE_ACCOUNT).as_ptr(),
            23,
            &mut raw,
        );
        let buffer = NetBuffer(raw);
        ensure!(
            status == NERR_Success && !raw.is_null(),
            "NetUserGetInfo(local, PiSandboxOffline, 23) failed: {status}"
        );
        let mut size = 0;
        ensure!(
            NetApiBufferSize(buffer.0.cast(), &mut size) == NERR_Success
                && size as usize >= std::mem::size_of::<USER_INFO_23>()
                && size <= 1024 * 1024,
            "invalid local SAM buffer size"
        );
        let info = &*(buffer.0 as *const USER_INFO_23);
        let name = sam_string(buffer.0, size as usize, info.usri23_name)?;
        ensure!(
            name.eq_ignore_ascii_case(super::OFFLINE_ACCOUNT),
            "local SAM account name mismatch"
        );
        let marker = sam_string(buffer.0, size as usize, info.usri23_comment)?;
        let sid = info.usri23_user_sid;
        offset_in_buffer(buffer.0 as usize, size as usize, sid as usize, 8)?;
        let sid_len = 8 + 4 * usize::from(*(sid as *const u8).add(1));
        ensure!(sid_len <= 68, "oversized SAM SID");
        offset_in_buffer(buffer.0 as usize, size as usize, sid as usize, sid_len)?;
        ensure!(
            IsValidSid(sid) != 0 && GetLengthSid(sid) as usize == sid_len,
            "invalid local SAM SID"
        );
        let sid = crate::winutil::string_from_sid_bytes(std::slice::from_raw_parts(
            sid.cast::<u8>(),
            sid_len,
        ))
        .map_err(anyhow::Error::msg)?;
        ensure!(sid.starts_with("S-1-5-21-"), "expected local SAM user SID");
        Ok(LocalAccountState {
            sid,
            flags: info.usri23_flags,
            marker,
        })
    }
}
/// Exists only following successful fresh NetUserAdd + matching creation marker.
/// It is not reconstructed from a missing credential record or a bare username.
/// Marker checks prevent accidental transaction/identity adoption, not attacks
/// by a malicious local administrator; SAM read/mutate is not atomic.
pub(super) struct FreshAccount {
    pub sid: String,
    marker: String,
    armed: bool,
}
impl FreshAccount {
    pub fn disarm(&mut self) {
        self.armed = false;
    }
    pub fn rollback(&mut self) -> Result<()> {
        self.armed = false; // One explicit attempt; Drop must not silently retry.
        let current = local_account_state().context("rollback identity read")?;
        ensure!(
            current.sid == self.sid && current.marker == self.marker,
            "fresh account ownership changed; rollback refused"
        );
        if current.flags & UF_ACCOUNTDISABLE != 0 {
            current.log("rollback-disabled-verified");
            return Ok(());
        }
        set_disabled(&self.sid, true).context("fresh account disable/readback")
    }
}
impl Drop for FreshAccount {
    fn drop(&mut self) {
        if self.armed {
            if let Err(error) = self.rollback() {
                eprintln!("phase=owned-account-drop; DISABLE ROLLBACK FAILED: {error:#}");
            }
        }
    }
}

pub(super) fn set_disabled(expected_sid: &str, disabled: bool) -> Result<()> {
    require_elevated()?;
    let state = local_account_state().context("phase=pre-flag-change local SAM read")?;
    ensure!(
        state.sid == expected_sid,
        "owned account SID changed; refusing flag mutation"
    );
    let flags = if disabled {
        state.flags | UF_ACCOUNTDISABLE
    } else {
        state.flags & !UF_ACCOUNTDISABLE
    };
    crate::winutil::set_local_user_flags(super::OFFLINE_ACCOUNT, flags)
        .context("phase=set-owned-account-flags")?;
    let observed = local_account_state().context("phase=verify-owned-account-flags")?;
    ensure!(
        observed.sid == expected_sid && (observed.flags & UF_ACCOUNTDISABLE != 0) == disabled,
        "owned account SID/state changed after flag mutation"
    );
    observed.log(if disabled {
        "disabled-verified"
    } else {
        "activated-verified"
    });
    Ok(())
}

// Adapted from pinned windows-sandbox-rs/src/identity.rs logon primitive.
pub(super) fn logon(password: &str, expected_sid: &str) -> Result<crate::process::Handle> {
    use windows_sys::Win32::Security::{
        LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    };
    let password = Zeroizing::new(to_wide(password));
    let mut token = 0;
    ensure!(
        unsafe {
            LogonUserW(
                to_wide(super::OFFLINE_ACCOUNT).as_ptr(),
                to_wide(".").as_ptr(),
                password.as_ptr(),
                LOGON32_LOGON_INTERACTIVE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        } != 0,
        "sandbox account logon failed: {}",
        std::io::Error::last_os_error()
    );
    let handle = unsafe { crate::process::Handle::from_raw(token)? };
    verify_token(&handle, expected_sid)?;
    Ok(handle)
}

pub(super) fn verify_token(handle: &crate::process::Handle, expected_sid: &str) -> Result<()> {
    let sid = unsafe { crate::token_user::get_user_sid_bytes(handle.raw())? };
    let actual = crate::winutil::string_from_sid_bytes(&sid).map_err(anyhow::Error::msg)?;
    ensure!(actual == expected_sid, "sandbox logon token SID mismatch");
    let groups = unsafe { crate::token::token_groups(handle.raw(), 1024 * 1024)? };
    for group in groups {
        let group_sid =
            crate::winutil::string_from_sid_bytes(&group.sid).map_err(anyhow::Error::msg)?;
        ensure!(
            group_sid != "S-1-5-32-544",
            "sandbox account has Administrators membership"
        );
    }
    Ok(())
}
