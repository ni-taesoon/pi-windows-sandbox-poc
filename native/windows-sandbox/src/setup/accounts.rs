// Derived from OpenAI Codex (Apache-2.0).
// Sources: codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs
//          codex-rs/windows-sandbox-rs/src/winutil.rs
// Revision: a956835d020762cb2b570053af06f643a11c0ecc
// Pi changes: fresh-only disabled account, no existing-account password reset,
// BCrypt entropy, zeroized temporary passwords, no Codex identities or state.
use super::to_wide;
use anyhow::{bail, ensure, Result};
use std::{
    ffi::OsStr,
    ptr::{null, null_mut},
};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER,
};
use windows_sys::Win32::NetworkManagement::NetManagement::{
    NERR_Success, NetUserAdd, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_SCRIPT, USER_INFO_1,
    USER_PRIV_USER,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, LookupAccountNameW, TokenElevation, SID_NAME_USE, TOKEN_ELEVATION,
    TOKEN_QUERY,
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

pub(super) fn create_disabled_account(name: &str, password: &str) -> Result<()> {
    ensure!(
        name == super::OFFLINE_ACCOUNT,
        "refusing non-product account"
    );
    let name_w = to_wide(OsStr::new(name));
    let password_w = Zeroizing::new(to_wide(OsStr::new(password)));
    let comment = to_wide("Pi standalone sandbox: disabled pending Windows validation");
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
    Ok(())
}

pub(super) fn account_sid_string(name: &str) -> Result<String> {
    let name_w = to_wide(OsStr::new(name));
    let mut sid_buffer = vec![0u8; 68];
    let mut sid_len = sid_buffer.len() as u32;
    let mut domain = Vec::<u16>::new();
    let mut domain_len = 0;
    let mut use_type: SID_NAME_USE = 0;
    loop {
        let ok = unsafe {
            LookupAccountNameW(
                null(),
                name_w.as_ptr(),
                sid_buffer.as_mut_ptr() as *mut _,
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut use_type,
            )
        };
        if ok != 0 {
            break;
        }
        let error = unsafe { GetLastError() };
        if error != ERROR_INSUFFICIENT_BUFFER {
            bail!("LookupAccountNameW failed: {error}");
        }
        sid_buffer.resize(sid_len as usize, 0);
        domain.resize(domain_len as usize, 0);
    }
    let mut sid_string = null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(sid_buffer.as_ptr() as *mut _, &mut sid_string) } != 0,
        "ConvertSidToStringSidW failed: {}",
        std::io::Error::last_os_error()
    );
    let result = unsafe {
        let mut len = 0;
        while *sid_string.add(len) != 0 {
            len += 1;
        }
        let result = String::from_utf16_lossy(std::slice::from_raw_parts(sid_string, len));
        LocalFree(sid_string as _);
        result
    };
    Ok(result)
}

pub(super) fn set_disabled(expected_sid: &str, disabled: bool) -> Result<()> {
    require_elevated()?;
    let actual = account_sid_string(&format!(".\\{}", super::OFFLINE_ACCOUNT))?;
    ensure!(
        actual == expected_sid,
        "owned account SID changed; refusing flag mutation"
    );
    let flags = crate::winutil::local_user_flags(super::OFFLINE_ACCOUNT)?
        .ok_or_else(|| anyhow::anyhow!("owned account missing"))?;
    let flags = if disabled {
        flags | UF_ACCOUNTDISABLE
    } else {
        flags & !UF_ACCOUNTDISABLE
    };
    crate::winutil::set_local_user_flags(super::OFFLINE_ACCOUNT, flags)
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
