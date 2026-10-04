// Adapted from OpenAI Codex Apache-2.0, revision a956835d020762cb2b570053af06f643a11c0ecc.
// Source: codex-rs/windows-sandbox-rs/src/elevated/runner_client.rs.
// Pi changes: suspended-only creation, pinned executable/ancestors, curated env,
// no profile/alias fallback, protected credential store, zeroized credentials.
//! Broker-side trusted-helper creation. The helper is an unrestricted account
//! process until its internal entrypoint constructs the restricted child token.
//! The broker MUST assign its kill job and harden process-object security before
//! resuming the initial thread. No function here resumes or runs the helper.
use super::{accounts, dpapi, no_reparse_dir as nr, store, to_wide};
use crate::process::Handle;
use anyhow::{ensure, Context, Result};
use std::{
    os::windows::io::{AsRawHandle, OwnedHandle},
    path::Path,
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
    System::Threading::*,
};
use zeroize::Zeroizing;

/// Retain through the complete helper lifetime. Any exit/error path terminates
/// this process on drop. The broker's separate kill job owns descendant cleanup.
pub struct SuspendedHelper {
    pub process: Handle,
    pub thread: Handle,
    pub pid: u32,
    pub account_sid: String,
    _image_pin: OwnedHandle,
    _directory_pins: Vec<OwnedHandle>,
}
impl Drop for SuspendedHelper {
    fn drop(&mut self) {
        unsafe {
            TerminateProcess(self.process.raw(), 1);
            WaitForSingleObject(self.process.raw(), 5000);
        }
    }
}

/// No shell, account setup, elevation, ambient environment, profile, or PATH
/// executable resolution. Arguments must be broker-generated internal protocol
/// arguments, not an untrusted command. Exact helper binary remains caller-owned.
pub fn launch_suspended_helper(
    store_path: &Path,
    broker_owner_sid: &str,
    helper_exe: &Path,
    helper_args: &[String],
    private_desktop: Option<&str>,
) -> Result<SuspendedHelper> {
    nr::validate_local_directory_path(helper_exe)?;
    ensure!(
        helper_exe
            .extension()
            .is_some_and(|v| v.eq_ignore_ascii_case("exe")),
        "helper must be an absolute .exe file"
    );
    ensure!(
        helper_args.iter().all(|a| !a.contains('\0')),
        "NUL in helper arguments"
    );
    ensure!(
        private_desktop.is_none_or(|v| !v.contains('\0')),
        "NUL in desktop name"
    );
    let record = store::read(store_path, broker_owner_sid)?;
    ensure!(record.ready, "account provisioning is not committed");
    let plain = Zeroizing::new(dpapi::unprotect(&record.password_dpapi)?);
    let password = std::str::from_utf8(&plain)?;
    // Confirms the stored identity is still a non-administrator before launch.
    let base_token = accounts::logon(password, &record.account_sid)?;
    let parent = helper_exe
        .parent()
        .context("helper has no parent directory")?;
    let mut directory_pins = Vec::new();
    for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let pin = nr::open_directory_no_reparse(
            ancestor,
            FILE_TRAVERSE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nr::DirectoryOpenDisposition::OpenExisting,
        )?;
        ensure_sandbox_cannot_modify(&pin, base_token.raw(), ancestor == parent)?;
        directory_pins.push(pin);
    }
    let name = helper_exe.file_name().context("helper has no filename")?;
    let mut name = to_wide(name);
    let image_pin = nr::open_no_reparse(
        directory_pins
            .last()
            .context("helper parent missing")?
            .as_raw_handle() as _,
        &mut name,
        FILE_READ_DATA | FILE_EXECUTE | READ_CONTROL,
        FILE_SHARE_READ,
        1,
        0x40,
        null(),
    )?;
    ensure_sandbox_cannot_modify(&image_pin, base_token.raw(), true)?;
    let exe = helper_exe.to_str().context("helper path must be Unicode")?;
    let mut argv = vec![exe.to_owned()];
    argv.extend_from_slice(helper_args);
    let mut command = to_wide(crate::winutil::argv_to_command_line(&argv));
    ensure!(command.len() <= 32767, "helper command line too long");
    let exe = to_wide(helper_exe);
    let cwd = to_wide(parent);
    let password = Zeroizing::new(to_wide(password));
    let mut environment = helper_environment()?;
    let mut desktop = private_desktop.map(to_wide);
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of_val(&startup) as u32;
    startup.dwFlags = STARTF_FORCEOFFFEEDBACK;
    startup.lpDesktop = desktop.as_mut().map_or(null_mut(), |v| v.as_mut_ptr());
    let mut info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessWithLogonW(
            to_wide(super::OFFLINE_ACCOUNT).as_ptr(),
            to_wide(".").as_ptr(),
            password.as_ptr(),
            0,
            exe.as_ptr(),
            command.as_mut_ptr(),
            CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            environment.as_mut_ptr().cast(),
            cwd.as_ptr(),
            &startup,
            &mut info,
        )
    };
    ensure!(
        ok != 0,
        "CreateProcessWithLogonW failed: {}",
        std::io::Error::last_os_error()
    );
    let process = unsafe { Handle::from_raw(info.hProcess)? };
    let thread = match unsafe { Handle::from_raw(info.hThread) } {
        Ok(thread) => thread,
        Err(error) => {
            unsafe {
                TerminateProcess(process.raw(), 1);
            }
            return Err(error);
        }
    };
    let child = SuspendedHelper {
        process,
        thread,
        pid: info.dwProcessId,
        account_sid: record.account_sid,
        _image_pin: image_pin,
        _directory_pins: directory_pins,
    };
    let mut process_token = 0;
    ensure!(
        unsafe { OpenProcessToken(child.process.raw(), TOKEN_QUERY, &mut process_token) } != 0,
        "cannot verify helper token: {}",
        std::io::Error::last_os_error()
    );
    let process_token = unsafe { Handle::from_raw(process_token)? };
    accounts::verify_token(&process_token, &child.account_sid)?;
    Ok(child)
}

fn helper_environment() -> Result<Vec<u16>> {
    use windows_sys::Win32::System::SystemInformation::{
        GetSystemDirectoryW, GetWindowsDirectoryW,
    };
    let mut windows = vec![0u16; 32768];
    let mut system = vec![0u16; 32768];
    let wn = unsafe { GetWindowsDirectoryW(windows.as_mut_ptr(), windows.len() as u32) } as usize;
    let sn = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
    ensure!(
        wn > 0 && wn < windows.len() && sn > 0 && sn < system.len(),
        "cannot determine trusted Windows directories"
    );
    let windows = String::from_utf16(&windows[..wn])?;
    let system = String::from_utf16(&system[..sn])?;
    let mut result = Vec::new();
    for entry in [
        format!("PATH={system}"),
        format!("SystemRoot={windows}"),
        format!("WINDIR={windows}"),
    ] {
        result.extend(to_wide(entry));
    }
    result.push(0);
    Ok(result)
}

/// Reject an image/path that the sandbox identity could rewrite or take over.
/// MAXIMUM_ALLOWED is evaluated against an impersonation token; unlike testing
/// an aggregate requested mask, any one writable permission is enough to reject.
fn ensure_sandbox_cannot_modify(
    handle: &OwnedHandle,
    base: HANDLE,
    protect_contents: bool,
) -> Result<()> {
    let mut token = 0;
    ensure!(
        unsafe { DuplicateToken(base, SecurityImpersonation, &mut token) } != 0,
        "DuplicateToken failed"
    );
    let token = unsafe { Handle::from_raw(token)? };
    let mut sd = null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut sd,
        )
    };
    ensure!(status == 0, "cannot inspect helper security: {status}");
    let mut mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let mut privileges = [0u64; 512];
    let mut length = std::mem::size_of_val(&privileges) as u32;
    let mut granted = 0;
    let mut access = 0;
    let ok = unsafe {
        AccessCheck(
            sd,
            token.raw(),
            0x0200_0000,
            &mut mapping,
            privileges.as_mut_ptr().cast(),
            &mut length,
            &mut granted,
            &mut access,
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        LocalFree(sd as _);
    }
    ensure!(ok != 0, "helper AccessCheck failed: {error}");
    ensure!(access != 0, "sandbox cannot read helper path");
    let mut mutation = WRITE_DAC | WRITE_OWNER | DELETE | FILE_DELETE_CHILD;
    if protect_contents {
        mutation |= FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES;
    }
    ensure!(granted & mutation == 0, "helper path is sandbox-writable");
    Ok(())
}
