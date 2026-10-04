// Derived from OpenAI Codex windows-sandbox-rs/src/desktop.rs, Apache-2.0.
// Policy cache, Codex naming and unrestricted legacy desktop path removed.
use crate::{token, winutil};
use anyhow::{ensure, Result};
use windows_sys::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
use windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows_sys::Win32::Security::Cryptography::{
    BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::System::StationsAndDesktops::*;
const ALL: u32 = DESKTOP_READOBJECTS
    | DESKTOP_CREATEWINDOW
    | DESKTOP_CREATEMENU
    | DESKTOP_HOOKCONTROL
    | DESKTOP_JOURNALRECORD
    | DESKTOP_JOURNALPLAYBACK
    | DESKTOP_ENUMERATE
    | DESKTOP_WRITEOBJECTS
    | DESKTOP_SWITCHDESKTOP
    | DESKTOP_DELETE
    | DESKTOP_READ_CONTROL
    | DESKTOP_WRITE_DAC
    | DESKTOP_WRITE_OWNER;
const PARTICIPANT: u32 = ALL & !(DESKTOP_WRITE_DAC | DESKTOP_WRITE_OWNER | DESKTOP_DELETE);
/// Keeps a freshly created per-launch private desktop alive. Never opens Default.
pub struct PrivateDesktop {
    handle: isize,
    name: String,
}
impl PrivateDesktop {
    /// # Safety
    /// `sandbox_token` must be a valid dedicated-account primary token whose logon
    /// SID is unique to this launch. The caller is the trusted owner/broker.
    pub unsafe fn for_token(sandbox_token: HANDLE) -> Result<Self> {
        Self::for_token_with_cap(sandbox_token, None)
    }
    /// # Safety
    /// As for_token; capability must be a validated per-launch SID if supplied.
    pub unsafe fn for_token_with_cap(
        sandbox_token: HANDLE,
        capability: Option<&str>,
    ) -> Result<Self> {
        let station = GetProcessWindowStation();
        ensure!(station != 0, "current window station unavailable");
        let mut station_name = [0u16; 256];
        let mut needed = 0;
        ensure!(
            GetUserObjectInformationW(
                station,
                UOI_NAME,
                station_name.as_mut_ptr().cast(),
                (station_name.len() * 2) as u32,
                &mut needed
            ) != 0,
            "cannot inspect current window station"
        );
        let end = station_name
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(station_name.len());
        ensure!(
            String::from_utf16_lossy(&station_name[..end]).eq_ignore_ascii_case("Winsta0"),
            "unsupported window station; broker must run in Winsta0"
        );
        let owner = crate::process::Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let owner_sid = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(owner.raw())?)
            .map_err(anyhow::Error::msg)?;
        let logon_sid = winutil::string_from_sid_bytes(&token::get_logon_sid_bytes(sandbox_token)?)
            .map_err(anyhow::Error::msg)?;
        let cap_ace = match capability {
            Some(value) => {
                let _validated = token::LocalSid::from_string(value)?;
                format!("(A;;0x{PARTICIPANT:x};;;{value})")
            }
            None => String::new(),
        };
        let sddl = winutil::to_wide(format!(
            "D:P(A;;0x{ALL:x};;;{owner_sid})(A;;0x{PARTICIPANT:x};;;{logon_sid}){cap_ace}"
        ));
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        ensure!(
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                std::ptr::null_mut()
            ) != 0,
            "private desktop security descriptor failed: {}",
            std::io::Error::last_os_error()
        );
        let mut random = [0u8; 16];
        if BCryptGenRandom(
            std::ptr::null_mut(),
            random.as_mut_ptr(),
            random.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        ) < 0
        {
            LocalFree(sd as HLOCAL);
            anyhow::bail!("desktop nonce generation failed");
        }
        let name = format!(
            "PiSandboxDesktop-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        let attrs = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let handle = CreateDesktopW(
            winutil::to_wide(&name).as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            ALL,
            &attrs,
        );
        let error = std::io::Error::last_os_error();
        LocalFree(sd as HLOCAL);
        ensure!(handle != 0, "create private desktop failed: {error}");
        Ok(Self {
            handle,
            name: format!("Winsta0\\{name}"),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
}
impl Drop for PrivateDesktop {
    fn drop(&mut self) {
        unsafe {
            CloseDesktop(self.handle);
        }
    }
}
