//! Experimental standalone two-stage launch. Never invoked by the public `run` CLI.
//! The trusted owner starts our own immutable helper using CreateProcessWithLogonW.
//! The helper restricts its OWN dedicated-account token before CreateProcessAsUserW.
use crate::{
    admission::AdmittedLaunch,
    process::{Handle, Job},
    protocol::{RunRequest, RunResult},
    setup, token, winutil,
};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*, Security::Authorization::*, Security::*, Storage::FileSystem::*,
    System::Pipes::*, System::Threading::*,
};
const MAX_FRAME: usize = 48 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HelperPayload {
    pub request: RunRequest,
    pub capability_sid: String,
    pub private_desktop: String,
}
struct Pipe {
    handle: Handle,
    name: String,
}
fn win(ok: i32) -> Result<()> {
    ensure!(
        ok != 0,
        "native broker API: {}",
        std::io::Error::last_os_error()
    );
    Ok(())
}
impl Pipe {
    fn create(owner: &str, account: &str) -> Result<Self> {
        unsafe {
            let mut random = [0u8; 16];
            ensure!(
                Cryptography::BCryptGenRandom(
                    null_mut(),
                    random.as_mut_ptr(),
                    16,
                    Cryptography::BCRYPT_USE_SYSTEM_PREFERRED_RNG
                ) >= 0,
                "pipe RNG failed"
            );
            let name = format!(
                r"\\.\pipe\pi-sandbox-{}",
                random
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            );
            let mut sd = null_mut();
            win(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                winutil::to_wide(format!(
                    "D:P(A;;GA;;;{owner})(A;;GA;;;{account})(A;;GA;;;SY)"
                ))
                .as_ptr(),
                1,
                &mut sd,
                null_mut(),
            ))?;
            let sa = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            // Duplex, first instance, local clients only, nonblocking byte transport.
            let raw = CreateNamedPipeW(
                winutil::to_wide(&name).as_ptr(),
                3 | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                65536,
                65536,
                0,
                &sa,
            );
            LocalFree(sd as HLOCAL);
            Ok(Self {
                handle: Handle::from_raw(raw)?,
                name,
            })
        }
    }
    fn connect(&self, expected: u32, deadline: Instant) -> Result<()> {
        loop {
            let ok = unsafe { ConnectNamedPipe(self.handle.raw(), null_mut()) };
            let error = unsafe { GetLastError() };
            if ok != 0 || error == ERROR_PIPE_CONNECTED {
                break;
            }
            ensure!(
                error == ERROR_PIPE_LISTENING || error == ERROR_NO_DATA,
                "pipe connection failed: {error}"
            );
            ensure!(Instant::now() < deadline, "helper pipe connection timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mut actual = 0;
        win(unsafe { GetNamedPipeClientProcessId(self.handle.raw(), &mut actual) })?;
        ensure!(actual == expected, "helper pipe PID mismatch");
        Ok(())
    }
    fn open(name: &str, expected_broker: u32) -> Result<Self> {
        ensure!(
            name.starts_with(r"\\.\pipe\pi-sandbox-")
                && name.len() == r"\\.\pipe\pi-sandbox-".len() + 32,
            "invalid broker pipe namespace"
        );
        ensure!(
            name.as_bytes()[name.len() - 32..]
                .iter()
                .all(|c| c.is_ascii_hexdigit()),
            "invalid pipe nonce"
        );
        let handle = unsafe {
            Handle::from_raw(CreateFileW(
                winutil::to_wide(name).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                0,
            ))?
        };
        let mut pid = 0;
        win(unsafe { GetNamedPipeServerProcessId(handle.raw(), &mut pid) })?;
        ensure!(pid == expected_broker, "broker pipe PID mismatch");
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        win(unsafe { SetNamedPipeHandleState(handle.raw(), &mode, null(), null()) })?;
        Ok(Self {
            handle,
            name: name.to_owned(),
        })
    }
    fn write_bytes(&self, bytes: &[u8], deadline: Instant) -> Result<()> {
        let mut offset = 0;
        while offset < bytes.len() {
            ensure!(Instant::now() < deadline, "pipe write timeout");
            let mut count = 0;
            let ok = unsafe {
                WriteFile(
                    self.handle.raw(),
                    bytes[offset..].as_ptr(),
                    (bytes.len() - offset).min(8192) as u32,
                    &mut count,
                    null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                ensure!(error == ERROR_NO_DATA, "pipe write failed: {error}");
            }
            offset += count as usize;
            if count == 0 {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }
    fn read_bytes(&self, count: usize, deadline: Instant) -> Result<Vec<u8>> {
        ensure!(count <= MAX_FRAME, "pipe frame too large");
        let mut bytes = vec![0u8; count];
        let mut offset = 0;
        while offset < count {
            ensure!(Instant::now() < deadline, "pipe read timeout");
            let mut available = 0;
            win(unsafe {
                PeekNamedPipe(
                    self.handle.raw(),
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            })?;
            if available == 0 {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            let mut read = 0;
            win(unsafe {
                ReadFile(
                    self.handle.raw(),
                    bytes[offset..].as_mut_ptr(),
                    available.min((count - offset) as u32),
                    &mut read,
                    null_mut(),
                )
            })?;
            ensure!(read > 0, "helper pipe closed");
            offset += read as usize;
        }
        Ok(bytes)
    }
    fn send<T: Serialize>(&self, value: &T, deadline: Instant) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        ensure!(bytes.len() <= MAX_FRAME, "outgoing frame too large");
        self.write_bytes(&(bytes.len() as u32).to_le_bytes(), deadline)?;
        self.write_bytes(&bytes, deadline)
    }
    fn receive<T: for<'de> Deserialize<'de>>(&self, deadline: Instant) -> Result<T> {
        let len = self.read_bytes(4, deadline)?;
        let len = u32::from_le_bytes(len.try_into().unwrap()) as usize;
        Ok(serde_json::from_slice(&self.read_bytes(len, deadline)?)?)
    }
}
unsafe fn protect_helper_object(handle: HANDLE, owner: &str) -> Result<()> {
    let mut sd = null_mut();
    // OWNER RIGHTS removes shared account owner's implicit WRITE_DAC. Only trusted
    // broker/system can mutate helper process/thread; this requires native validation.
    win(ConvertStringSecurityDescriptorToSecurityDescriptorW(
        winutil::to_wide(format!("D:P(A;;RC;;;OW)(A;;GA;;;{owner})(A;;GA;;;SY)")).as_ptr(),
        1,
        &mut sd,
        null_mut(),
    ))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    if GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) == 0 {
        LocalFree(sd as HLOCAL);
        anyhow::bail!("helper DACL extraction failed");
    }
    let code = SetSecurityInfo(
        handle,
        SE_KERNEL_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        null_mut(),
        null_mut(),
        dacl,
        null(),
    );
    LocalFree(sd as HLOCAL);
    ensure!(code == 0, "protect helper object failed: {code}");
    Ok(())
}
/// Trusted experimental library entrypoint, distinct from the disabled public CLI.
/// # Safety
/// Caller must authenticate/authorize policy, digest and parent process; verify
/// effective offline controls immediately before use; ensure helper_exe is the
/// trusted product build and all broker/store paths are outside writable roots.
/// No administrator agent is required: CreateProcessWithLogonW establishes the
/// helper account, then the helper restricts a derivative of its own token.
/// Supported setup/OS/secondary-logon service and process-object protection must
/// pass Windows integration tests before this is a production execution boundary.
pub unsafe fn run_via_dedicated_helper(
    store_path: &Path,
    helper_exe: &Path,
    request: RunRequest,
) -> Result<RunResult> {
    request.validate()?;
    let current = Handle::from_raw(token::get_current_token_for_restriction()?)?;
    let owner = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(current.raw())?)
        .map_err(anyhow::Error::msg)?;
    let account_lease = crate::admission::acquire_account_lease(&owner)?;
    let identity = setup::logon_offline_identity(store_path, &owner)?;
    let pipe = Pipe::create(&owner, identity.sid())?;
    let broker_pid = GetCurrentProcessId();
    let args = vec![
        "internal-experimental-helper".into(),
        pipe.name.clone(),
        broker_pid.to_string(),
    ];
    let helper =
        setup::launch::launch_suspended_helper(store_path, &owner, helper_exe, &args, None)?;
    let job = Job::new()?;
    job.assign_suspended(&helper.process)?;
    protect_helper_object(helper.process.raw(), &owner)?;
    protect_helper_object(helper.thread.raw(), &owner)?;
    let mut base = 0;
    win(OpenProcessToken(
        helper.process.raw(),
        TOKEN_QUERY
            | TOKEN_DUPLICATE
            | TOKEN_ASSIGN_PRIMARY
            | TOKEN_ADJUST_DEFAULT
            | TOKEN_ADJUST_PRIVILEGES,
        &mut base,
    ))?;
    let base = Handle::from_raw(base)?;
    let lease =
        AdmittedLaunch::prepare_under_lease(&base, &helper.account_sid, request, &account_lease)?;
    let payload = lease.helper_payload();
    ensure!(
        ResumeThread(helper.thread.raw()) != u32::MAX,
        "resume helper failed"
    );
    let startup = Instant::now() + Duration::from_secs(10);
    pipe.connect(helper.pid, startup)?;
    pipe.send(&payload, startup)?;
    let result: RunResult = pipe
        .receive(
            Instant::now()
                + Duration::from_millis(u64::from(payload.request.timeout_ms))
                + Duration::from_secs(15),
        )
        .context("helper failed; account ACLs retained for verified recovery")?;
    ensure!(result.kind == "result", "invalid helper result type");
    ensure!(
        WaitForSingleObject(helper.process.raw(), 5000) == WAIT_OBJECT_0,
        "helper exit not verified"
    );
    job.terminate()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while job.active_processes()? != 0 {
        ensure!(Instant::now() < deadline, "outer job cleanup unverified");
        std::thread::sleep(Duration::from_millis(5));
    }
    lease.finish_after_verified_cleanup(result)
}
/// Entry used only by our dedicated-account helper binary mode. Reads no secrets.
pub fn helper_main(name: &str, expected_broker: u32) -> Result<()> {
    ensure!(expected_broker > 0, "missing broker identity");
    let pipe = Pipe::open(name, expected_broker)?;
    let payload: HelperPayload = pipe.receive(Instant::now() + Duration::from_secs(10))?;
    payload.request.validate()?;
    // The authenticated parent liveness handle is the transport's actual broker.
    let mut request = payload.request;
    request.parent_pid = expected_broker;
    unsafe {
        let base = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let actual = token::get_user_sid_bytes(base.raw())?;
        let expected = winutil::resolve_sid(&format!(".\\{}", setup::OFFLINE_ACCOUNT))?;
        ensure!(actual == expected, "helper is not dedicated Pi account");
        let cap = token::LocalSid::from_string(&payload.capability_sid)?;
        let restricted = Handle::from_raw(token::create_strict_write_token_from(
            base.raw(),
            &[cap.as_ptr()],
        )?)?;
        let result =
            crate::process::run_restricted(restricted.raw(), &payload.private_desktop, &request)?;
        pipe.send(&result, Instant::now() + Duration::from_secs(10))?;
    }
    Ok(())
}
