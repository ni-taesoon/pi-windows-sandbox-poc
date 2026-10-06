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
#[derive(Clone, Copy)]
enum HelperExecution {
    Restricted,
    #[cfg(feature = "lab-minimal-load-comparison")]
    FixedMinimalLoad,
    #[cfg(feature = "lab-pinned-codex-token-comparison")]
    FixedPinnedCodexToken,
}
#[cfg(feature = "lab-minimal-load-comparison")]
impl HelperExecution {
    fn is_fixed_comparison(self) -> bool {
        match self {
            Self::Restricted => false,
            Self::FixedMinimalLoad => true,
            #[cfg(feature = "lab-pinned-codex-token-comparison")]
            Self::FixedPinnedCodexToken => true,
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HelperPayload {
    pub request: RunRequest,
    pub capability_sid: String,
    pub private_desktop: String,
    // A handle-table value in this helper, never a broker-local handle or a PID.
    pub parent_wait_handle: u64,
}
struct Pipe {
    handle: Handle,
    name: String,
}
fn win(api: &'static str, ok: i32) -> Result<()> {
    if ok == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        anyhow::bail!("native broker API failed: api={api}; win32={code}");
    }
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
            win(
                "pipe-sddl/ConvertStringSecurityDescriptorToSecurityDescriptorW",
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    winutil::to_wide(format!(
                        "D:P(A;;GA;;;{owner})(A;;GA;;;{account})(A;;GA;;;SY)"
                    ))
                    .as_ptr(),
                    1,
                    &mut sd,
                    null_mut(),
                ),
            )?;
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
        win("pipe-client-identity/GetNamedPipeClientProcessId", unsafe {
            GetNamedPipeClientProcessId(self.handle.raw(), &mut actual)
        })?;
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
        win("pipe-server-identity/GetNamedPipeServerProcessId", unsafe {
            GetNamedPipeServerProcessId(handle.raw(), &mut pid)
        })?;
        ensure!(pid == expected_broker, "broker pipe PID mismatch");
        let mode = PIPE_READMODE_BYTE | PIPE_NOWAIT;
        win("pipe-read-mode/SetNamedPipeHandleState", unsafe {
            SetNamedPipeHandleState(handle.raw(), &mode, null(), null())
        })?;
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
            win("pipe-read-available/PeekNamedPipe", unsafe {
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
            win("pipe-read/ReadFile", unsafe {
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
    win(
        "helper-object-sddl/ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            winutil::to_wide(format!("D:P(A;;RC;;;OW)(A;;GA;;;{owner})(A;;GA;;;SY)")).as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ),
    )?;
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
/// Install a noninheritable, wait-only reference to this broker into the exact
/// suspended helper returned by trusted creation. Never open a target by PID.
/// The returned value belongs to the helper's handle table: never CloseHandle it
/// in the broker. SuspendedHelper/outer-job cleanup reclaims it on every failure.
unsafe fn duplicate_parent_wait_handle(helper_process: &Handle) -> Result<u64> {
    let mut remote = 0;
    win(
        "parent-wait-transfer/DuplicateHandle",
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentProcess(),
            helper_process.raw(),
            &mut remote,
            SYNCHRONIZE,
            0, // Not inheritable by the restricted command.
            0, // Explicit minimal rights, not SAME_ACCESS or CLOSE_SOURCE.
        ),
    )?;
    Ok(remote as usize as u64)
}

/// Borrow the handoff slot; own only a fresh duplicate. Even malformed numeric
/// input must never be adopted into Handle or closed as an arbitrary local slot.
/// The original handoff slot remains open until this one-shot helper exits.
/// # Safety
/// Value must come from our authenticated broker, which installed a wait-only
/// process handle before resuming this helper. Numeric validation cannot itself
/// authenticate a kernel object's type or identity; do not expose this to run IPC.
unsafe fn duplicate_received_parent_wait_handle(value: u64) -> Result<Handle> {
    ensure!(
        value > 0 && value <= isize::MAX as u64,
        "invalid parent wait handle"
    );
    let mut local = 0;
    win(
        "received-parent-wait-copy/DuplicateHandle",
        DuplicateHandle(
            GetCurrentProcess(),
            value as HANDLE,
            GetCurrentProcess(),
            &mut local,
            SYNCHRONIZE,
            0,
            0, // Never close or take ownership of the received numeric source slot.
        ),
    )?;
    Handle::from_raw(local)
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
    run_helper_impl(store_path, helper_exe, request, HelperExecution::Restricted,
        #[cfg(feature = "lab-minimal-load-comparison")]
        None,
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        None,
    )
}

/// Lab-only fixed comparison. Never called by the product `run` command.
/// # Safety
/// All run_via_dedicated_helper prerequisites apply. The driver must retain the
/// reviewed, hash-bound fixture/helper/ancestor pins through both child launches.
/// The extra ordinary-account process may execute only this fixed trusted loader.
#[cfg(feature = "lab-minimal-load-comparison")]
pub unsafe fn run_fixed_minimal_load_comparison(
    store_path: &Path,
    helper_exe: &Path,
    request: crate::minimal_load::FixedLoadRequest,
    record_account: &mut dyn FnMut(&crate::minimal_load::AccountControlAttempt) -> Result<()>,
) -> Result<RunResult> {
    ensure!(store_path == Path::new(r"C:\PiSandboxLab\store")
        && helper_exe == Path::new(r"C:\PiSandboxLab\trusted\pi-windows-sandbox.exe"),
        "fixed lab store/helper required");
    run_helper_impl(store_path, helper_exe, request.into_request(),
        HelperExecution::FixedMinimalLoad, Some(record_account),
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        None,
    )
}

/// Extra pinned-token condition for the immutable no-argument loader only.
/// This is never a production policy selector or an execution fallback.
/// # Safety
/// All fixed comparison prerequisites apply. Explicit authorization must cover
/// the broader pinned token/default-DACL policy in this disposable offline lab.
/// The recorder must persist each frame and reject incomplete strict observations
/// before returning, because its success permits the extra fixed child to start.
#[cfg(feature = "lab-pinned-codex-token-comparison")]
pub unsafe fn run_fixed_pinned_codex_token_comparison(
    store_path: &Path,
    helper_exe: &Path,
    request: crate::minimal_load::FixedLoadRequest,
    record_account: &mut dyn FnMut(&crate::minimal_load::AccountControlAttempt) -> Result<()>,
    record_pinned: &mut dyn FnMut(&crate::minimal_load::PinnedTokenFrame) -> Result<()>,
) -> Result<RunResult> {
    ensure!(store_path == Path::new(r"C:\PiSandboxLab\store")
        && helper_exe == Path::new(r"C:\PiSandboxLab\trusted\pi-windows-sandbox.exe"),
        "fixed lab store/helper required");
    run_helper_impl(store_path, helper_exe, request.into_request(),
        HelperExecution::FixedPinnedCodexToken, Some(record_account), Some(record_pinned))
}

#[cfg(feature = "lab-pinned-codex-token-comparison")]
fn receive_pinned_token_comparison(
    pipe: &Pipe,
    deadline: Instant,
    record: &mut dyn FnMut(&crate::minimal_load::PinnedTokenFrame) -> Result<()>,
) -> Result<RunResult> {
    use crate::minimal_load::{PinnedTokenFrame, PinnedTokenReady};
    let strict_frame: PinnedTokenFrame = pipe.receive(deadline)
        .context("unchanged strict observation unavailable; pinned-token child NOT_ATTEMPTED")?;
    let strict = strict_frame.expect_unchanged_strict()?;
    record(&strict_frame)?;
    ensure!(strict.can_continue(), "strict cleanup incomplete; pinned-token child NOT_ATTEMPTED");
    let result = strict.run().context("strict result missing")?.clone();
    // The helper cannot create the pinned-token child before durable evidence.
    pipe.send(&PinnedTokenReady::StrictEvidenceRecorded, deadline)?;
    let pinned_frame: PinnedTokenFrame = pipe.receive(deadline)
        .context("pinned-token observation unavailable; strict evidence retained")?;
    let pinned = pinned_frame.expect_pinned_codex_token()?;
    record(&pinned_frame)?;
    ensure!(pinned.can_continue(), "pinned-token process completion/cleanup unverified");
    // Return only the unchanged strict result, never the compatibility result.
    Ok(result)
}

unsafe fn run_helper_impl(
    store_path: &Path,
    helper_exe: &Path,
    request: RunRequest,
    execution: HelperExecution,
    #[cfg(feature = "lab-minimal-load-comparison")]
    mut record_account: Option<&mut dyn FnMut(&crate::minimal_load::AccountControlAttempt) -> Result<()>>,
    #[cfg(feature = "lab-pinned-codex-token-comparison")]
    record_pinned: Option<&mut dyn FnMut(&crate::minimal_load::PinnedTokenFrame) -> Result<()>>,
) -> Result<RunResult> {
    request.validate()?;
    #[cfg(feature = "lab-minimal-load-comparison")]
    if execution.is_fixed_comparison() {
        crate::minimal_load::FixedLoadRequest::new(request.clone())?;
        ensure!(record_account.is_some(), "fixed control recorder required");
    }
    #[cfg(feature = "lab-pinned-codex-token-comparison")]
    ensure!(matches!(execution, HelperExecution::FixedPinnedCodexToken) == record_pinned.is_some(),
        "pinned-token recorder/mode mismatch");
    let current = Handle::from_raw(token::get_current_token_for_restriction()?)?;
    let owner = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(current.raw())?)
        .map_err(anyhow::Error::msg)?;
    let account_lease =
        crate::admission::acquire_account_lease(&owner).context("broker.phase=account-lease")?;
    let identity = setup::logon_offline_identity(store_path, &owner)
        .context("broker.phase=dedicated-logon")?;
    let pipe = Pipe::create(&owner, identity.sid()).context("broker.phase=pipe-create")?;
    let broker_pid = GetCurrentProcessId();
    let command = match execution {
        HelperExecution::Restricted => "internal-experimental-helper",
        #[cfg(feature = "lab-minimal-load-comparison")]
        HelperExecution::FixedMinimalLoad => "internal-fixed-minimal-load-helper",
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        HelperExecution::FixedPinnedCodexToken => "internal-fixed-pinned-codex-token-helper",
    };
    let args = vec![
        command.into(),
        pipe.name.clone(),
        broker_pid.to_string(),
    ];
    let helper =
        setup::launch::launch_suspended_helper(store_path, &owner, helper_exe, &args, None)
            .context("broker.phase=suspended-helper-launch")?;
    let job = Job::new().context("broker.phase=outer-job-create")?;
    job.assign_suspended(&helper.process)
        .context("broker.phase=outer-job-assign")?;
    protect_helper_object(helper.process.raw(), &owner)
        .context("broker.phase=helper-process-protection")?;
    protect_helper_object(helper.thread.raw(), &owner)
        .context("broker.phase=helper-thread-protection")?;
    let parent_wait_handle = duplicate_parent_wait_handle(&helper.process)
        .context("broker.phase=parent-wait-transfer")?;
    let mut base = 0;
    win(
        "helper-base-token/OpenProcessToken",
        OpenProcessToken(
            helper.process.raw(),
            // Admission reads this actual helper's SID/logon session only.
            // The helper creates its own restricted derivative after admission.
            TOKEN_QUERY,
            &mut base,
        ),
    )?;
    let base = Handle::from_raw(base)?;
    let lease =
        AdmittedLaunch::prepare_under_lease(&base, &helper.account_sid, request, &account_lease)
            .context("broker.phase=policy-admission")?;
    let payload = lease.helper_payload(parent_wait_handle);
    ensure!(
        ResumeThread(helper.thread.raw()) != u32::MAX,
        "resume helper failed"
    );
    let startup = Instant::now() + Duration::from_secs(10);
    pipe.connect(helper.pid, startup)?;
    pipe.send(&payload, startup)?;
    let response_budget = match execution {
        HelperExecution::Restricted => Duration::from_millis(u64::from(payload.request.timeout_ms))
            + Duration::from_secs(15),
        // Two bounded runs, their cleanup, and bounded result transport. No retry.
        #[cfg(feature = "lab-minimal-load-comparison")]
        HelperExecution::FixedMinimalLoad => Duration::from_secs(70),
        // Three bounded dedicated-account runs and one evidence acknowledgement.
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        HelperExecution::FixedPinnedCodexToken => Duration::from_secs(105),
    };
    let response_deadline = Instant::now() + response_budget;
    #[cfg(feature = "lab-minimal-load-comparison")]
    if execution.is_fixed_comparison() {
        let account: crate::minimal_load::AccountControlAttempt = pipe.receive(response_deadline)
            .context("fixed account control unavailable; restricted result unavailable")?;
        record_account.as_mut().context("fixed control recorder missing")?(&account)?;
        ensure!(account.can_continue(),
            "fixed account control incomplete; restricted child NOT_ATTEMPTED");
    }
    // This feature omits only observational telemetry on both sides of the pipe.
    // Admission, identity, token, desktop, network and cleanup enforcement remain unchanged.
    #[cfg(not(feature = "lab-minimal-load-comparison"))]
    {
        let startup_diagnostics: crate::startup_diagnostics::StartupDiagnostics = pipe
            .receive(response_deadline)
            .context("helper startup diagnostics unavailable")?;
        eprintln!(
            "helper_startup_access={}",
            serde_json::to_string(&startup_diagnostics)?
        );
    }
    #[cfg(feature = "lab-loader-trace")]
    {
        let loader_trace: crate::loader_trace::LoaderTrace = pipe
            .receive(response_deadline)
            .context("helper loader trace unavailable")?;
        eprintln!(
            "helper_loader_trace={}",
            serde_json::to_string(&loader_trace)?
        );
    }
    #[cfg(feature = "lab-pinned-codex-token-comparison")]
    let result: RunResult = if matches!(execution, HelperExecution::FixedPinnedCodexToken) {
        receive_pinned_token_comparison(&pipe, response_deadline,
            record_pinned.context("pinned-token recorder missing")?)?
    } else {
        pipe.receive(response_deadline)
            .context("helper failed; account ACLs retained for verified recovery")?
    };
    #[cfg(not(feature = "lab-pinned-codex-token-comparison"))]
    let result: RunResult = pipe
        .receive(response_deadline)
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
    helper_main_impl(name, expected_broker, HelperExecution::Restricted)
}
#[cfg(feature = "lab-minimal-load-comparison")]
pub fn fixed_minimal_load_helper_main(name: &str, expected_broker: u32) -> Result<()> {
    helper_main_impl(name, expected_broker, HelperExecution::FixedMinimalLoad)
}
#[cfg(feature = "lab-pinned-codex-token-comparison")]
pub fn fixed_pinned_codex_token_helper_main(name: &str, expected_broker: u32) -> Result<()> {
    helper_main_impl(name, expected_broker, HelperExecution::FixedPinnedCodexToken)
}
fn helper_main_impl(name: &str, expected_broker: u32, execution: HelperExecution) -> Result<()> {
    ensure!(expected_broker > 0, "missing broker identity");
    let pipe = Pipe::open(name, expected_broker)?;
    let payload: HelperPayload = pipe.receive(Instant::now() + Duration::from_secs(10))?;
    payload.request.validate()?;
    // Pipe::open has authenticated the transport server PID. Only that trusted
    // broker installs and sends this handle; request.parent_pid is not used for it.
    let request = payload.request;
    #[cfg(feature = "lab-minimal-load-comparison")]
    let fixed_request = match execution {
        HelperExecution::FixedMinimalLoad => Some(crate::minimal_load::FixedLoadRequest::new(request.clone())?),
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        HelperExecution::FixedPinnedCodexToken => Some(crate::minimal_load::FixedLoadRequest::new(request.clone())?),
        HelperExecution::Restricted => None,
    };
    let _ = execution;
    unsafe {
        let parent = duplicate_received_parent_wait_handle(payload.parent_wait_handle)?;
        let base = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let actual = token::get_user_sid_bytes(base.raw())?;
        let expected = winutil::sid_bytes_from_string(&setup::local_offline_account_sid()?)?;
        ensure!(actual == expected, "helper is not dedicated Pi account");
        let cap = token::LocalSid::from_string(&payload.capability_sid)?;
        let restricted = Handle::from_raw(token::create_strict_write_token_from(
            base.raw(),
            &[cap.as_ptr()],
        )?)?;
        // This is the one-shot dedicated helper, not the owner/broker process.
        // Preserve all existing bits; child startup errors must not wait on an
        // invisible critical-error dialog on the isolated desktop. WER behavior,
        // console flags and security policy are deliberately unchanged.
        use windows_sys::Win32::System::Diagnostics::Debug::{
            GetErrorMode, SetErrorMode, SEM_FAILCRITICALERRORS,
        };
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
        ensure!(
            GetErrorMode() & SEM_FAILCRITICALERRORS != 0,
            "helper critical-error mode was not set"
        );
        #[cfg(feature = "lab-minimal-load-comparison")]
        if let Some(fixed_request) = &fixed_request {
            // The unchanged restricted derivative is already prepared. Its base
            // helper identity is not modified. Runs are sequential on one desktop.
            let account = crate::minimal_load::AccountControlAttempt::from_result(
                crate::process::run_fixed_account_control(
                    fixed_request, &payload.private_desktop, &parent));
            pipe.send(&account, Instant::now() + Duration::from_secs(10))?;
            ensure!(account.can_continue(),
                "fixed account control incomplete; restricted child NOT_ATTEMPTED");
        }
        #[cfg(feature = "lab-pinned-codex-token-comparison")]
        if matches!(execution, HelperExecution::FixedPinnedCodexToken) {
            use crate::minimal_load::{AccountControlAttempt, PinnedTokenFrame, PinnedTokenReady};
            let fixed = fixed_request.as_ref().context("fixed pinned-token request missing")?;
            let strict = AccountControlAttempt::from_result(crate::process::run_restricted_with_parent(
                restricted.raw(), &payload.private_desktop, fixed.request(), &parent));
            pipe.send(&PinnedTokenFrame::UnchangedStrict { attempt: strict.clone() },
                Instant::now() + Duration::from_secs(10))?;
            ensure!(strict.can_continue(), "strict cleanup incomplete; pinned-token child NOT_ATTEMPTED");
            let _: PinnedTokenReady = pipe.receive(Instant::now() + Duration::from_secs(10))
                .context("strict evidence acknowledgement missing; pinned-token child NOT_ATTEMPTED")?;
            let pinned = AccountControlAttempt::from_result((|| -> Result<RunResult> {
                // Exact offline dedicated-runner constructor at pinned Codex
                // a956835d020762cb2b570053af06f643a11c0ecc. Start from the original
                // authenticated base, never the already-restricted derivative.
                // Empty extras: no network proxy SID. No device/global ACL changes.
                let pinned_token = Handle::from_raw(token::create_workspace_write_token_with_caps_and_user_from(
                    base.raw(), &[cap.as_ptr()], &[],
                )?)?;
                crate::process::run_restricted_with_parent(
                    pinned_token.raw(), &payload.private_desktop, fixed.request(), &parent)
            })());
            pipe.send(&PinnedTokenFrame::PinnedCodexToken { attempt: pinned.clone() },
                Instant::now() + Duration::from_secs(10))?;
            ensure!(pinned.can_continue(), "pinned-token process completion/cleanup unverified");
            return Ok(());
        }
        #[cfg(not(feature = "lab-minimal-load-comparison"))]
        {
            let startup_diagnostics = crate::startup_diagnostics::inspect(
                base.raw(),
                restricted.raw(),
                &payload.private_desktop,
            );
            pipe.send(
                &startup_diagnostics,
                Instant::now() + Duration::from_secs(10),
            )?;
        }
        #[cfg(feature = "lab-loader-trace")]
        let result = {
            let mut trace = crate::loader_trace::LoaderTrace::default();
            let fixed_probe = request.argv.len() == 1
                && request.argv[0] == r"C:\PiSandboxLab\trusted\loader_probe.exe";
            let result = if cfg!(feature = "lab-sechost-breakpoints") && !fixed_probe {
                #[cfg(feature = "lab-sechost-breakpoints")]
                trace.original_not_debugged();
                crate::process::run_restricted_with_parent(
                    restricted.raw(),
                    &payload.private_desktop,
                    &request,
                    &parent,
                )
            } else {
                crate::process::run_restricted_with_parent_trace(
                    restricted.raw(),
                    &payload.private_desktop,
                    &request,
                    &parent,
                    &mut trace,
                )
            };
            if result.is_err() {
                trace.runner_failed();
            }
            pipe.send(&trace, Instant::now() + Duration::from_secs(10))?;
            result?
        };
        #[cfg(not(feature = "lab-loader-trace"))]
        let result = crate::process::run_restricted_with_parent(
            restricted.raw(),
            &payload.private_desktop,
            &request,
            &parent,
        )?;
        pipe.send(&result, Instant::now() + Duration::from_secs(10))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // These tests require Windows and exercise real handle-table operations.
    // They do not claim to exercise cross-account creation or hardened DACLs.
    unsafe fn current_process_handle() -> Handle {
        let mut raw = 0;
        assert_ne!(
            DuplicateHandle(
                GetCurrentProcess(),
                GetCurrentProcess(),
                GetCurrentProcess(),
                &mut raw,
                PROCESS_DUP_HANDLE,
                0,
                0
            ),
            0
        );
        Handle::from_raw(raw).unwrap()
    }

    #[test]
    fn transferred_parent_is_wait_only_and_not_inheritable() {
        unsafe {
            let target = current_process_handle();
            let remote = duplicate_parent_wait_handle(&target).unwrap();
            // Target is THIS process in this test, so the test owns the source.
            // Production must never wrap this remote number on the broker side.
            let handoff = Handle::from_raw(remote as HANDLE).unwrap();
            let parent = duplicate_received_parent_wait_handle(remote).unwrap();
            for handle in [&handoff, &parent] {
                assert_eq!(WaitForSingleObject(handle.raw(), 0), WAIT_TIMEOUT);
                let mut flags = 0;
                assert_ne!(GetHandleInformation(handle.raw(), &mut flags), 0);
                assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
                let mut code = 0;
                assert_eq!(
                    GetExitCodeProcess(handle.raw(), &mut code),
                    0,
                    "wait handle must not grant process query access"
                );
                assert_eq!(GetLastError(), ERROR_ACCESS_DENIED);
            }
            drop(parent);
            // Taking and dropping our duplicate must not close the received slot.
            assert_eq!(WaitForSingleObject(handoff.raw(), 0), WAIT_TIMEOUT);
        }
    }

    #[test]
    fn received_numeric_handles_reject_pseudohandles_and_overflow() {
        unsafe {
            for value in [0, u64::MAX, (isize::MAX as u64) + 1] {
                assert!(duplicate_received_parent_wait_handle(value).is_err());
            }
        }
    }

    #[test]
    fn denied_pid_open_still_allows_existing_handle_attenuation() {
        unsafe {
            // This fixture creates an isolated suspended process with its DACL
            // already set. It does not alter the runner's security or accounts.
            // Same-account denial exercises the OS access check, not the full
            // CreateProcessWithLogonW/PiSandboxOffline integration scenario.
            let mut sd = null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    winutil::to_wide("D:P(D;;0x00100000;;;WD)(A;;GA;;;OW)").as_ptr(),
                    1,
                    &mut sd,
                    null_mut()
                ),
                0
            );
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            let executable = winutil::to_wide(std::env::current_exe().unwrap());
            let mut startup: STARTUPINFOW = std::mem::zeroed();
            startup.cb = std::mem::size_of_val(&startup) as u32;
            let mut info: PROCESS_INFORMATION = std::mem::zeroed();
            let created = CreateProcessW(
                executable.as_ptr(),
                null_mut(),
                &attributes,
                null(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                null(),
                null(),
                &startup,
                &mut info,
            );
            let error = std::io::Error::last_os_error();
            LocalFree(sd as HLOCAL);
            assert_ne!(created, 0, "fixture creation failed: {error}");
            struct Child(Handle);
            impl Drop for Child {
                fn drop(&mut self) {
                    unsafe {
                        TerminateProcess(self.0.raw(), 1);
                        WaitForSingleObject(self.0.raw(), 5000);
                    }
                }
            }
            let child = Child(Handle::from_raw(info.hProcess).unwrap());
            let _thread = Handle::from_raw(info.hThread).unwrap();
            let reopened = OpenProcess(SYNCHRONIZE, 0, info.dwProcessId);
            let open_error = GetLastError();
            if reopened != 0 {
                CloseHandle(reopened);
            }
            assert_eq!(reopened, 0, "DACL must deny a new PID-based wait open");
            assert_eq!(open_error, ERROR_ACCESS_DENIED);
            let mut raw = 0;
            assert_ne!(
                DuplicateHandle(
                    GetCurrentProcess(),
                    child.0.raw(),
                    GetCurrentProcess(),
                    &mut raw,
                    SYNCHRONIZE,
                    0,
                    0
                ),
                0
            );
            let handoff = Handle::from_raw(raw).unwrap();
            let parent = duplicate_received_parent_wait_handle(raw as u64).unwrap();
            assert_eq!(WaitForSingleObject(parent.raw(), 0), WAIT_TIMEOUT);
            assert_ne!(TerminateProcess(child.0.raw(), 1), 0);
            assert_eq!(WaitForSingleObject(parent.raw(), 5000), WAIT_OBJECT_0);
            drop(parent);
            assert_eq!(WaitForSingleObject(handoff.raw(), 0), WAIT_OBJECT_0);
        }
    }
}

#[cfg(feature = "lab-python-isolation-acceptance")]
#[path = "python_isolation/broker.rs"]
mod python_isolation_lab;
#[cfg(feature = "lab-python-isolation-acceptance")]
pub use python_isolation_lab::{fixed_python_isolation_helper_main, run_fixed_python_acceptance};
