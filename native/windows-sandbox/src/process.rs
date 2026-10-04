// Adapted from OpenAI Codex windows-sandbox-rs/src/process.rs and
// utils/pty/src/win/job.rs (Apache-2.0). No compatibility host fallback.
use crate::proc_thread_attr::ProcThreadAttributeList;
use crate::protocol::{RunRequest, RunResult, StopReason};
use crate::winutil::{argv_to_command_line, to_wide};
use anyhow::{ensure, Context, Result};
use base64::Engine;
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile, SYNCHRONIZE};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Pipes::{CreatePipe, PeekNamedPipe};
use windows_sys::Win32::System::Threading::*;

/// Owned kernel handle. Never inherited except an explicit child stdio list.
pub struct Handle(HANDLE);
impl Handle {
    /// # Safety
    /// `raw` must be a newly owned valid kernel handle, closed exactly once here.
    pub unsafe fn from_raw(raw: HANDLE) -> Result<Self> {
        ensure!(
            raw != 0 && raw != INVALID_HANDLE_VALUE,
            "invalid Windows handle"
        );
        Ok(Self(raw))
    }
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// A kill-on-close job. Breakaway and preserve-descendants are intentionally absent.
pub struct Job(Handle);
impl Job {
    pub fn new() -> Result<Self> {
        let handle = unsafe { Handle::from_raw(CreateJobObjectW(null(), null()))? };
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        win(unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        })?;
        Ok(Self(handle))
    }
    pub fn raw(&self) -> HANDLE {
        self.0.raw()
    }
    /// Assign only a trusted helper that is still suspended. Never resumes on failure.
    pub fn assign_suspended(&self, process: &Handle) -> Result<()> {
        win(unsafe { AssignProcessToJobObject(self.0.raw(), process.raw()) })
    }
    pub fn terminate(&self) -> Result<()> {
        win(unsafe { TerminateJobObject(self.0.raw(), 1) })
    }
    pub fn active_processes(&self) -> Result<u32> {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        win(unsafe {
            QueryInformationJobObject(
                self.0.raw(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                null_mut(),
            )
        })?;
        Ok(info.ActiveProcesses)
    }
}
fn win(result: i32) -> Result<()> {
    if result == 0 {
        Err(std::io::Error::last_os_error()).context("Windows sandbox API failed")
    } else {
        Ok(())
    }
}
fn pipe() -> Result<(Handle, Handle)> {
    let (mut read, mut write) = (0, 0);
    win(unsafe { CreatePipe(&mut read, &mut write, null(), 0) })?;
    unsafe { Ok((Handle::from_raw(read)?, Handle::from_raw(write)?)) }
}
fn drain(handle: &Handle, output: &mut Vec<u8>, limit: usize, truncated: &mut bool) -> Result<()> {
    // Bounded work per iteration prevents a noisy child from starving timeout/liveness checks.
    for _ in 0..16 {
        let mut available = 0;
        let ok = unsafe {
            PeekNamedPipe(
                handle.raw(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        };
        if ok == 0 {
            if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                return Ok(());
            }
            return win(ok);
        }
        if available == 0 {
            return Ok(());
        }
        let mut buf = [0u8; 8192];
        let mut read = 0;
        win(unsafe {
            ReadFile(
                handle.raw(),
                buf.as_mut_ptr(),
                available.min(buf.len() as u32),
                &mut read,
                null_mut(),
            )
        })?;
        let keep = (limit.saturating_sub(output.len())).min(read as usize);
        output.extend_from_slice(&buf[..keep]);
        *truncated |= keep < read as usize;
    }
    Ok(())
}

/// Launch with a previously restricted dedicated-account token and protected private desktop.
/// This is a low-level primitive, NOT an authorization or provisioning endpoint.
///
/// # Safety
/// Caller must authenticate policy outside the sandbox, verify dedicated-account offline WFP/
/// firewall protection, install and verify ACLs including explicit denies, supply a valid primary
/// restricted token and keep its private desktop alive. Token must NOT belong to the signed-in
/// user. `private_desktop` must be a protected Pi private desktop, never interactive Default.
/// This function does not provision, mutate ACLs, log on, or authorize untrusted policy input.
/// Parent PID must be authenticated by the caller; numeric PID by itself is not authentication.
pub unsafe fn run_restricted(
    token: HANDLE,
    private_desktop: &str,
    request: &RunRequest,
) -> Result<RunResult> {
    request.validate()?;
    let parent = Handle::from_raw(OpenProcess(SYNCHRONIZE, 0, request.parent_pid))?;
    run_restricted_with_parent(token, private_desktop, request, &parent)
}

/// Handle-based primitive for the dedicated helper: no cross-account OpenProcess.
/// # Safety
/// All run_restricted prerequisites apply. `parent` must reference the authenticated
/// broker process with SYNCHRONIZE rights and remain alive through this call.
/// The caller retains ownership; this function never closes the borrowed handle.
pub(crate) unsafe fn run_restricted_with_parent(
    token: HANDLE,
    private_desktop: &str,
    request: &RunRequest,
    parent: &Handle,
) -> Result<RunResult> {
    request.validate()?;
    ensure!(token != 0 && token != INVALID_HANDLE_VALUE, "invalid token");
    ensure!(
        private_desktop
            .strip_prefix("Winsta0\\PiSandboxDesktop-")
            .is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())),
        "protected private desktop required"
    );
    ensure!(
        std::path::Path::new(&request.argv[0]).is_absolute(),
        "absolute executable required"
    );
    ensure!(
        std::path::Path::new(&request.cwd).is_absolute(),
        "absolute cwd required"
    );
    ensure!(
        WaitForSingleObject(parent.raw(), 0) == WAIT_TIMEOUT,
        "parent not alive"
    );
    let job = Job::new()?;
    let (stdin_read, stdin_write) = pipe()?;
    let (stdout_read, stdout_write) = pipe()?;
    let (stderr_read, stderr_write) = pipe()?;
    let handles = vec![stdin_read.raw(), stdout_write.raw(), stderr_write.raw()];
    for h in &handles {
        win(SetHandleInformation(
            *h,
            HANDLE_FLAG_INHERIT,
            HANDLE_FLAG_INHERIT,
        ))?;
    }
    let mut attrs = ProcThreadAttributeList::new(2)?;
    attrs.set_job(job.0.raw())?;
    attrs.set_handle_list(handles)?;
    let mut startup: STARTUPINFOEXW = std::mem::zeroed();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = stdin_read.raw();
    startup.StartupInfo.hStdOutput = stdout_write.raw();
    startup.StartupInfo.hStdError = stderr_write.raw();
    let mut desktop = to_wide(private_desktop);
    startup.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    startup.lpAttributeList = attrs.as_mut_ptr();
    let executable = to_wide(&request.argv[0]);
    let mut command = to_wide(argv_to_command_line(&request.argv));
    let cwd = to_wide(&request.cwd);
    let mut entries: Vec<_> = request.env.iter().collect();
    entries.sort_by_key(|(k, _)| k.to_uppercase());
    let mut env: Vec<u16> = entries
        .iter()
        .flat_map(|(k, v)| to_wide(format!("{k}={v}")))
        .collect();
    env.push(0);
    if env.len() == 1 {
        env.push(0);
    }
    let mut info: PROCESS_INFORMATION = std::mem::zeroed();
    win(CreateProcessAsUserW(
        token,
        executable.as_ptr(),
        command.as_mut_ptr(),
        null(),
        null(),
        1,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
        env.as_ptr().cast::<c_void>(),
        cwd.as_ptr(),
        &startup.StartupInfo,
        &mut info,
    ))?;
    let process = Handle::from_raw(info.hProcess)?;
    let _thread = Handle::from_raw(info.hThread)?;
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    let input = request.stdin.as_bytes().to_vec();
    // Only this newly created noninheritable parent handle moves into the writer.
    let writer = std::thread::spawn(move || {
        let mut offset = 0;
        while offset < input.len() {
            let mut written = 0;
            if WriteFile(
                stdin_write.raw(),
                input[offset..].as_ptr(),
                (input.len() - offset).min(8192) as u32,
                &mut written,
                null_mut(),
            ) == 0
                || written == 0
            {
                break;
            }
            offset += written as usize;
        }
    });
    let start = Instant::now();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let (mut timed_out, mut truncated) = (false, false);
    let stop_reason = loop {
        drain(
            &stdout_read,
            &mut stdout,
            request.max_output_bytes,
            &mut truncated,
        )?;
        drain(
            &stderr_read,
            &mut stderr,
            request.max_output_bytes,
            &mut truncated,
        )?;
        if truncated {
            break StopReason::OutputLimit;
        }
        if WaitForSingleObject(parent.raw(), 0) != WAIT_TIMEOUT {
            break StopReason::ParentDeath;
        }
        match WaitForSingleObject(process.raw(), 0) {
            WAIT_OBJECT_0 => break StopReason::Exited,
            WAIT_TIMEOUT => {}
            _ => anyhow::bail!("process wait failed"),
        }
        timed_out = start.elapsed() >= Duration::from_millis(request.timeout_ms.into());
        if timed_out {
            break StopReason::Timeout;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    job.terminate()?; // Also terminate descendants after a normal root exit.
    let cleanup = Instant::now();
    while job.active_processes()? != 0 {
        ensure!(
            cleanup.elapsed() < Duration::from_secs(5),
            "job cleanup unverified"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    ensure!(
        WaitForSingleObject(process.raw(), 5000) == WAIT_OBJECT_0,
        "root exit unverified"
    );
    let mut exit_code = 1;
    win(GetExitCodeProcess(process.raw(), &mut exit_code))?;
    ensure!(
        exit_code != STILL_ACTIVE as u32,
        "root still active after cleanup"
    );
    // Drain until pipe EOF/no data after all writers in the contained tree are dead.
    for _ in 0..128 {
        let before = stdout.len() + stderr.len();
        drain(
            &stdout_read,
            &mut stdout,
            request.max_output_bytes,
            &mut truncated,
        )?;
        drain(
            &stderr_read,
            &mut stderr,
            request.max_output_bytes,
            &mut truncated,
        )?;
        if stdout.len() + stderr.len() == before {
            break;
        }
    }
    if writer.is_finished() {
        let _ = writer.join();
    }
    Ok(RunResult {
        stop_reason,
        kind: "result".into(),
        exit_code,
        stdout_base64: base64::engine::general_purpose::STANDARD.encode(&stdout),
        stderr_base64: base64::engine::general_purpose::STANDARD.encode(&stderr),
        timed_out,
        truncated,
        terminated: true,
        cleanup_verified: true,
    })
}
