//! Explicit lab debugger: no attach, memory/context operations, injection or grants.
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::{
    marker::PhantomData,
    ptr::null_mut,
    rc::Rc,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::{GetFinalPathNameByHandleW, ReadFile, SetFilePointerEx, FILE_BEGIN},
    System::{Diagnostics::Debug::*, JobObjects::*},
};
const STORED_EVENTS: usize = 256;
const EVENT_LIMIT: u32 = 4096;
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Kind {
    ProcessCreated,
    ThreadCreated,
    ThreadExited,
    DllLoaded,
    DllUnloaded,
    Exception,
    DebugStringSkipped,
    Rip,
    ProcessExited,
    Other,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Event {
    kind: Kind,
    module: Option<String>,
    code: Option<u32>,
    first_chance: Option<bool>,
    initial_breakpoint_handled: bool,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LoaderTrace {
    events: Vec<Event>,
    event_count: u32,
    stored_events_truncated: bool,
    event_limit_reached: bool,
    exit_event_continued: bool,
    cleanup_verified: bool,
    failure: Option<Failure>,
    normal_validation_eligible: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Stage {
    Wait,
    Continue,
    UnexpectedProcess,
    Runner,
    Termination,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Failure {
    stage: Stage,
    win32: Option<u32>,
}
impl LoaderTrace {
    pub fn runner_failed(&mut self) {
        if self.failure.is_none() {
            self.failure = Some(Failure {
                stage: Stage::Runner,
                win32: None,
            });
        }
    }
}
struct Pending {
    pid: u32,
    tid: u32,
    status: i32,
    is_exit: bool,
    attempts: u8,
}
pub(crate) struct DebugPump<'a> {
    trace: &'a mut LoaderTrace,
    pid: u32,
    job: HANDLE,
    pending: Option<Pending>,
    initial_breakpoint_seen: bool,
    create_seen: bool,
    cleanup_deadline: Option<Instant>,
    ntdll_range: Option<(usize, usize)>,
    _same_thread: PhantomData<Rc<()>>,
}
fn image_size(header: &[u8]) -> Option<usize> {
    if header.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32::from_le_bytes(header.get(60..64)?.try_into().ok()?) as usize;
    if header.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let optional = pe.checked_add(24)?;
    let magic = u16::from_le_bytes(
        header
            .get(optional..optional.checked_add(2)?)?
            .try_into()
            .ok()?,
    );
    if magic != 0x10b && magic != 0x20b {
        return None;
    }
    let size = u32::from_le_bytes(
        header
            .get(optional.checked_add(56)?..optional.checked_add(60)?)?
            .try_into()
            .ok()?,
    ) as usize;
    (4096..=128 * 1024 * 1024).contains(&size).then_some(size)
}
unsafe fn module_and_close(file: HANDLE) -> (Option<String>, Option<usize>) {
    if file == 0 || file == INVALID_HANDLE_VALUE {
        return (None, None);
    }
    // These are transferred FILE handles, not OS-managed debug process/thread handles.
    // All metadata comes from the file; no target-memory pointer is read.
    let result = (|| -> Option<(String, Option<usize>)> {
        let mut buffer = vec![0u16; 32768];
        let length = GetFinalPathNameByHandleW(file, buffer.as_mut_ptr(), buffer.len() as u32, 0);
        if length == 0 || length as usize >= buffer.len() {
            return None;
        }
        let path = String::from_utf16(&buffer[..length as usize]).ok()?;
        let name = path.rsplit(['\\', '/']).next()?.to_ascii_lowercase();
        if name.len() > 132
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || !(name.ends_with(".dll") || name.ends_with(".exe"))
        {
            return None;
        }
        let mut size = None;
        if name == "ntdll.dll" {
            let mut header = [0u8; 4096];
            let mut read = 0;
            if SetFilePointerEx(file, 0, null_mut(), FILE_BEGIN) != 0
                && ReadFile(file, header.as_mut_ptr(), 4096, &mut read, null_mut()) != 0
            {
                size = image_size(&header[..(read as usize).min(header.len())]);
            }
        }
        Some((name, size))
    })();
    CloseHandle(file);
    result.map_or((None, None), |(name, size)| (Some(name), size))
}
impl<'a> DebugPump<'a> {
    pub fn new(pid: u32, job: HANDLE, trace: &'a mut LoaderTrace) -> Self {
        Self {
            trace,
            pid,
            job,
            pending: None,
            initial_breakpoint_seen: false,
            create_seen: false,
            cleanup_deadline: None,
            ntdll_range: None,
            _same_thread: PhantomData,
        }
    }
    pub fn exited(&self) -> bool {
        self.trace.exit_event_continued
    }
    pub fn limit_reached(&self) -> bool {
        self.trace.event_limit_reached
    }
    pub fn begin_cleanup(&mut self, deadline: Instant) {
        if self.cleanup_deadline.is_none() {
            self.cleanup_deadline = Some(deadline);
        }
    }
    pub fn verified_cleanup(&mut self) {
        self.trace.cleanup_verified = true;
    }
    unsafe fn continue_pending(&mut self) -> Result<()> {
        if let Some(pending) = &mut self.pending {
            ensure!(
                pending.attempts < 2,
                "debug continuation retry bound reached"
            );
            pending.attempts += 1;
            if ContinueDebugEvent(pending.pid, pending.tid, pending.status) == 0 {
                let code = GetLastError();
                self.trace.failure = Some(Failure {
                    stage: Stage::Continue,
                    win32: Some(code),
                });
                anyhow::bail!("debug ContinueDebugEvent failed: win32={code}");
            }
            if pending.is_exit {
                self.trace.exit_event_continued = true;
            }
            self.pending = None;
        }
        Ok(())
    }
    pub unsafe fn poll(&mut self, wait_ms: u32) -> Result<()> {
        self.continue_pending()?;
        if self.exited() {
            return Ok(());
        }
        let mut raw: DEBUG_EVENT = std::mem::zeroed();
        if WaitForDebugEvent(&mut raw, wait_ms) == 0 {
            let code = GetLastError();
            if code == ERROR_SEM_TIMEOUT {
                return Ok(());
            }
            self.trace.failure = Some(Failure {
                stage: Stage::Wait,
                win32: Some(code),
            });
            anyhow::bail!("debug WaitForDebugEvent failed: win32={code}");
        }
        let mut event = Event {
            kind: Kind::Other,
            module: None,
            code: None,
            first_chance: None,
            initial_breakpoint_handled: false,
        };
        let mut status = DBG_CONTINUE;
        match raw.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                event.kind = Kind::ProcessCreated;
                event.module = module_and_close(raw.u.CreateProcessInfo.hFile).0;
                self.create_seen = true;
            }
            LOAD_DLL_DEBUG_EVENT => {
                event.kind = Kind::DllLoaded;
                let (module, size) = module_and_close(raw.u.LoadDll.hFile);
                if module.as_deref() == Some("ntdll.dll") && raw.dwProcessId == self.pid {
                    if let Some(size) = size {
                        let start = raw.u.LoadDll.lpBaseOfDll as usize;
                        self.ntdll_range = start.checked_add(size).map(|end| (start, end));
                    }
                }
                event.module = module;
            }
            UNLOAD_DLL_DEBUG_EVENT => event.kind = Kind::DllUnloaded,
            CREATE_THREAD_DEBUG_EVENT => event.kind = Kind::ThreadCreated,
            EXIT_THREAD_DEBUG_EVENT => {
                event.kind = Kind::ThreadExited;
                event.code = Some(raw.u.ExitThread.dwExitCode);
            }
            OUTPUT_DEBUG_STRING_EVENT => event.kind = Kind::DebugStringSkipped, // Never read the target string pointer.
            RIP_EVENT => {
                event.kind = Kind::Rip;
                event.code = Some(raw.u.RipInfo.dwError);
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                event.kind = Kind::ProcessExited;
                event.code = Some(raw.u.ExitProcess.dwExitCode);
            }
            EXCEPTION_DEBUG_EVENT => {
                let exception = raw.u.Exception;
                event.kind = Kind::Exception;
                event.code = Some(exception.ExceptionRecord.ExceptionCode as u32);
                event.first_chance = Some(exception.dwFirstChance != 0);
                let initial = raw.dwProcessId == self.pid
                    && self.create_seen
                    && !self.initial_breakpoint_seen
                    && exception.dwFirstChance != 0
                    && exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT
                    && self.ntdll_range.is_some_and(|(start, end)| {
                        let address = exception.ExceptionRecord.ExceptionAddress as usize;
                        address >= start && address < end
                    });
                if initial {
                    self.initial_breakpoint_seen = true;
                    event.initial_breakpoint_handled = true;
                } else {
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            }
            _ => {}
        }
        self.pending = Some(Pending {
            pid: raw.dwProcessId,
            tid: raw.dwThreadId,
            status,
            is_exit: raw.dwProcessId == self.pid
                && raw.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT,
            attempts: 0,
        });
        self.trace.event_count = self.trace.event_count.saturating_add(1);
        if self.trace.events.len() < STORED_EVENTS {
            self.trace.events.push(event);
        } else {
            self.trace.stored_events_truncated = true;
        }
        self.trace.event_limit_reached |= self.trace.event_count >= EVENT_LIMIT;
        let matches = raw.dwProcessId == self.pid;
        self.continue_pending()?; // Never leave a successfully read event suspended for bookkeeping.
        if !matches {
            self.trace.failure = Some(Failure {
                stage: Stage::UnexpectedProcess,
                win32: None,
            });
            anyhow::bail!("unexpected debug process");
        }
        Ok(())
    }
    unsafe fn job_empty(&self) -> bool {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
        QueryInformationJobObject(
            self.job,
            JobObjectBasicAccountingInformation,
            (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            std::mem::size_of_val(&info) as u32,
            null_mut(),
        ) != 0
            && info.ActiveProcesses == 0
    }
}
impl Drop for DebugPump<'_> {
    fn drop(&mut self) {
        if self.trace.cleanup_verified {
            return;
        }
        unsafe {
            if TerminateJobObject(self.job, 1) == 0 {
                self.trace.failure = Some(Failure {
                    stage: Stage::Termination,
                    win32: Some(GetLastError()),
                });
            }
            let deadline = self
                .cleanup_deadline
                .unwrap_or_else(|| Instant::now() + Duration::from_secs(5));
            while Instant::now() < deadline {
                if self.poll(10).is_err() {
                    break;
                }
                if self.exited() && self.job_empty() {
                    self.trace.cleanup_verified = true;
                    break;
                }
            }
            // On inconclusive cleanup, helper exit and the outer kill job remain
            // the final containment layers. Never detach or disable debugger kill-on-exit.
        }
    }
}
