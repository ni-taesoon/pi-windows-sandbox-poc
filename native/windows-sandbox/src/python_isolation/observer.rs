//! Trusted native observation. Script output cannot establish token/Job identity.
use super::{IdentityEvidence, NativeEvidence, PYTHON};
use crate::{process::{Handle, Job}, token, winutil};
use anyhow::{ensure, Context, Result};
use std::{mem::{size_of, zeroed}, ptr::null_mut, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, Security::*, Storage::FileSystem::SYNCHRONIZE,
    System::{Diagnostics::ToolHelp::*, JobObjects::*, StationsAndDesktops::*, Threading::*}};
struct Observed { handle: Handle, evidence: IdentityEvidence }
struct PendingChild { handle: Handle, pid: u32, seen: Instant }
pub(crate) struct Observer { root_pid: u32, root_thread: u32, root: Option<Observed>,
    children: Vec<Observed>, pending: Option<PendingChild>, root_error: Option<String>, descendant_error: Option<String>, pub evidence: NativeEvidence }
impl Observer {
    pub fn new() -> Self { Self { root_pid: 0, root_thread: 0, root: None, children: Vec::new(), pending: None,
        root_error: None, descendant_error: None, evidence: NativeEvidence::default() } }
    pub unsafe fn root(&mut self, process: &Handle, pid: u32, tid: u32, job: &Job) {
        self.root_pid = pid; self.root_thread = tid;
        self.try_root(process, job);
    }
    unsafe fn try_root(&mut self, process: &Handle, job: &Job) {
        if self.root.is_some() { return; }
        let result = (|| -> Result<Observed> {
            let mut duplicate = 0;
            ensure!(DuplicateHandle(GetCurrentProcess(), process.raw(), GetCurrentProcess(), &mut duplicate,
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, 0) != 0, "root observer handle duplication failed");
            let handle = Handle::from_raw(duplicate)?;
            let evidence = inspect(&handle, self.root_pid, self.root_thread, job)?;
            Ok(Observed { handle, evidence })
        })();
        match result { Ok(root) => self.root = Some(root), Err(e) => self.root_error = Some(format!("root: {e:#}")) }
    }
    pub unsafe fn poll(&mut self, process: &Handle, job: &Job) {
        self.try_root(process, job);
        if let Err(e) = self.poll_children(job) { if self.descendant_error.is_none() { self.descendant_error = Some(format!("descendant: {e:#}")); }; }
    }
    unsafe fn poll_children(&mut self, job: &Job) -> Result<()> {
        if self.pending.as_ref().is_some_and(|c| c.seen.elapsed() >= Duration::from_millis(100)) {
            let child = self.pending.as_ref().unwrap();
            let tid = child_thread(child.pid, self.root_pid)?;
            let evidence = inspect(&child.handle, child.pid, tid, job)?;
            let child = self.pending.take().unwrap();
            self.children.push(Observed { handle: child.handle, evidence });
        }
        // Fixed suite can contain only a root and one child; spare slots detect expansion.
        #[repr(C)] struct Pids { assigned: u32, count: u32, pids: [usize; 8] }
        let mut pids: Pids = zeroed();
        ensure!(QueryInformationJobObject(job.raw(), JobObjectBasicProcessIdList,
            (&mut pids as *mut Pids).cast(), size_of::<Pids>() as u32, null_mut()) != 0, "query exact Job process list failed");
        ensure!(pids.assigned <= 2 && pids.count <= 2, "unexpected process tree expansion");
        for &pid in &pids.pids[..pids.count as usize] {
            let pid: u32 = pid.try_into()?;
            if pid == self.root_pid || self.children.iter().any(|c| c.evidence.pid == pid)
                || self.pending.as_ref().is_some_and(|c| c.pid == pid) { continue; }
            ensure!(self.children.is_empty() && self.pending.is_none(), "unexpected additional descendant");
            let handle = Handle::from_raw(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid))?;
            let mut member = 0;
            ensure!(IsProcessInJob(handle.raw(),job.raw(),&mut member) != 0 && member != 0, "discovered child outside exact Job");
            // Retain the discovered exact process now, before any PID can be reused.
            // Its desktop setup may still be in progress immediately after CreateProcess.
            self.pending = Some(PendingChild { handle, pid, seen: Instant::now() });
        }
        Ok(())
    }
    pub unsafe fn finish(&mut self, job: &Job) {
        self.evidence.job_empty = job.active_processes().is_ok_and(|n| n == 0);
        self.evidence.unobserved_handles_signaled = self.pending.as_ref().map_or(true, |p|
            WaitForSingleObject(p.handle.raw(), 5000) == WAIT_OBJECT_0);
        if self.pending.is_some() && self.descendant_error.is_none() {
            self.descendant_error = Some("descendant exited before identity observation completed".into());
        }
        if let Some(mut root) = self.root.take() {
            root.evidence.retained_handle_signaled = WaitForSingleObject(root.handle.raw(), 0) == WAIT_OBJECT_0;
            self.evidence.root = Some(root.evidence);
        }
        self.evidence.descendants = self.children.drain(..).map(|mut c| {
            c.evidence.retained_handle_signaled = WaitForSingleObject(c.handle.raw(), 5000) == WAIT_OBJECT_0; c.evidence
        }).collect();
        // A transient root desktop lookup may succeed on a later sample. Any child
        // observation failure is retained conservatively even if later data exists.
        self.evidence.error = self.descendant_error.take().or_else(|| if self.evidence.root.is_none() { self.root_error.take() } else { None });
    }
}
unsafe fn child_thread(pid: u32, parent: u32) -> Result<u32> {
    let snapshot = Handle::from_raw(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0))?;
    let mut entry: PROCESSENTRY32W = zeroed(); entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = Process32FirstW(snapshot.raw(), &mut entry); let mut matched = false;
    while ok != 0 { if entry.th32ProcessID == pid { ensure!(entry.th32ParentProcessID == parent, "unexpected child parent"); matched = true; break; }
        ok = Process32NextW(snapshot.raw(), &mut entry); }
    ensure!(matched, "child not present in process snapshot");
    let mut thread: THREADENTRY32 = zeroed(); thread.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ok = Thread32First(snapshot.raw(), &mut thread);
    while ok != 0 { if thread.th32OwnerProcessID == pid { return Ok(thread.th32ThreadID); }
        ok = Thread32Next(snapshot.raw(), &mut thread); }
    anyhow::bail!("child thread missing")
}
unsafe fn inspect(process: &Handle, pid: u32, tid: u32, job: &Job) -> Result<IdentityEvidence> {
    ensure!(GetProcessId(process.raw()) == pid && WaitForSingleObject(process.raw(), 0) == WAIT_TIMEOUT,
        "process identity/liveness unavailable");
    let mut member = 0;
    ensure!(IsProcessInJob(process.raw(), job.raw(), &mut member) != 0 && member != 0, "not member of exact sandbox Job");
    let mut image = [0u16; 1024]; let mut len = image.len() as u32;
    ensure!(QueryFullProcessImageNameW(process.raw(), 0, image.as_mut_ptr(), &mut len) != 0, "image lookup failed");
    let image = String::from_utf16(&image[..len as usize])?;
    ensure!(image.eq_ignore_ascii_case(PYTHON), "unexpected executable in sandbox Job");
    let mut raw = 0;
    ensure!(OpenProcessToken(process.raw(), TOKEN_QUERY, &mut raw) != 0, "target token query denied");
    let token_handle = Handle::from_raw(raw)?;
    let user_sid = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(token_handle.raw())?).map_err(anyhow::Error::msg)?;
    let restricting_sids = restricting_sids(token_handle.raw())?;
    let desktop = GetThreadDesktop(tid);
    ensure!(desktop != 0, "target thread desktop unavailable");
    let mut name = [0u16; 256]; let mut needed = 0;
    ensure!(GetUserObjectInformationW(desktop, UOI_NAME, name.as_mut_ptr().cast(), (name.len()*2) as u32, &mut needed) != 0,
        "target desktop name query failed");
    let n = name.iter().position(|c| *c == 0).context("desktop name not terminated")?;
    let desktop = format!("Winsta0\\{}", String::from_utf16(&name[..n])?);
    ensure!(desktop.starts_with("Winsta0\\PiSandboxDesktop-"), "target not on private desktop");
    Ok(IdentityEvidence { pid, image, user_sid, restricting_sids, desktop, exact_job_member: true, retained_handle_signaled: false })
}
unsafe fn restricting_sids(handle: HANDLE) -> Result<Vec<String>> {
    let mut needed = 0;
    GetTokenInformation(handle, TokenRestrictedSids, null_mut(), 0, &mut needed);
    ensure!(needed as usize >= size_of::<u32>() && needed <= 65536, "restrictor buffer bounds");
    // usize allocation ensures TOKEN_GROUPS alignment.
    let mut buffer = vec![0usize; (needed as usize + size_of::<usize>() - 1) / size_of::<usize>()];
    ensure!(GetTokenInformation(handle, TokenRestrictedSids, buffer.as_mut_ptr().cast(), needed, &mut needed) != 0, "restrictor query failed");
    ensure!(needed as usize <= buffer.len() * size_of::<usize>(), "restrictor returned size overflow");
    let count = std::ptr::read(buffer.as_ptr().cast::<u32>()) as usize;
    ensure!(count <= 16, "too many restricting SIDs");
    let offset = std::mem::offset_of!(TOKEN_GROUPS, Groups);
    if count == 0 { return Ok(Vec::new()); }
    ensure!(offset + count * size_of::<SID_AND_ATTRIBUTES>() <= needed as usize, "restrictor array out of bounds");
    let entries = (buffer.as_ptr().cast::<u8>()).add(offset).cast::<SID_AND_ATTRIBUTES>();
    let mut result = Vec::new();
    for group in std::slice::from_raw_parts(entries, count) {
        let start = group.Sid as usize; let lower = buffer.as_ptr() as usize; let upper = lower + needed as usize;
        ensure!(start >= lower && start.checked_add(8).is_some_and(|x| x <= upper), "restrictor SID pointer bounds");
        let sub_count = *((group.Sid as *const u8).add(1)) as usize;
        ensure!(start.checked_add(8 + 4 * sub_count).is_some_and(|x| x <= upper) && IsValidSid(group.Sid) != 0, "restrictor SID bounds/format");
        result.push(winutil::string_from_sid_bytes(std::slice::from_raw_parts(group.Sid.cast(), GetLengthSid(group.Sid) as usize)).map_err(anyhow::Error::msg)?);
    }
    result.sort(); Ok(result)
}
