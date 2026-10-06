//! Trusted native observation. Script output cannot establish token/Job identity.
use super::{IdentityEvidence, NativeEvidence, JobPidSnapshot, JobMemberEvidence, NativeDiagnostics, DesktopEvidence, PYTHON, CONHOST};
use crate::{process::{Handle, Job}, token, winutil};
use anyhow::{ensure, Context, Result};
use std::{mem::{size_of, zeroed}, ptr::null_mut, time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, Security::*, Storage::FileSystem::SYNCHRONIZE,
    System::{Diagnostics::ToolHelp::*, JobObjects::*, StationsAndDesktops::*, Threading::*}};
struct Observed { handle: Handle, evidence: IdentityEvidence, thread_id: Option<u32> }
struct PendingChild { handle: Handle, pid: u32, seen: Instant }
pub(crate) struct Observer { root_pid: u32, root_thread: u32, root: Option<Observed>,
    children: Vec<Observed>, console_hosts: Vec<Observed>, unclassified: Vec<(u32,Handle)>, pending: Option<PendingChild>, root_error: Option<String>, descendant_error: Option<String>, pub evidence: NativeEvidence }
impl Observer {
    pub fn new() -> Self { Self { root_pid: 0, root_thread: 0, root: None, children: Vec::new(), console_hosts: Vec::new(), unclassified: Vec::new(), pending: None,
        root_error: None, descendant_error: None, evidence: NativeEvidence::default() } }
    pub unsafe fn root(&mut self, process: &Handle, pid: u32, tid: u32, job: &Job) {
        self.root_pid = pid; self.root_thread = tid;
        self.evidence.diagnostics.expected_root_pid = pid;
        self.evidence.diagnostics.expected_root_thread_id = tid;
        self.try_root(process, job);
    }
    unsafe fn try_root(&mut self, process: &Handle, job: &Job) {
        if let Some(root)=self.root.as_mut() { refresh_desktop(root); return; }
        let result = (|| -> Result<Observed> {
            let mut duplicate = 0;
            api(DuplicateHandle(GetCurrentProcess(), process.raw(), GetCurrentProcess(), &mut duplicate,
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, 0), "DuplicateHandle(root-query-copy)")?;
            let handle = Handle::from_raw(duplicate)?;
            let evidence = inspect(&handle, self.root_pid, Some(self.root_thread), job, PYTHON)?;
            Ok(Observed { handle, evidence, thread_id:Some(self.root_thread) })
        })();
        match result {
            Ok(root) => self.root = Some(root),
            Err(e) => {
                let error = format!("root: {e:#}");
                self.evidence.diagnostics.root_error(error.clone());
                self.root_error = Some(error);
            }
        }
    }
    pub unsafe fn poll(&mut self, process: &Handle, job: &Job) {
        self.try_root(process, job);
        for child in &mut self.children { refresh_desktop(child); }
        if let Err(e) = self.poll_children(job) {
            let error = format!("descendant: {e:#}");
            self.evidence.diagnostics.descendant_error(error.clone());
            if self.descendant_error.is_none() { self.descendant_error = Some(error); }
        }
    }
    unsafe fn poll_children(&mut self, job: &Job) -> Result<()> {
        // At most Python root + one Python child + one independently verified system conhost.
        #[repr(C)] struct Pids { assigned: u32, count: u32, pids: [usize; 8] }
        let mut pids: Pids = zeroed();
        let query = QueryInformationJobObject(job.raw(), JobObjectBasicProcessIdList,
            (&mut pids as *mut Pids).cast(), size_of::<Pids>() as u32, null_mut());
        let query_error = if query == 0 { Some(format!("api=QueryInformationJobObject(PIDs); win32={}", GetLastError())) } else { None };
        // Record before any rejection. Failed-query buffers are never read as PID evidence.
        let observed_pids = if query != 0 {
            pids.pids[..(pids.count as usize).min(pids.pids.len())].iter()
                .filter_map(|pid| u32::try_from(*pid).ok()).collect::<Vec<_>>()
        } else { Vec::new() };
        if pids.count as usize > pids.pids.len() || pids.assigned > pids.count { self.evidence.diagnostics.truncated = true; }
        self.evidence.diagnostics.snapshot(JobPidSnapshot { assigned:pids.assigned, returned:pids.count,
            pids:observed_pids.clone(), query_error:query_error.clone() });
        if let Some(error) = query_error { anyhow::bail!("{error}"); }
        for pid in observed_pids {
            if self.evidence.diagnostics.job_members.iter().any(|member| member.pid == pid) { continue; }
            if self.evidence.diagnostics.job_members.len() >= NativeDiagnostics::LIMIT {
                self.evidence.diagnostics.truncated = true; continue;
            }
            let image = member_image(pid,job);
            self.evidence.diagnostics.member(JobMemberEvidence {pid,image:image.as_ref().ok().cloned(),
                query_error:image.err().map(|error|format!("{error:#}"))});
        }
        ensure!(pids.assigned <= 3 && pids.count <= 3,
            "unexpected process tree expansion: expectedRootPid={}; assigned={}; returned={}", self.root_pid,pids.assigned,pids.count);
        if self.pending.as_ref().is_some_and(|c| c.seen.elapsed() >= Duration::from_millis(100)) {
            let child = self.pending.as_ref().unwrap();
            let tid = child_thread(child.pid, self.root_pid)?;
            let evidence = inspect(&child.handle, child.pid, Some(tid), job, PYTHON)?;
            let child = self.pending.take().unwrap();
            self.children.push(Observed { handle: child.handle, evidence, thread_id:Some(tid) });
        }

        for &pid in &pids.pids[..pids.count as usize] {
            let pid: u32 = pid.try_into()?;
            if pid == self.root_pid || self.children.iter().any(|c| c.evidence.pid == pid)
                || self.pending.as_ref().is_some_and(|c| c.pid == pid)
                || self.console_hosts.iter().any(|c| c.evidence.pid == pid)
                || self.unclassified.iter().any(|(seen,_)| *seen == pid) { continue; }
            let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid);
            api((raw != 0) as i32, "OpenProcess(discovered-child)")?;
            let handle = Handle::from_raw(raw)?;
            let mut member = 0;
            api(IsProcessInJob(handle.raw(),job.raw(),&mut member), "IsProcessInJob(discovered-child)")?;
            ensure!(member != 0, "discovered child outside exact Job: pid={pid}");
            let classification = (|| -> Result<Option<IdentityEvidence>> {
                let image = process_image(&handle)?;
                if image.eq_ignore_ascii_case(CONHOST) {
                    ensure!(self.console_hosts.is_empty(), "multiple console hosts in fixed Job");
                    // Infrastructure token/restrictors are reported separately; it is
                    // not a Python descendant and does not inherit its acceptance rule.
                    return Ok(Some(inspect(&handle,pid,None,job,CONHOST)?));
                }
                ensure!(image.eq_ignore_ascii_case(PYTHON), "unexpected Job image: pid={pid}; image={image}");
                ensure!(self.children.is_empty() && self.pending.is_none(), "unexpected additional Python descendant");
                Ok(None)
            })();
            match classification {
                Ok(Some(evidence)) => self.console_hosts.push(Observed {handle,evidence,thread_id:None}),
                Ok(None) => self.pending=Some(PendingChild {handle,pid,seen:Instant::now()}),
                Err(error) => { self.unclassified.push((pid,handle)); return Err(error); }
            }
        }
        Ok(())
    }
    pub unsafe fn finish(&mut self, job: &Job) {
        self.evidence.job_empty = job.active_processes().is_ok_and(|n| n == 0);
        self.evidence.unobserved_handles_signaled = self.pending.as_ref().map_or(true, |p|
            WaitForSingleObject(p.handle.raw(), 5000) == WAIT_OBJECT_0)
            && self.unclassified.iter().all(|(_,handle)| WaitForSingleObject(handle.raw(),5000) == WAIT_OBJECT_0);
        if self.pending.is_some() && self.descendant_error.is_none() {
            let error = "descendant exited before identity observation completed".to_owned();
            self.evidence.diagnostics.descendant_error(error.clone());
            self.descendant_error = Some(error);
        }
        if let Some(mut root) = self.root.take() {
            root.evidence.retained_handle_signaled = WaitForSingleObject(root.handle.raw(), 0) == WAIT_OBJECT_0;
            self.evidence.root = Some(root.evidence);
        }
        self.evidence.descendants = self.children.drain(..).map(|mut c| {
            c.evidence.retained_handle_signaled = WaitForSingleObject(c.handle.raw(), 5000) == WAIT_OBJECT_0; c.evidence
        }).collect();
        self.evidence.console_hosts = self.console_hosts.drain(..).map(|mut c| {
            c.evidence.retained_handle_signaled=WaitForSingleObject(c.handle.raw(),5000) == WAIT_OBJECT_0;
            c.evidence
        }).collect();
        // A transient root identity lookup may succeed on a later sample. Any child
        // observation failure is retained conservatively even if later data exists.
        let root_error = if self.evidence.root.is_none() { self.root_error.take() } else { None };
        self.evidence.error = match (root_error,self.descendant_error.take()) {
            (Some(root),Some(child)) => Some(format!("{root}; {child}")),
            (Some(error),None) | (None,Some(error)) => Some(error), (None,None) => None,
        };
    }
}
unsafe fn child_thread(pid: u32, parent: u32) -> Result<u32> {
    let raw = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    api((raw != INVALID_HANDLE_VALUE) as i32,"CreateToolhelp32Snapshot(child-parent-thread)")?;
    let snapshot = Handle::from_raw(raw)?;
    let mut entry: PROCESSENTRY32W = zeroed(); entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    let mut ok = Process32FirstW(snapshot.raw(), &mut entry);
    api(ok,"Process32FirstW(child-parent)")?; let mut matched = false;
    while ok != 0 { if entry.th32ProcessID == pid { ensure!(entry.th32ParentProcessID == parent, "unexpected child parent"); matched = true; break; }
        ok = Process32NextW(snapshot.raw(), &mut entry);
        if ok == 0 { let code=GetLastError(); ensure!(code == ERROR_NO_MORE_FILES,"api=Process32NextW(child-parent); win32={code}"); }
    }
    ensure!(matched, "child not present in process snapshot");
    let mut thread: THREADENTRY32 = zeroed(); thread.dwSize = size_of::<THREADENTRY32>() as u32;
    let mut ok = Thread32First(snapshot.raw(), &mut thread);
    api(ok,"Thread32First(child-thread)")?;
    while ok != 0 { if thread.th32OwnerProcessID == pid { return Ok(thread.th32ThreadID); }
        ok = Thread32Next(snapshot.raw(), &mut thread);
        if ok == 0 { let code=GetLastError(); ensure!(code == ERROR_NO_MORE_FILES,"api=Thread32Next(child-thread); win32={code}"); }
    }
    anyhow::bail!("child thread missing")
}
unsafe fn inspect(process: &Handle, pid: u32, tid: Option<u32>, job: &Job, expected_image: &str) -> Result<IdentityEvidence> {
    let actual = GetProcessId(process.raw());
    api((actual != 0) as i32,"GetProcessId(identity)")?;
    ensure!(actual == pid,"process PID mismatch: expected={pid}; actual={actual}");
    let wait = WaitForSingleObject(process.raw(),0);
    if wait == WAIT_FAILED { anyhow::bail!("api=WaitForSingleObject(identity); win32={}",GetLastError()); }
    ensure!(wait == WAIT_TIMEOUT,"process identity/liveness unavailable: pid={pid}; wait={wait}");
    let mut member = 0;
    api(IsProcessInJob(process.raw(), job.raw(), &mut member),"IsProcessInJob(identity)")?;
    ensure!(member != 0,"not member of exact sandbox Job: pid={pid}");
    let image = process_image(process)?;
    ensure!(image.eq_ignore_ascii_case(expected_image), "unexpected executable in sandbox Job: pid={pid}; image={image}");
    let mut raw = 0;
    api(OpenProcessToken(process.raw(), TOKEN_QUERY, &mut raw),"OpenProcessToken(identity)")?;
    let token_handle = Handle::from_raw(raw)?;
    let user_sid = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(token_handle.raw())?).map_err(anyhow::Error::msg)?;
    let restricting_sids = restricting_sids(token_handle.raw())?;
    // Desktop attachment is independent and can be unavailable for a console-only
    // process. Never discard the token/image/Job facts already observed above.
    let desktop = match tid {
        Some(tid) => match inspect_desktop(tid) {
            Ok(name) => DesktopEvidence::Observed {name},
            Err(error) => DesktopEvidence::Unavailable {error:format!("{error:#}")},
        },
        None => DesktopEvidence::Unavailable {error:"console-host desktop is outside the Python desktop observation".into()},
    };
    Ok(IdentityEvidence { pid, image, user_sid, restricting_sids, desktop, exact_job_member: true, retained_handle_signaled: false })
}
// Retry only an unavailable desktop query while the retained process is alive.
// This preserves token/Job evidence from CREATE_SUSPENDED and can observe a later
// lazy desktop attachment, without manufacturing an expected-name observation.
unsafe fn refresh_desktop(observed: &mut Observed) {
    let Some(tid)=observed.thread_id else { return };
    if !matches!(observed.evidence.desktop,DesktopEvidence::Unavailable {..})
        || WaitForSingleObject(observed.handle.raw(),0) != WAIT_TIMEOUT { return; }
    observed.evidence.desktop=match inspect_desktop(tid) {
        Ok(name)=>DesktopEvidence::Observed {name},
        Err(error)=>DesktopEvidence::Unavailable {error:format!("{error:#}")},
    };
}
unsafe fn process_image(process: &Handle) -> Result<String> {
    let mut image=[0u16;1024]; let mut len=image.len() as u32;
    api(QueryFullProcessImageNameW(process.raw(),0,image.as_mut_ptr(),&mut len),"QueryFullProcessImageNameW(identity)")?;
    Ok(String::from_utf16(&image[..len as usize])?)
}
unsafe fn inspect_desktop(tid: u32) -> Result<String> {
    // Clear stale error state so a null handle/error=0 is honestly reported as
    // unavailable with no reported Win32 reason, not as a prior unrelated error.
    SetLastError(0);
    let desktop=GetThreadDesktop(tid);
    api((desktop != 0) as i32,"GetThreadDesktop(identity)")?;
    let mut name=[0u16;256];let mut needed=0;
    api(GetUserObjectInformationW(desktop,UOI_NAME,name.as_mut_ptr().cast(),(name.len()*2) as u32,&mut needed),
        "GetUserObjectInformationW(identity-desktop-name)")?;
    let n=name.iter().position(|c|*c == 0).context("desktop name not terminated")?;
    Ok(String::from_utf16(&name[..n])?)
}

unsafe fn restricting_sids(handle: HANDLE) -> Result<Vec<String>> {
    let mut needed = 0;
    GetTokenInformation(handle, TokenRestrictedSids, null_mut(), 0, &mut needed);
    let sizing_error = GetLastError();
    ensure!(needed as usize >= size_of::<u32>() && needed <= 65536,
        "api=GetTokenInformation(restrictor-size); win32={sizing_error}; bytes={needed}");
    // usize allocation ensures TOKEN_GROUPS alignment.
    let mut buffer = vec![0usize; (needed as usize + size_of::<usize>() - 1) / size_of::<usize>()];
    api(GetTokenInformation(handle, TokenRestrictedSids, buffer.as_mut_ptr().cast(), needed, &mut needed),"GetTokenInformation(restrictor-data)")?;
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

/// Read-only metadata for PIDs returned by this exact Job, never arbitrary processes.
unsafe fn member_image(pid: u32,job: &Job) -> Result<String> {
    let raw=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,0,pid);
    api((raw != 0) as i32,"OpenProcess(Job-member-diagnostic)")?;
    let handle=Handle::from_raw(raw)?;
    let mut member=0;
    api(IsProcessInJob(handle.raw(),job.raw(),&mut member),"IsProcessInJob(Job-member-diagnostic)")?;
    ensure!(member != 0,"listed PID no longer belongs to exact Job: pid={pid}");
    let mut image=[0u16;1024];let mut length=image.len() as u32;
    api(QueryFullProcessImageNameW(handle.raw(),0,image.as_mut_ptr(),&mut length),"QueryFullProcessImageNameW(Job-member-diagnostic)")?;
    Ok(String::from_utf16(&image[..length as usize])?)
}
/// Must be called immediately after the named API, with no intervening Win32 call.
unsafe fn api(ok: i32,name: &'static str) -> Result<()> {
    if ok == 0 {
        let error=GetLastError();
        anyhow::bail!("api={name}; win32={error}");
    }
    Ok(())
}
