//! Source contracts for the explicit diagnostic mode, not native debugger tests.
const TRACE: &str = include_str!("../src/loader_trace.rs");
const PROCESS: &str = include_str!("../src/process.rs");
const LAB: &str = include_str!("../examples/python_lab/windows.rs");
#[test]
fn diagnostic_mode_cannot_be_normal_validation() {
    assert!(include_str!("../Cargo.toml").contains("default = []"));
    assert!(LAB.contains("loaderTraceDiagnostic"));
    assert!(LAB.contains("LOADER_TRACE_DIAGNOSTIC_ONLY"));
    let result = LAB
        .split("done.store(true, Ordering::SeqCst)")
        .nth(1)
        .unwrap();
    assert!(
        result.find("LOADER_TRACE_DIAGNOSTIC_ONLY").unwrap()
            < result.find("let result = launched?").unwrap()
    );
    assert!(TRACE.contains("normal_validation_eligible: bool"));
}
#[test]
fn no_attach_memory_context_injection_or_permission_changes() {
    for forbidden in [
        "DebugActiveProcess(",
        "DebugActiveProcessStop(",
        "DebugSetProcessKillOnExit(",
        "ReadProcessMemory(",
        "WriteProcessMemory(",
        "GetThreadContext(",
        "SetThreadContext(",
        "VirtualAllocEx(",
        "CreateRemoteThread(",
        "AdjustTokenPrivileges(",
        "SetSecurityInfo(",
        "lpImageName",
    ] {
        assert!(!TRACE.contains(forbidden), "forbidden {forbidden}");
    }
    assert!(PROCESS.contains("DEBUG_ONLY_THIS_PROCESS"));
    assert!(!PROCESS.contains("DEBUG_PROCESS"));
    assert!(TRACE.contains("PhantomData<Rc<()>>"));
}
#[test]
fn debug_event_handle_ownership_and_exception_policy_are_narrow() {
    assert!(TRACE.contains("CloseHandle(file)"));
    assert!(!TRACE.contains("CreateProcessInfo.hProcess"));
    assert!(!TRACE.contains("CreateProcessInfo.hThread"));
    assert!(!TRACE.contains("CreateThread.hThread"));
    assert!(TRACE.contains("exception.dwFirstChance != 0"));
    assert!(TRACE.contains("!self.initial_breakpoint_seen"));
    assert!(TRACE.contains("self.ntdll_range.is_some_and"));
    assert!(TRACE.contains("status = DBG_EXCEPTION_NOT_HANDLED"));
    assert!(TRACE.contains("DebugStringSkipped"));
}
#[test]
fn event_pumping_retains_deadlines_and_kill_job_cleanup() {
    assert!(TRACE.contains("const STORED_EVENTS: usize = 256"));
    assert!(TRACE.contains("const EVENT_LIMIT: u32 = 4096"));
    assert!(TRACE.contains("pending.attempts < 2"));
    assert!(TRACE.contains("self.cleanup_deadline"));
    assert!(TRACE.contains("TerminateJobObject(self.job, 1)"));
    assert!(TRACE.contains("self.exited() && self.job_empty()"));
    assert!(PROCESS.contains("debugger.poll(10)?"));
    assert!(PROCESS.contains("finished &= debugger.exited()"));
    assert!(PROCESS.contains("Duration::from_millis(request.timeout_ms.into())"));
    assert!(PROCESS.contains("attrs.set_job(job.0.raw())?"));
    assert!(!TRACE.contains("INFINITE"));
}
