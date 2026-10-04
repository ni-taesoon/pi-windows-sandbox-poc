const HW: &str = include_str!("../src/sechost_breakpoints.rs");
const TRACE: &str = include_str!("../src/loader_trace.rs");
const BROKER: &str = include_str!("../src/broker.rs");
#[test]
fn hardware_diagnostic_has_no_memory_code_or_permission_operations() {
    for forbidden in [
        "ReadProcessMemory",
        "WriteProcessMemory",
        "OpenProcess(",
        "OpenThread(",
        "SuspendThread",
        "SetSecurity",
        "AdjustToken",
        "DebugActiveProcess",
        "RtlMoveMemory",
    ] {
        assert!(!HW.contains(forbidden));
    }
    let setter = HW
        .split("unsafe fn set_debug")
        .nth(1)
        .unwrap()
        .split("pub unsafe fn arm")
        .next()
        .unwrap();
    assert!(setter.contains("CONTEXT_DEBUG_REGISTERS_AMD64"));
    for forbidden in [
        "CONTEXT_CONTROL",
        "CONTEXT_INTEGER",
        ".Rip",
        ".Rsp",
        ".EFlags",
    ] {
        assert!(!setter.contains(forbidden));
    }
    assert!(HW.contains("c.Rdx == 1") || HW.contains("c.Rdx==1"));
    assert!(HW.contains("c.Rsp == self.stack") || HW.contains("c.Rsp==self.stack"));
    assert!(HW.contains("9e91b726a67d75fbe3cc9e74fbe70332c8d9f8726cffba49370a5e6bc73e4635"));
}
#[test]
fn only_fixed_probe_gets_debug_creation_and_original_python_is_ordinary() {
    assert!(BROKER.contains("request.argv.len() == 1"));
    assert!(BROKER.contains(r#"request.argv[0] == r"C:\PiSandboxLab\trusted\loader_probe.exe""#));
    assert!(BROKER.contains("cfg!(feature = \"lab-sechost-breakpoints\") && !fixed_probe"));
    assert!(BROKER.contains("run_restricted_with_parent("));
}
#[test]
fn errors_kill_and_continue_and_outputs_do_not_expose_context() {
    assert!(
        TRACE.contains("TerminateJobObject(self.job, 1)")
            || TRACE.contains("TerminateJobObject(self.job,1)")
    );
    assert!(TRACE.contains("self.continue_pending()?"));
    let output = HW
        .split("pub(crate) struct Hit")
        .nth(1)
        .unwrap()
        .split("#[derive(Default)]")
        .next()
        .unwrap();
    assert!(output.contains("site_rva"));
    assert!(output.contains("eax"));
    for forbidden in ["stack", "base", "Rsp", "Rip", "Dr0", "thread"] {
        assert!(!output.contains(forbidden));
    }
    assert!(HW.contains("process_exited_without_verified_attach_return"));
    assert!(HW.contains("unowned single-step diagnostic event"));
}

#[test]
fn both_context_api_buffers_have_explicit_x64_alignment() {
    assert!(HW.contains("#[repr(C, align(16))]"));
    assert!(HW.contains("std::mem::align_of::<AlignedContext>() >= 16"));
    assert!(HW.contains("std::mem::offset_of!(AlignedContext, context) == 0"));
    assert_eq!(
        HW.matches("let mut aligned: AlignedContext = std::mem::zeroed()")
            .count(),
        2
    );
    assert_eq!(HW.matches("let context = &mut aligned.context").count(), 2);
    assert!(HW.contains("GetThreadContext(self.thread, context)"));
    assert!(HW.contains("SetThreadContext(self.thread, context)"));
    assert!(!HW.contains("let mut context: CONTEXT"));
}
