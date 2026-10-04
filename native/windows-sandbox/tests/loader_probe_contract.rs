const LAB: &str = include_str!("../examples/python_lab/windows.rs");
const PROBE: &str = include_str!("../../windows-loader-probe/loader_probe.c");
const BUILD: &str = include_str!("../../../scripts/build_windows_loader_probe.ps1");
#[test]
fn probe_is_fixed_native_loader_only_with_safe_output_failures() {
    for forbidden in [
        "GetCommandLine",
        "CreateProcess",
        "GetProcAddress",
        "Py_Initialize",
        "Py_Main",
        "printf(",
        "SetSecurityInfo",
        "Impersonate",
    ] {
        assert!(!PROBE.contains(forbidden));
    }
    assert!(PROBE.contains("LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32"));
    assert!(PROBE.contains("DWORD error = GetLastError()"));
    assert!(PROBE.contains("ExitProcess(0xE0010001)"));
    assert!(PROBE.contains("ExitProcess(0xE0010002)"));
    assert!(PROBE.contains("ExitProcess(0xE0020001)"));
    assert!(BUILD.contains("/NODEFAULTLIB /ENTRY:lab_probe_entry"));
    assert!(BUILD.contains("kernel32.lib"));
    assert!(BUILD.contains("verify-probe"));
    assert!(!BUILD.contains("/GS-"));
}
#[test]
fn original_python_evidence_precedes_separate_nonpass_probe() {
    let completion = LAB
        .split("let (observations, observer_error) = match observer.join()")
        .nth(1)
        .unwrap();
    assert!(
        completion.find("trusted\\run-evidence.json").unwrap()
            < completion
                .find("loader_probe_differential(&expected_sid")
                .unwrap()
    );
    assert!(LAB.contains("r.exit_code == 0xC0000142"));
    assert!(LAB.contains("r.cleanup_verified"));
    assert!(LAB.contains("loader-probe-evidence.json"));
    assert!(LAB.contains("LOADER_PROBE_DIAGNOSTIC_ONLY"));
    assert!(LAB.contains("&path(r\"trusted\\loader_probe.exe\"),"));
    assert!(LAB.contains("timeout_ms: 15000"));
}

#[test]
fn compiler_range_check_failure_is_intrinsic_and_nonreturning() {
    assert!(PROBE.contains("#include <intrin.h>"));
    let body = PROBE
        .split("__declspec(noreturn) void __cdecl __report_rangecheckfailure(void) {")
        .nth(1)
        .expect("compiler range-check helper is present")
        .split('}')
        .next()
        .unwrap()
        .trim();
    assert_eq!(body, "__fastfail(FAST_FAIL_RANGE_CHECK_FAILURE);");
    assert!(BUILD.contains("/GS "));
    assert!(BUILD.contains("/NODEFAULTLIB"));
    assert!(BUILD.contains("verify-probe"));
}

#[test]
fn dependency_sequence_is_fixed_bounded_and_precedes_python() {
    let entry = PROBE
        .split("void WINAPI lab_probe_entry(void) {")
        .nth(1)
        .unwrap();
    let expected = [
        "ucrtbase", "msvcrt", "rpcrt4", "sechost", "advapi32", "bcrypt", "version", "ws2_32",
    ];
    let actual: Vec<_> = entry
        .lines()
        .filter(|line| line.trim_start().starts_with("load_system("))
        .collect();
    assert_eq!(actual.len(), expected.len());
    for (line, name) in actual.iter().zip(expected) {
        assert_eq!(
            line.trim(),
            format!("load_system(L\"\\\\{name}.dll\",\"{name}\");")
        );
    }
    assert!(entry.find("\"ws2_32\"").unwrap() < entry.find("\"python312\"").unwrap());
    assert!(PROBE.contains("if (length >= 32767)"));
    assert!(!PROBE.contains("FreeLibrary("));
}
