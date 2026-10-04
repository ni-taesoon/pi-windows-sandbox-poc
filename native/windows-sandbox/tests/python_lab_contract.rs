//! Portable source-contract regressions only, not Windows execution evidence.
const DRIVER: &str = include_str!("../examples/python_lab/windows.rs");
const SOURCES: &str = include_str!("../../../scripts/windows_lab_stage_sources.ps1");
const STAGER: &str = include_str!("../../../scripts/stage_windows_python_lab.ps1");
#[test]
fn production_gate_and_fixed_lab_surface_remain_separate() {
    assert!(!pi_windows_sandbox::NATIVE_VALIDATED);
    assert!(DRIVER.contains(r#"["setup", "run", "disable"]"#));
    assert!(DRIVER.contains(r#"const ROOT: &str = r"C:\PiSandboxLab""#));
    assert!(DRIVER.contains("broker::run_via_dedicated_helper"));
    assert!(!DRIVER.contains("std::process::Command"));
    assert!(!DRIVER.contains("std::io::stdin"));
    assert!(!DRIVER.contains("run_restricted("));
}
#[test]
fn native_evidence_is_required_before_narrow_pass() {
    for requirement in [
        "network::verify_offline_protection",
        "IsTokenRestricted",
        "IsProcessInJob",
        "QueryFullProcessImageNameW",
        "StopReason::Exited",
        "result.terminated",
        "result.cleanup_verified",
        "FILE_FLAG_OPEN_REPARSE_POINT",
        "info.nNumberOfLinks == 1",
        "o.exited()",
        "TokenIsElevated",
    ] {
        assert!(DRIVER.contains(requirement), "missing {requirement}");
    }
    let main =
        &DRIVER[DRIVER.find("pub fn main()").unwrap()..DRIVER.find("fn dispatch()").unwrap()];
    assert!(
        main.find("let run = dispatch()").unwrap()
            < main.find("setup::disable_offline_account").unwrap()
    );
    assert!(
        main.find("if let Err(error) = disable").unwrap() < main.find("LAB_SMOKE_PASS").unwrap()
    );
}
#[test]
fn staging_requires_explicit_scope_and_hashes() {
    for requirement in [
        "ApprovedDisposableVm",
        "ImageOS -ne 'win22'",
        "BuildNumber -ne '20348'",
        "ExpectedDriverSha256",
        "ExpectedHelperSha256",
        "ExpectedPythonSha256",
        "ApprovedSourceSha256",
        "Existing lab root refused",
    ] {
        assert!(STAGER.contains(requirement), "missing {requirement}");
    }
    assert!(!STAGER.contains("Invoke-WebRequest"));
    assert!(!STAGER.contains("Set-NetFirewallProfile"));
    assert!(!STAGER.contains("EnableLUA"));
}

#[test]
fn staging_selects_only_copied_inputs_and_diagnoses_links() {
    assert!(SOURCES.contains("Reparse-containing stage source refused:"));
    for field in [
        "sourceRole =",
        "path = $Item.FullName",
        "linkType =",
        "attributes =",
    ] {
        assert!(SOURCES.contains(field));
    }
    assert!(SOURCES.contains("'helper-executable'"));
    assert!(SOURCES.contains("'driver-executable'"));
    assert!(!SOURCES.contains("Get-ChildItem -LiteralPath $build"));
    assert!(!SOURCES.contains("Get-ChildItem -LiteralPath $BuildDirectory"));
    assert!(!STAGER.contains("Copy-Item -Path"));
    assert!(!STAGER.contains("-Recurse"));
    assert!(STAGER.contains("foreach ($entry in $selection.runtimeEntries)"));
    assert!(
        SOURCES
            .find("Assert-LabSourceItem -Item $item -Role 'python-runtime'")
            .unwrap()
            < SOURCES.find("foreach ($child in Get-ChildItem").unwrap()
    );
}

#[test]
fn only_observed_unused_root_alias_can_be_excluded() {
    for required in [
        "$source -eq (Join-Path $runtime 'python3.exe')",
        "$item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::Directory)",
        "$item.LinkType -eq 'SymbolicLink'",
        "unused-root-python3-symbolic-link-not-copied",
        "skippedRuntimeEntries=$skipped.ToArray()",
    ] {
        assert!(SOURCES.contains(required), "missing {required}");
    }
    assert!(!SOURCES.contains("ResolveLinkTarget"));
    assert!(!SOURCES.contains(".Target"));
    assert!(STAGER.contains("excludedRuntimeEntries=@($selection.skippedRuntimeEntries)"));
    assert!(DRIVER.contains(r#"runtime\python.exe"#));
}

#[test]
fn fixed_python_progress_markers_preserve_bounded_fixture() {
    assert!(DRIVER.contains("PI_LAB_SCRIPT_ENTERED"));
    assert!(DRIVER.contains("PI_LAB_IMPORTS_READY"));
    let fixture = DRIVER
        .split("const SCRIPT: &str =")
        .nth(1)
        .unwrap()
        .split("const OUTPUT:")
        .next()
        .unwrap();
    assert!(
        fixture.find("PI_LAB_SCRIPT_ENTERED").unwrap()
            < fixture.find("import pathlib, time").unwrap()
    );
    assert!(fixture.find("PI_LAB_IMPORTS_READY").unwrap() < fixture.find("p.write_bytes").unwrap());
    assert!(fixture.contains("flush=True"));
    assert!(DRIVER.contains("timeout_ms: 15000"));
    assert!(DRIVER.contains("exitCodeHex"));
}

#[test]
fn observer_failures_cannot_erase_broker_diagnostics_or_become_success() {
    let completed = DRIVER
        .split("done.store(true, Ordering::SeqCst)")
        .nth(1)
        .unwrap();
    let write = completed.find("trusted\\run-evidence.json").unwrap();
    let reject = completed
        .find("if let Some(error) = observer_error")
        .unwrap();
    let result = completed.find("let result = launched?").unwrap();
    assert!(write < reject && reject < result);
    assert!(completed.contains("observerError"));
    assert!(completed.contains("exitCodeHex"));
    assert!(!completed[..write].contains("observed?"));
    assert!(!completed[..write].contains("map_err(|_| anyhow::anyhow!(\"observer panicked\"))?"));
    let diagnostic = DRIVER
        .split("unsafe fn observer_api(")
        .nth(1)
        .unwrap()
        .split("fn observe(")
        .next()
        .unwrap();
    assert!(
        diagnostic.find("last_os_error()").unwrap()
            < diagnostic.find("WaitForSingleObject").unwrap()
    );
    assert!(diagnostic.contains("process.raw(), 0"));
    assert!(!diagnostic.contains("OpenProcess"));
    assert!(diagnostic.contains("retained_handle_wait"));
}
