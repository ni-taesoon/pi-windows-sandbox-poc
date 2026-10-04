//! Portable source-contract regressions only, not Windows execution evidence.
const DRIVER: &str = include_str!("../examples/python_lab/windows.rs");
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
        "Reparse-containing stage source refused",
    ] {
        assert!(STAGER.contains(requirement), "missing {requirement}");
    }
    assert!(!STAGER.contains("Invoke-WebRequest"));
    assert!(!STAGER.contains("Set-NetFirewallProfile"));
    assert!(!STAGER.contains("EnableLUA"));
}
