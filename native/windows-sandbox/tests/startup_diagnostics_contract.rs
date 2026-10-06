//! Portable structural guards for read-only telemetry; not native AccessCheck proof.
const DIAG: &str = include_str!("../src/startup_diagnostics.rs");
const BROKER: &str = include_str!("../src/broker.rs");
#[test]
fn read_only_access_checks_do_not_mutate_identity_or_security() {
    for required in [
        "GetUserObjectSecurity",
        "DuplicateToken(token, SecurityImpersonation",
        "AccessCheck(",
        "OWNER_SECURITY_INFORMATION",
        "GROUP_SECURITY_INFORMATION",
        "DACL_SECURITY_INFORMATION",
        "IsValidSecurityDescriptor",
    ] {
        assert!(DIAG.contains(required), "missing {required}");
    }
    for forbidden in [
        "SetSecurityInfo(",
        "SetUserObjectSecurity(",
        "SetProcessWindowStation(",
        "SetThreadDesktop(",
        "ImpersonateLoggedOnUser(",
        "SetThreadToken(",
        "AdjustTokenPrivileges(",
        "CreateDesktopW(",
        "CreateWindowStationW(",
    ] {
        assert!(!DIAG.contains(forbidden), "unexpected mutation {forbidden}");
    }
    assert!(DIAG.contains("DESKTOP_READ_CONTROL | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS"));
}
#[test]
fn serialized_telemetry_contains_no_names_descriptors_or_identity_values() {
    let schema = &DIAG[..DIAG.find("type DResult").unwrap()];
    assert!(!schema.contains("String"));
    assert!(!schema.contains("Vec<u8>"));
    assert!(!schema.contains("session_id"));
    assert!(!schema.contains("sid:"));
    assert!(schema.contains("same_token_session: Option<bool>"));
    assert!(DIAG.contains("(20..=65536).contains(&needed)"));
    assert_eq!(
        DIAG.matches("window_station_is_expected == Some(true)")
            .count(),
        2
    );
    assert!(DIAG.contains("ApiStage::AccessCheck"));
}
#[test]
fn diagnostics_are_reported_before_workload_and_share_original_deadline() {
    let helper = BROKER.split("pub fn helper_main(").nth(1).unwrap();
    assert!(
        helper.find("startup_diagnostics::inspect").unwrap()
            < helper.find("process::run_restricted_with_parent").unwrap()
    );
    assert!(
        helper.find("&startup_diagnostics,").unwrap()
            < helper.find("process::run_restricted_with_parent").unwrap()
    );
    // The existing telemetry/result suffix still has its original three receives.
    // The distinct feature-only fixed comparison adds one account-control frame.
    let original = BROKER.split("// This feature omits only observational telemetry").nth(1).unwrap();
    assert_eq!(original.matches(".receive(response_deadline)").count(), 3);
    assert_eq!(BROKER.matches(".receive(response_deadline)").count(), 4);
    assert!(BROKER.contains("HelperExecution::Restricted => Duration::from_millis(u64::from(payload.request.timeout_ms))"));
    assert!(BROKER.contains("helper_startup_access={}"));
}
