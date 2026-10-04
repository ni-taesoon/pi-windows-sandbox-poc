//! Host-runnable source-contract regressions. These do not execute Windows APIs.
const BROKER: &str = include_str!("../src/broker.rs");
const PROCESS: &str = include_str!("../src/process.rs");

#[test]
fn dedicated_helper_uses_transferred_wait_handle_not_cross_account_open() {
    let helper = BROKER.split("pub fn helper_main(").nth(1).unwrap();
    assert!(helper.contains("run_restricted_with_parent("),
        "helper still reopens broker by PID under the dedicated account, which needs broker DACL access after admission");
    assert!(!helper.contains("request.parent_pid = expected_broker"));
    assert!(helper.contains("duplicate_received_parent_wait_handle(payload.parent_wait_handle)"));
}

#[test]
fn handoff_is_wait_only_noninheritable_and_precedes_admission_and_resume() {
    let launch = BROKER
        .split("pub unsafe fn run_via_dedicated_helper(")
        .nth(1)
        .unwrap()
        .split("pub fn helper_main(")
        .next()
        .unwrap();
    let transfer = launch
        .find("duplicate_parent_wait_handle(&helper.process)")
        .expect("no broker-owned handle transfer");
    assert!(transfer < launch.find("AdmittedLaunch::prepare_under_lease").unwrap());
    assert!(transfer < launch.find("ResumeThread").unwrap());
    assert!(BROKER.contains("pub parent_wait_handle: u64"));
    let duplicate = BROKER
        .split("unsafe fn duplicate_parent_wait_handle(")
        .nth(1)
        .unwrap()
        .split("///")
        .next()
        .unwrap();
    assert!(duplicate.contains("SYNCHRONIZE"));
    assert!(!duplicate.contains("DUPLICATE_SAME_ACCESS"));
    assert!(!duplicate.contains("DUPLICATE_CLOSE_SOURCE"));
    let runner = PROCESS
        .split("pub(crate) unsafe fn run_restricted_with_parent(")
        .nth(1)
        .expect("no handle-based runner");
    assert!(!runner.contains("OpenProcess("));
}

#[test]
fn broker_api_errors_have_static_phase_labels_and_numeric_codes() {
    assert!(BROKER.contains("fn win(api: &'static str, ok: i32)"));
    assert!(BROKER.contains("api={api}; win32={code}"));
    for label in [
        "pipe-sddl/ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "helper-object-sddl/ConvertStringSecurityDescriptorToSecurityDescriptorW",
        "pipe-client-identity/GetNamedPipeClientProcessId",
        "pipe-server-identity/GetNamedPipeServerProcessId",
        "pipe-read-mode/SetNamedPipeHandleState",
        "pipe-read-available/PeekNamedPipe",
        "pipe-read/ReadFile",
        "parent-wait-transfer/DuplicateHandle",
        "received-parent-wait-copy/DuplicateHandle",
        "helper-base-token/OpenProcessToken",
    ] {
        assert_eq!(
            BROKER.matches(label).count(),
            1,
            "missing or ambiguous API label"
        );
    }
    assert!(BROKER.contains("broker.phase=suspended-helper-launch"));
    assert!(BROKER.contains("broker.phase=policy-admission"));
    let wrapper = &BROKER[BROKER.find("fn win(").unwrap()..BROKER.find("impl Pipe").unwrap()];
    assert!(!wrapper.contains("owner"));
    assert!(!wrapper.contains("path"));
    assert!(!wrapper.contains("request"));
}

#[test]
fn cross_account_admission_is_query_only_and_cannot_launch_directly() {
    let launch = BROKER
        .split("pub unsafe fn run_via_dedicated_helper(")
        .nth(1)
        .unwrap()
        .split("pub fn helper_main(")
        .next()
        .unwrap();
    let token_open = launch
        .split("OpenProcessToken(")
        .nth(1)
        .unwrap()
        .split("&mut base")
        .next()
        .unwrap();
    assert!(token_open.contains("TOKEN_QUERY"));
    for forbidden in [
        "TOKEN_DUPLICATE",
        "TOKEN_ASSIGN_PRIMARY",
        "TOKEN_ADJUST_DEFAULT",
        "TOKEN_ADJUST_PRIVILEGES",
    ] {
        assert!(!token_open.contains(forbidden));
    }
    let admission = include_str!("../src/admission.rs");
    let helper_admit = admission
        .split("pub(crate) unsafe fn prepare_under_lease(")
        .nth(1)
        .unwrap()
        .split("unsafe fn prepare_impl(")
        .next()
        .unwrap();
    assert!(helper_admit.contains("ExecutionPath::DedicatedHelper"));
    assert!(admission.contains("ExecutionPath::DedicatedHelper => None"));
    assert!(admission.contains("helper-only admission cannot execute directly"));
    assert!(admission.contains("PrivateDesktop::for_token_with_cap(base.raw()"));
    let helper = BROKER.split("pub fn helper_main(").nth(1).unwrap();
    assert!(helper.contains("token::create_strict_write_token_from("));
    assert!(helper.contains("process::run_restricted_with_parent("));
}

#[test]
fn critical_error_mode_is_confined_to_dedicated_helper() {
    let (owner, helper) = BROKER.split_once("pub fn helper_main(").unwrap();
    assert!(!owner.contains("SetErrorMode("));
    assert!(helper.contains("SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS)"));
    assert!(
        helper.find("SetErrorMode(").unwrap()
            < helper.find("process::run_restricted_with_parent(").unwrap()
    );
    assert!(!BROKER.contains("SEM_NOALIGNMENTFAULTEXCEPT"));
    assert!(!BROKER.contains("SEM_NOGPFAULTERRORBOX"));
    assert!(!PROCESS.contains("CREATE_DEFAULT_ERROR_MODE"));
    assert!(PROCESS.contains("CREATE_NO_WINDOW"));
    assert!(PROCESS.contains("Duration::from_millis(request.timeout_ms.into())"));
}
