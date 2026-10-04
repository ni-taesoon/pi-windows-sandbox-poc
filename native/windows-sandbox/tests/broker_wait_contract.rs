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
