//! Pure lab contracts. No Windows process launch or security mutation.
#![cfg(feature = "lab-minimal-load-comparison")]
use pi_windows_sandbox::{
    minimal_load::{AccountControlAttempt, FixedLoadRequest, FIXTURE, WORK},
    protocol::{Policy, RunRequest, RunResult, StopReason},
};
use std::collections::HashMap;

fn request() -> RunRequest {
    RunRequest {
        schema_version: 1, argv: vec![FIXTURE.into()], cwd: WORK.into(),
        env: HashMap::from([("SystemRoot".into(), r"C:\Windows".into()),
            ("TEMP".into(), WORK.into()), ("TMP".into(), WORK.into())]),
        stdin: String::new(), timeout_ms: 15000, max_output_bytes: 4096,
        parent_pid: 42, policy_hash: "0".repeat(64),
        policy: Policy { workspace: WORK.into(), writable_roots: vec![WORK.into()],
            deny_read: vec![], deny_write: vec![], network: "disabled".into() },
    }
}
fn completed() -> RunResult {
    RunResult { stop_reason: StopReason::Exited, kind: "result".into(), exit_code: 0,
        stdout_base64: String::new(), stderr_base64: String::new(), timed_out: false,
        truncated: false, terminated: true, cleanup_verified: true }
}
#[test]
fn accepts_only_the_fixed_fixture_request() {
    assert!(FixedLoadRequest::new(request()).is_ok());
    let mutations: &[fn(&mut RunRequest)] = &[
        |r| r.argv[0] = r"C:\Windows\System32\cmd.exe".into(),
        |r| r.argv.push("extra".into()),
        |r| r.cwd = r"C:\".into(),
        |r| r.stdin = "input".into(),
        |r| r.timeout_ms += 1,
        |r| r.max_output_bytes += 1,
        |r| { r.env.insert("PATH".into(), r"C:\Windows\System32".into()); },
        |r| { r.env.remove("TEMP"); },
        |r| { r.env.insert("TMP".into(), r"C:\other".into()); },
        |r| r.policy.workspace = r"C:\other".into(),
        |r| r.policy.writable_roots.push(r"C:\other".into()),
        |r| r.policy.writable_roots.clear(),
        |r| r.policy.deny_read.push(r"C:\other".into()),
        |r| r.policy.deny_write.push(r"C:\other".into()),
        |r| r.policy.network = "enabled".into(),
        |r| r.parent_pid = 0,
        |r| r.schema_version = 2,
        |r| r.policy_hash.clear(),
    ];
    for mutate in mutations {
        let mut changed = request();
        mutate(&mut changed);
        assert!(FixedLoadRequest::new(changed).is_err());
    }
}
#[test]
fn cleanup_and_normal_exit_are_required_before_second_child() {
    for code in [0, 1] {
        let mut run = completed(); run.exit_code = code;
        assert!(AccountControlAttempt::Recorded { run }.can_continue());
    }
    let mutations: &[fn(&mut RunResult)] = &[
        |r| r.terminated = false,
        |r| r.cleanup_verified = false,
        |r| r.timed_out = true,
        |r| r.truncated = true,
        |r| r.stop_reason = StopReason::ParentDeath,
        |r| r.stop_reason = StopReason::Timeout,
        |r| r.stop_reason = StopReason::OutputLimit,
        |r| r.kind = "invalid".into(),
    ];
    for mutate in mutations {
        let mut run = completed(); mutate(&mut run);
        assert!(!AccountControlAttempt::Recorded { run }.can_continue());
    }
    assert!(!AccountControlAttempt::Failed { error: "launch failure".into() }.can_continue());
}
#[test]
fn first_attempt_frame_is_distinct_and_strict() {
    let attempt = AccountControlAttempt::Recorded { run: completed() };
    let bytes = serde_json::to_vec(&attempt).unwrap();
    assert!(serde_json::from_slice::<AccountControlAttempt>(&bytes).unwrap().can_continue());
    assert!(serde_json::from_value::<AccountControlAttempt>(serde_json::to_value(completed()).unwrap()).is_err());
    assert!(serde_json::from_str::<AccountControlAttempt>(r#"{"status":"FAILED","error":"x","extra":true}"#).is_err());
    assert!(serde_json::from_str::<AccountControlAttempt>(r#"{"status":"RECORDED"}"#).is_err());
}
