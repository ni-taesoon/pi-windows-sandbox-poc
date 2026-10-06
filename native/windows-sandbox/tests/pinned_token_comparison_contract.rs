//! Pure framing and fail-stop contracts. No token creation or Windows execution.
#![cfg(feature = "lab-pinned-codex-token-comparison")]
use pi_windows_sandbox::{
    minimal_load::{AccountControlAttempt, PinnedTokenFrame, PinnedTokenReady},
    protocol::{RunResult, StopReason},
};

fn completed(exit_code: u32) -> AccountControlAttempt {
    AccountControlAttempt::Recorded { run: RunResult {
        kind: "result".into(), stop_reason: StopReason::Exited, exit_code,
        stdout_base64: String::new(), stderr_base64: String::new(),
        timed_out: false, truncated: false, terminated: true, cleanup_verified: true,
    } }
}

#[test]
fn strict_failure_and_pinned_success_are_never_substituted() {
    let strict = PinnedTokenFrame::UnchangedStrict { attempt: completed(1) };
    let pinned = PinnedTokenFrame::PinnedCodexToken { attempt: completed(0) };
    assert_eq!(strict.expect_unchanged_strict().unwrap().run().unwrap().exit_code, 1);
    assert_eq!(pinned.expect_pinned_codex_token().unwrap().run().unwrap().exit_code, 0);
    assert!(strict.expect_pinned_codex_token().is_err());
    assert!(pinned.expect_unchanged_strict().is_err());
    for frame in [strict, pinned] {
        let bytes = serde_json::to_vec(&frame).unwrap();
        let parsed: PinnedTokenFrame = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(serde_json::to_value(frame).unwrap(), serde_json::to_value(parsed).unwrap());
    }
}

#[test]
fn framing_rejects_unknown_fields_conditions_and_unframed_results() {
    let frame = PinnedTokenFrame::UnchangedStrict { attempt: completed(1) };
    let good = serde_json::to_value(&frame).unwrap();
    for field in ["condition", "attempt"] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<PinnedTokenFrame>(missing).is_err());
    }
    let mut extra = good.clone(); extra["policy"] = serde_json::json!("anything");
    assert!(serde_json::from_value::<PinnedTokenFrame>(extra).is_err());
    let mut unknown = good.clone(); unknown["condition"] = serde_json::json!("CUSTOM_TOKEN");
    assert!(serde_json::from_value::<PinnedTokenFrame>(unknown).is_err());
    assert!(serde_json::from_value::<PinnedTokenFrame>(serde_json::to_value(completed(0)).unwrap()).is_err());
    let mut nested_extra = good; nested_extra["attempt"]["extra"] = serde_json::json!(true);
    assert!(serde_json::from_value::<PinnedTokenFrame>(nested_extra).is_err());
}

#[test]
fn acknowledgement_is_a_single_exact_message() {
    let bytes = serde_json::to_vec(&PinnedTokenReady::StrictEvidenceRecorded).unwrap();
    assert!(serde_json::from_slice::<PinnedTokenReady>(&bytes).is_ok());
    for bad in [br#""Proceed""#.as_slice(), br#"{}"#.as_slice(),
        br#"{"StrictEvidenceRecorded":true}"#.as_slice(), br#"true"#.as_slice()] {
        assert!(serde_json::from_slice::<PinnedTokenReady>(bad).is_err());
    }
}

#[test]
fn incomplete_strict_attempt_never_allows_the_extra_condition() {
    let failure = PinnedTokenFrame::UnchangedStrict {
        attempt: AccountControlAttempt::Failed { error: "launch failed".into() },
    };
    assert!(!failure.expect_unchanged_strict().unwrap().can_continue());
    let mut attempt = completed(1);
    if let AccountControlAttempt::Recorded { run } = &mut attempt { run.cleanup_verified = false; }
    let incomplete = PinnedTokenFrame::UnchangedStrict { attempt };
    assert!(!incomplete.expect_unchanged_strict().unwrap().can_continue());
}
