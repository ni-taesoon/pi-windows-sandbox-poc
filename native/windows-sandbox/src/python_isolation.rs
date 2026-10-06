//! Fixed, default-off acceptance contracts. Nothing here extends the product protocol.
use crate::protocol::{Policy, RunRequest, RunResult, StopReason};
use anyhow::{ensure, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub const ROOT: &str = r"C:\PiSandboxLab";
pub const PYTHON: &str = r"C:\PiSandboxLab\runtime\python.exe";
pub const SCRIPT: &str = r"C:\PiSandboxLab\trusted\python-isolation-fixture.py";
pub const WORK: &str = r"C:\PiSandboxLab\work";
pub const OUTSIDE: &str = r"C:\PiSandboxLab\fixtures\outside-world";
pub const OUTPUT: &[u8] = b"PYTHON_ISOLATION_OK\n";
pub const MAX_FRAME: usize = 64 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case { OrdinaryOutside, StrictBoundary, StrictChildNormalExit, StrictChildTimeout,
    PinnedBoundary, PinnedChildNormalExit, PinnedChildTimeout }
impl Case {
    pub const ALL: [Self; 7] = [Self::OrdinaryOutside, Self::StrictBoundary,
        Self::StrictChildNormalExit, Self::StrictChildTimeout, Self::PinnedBoundary,
        Self::PinnedChildNormalExit, Self::PinnedChildTimeout];
    pub fn name(self) -> &'static str { match self {
        Self::OrdinaryOutside => "ordinary-outside", Self::StrictBoundary => "strict-boundary",
        Self::StrictChildNormalExit => "strict-child-normal-exit", Self::StrictChildTimeout => "strict-child-timeout",
        Self::PinnedBoundary => "pinned-boundary", Self::PinnedChildNormalExit => "pinned-child-normal-exit",
        Self::PinnedChildTimeout => "pinned-child-timeout" } }
    pub fn pinned(self) -> bool { matches!(self, Self::PinnedBoundary | Self::PinnedChildNormalExit | Self::PinnedChildTimeout) }
    pub fn boundary(self) -> bool { matches!(self, Self::StrictBoundary | Self::PinnedBoundary) }
    pub fn descendant(self) -> bool { !self.boundary() && self != Self::OrdinaryOutside }
    pub fn timeout(self) -> bool { matches!(self, Self::StrictChildTimeout | Self::PinnedChildTimeout) }
    pub fn label(self) -> &'static str { if self.pinned() { "pinned" } else if self == Self::OrdinaryOutside { "ordinary" } else { "strict" } }
}
pub fn fixed_policy() -> Policy { Policy { workspace: WORK.into(), writable_roots: vec![WORK.into()],
    deny_read: vec![format!(r"{WORK}\denied-read")], deny_write: vec![format!(r"{WORK}\denied-write")], network: "disabled".into() } }
pub fn request(case: Case, parent_pid: u32, policy_hash: String) -> RunRequest { RunRequest {
    schema_version: 1, argv: vec![PYTHON.into(), "-I".into(), "-S".into(), "-B".into(), SCRIPT.into(), case.name().into()],
    cwd: WORK.into(), env: HashMap::from([("SystemRoot".into(), r"C:\Windows".into()),
        ("TEMP".into(), WORK.into()), ("TMP".into(), WORK.into())]), stdin: String::new(),
    timeout_ms: if case.timeout() { 8000 } else { 15000 }, max_output_bytes: 16384,
    parent_pid, policy_hash, policy: fixed_policy() } }
pub struct FixedRequest { request: RunRequest, case: Case }
impl FixedRequest {
    pub fn new(request: RunRequest) -> Result<Self> {
        request.validate()?;
        let case = Case::ALL.into_iter().find(|c| request.argv.last().is_some_and(|a| a == c.name()))
            .ok_or_else(|| anyhow::anyhow!("unknown fixed Python case"))?;
        let expected = self::request(case, request.parent_pid, request.policy_hash.clone());
        ensure!(serde_json::to_value(&request)? == serde_json::to_value(expected)?, "fixed Python request was altered");
        Ok(Self { request, case })
    }
    pub fn case(&self) -> Case { self.case }
    pub fn request(&self) -> &RunRequest { &self.request }
    pub(crate) fn into_request(self) -> RunRequest { self.request }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityEvidence {
    pub pid: u32, pub image: String, pub user_sid: String, pub restricting_sids: Vec<String>,
    pub desktop: String, pub exact_job_member: bool, pub retained_handle_signaled: bool,
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEvidence {
    pub root: Option<IdentityEvidence>, pub descendants: Vec<IdentityEvidence>,
    pub error: Option<String>, pub job_empty: bool, pub unobserved_handles_signaled: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Frame {
    pub case: Case, pub account_sid: String, pub capability_sid: String, pub private_desktop: String,
    pub run: Option<RunResult>, pub launch_error: Option<String>, pub native: NativeEvidence,
}
impl Frame {
    pub fn cleanup_verified(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.kind == "result" && r.cleanup_verified && r.terminated)
            && self.native.job_empty && self.native.unobserved_handles_signaled
            && self.native.root.as_ref().map_or(true, |r| r.retained_handle_signaled)
            && self.native.descendants.iter().all(|c| c.retained_handle_signaled)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorded { pub case: Case }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Probe { Success, PermissionDenied { winerror: u32 }, Inconclusive { winerror: Option<u32> } }
impl Probe {
    pub fn explicit_denial(&self) -> bool { matches!(self, Self::PermissionDenied { winerror: 5 | 10013 }) }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptEvidence {
    pub schema_version: u32, pub mode: Case, pub python: [u32; 3], pub marker: String,
    pub outside_read: Option<Probe>, pub outside_write: Option<Probe>,
    pub input_ok: Option<bool>, pub output_ok: Option<bool>,
    pub denied_read: Option<Probe>, pub denied_write: Option<Probe>,
    pub tcp4: Option<Probe>, pub tcp6: Option<Probe>,
}
pub fn parse_script(frame: &Frame) -> Result<ScriptEvidence> {
    let run = frame.run.as_ref().ok_or_else(|| anyhow::anyhow!("process result missing"))?;
    ensure!(run.kind == "result" && run.cleanup_verified && run.terminated && !run.truncated, "incomplete process evidence");
    ensure!(if frame.case.timeout() { run.stop_reason == StopReason::Timeout && run.timed_out }
        else { run.stop_reason == StopReason::Exited && !run.timed_out && run.exit_code == 0 }, "unexpected stop reason/exit");
    let stdout = base64::engine::general_purpose::STANDARD.decode(&run.stdout_base64)?;
    let stderr = base64::engine::general_purpose::STANDARD.decode(&run.stderr_base64)?;
    ensure!(stdout.len() <= 16384 && stderr.is_empty(), "invalid Python output bounds/stderr");
    let result: ScriptEvidence = serde_json::from_slice(&stdout)?;
    ensure!(result.schema_version == 1 && result.mode == frame.case && result.python == [3,12,10], "Python identity/mode mismatch");
    ensure!(result.marker == if frame.case.descendant() { "CHILD_STARTED" } else { "PYTHON_ISOLATION_OK" }, "positive marker missing");
    if frame.case.boundary() {
        ensure!(result.input_ok == Some(true) && result.output_ok == Some(true), "positive file markers missing");
        ensure!(result.outside_read.is_some() && result.outside_write.is_some()
            && result.denied_read.is_some() && result.denied_write.is_some()
            && result.tcp4.is_some() && result.tcp6.is_some(), "missing boundary observation");
    } else if frame.case == Case::OrdinaryOutside {
        ensure!(result.outside_read.is_some() && result.outside_write.is_some(), "ordinary outside control missing");
        ensure!(result.input_ok.is_none() && result.output_ok.is_none() && result.denied_read.is_none()
            && result.denied_write.is_none() && result.tcp4.is_none() && result.tcp6.is_none(), "ordinary baseline exceeded fixed scope");
    }
    if frame.case.descendant() {
        ensure!(result.input_ok.is_none() && result.output_ok.is_none() && result.outside_read.is_none()
            && result.outside_write.is_none() && result.denied_read.is_none() && result.denied_write.is_none()
            && result.tcp4.is_none() && result.tcp6.is_none(), "descendant case exceeded fixed scope");
    }
    Ok(result)
}
pub fn native_valid(frame: &Frame) -> bool {
    let expected_restrictors = if frame.case == Case::OrdinaryOutside { Vec::new() }
        else if frame.case.pinned() { // Pinned token additionally carries Everyone, user and logon SID.
            let Some(root) = &frame.native.root else { return false };
            if !root.restricting_sids.iter().any(|s| s.starts_with("S-1-5-5-")) { return false; }
            vec![frame.capability_sid.as_str(), frame.account_sid.as_str(), "S-1-1-0"]
        } else { vec![frame.capability_sid.as_str()] };
    let valid = |e: &IdentityEvidence| e.user_sid == frame.account_sid && e.image.eq_ignore_ascii_case(PYTHON)
        && e.desktop == frame.private_desktop && e.exact_job_member && e.retained_handle_signaled
        && expected_restrictors.iter().all(|s| e.restricting_sids.iter().any(|x| x == s))
        && if frame.case == Case::OrdinaryOutside { e.restricting_sids.is_empty() }
            else if frame.case.pinned() { e.restricting_sids.len() == 4 }
            else { e.restricting_sids.len() == 1 };
    frame.native.error.is_none() && frame.cleanup_verified() && frame.native.root.as_ref().is_some_and(valid)
        && if frame.case.descendant() { frame.native.descendants.len() == 1 && frame.native.descendants.iter().all(|e| valid(e) && frame.native.root.as_ref().is_some_and(|r| r.restricting_sids == e.restricting_sids)) }
           else { frame.native.descendants.is_empty() }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict { ObservedPass, PolicyBoundaryFail, Inconclusive, NotTested }
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment { pub python_success: bool, pub identity: Verdict, pub outside_write: Verdict,
    pub outside_read: Option<Probe>, pub broad_read_truth: Verdict, pub explicit_denies: Verdict, pub loopback_only: Verdict,
    pub descendant_cleanup: Verdict, pub parent_death: Verdict, pub full_pass: bool }
pub fn assess(frame: &Frame, output_bytes_match: bool, ordinary_outside_write_succeeded: bool,
    live_owner_controls: bool) -> Assessment {
    let script = parse_script(frame).ok();
    let valid_native = native_valid(frame);
    let boundary = script.as_ref().filter(|_| frame.case.boundary());
    let outside_write = match boundary.and_then(|s| s.outside_write.as_ref()) {
        Some(Probe::Success) => Verdict::PolicyBoundaryFail,
        Some(p) if matches!(p, Probe::PermissionDenied {winerror:5}) && ordinary_outside_write_succeeded => Verdict::ObservedPass,
        _ => Verdict::Inconclusive };
    let file_deny = |p: Option<&Probe>| matches!(p, Some(Probe::PermissionDenied {winerror:5}));
    let socket_deny = |p: Option<&Probe>| matches!(p, Some(Probe::PermissionDenied {winerror:10013}));
    Assessment { python_success: script.is_some() && (!frame.case.boundary() || output_bytes_match),
        identity: if valid_native { Verdict::ObservedPass } else { Verdict::Inconclusive },
        outside_write, outside_read: script.as_ref().and_then(|s| s.outside_read.clone()),
        broad_read_truth: if boundary.is_some_and(|s| matches!(s.outside_read, Some(Probe::Success))) { Verdict::ObservedPass } else { Verdict::Inconclusive },
        explicit_denies: if boundary.is_some_and(|s| file_deny(s.denied_read.as_ref()) && file_deny(s.denied_write.as_ref())) { Verdict::ObservedPass } else if boundary.is_some_and(|s| matches!(s.denied_read, Some(Probe::Success)) || matches!(s.denied_write, Some(Probe::Success))) { Verdict::PolicyBoundaryFail } else { Verdict::Inconclusive },
        loopback_only: if live_owner_controls && boundary.is_some_and(|s| socket_deny(s.tcp4.as_ref()) && socket_deny(s.tcp6.as_ref())) { Verdict::ObservedPass }
            else if boundary.is_some_and(|s| matches!(s.tcp4, Some(Probe::Success)) || matches!(s.tcp6, Some(Probe::Success))) { Verdict::PolicyBoundaryFail } else { Verdict::Inconclusive },
        descendant_cleanup: if frame.case.descendant() { if script.is_some() && valid_native { Verdict::ObservedPass } else { Verdict::Inconclusive } } else { Verdict::NotTested },
        parent_death: Verdict::NotTested, full_pass: false }
}
#[cfg(windows)]
#[path = "python_isolation/observer.rs"]
pub(crate) mod observer;
