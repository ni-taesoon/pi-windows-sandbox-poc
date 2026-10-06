//! Fixed, default-off acceptance contracts. Nothing here extends the product protocol.
use crate::protocol::{Policy, RunRequest, RunResult, StopReason};
use anyhow::{ensure, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
pub const ROOT: &str = r"C:\PiSandboxLab";
pub const CONHOST: &str = r"C:\Windows\System32\conhost.exe";
pub const PYTHON: &str = r"C:\PiSandboxLab\runtime\python.exe";
pub const SCRIPT: &str = r"C:\PiSandboxLab\trusted\python-isolation-fixture.py";
pub const WORK: &str = r"C:\PiSandboxLab\work";
pub const OUTSIDE: &str = r"C:\PiSandboxLab\fixtures\outside-world";
pub const OUTSIDE_LOGON: &str = r"C:\PiSandboxLab\fixtures\outside-logon";
pub const SESSION_OUTPUT: &[u8] = b"AUTHORIZED_SESSION_GRANT_OBSERVED\n";
pub const OUTPUT: &[u8] = b"PYTHON_ISOLATION_OK\n";
pub const MAX_FRAME: usize = 64 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case { OrdinaryOutside, StrictBoundary, StrictChildNormalExit, StrictChildTimeout,
    PinnedBoundary, PinnedChildNormalExit, PinnedChildTimeout,
    #[cfg(feature = "lab-python-policy-repair-comparison")]
    CandidateBoundary,
    #[cfg(feature = "lab-python-policy-repair-comparison")]
    CandidateChildNormalExit,
    #[cfg(feature = "lab-python-policy-repair-comparison")]
    CandidateChildTimeout,
    #[cfg(feature="lab-python-logon-sid-comparison")]
    SessionBoundary,
    #[cfg(feature="lab-python-logon-sid-comparison")]
    SessionChildNormalExit,
    #[cfg(feature="lab-python-logon-sid-comparison")]
    SessionChildTimeout,
}
impl Case {
    #[cfg(not(feature = "lab-python-policy-repair-comparison"))]
    pub const ALL: [Self; 7] = [Self::OrdinaryOutside, Self::StrictBoundary,
        Self::StrictChildNormalExit, Self::StrictChildTimeout, Self::PinnedBoundary,
        Self::PinnedChildNormalExit, Self::PinnedChildTimeout];
    #[cfg(all(feature = "lab-python-policy-repair-comparison",not(feature="lab-python-logon-sid-comparison")))]
    pub const ALL: [Self; 10] = [Self::OrdinaryOutside, Self::StrictBoundary,
        Self::StrictChildNormalExit, Self::StrictChildTimeout, Self::PinnedBoundary,
        Self::PinnedChildNormalExit, Self::PinnedChildTimeout, Self::CandidateBoundary,
        Self::CandidateChildNormalExit, Self::CandidateChildTimeout];
    #[cfg(feature="lab-python-logon-sid-comparison")]
    pub const ALL: [Self;13] = [Self::OrdinaryOutside,Self::StrictBoundary,Self::StrictChildNormalExit,
        Self::StrictChildTimeout,Self::PinnedBoundary,Self::PinnedChildNormalExit,Self::PinnedChildTimeout,
        Self::CandidateBoundary,Self::CandidateChildNormalExit,Self::CandidateChildTimeout,
        Self::SessionBoundary,Self::SessionChildNormalExit,Self::SessionChildTimeout];
    pub fn name(self) -> &'static str { match self {
        Self::OrdinaryOutside => "ordinary-outside", Self::StrictBoundary => "strict-boundary",
        Self::StrictChildNormalExit => "strict-child-normal-exit", Self::StrictChildTimeout => "strict-child-timeout",
        Self::PinnedBoundary => "pinned-boundary", Self::PinnedChildNormalExit => "pinned-child-normal-exit",
        Self::PinnedChildTimeout => "pinned-child-timeout",
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        Self::CandidateBoundary => "candidate-boundary",
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        Self::CandidateChildNormalExit => "candidate-child-normal-exit",
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        Self::CandidateChildTimeout => "candidate-child-timeout",
        #[cfg(feature="lab-python-logon-sid-comparison")]
        Self::SessionBoundary => "session-boundary",
        #[cfg(feature="lab-python-logon-sid-comparison")]
        Self::SessionChildNormalExit => "session-child-normal-exit",
        #[cfg(feature="lab-python-logon-sid-comparison")]
        Self::SessionChildTimeout => "session-child-timeout",
    } }
    pub fn pinned(self) -> bool { matches!(self, Self::PinnedBoundary | Self::PinnedChildNormalExit | Self::PinnedChildTimeout) }
    pub fn candidate(self) -> bool {
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        { matches!(self,Self::CandidateBoundary | Self::CandidateChildNormalExit | Self::CandidateChildTimeout) }
        #[cfg(not(feature = "lab-python-policy-repair-comparison"))]
        { false }
    }
    pub fn session(self) -> bool {
        #[cfg(feature="lab-python-logon-sid-comparison")]
        { matches!(self,Self::SessionBoundary | Self::SessionChildNormalExit | Self::SessionChildTimeout) }
        #[cfg(not(feature="lab-python-logon-sid-comparison"))]
        { false }
    }
    pub fn boundary(self) -> bool { match self {
        Self::StrictBoundary | Self::PinnedBoundary => true,
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        Self::CandidateBoundary => true,
        #[cfg(feature="lab-python-logon-sid-comparison")]
        Self::SessionBoundary => true,
        _ => false,
    } }
    pub fn descendant(self) -> bool { !self.boundary() && self != Self::OrdinaryOutside }
    pub fn timeout(self) -> bool { match self {
        Self::StrictChildTimeout | Self::PinnedChildTimeout => true,
        #[cfg(feature = "lab-python-policy-repair-comparison")]
        Self::CandidateChildTimeout => true,
        #[cfg(feature="lab-python-logon-sid-comparison")]
        Self::SessionChildTimeout => true,
        _ => false,
    } }
    pub fn label(self) -> &'static str { if self.session() { "session" } else if self.candidate() { "candidate" } else if self.pinned() { "pinned" } else if self == Self::OrdinaryOutside { "ordinary" } else { "strict" } }
}
pub fn compiled_feature() -> &'static str {
    if cfg!(feature="lab-python-logon-sid-comparison") { "lab-python-logon-sid-comparison" }
    else if cfg!(feature="lab-python-policy-repair-comparison") { "lab-python-policy-repair-comparison" }
    else { "lab-python-isolation-acceptance" }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all="SCREAMING_SNAKE_CASE")]
pub enum DefaultDaclRole { Logon, OwnerRights }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct DefaultDaclAce { pub role: DefaultDaclRole, pub mask: u32, pub flags: u8 }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct CandidateTokenConfiguration {
    pub profile: String, pub restricting_sids: Vec<String>, pub default_dacl_aces: Vec<DefaultDaclAce>,
}
impl CandidateTokenConfiguration {
    pub fn matches_capability(&self,capability: &str) -> bool {
        self.profile == "CAP_ONLY_UPSTREAM_DEFAULT_DACL_V1"
            && self.restricting_sids.len() == 1 && self.restricting_sids[0] == capability
            && self.default_dacl_aces.len() == 2
            && self.default_dacl_aces.iter().filter(|a|a.role == DefaultDaclRole::Logon && a.mask == 0x10000000 && a.flags == 0).count() == 1
            && self.default_dacl_aces.iter().filter(|a|a.role == DefaultDaclRole::OwnerRights && a.mask == 0x00020000 && a.flags == 0).count() == 1
    }
}
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct SessionTokenConfiguration {
    pub profile: String, pub base_restricting_sid_count: usize, pub actual_logon_sid: String,
    pub restricting_sids: Vec<String>, pub default_dacl_aces: Vec<DefaultDaclAce>,
}
impl SessionTokenConfiguration {
    pub fn matches_capability(&self,capability: &str) -> bool {
        let mut expected=vec![capability.to_owned(),self.actual_logon_sid.clone()];expected.sort();
        let mut actual=self.restricting_sids.clone();actual.sort();
        self.profile == "CAP_PLUS_ACTUAL_LOGON_UPSTREAM_DEFAULT_DACL_V1" && self.base_restricting_sid_count == 0
            && self.actual_logon_sid.starts_with("S-1-5-5-") && self.actual_logon_sid != capability && actual == expected
            && (CandidateTokenConfiguration {profile:"CAP_ONLY_UPSTREAM_DEFAULT_DACL_V1".into(),
                restricting_sids:vec![capability.into()],default_dacl_aces:self.default_dacl_aces.clone()}).matches_capability(capability)
    }
}
/// Constructed only by the trusted broker from its authenticated helper token.
#[cfg(feature="lab-python-logon-sid-comparison")]
pub struct VerifiedSessionIdentity {pub(crate) account_sid:String,pub(crate) logon_sid:String,pub(crate) capability_sid:String}
#[cfg(feature="lab-python-logon-sid-comparison")]
impl VerifiedSessionIdentity {
    pub fn account_sid(&self)->&str {&self.account_sid}
    pub fn logon_sid(&self)->&str {&self.logon_sid}
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
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DesktopEvidence {
    Observed { name: String },
    Unavailable { error: String },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityEvidence {
    pub pid: u32, pub image: String, pub user_sid: String, pub restricting_sids: Vec<String>,
    pub desktop: DesktopEvidence, pub exact_job_member: bool, pub retained_handle_signaled: bool,
}
/// Bounded diagnostic metadata; never substitutes for identity or cleanup evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobPidSnapshot {
    pub assigned: u32, pub returned: u32, pub pids: Vec<u32>, pub query_error: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JobMemberEvidence { pub pid: u32, pub image: Option<String>, pub query_error: Option<String> }
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeDiagnostics {
    pub expected_root_pid: u32, pub expected_root_thread_id: u32,
    pub root_first_error: Option<String>, pub root_last_error: Option<String>,
    pub descendant_first_error: Option<String>, pub job_pid_snapshots: Vec<JobPidSnapshot>,
    pub job_members: Vec<JobMemberEvidence>, pub truncated: bool,
}
impl NativeDiagnostics {
    pub const LIMIT: usize = 8;
    fn bounded_error(value: String) -> String { value.chars().take(512).collect() }
    pub fn root_error(&mut self, value: String) {
        let value = Self::bounded_error(value);
        self.root_first_error.get_or_insert_with(|| value.clone());
        self.root_last_error = Some(value);
    }
    pub fn descendant_error(&mut self, value: String) {
        self.descendant_first_error.get_or_insert_with(|| Self::bounded_error(value));
    }
    pub fn snapshot(&mut self, mut value: JobPidSnapshot) {
        if value.pids.len() > Self::LIMIT { value.pids.truncate(Self::LIMIT); self.truncated = true; }
        value.query_error = value.query_error.map(Self::bounded_error);
        if self.job_pid_snapshots.last() == Some(&value) { return; }
        if self.job_pid_snapshots.len() < Self::LIMIT { self.job_pid_snapshots.push(value); }
        else { self.truncated = true; }
    }
    pub fn member(&mut self, mut value: JobMemberEvidence) {
        if self.job_members.iter().any(|m| m.pid == value.pid) { return; }
        value.query_error = value.query_error.map(Self::bounded_error);
        if value.image.as_ref().is_some_and(|image| image.len() > 1024) {
            value.image = None; value.query_error = Some("member image exceeded diagnostic bounds".into());
            self.truncated = true;
        }
        if self.job_members.len() < Self::LIMIT { self.job_members.push(value); }
        else { self.truncated = true; }
    }
}
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeEvidence {
    pub root: Option<IdentityEvidence>, pub descendants: Vec<IdentityEvidence>,
    #[serde(default)]
    pub console_hosts: Vec<IdentityEvidence>,
    pub error: Option<String>, pub job_empty: bool, pub unobserved_handles_signaled: bool,
    #[serde(default)]
    pub diagnostics: NativeDiagnostics,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Frame {
    pub case: Case, pub account_sid: String, pub capability_sid: String, pub private_desktop: String,
    pub run: Option<RunResult>, pub launch_error: Option<String>, pub native: NativeEvidence,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub candidate_token: Option<CandidateTokenConfiguration>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub session_token: Option<SessionTokenConfiguration>,
}
impl Frame {
    pub fn cleanup_verified(&self) -> bool {
        self.run.as_ref().is_some_and(|r| r.kind == "result" && r.cleanup_verified && r.terminated)
            && self.native.job_empty && self.native.unobserved_handles_signaled
            && self.native.root.as_ref().map_or(true, |r| r.retained_handle_signaled)
            && self.native.descendants.iter().all(|c| c.retained_handle_signaled)
            && self.native.console_hosts.iter().all(|c| c.retained_handle_signaled)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recorded { pub case: Case }
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum Probe {
    Success,
    PermissionDenied { winerror: Option<u32>, errno: Option<i32>, #[serde(rename = "errorType")] error_type: Option<String> },
    Inconclusive { winerror: Option<u32>, errno: Option<i32>, #[serde(rename = "errorType")] error_type: Option<String> },
}
impl Probe {
    fn errno_permission(&self) -> bool {
        matches!(self, Self::PermissionDenied {winerror:None,errno:Some(1 | 13),error_type:Some(kind)} if kind == "PermissionError")
    }
    pub fn file_denial(&self) -> bool {
        matches!(self, Self::PermissionDenied {winerror:Some(5),..}) || self.errno_permission()
    }
    pub fn socket_denial(&self) -> bool {
        matches!(self, Self::PermissionDenied {winerror:Some(10013),..}) || self.errno_permission()
    }
    pub fn explicit_denial(&self) -> bool { self.file_denial() || self.socket_denial() }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScriptEvidence {
    pub schema_version: u32, pub mode: Case, pub python: [u32; 3], pub marker: String,
    pub outside_read: Option<Probe>, pub outside_write: Option<Probe>,
    pub input_ok: Option<bool>, pub output_ok: Option<bool>,
    pub denied_read: Option<Probe>, pub denied_write: Option<Probe>,
    pub tcp4: Option<Probe>, pub tcp6: Option<Probe>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    pub session_grant_write: Option<Probe>,
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
    if frame.case.session() && frame.case.boundary() { ensure!(result.session_grant_write.is_some(),"session grant probe missing"); }
    else { ensure!(result.session_grant_write.is_none(),"session grant probe outside fixed session boundary"); }
    if frame.case.descendant() {
        ensure!(result.input_ok.is_none() && result.output_ok.is_none() && result.outside_read.is_none()
            && result.outside_write.is_none() && result.denied_read.is_none() && result.denied_write.is_none()
            && result.tcp4.is_none() && result.tcp6.is_none(), "descendant case exceeded fixed scope");
    }
    Ok(result)
}
pub fn native_valid(frame: &Frame) -> bool {
    let expected_restrictors = if frame.case == Case::OrdinaryOutside { Vec::new() }
        else if frame.case.session() {
            let Some(session)=&frame.session_token else { return false };
            if !session.matches_capability(&frame.capability_sid) {return false;}
            vec![frame.capability_sid.as_str(),session.actual_logon_sid.as_str()]
        }
        else if frame.case.pinned() { // Pinned token additionally carries Everyone, user and logon SID.
            let Some(root) = &frame.native.root else { return false };
            if !root.restricting_sids.iter().any(|s| s.starts_with("S-1-5-5-")) { return false; }
            vec![frame.capability_sid.as_str(), frame.account_sid.as_str(), "S-1-1-0"]
        } else { vec![frame.capability_sid.as_str()] };
    let valid = |e: &IdentityEvidence| e.user_sid == frame.account_sid && e.image.eq_ignore_ascii_case(PYTHON)
        && e.exact_job_member && e.retained_handle_signaled
        && expected_restrictors.iter().all(|s| e.restricting_sids.iter().any(|x| x == s))
        && if frame.case == Case::OrdinaryOutside { e.restricting_sids.is_empty() }
            else if frame.case.session() { e.restricting_sids.len() == 2 }
            else if frame.case.pinned() { e.restricting_sids.len() == 4 }
            else { e.restricting_sids.len() == 1 };
    (!frame.case.candidate() || frame.candidate_token.as_ref().is_some_and(|c|c.matches_capability(&frame.capability_sid)))
        && frame.native.error.is_none() && frame.cleanup_verified() && frame.native.root.as_ref().is_some_and(valid)
        && frame.native.console_hosts.len() <= 1 && frame.native.console_hosts.iter().all(|host|
            host.image.eq_ignore_ascii_case(CONHOST) && host.user_sid == frame.account_sid
            && host.exact_job_member && host.retained_handle_signaled)
        && if frame.case.descendant() { frame.native.descendants.len() == 1 && frame.native.descendants.iter().all(|e| valid(e) && frame.native.root.as_ref().is_some_and(|r| r.restricting_sids == e.restricting_sids)) }
           else { frame.native.descendants.is_empty() }
}
/// Desktop observation is independent of token/Job identity. GetThreadDesktop may
/// be unavailable for a console-only thread; expected startup settings are not proof.
/// UOI_NAME returns the actual desktop leaf name, not a verified window-station path.
pub fn desktop_verdict(frame: &Frame) -> Verdict {
    let expected = frame.private_desktop.rsplit('\\').next().unwrap_or("");
    let mut unavailable = frame.native.root.is_none()
        || (frame.case.descendant() && frame.native.descendants.len() != 1);
    for identity in frame.native.root.iter().chain(frame.native.descendants.iter()) {
        match &identity.desktop {
            DesktopEvidence::Observed {name} if name != expected => return Verdict::PolicyBoundaryFail,
            DesktopEvidence::Observed {..} => {},
            DesktopEvidence::Unavailable {..} => unavailable = true,
        }
    }
    if unavailable { Verdict::Inconclusive } else { Verdict::ObservedPass }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict { ObservedPass, PolicyBoundaryFail, Inconclusive, NotTested, AuthorizedSessionGrantObserved }
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Assessment { pub python_success: bool, pub identity: Verdict, pub desktop: Verdict, pub outside_write: Verdict,
    pub outside_read: Option<Probe>, pub broad_read_truth: Verdict, pub explicit_denies: Verdict, pub loopback_only: Verdict,
    pub descendant_cleanup: Verdict, pub parent_death: Verdict, pub full_pass: bool, pub session_grant: Verdict }
pub fn assess(frame: &Frame, output_bytes_match: bool, ordinary_outside_write_succeeded: bool,
    live_owner_controls: bool) -> Assessment {
    let script = parse_script(frame).ok();
    let valid_native = native_valid(frame);
    let boundary = script.as_ref().filter(|_| frame.case.boundary());
    let outside_write = match boundary.and_then(|s| s.outside_write.as_ref()) {
        Some(Probe::Success) => Verdict::PolicyBoundaryFail,
        Some(p) if p.file_denial() && ordinary_outside_write_succeeded => Verdict::ObservedPass,
        _ => Verdict::Inconclusive };
    let file_deny = |p: Option<&Probe>| p.is_some_and(Probe::file_denial);
    let socket_deny = |p: Option<&Probe>| p.is_some_and(Probe::socket_denial);
    Assessment { python_success: script.is_some() && (!frame.case.boundary() || output_bytes_match),
        identity: if valid_native { Verdict::ObservedPass } else { Verdict::Inconclusive },
        desktop: desktop_verdict(frame),
        outside_write, outside_read: script.as_ref().and_then(|s| s.outside_read.clone()),
        broad_read_truth: if boundary.is_some_and(|s| matches!(s.outside_read, Some(Probe::Success))) { Verdict::ObservedPass } else { Verdict::Inconclusive },
        explicit_denies: if boundary.is_some_and(|s| file_deny(s.denied_read.as_ref()) && file_deny(s.denied_write.as_ref())) { Verdict::ObservedPass } else if boundary.is_some_and(|s| matches!(s.denied_read, Some(Probe::Success)) || matches!(s.denied_write, Some(Probe::Success))) { Verdict::PolicyBoundaryFail } else { Verdict::Inconclusive },
        loopback_only: if live_owner_controls && boundary.is_some_and(|s| socket_deny(s.tcp4.as_ref()) && socket_deny(s.tcp6.as_ref())) { Verdict::ObservedPass }
            else if boundary.is_some_and(|s| matches!(s.tcp4, Some(Probe::Success)) || matches!(s.tcp6, Some(Probe::Success))) { Verdict::PolicyBoundaryFail } else { Verdict::Inconclusive },
        descendant_cleanup: if frame.case.descendant() { if script.is_some() && valid_native { Verdict::ObservedPass } else { Verdict::Inconclusive } } else { Verdict::NotTested },
        parent_death: Verdict::NotTested, full_pass: false,
        session_grant:if frame.case.session() && frame.case.boundary(){Verdict::Inconclusive}else{Verdict::NotTested} }
}
/// Candidate-only evaluation cannot replace the separately evaluated controls.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all="camelCase")]
pub struct CandidateAcceptance {
    pub recorded: usize, pub python_success: bool, pub identity_acceptance: bool,
    pub filesystem_acceptance: bool, pub loopback_acceptance: bool,
    pub cleanup_acceptance: bool, pub bounded_core_acceptance: bool,
}
pub fn candidate_acceptance(assessments: &[(Case,Assessment)],ordinary_ok: bool,suite_complete: bool) -> CandidateAcceptance {
    let candidates=assessments.iter().filter(|(case,_)|case.candidate()).collect::<Vec<_>>();
    let complete=cfg!(feature="lab-python-policy-repair-comparison") && candidates.len() == 3
        && candidates.iter().map(|(case,_)|*case).eq(Case::ALL.into_iter().filter(|case|case.candidate()));
    let python_success=complete && candidates.iter().all(|(_,a)|a.python_success);
    let identity_acceptance=complete && candidates.iter().all(|(_,a)|a.identity == Verdict::ObservedPass);
    let filesystem_acceptance=candidates.iter().find(|(case,_)|case.boundary()).is_some_and(|(_,a)|
        a.python_success && a.outside_write == Verdict::ObservedPass && a.broad_read_truth == Verdict::ObservedPass
        && a.explicit_denies == Verdict::ObservedPass);
    let loopback_acceptance=candidates.iter().find(|(case,_)|case.boundary()).is_some_and(|(_,a)|a.loopback_only == Verdict::ObservedPass);
    let cleanup_acceptance=complete && candidates.iter().filter(|(case,_)|case.descendant()).all(|(_,a)|a.descendant_cleanup == Verdict::ObservedPass);
    let bounded_core_acceptance=ordinary_ok && suite_complete && python_success && identity_acceptance
        && filesystem_acceptance && loopback_acceptance && cleanup_acceptance
        && candidates.iter().all(|(_,a)|a.desktop != Verdict::PolicyBoundaryFail);
    CandidateAcceptance {recorded:candidates.len(),python_success,identity_acceptance,filesystem_acceptance,
        loopback_acceptance,cleanup_acceptance,bounded_core_acceptance}
}
pub fn session_grant_verdict(frame:&Frame,artifact_bytes_match:bool,grant_verified:bool)->Verdict{
    if !frame.case.session() || !frame.case.boundary(){return Verdict::NotTested;}
    if artifact_bytes_match && grant_verified && native_valid(frame)
        && parse_script(frame).is_ok_and(|s|matches!(s.session_grant_write,Some(Probe::Success))){
        Verdict::AuthorizedSessionGrantObserved
    }else{Verdict::Inconclusive}
}
pub fn session_profile_acceptance(assessments:&[(Case,Assessment)],ordinary_ok:bool,suite_complete:bool,grant_restored:bool)->bool{
    let sessions=assessments.iter().filter(|(case,_)|case.session()).collect::<Vec<_>>();
    cfg!(feature="lab-python-logon-sid-comparison") && ordinary_ok && suite_complete && grant_restored && sessions.len()==3
        && sessions.iter().map(|(case,_)|*case).eq(Case::ALL.into_iter().filter(|case|case.session()))
        && sessions.iter().all(|(case,a)|a.python_success && a.identity==Verdict::ObservedPass && a.desktop!=Verdict::PolicyBoundaryFail
            && if case.boundary(){a.outside_write==Verdict::ObservedPass && a.broad_read_truth==Verdict::ObservedPass
                && a.explicit_denies==Verdict::ObservedPass && a.loopback_only==Verdict::ObservedPass
                && a.session_grant==Verdict::AuthorizedSessionGrantObserved}
                else{a.descendant_cleanup==Verdict::ObservedPass})
}
pub fn any_policy_boundary_failure(assessments: &[(Case,Assessment)]) -> bool {
    assessments.iter().any(|(_,a)|a.outside_write == Verdict::PolicyBoundaryFail
        || a.explicit_denies == Verdict::PolicyBoundaryFail || a.loopback_only == Verdict::PolicyBoundaryFail
        || a.desktop == Verdict::PolicyBoundaryFail)
}
#[cfg(all(windows,feature="lab-python-logon-sid-comparison"))]
#[path="python_isolation/session_grant.rs"]
pub mod session_grant;
#[cfg(windows)]
#[path = "python_isolation/observer.rs"]
pub(crate) mod observer;
