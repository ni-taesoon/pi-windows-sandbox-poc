//! Lab-only fixed request and result contracts. No process or security APIs.
//! This is not an unrestricted execution option in the product protocol.
use crate::protocol::{RunRequest, RunResult, StopReason};
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub const FIXTURE: &str = r"C:\PiSandboxLab\trusted\minimal_load.exe";
pub const WORK: &str = r"C:\PiSandboxLab\work";

/// An exact trusted fixture request; fields cannot be altered after validation.
/// Content identity still requires the driver's hash-bound image/ancestor pins.
pub struct FixedLoadRequest(RunRequest);
impl FixedLoadRequest {
    pub fn new(request: RunRequest) -> Result<Self> {
        request.validate()?;
        ensure!(request.argv == [FIXTURE], "only the fixed no-argument loader is permitted");
        ensure!(request.cwd == WORK && request.stdin.is_empty(), "fixed cwd and empty stdin required");
        ensure!(request.timeout_ms == 15000 && request.max_output_bytes == 4096,
            "fixed process bounds required");
        ensure!(request.env == HashMap::from([
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("TEMP".into(), WORK.into()),
            ("TMP".into(), WORK.into()),
        ]), "only the fixed explicit environment is permitted");
        ensure!(request.policy.workspace == WORK && request.policy.writable_roots == [WORK]
            && request.policy.deny_read.is_empty() && request.policy.deny_write.is_empty()
            && request.policy.network == "disabled", "only the existing fixed offline policy is permitted");
        Ok(Self(request))
    }
    pub(crate) fn request(&self) -> &RunRequest { &self.0 }
    pub(crate) fn into_request(self) -> RunRequest { self.0 }
}

/// A separate, bounded protocol frame preserves the control result even if the
/// subsequent restricted launch fails. This never substitutes for that launch.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum AccountControlAttempt {
    Recorded { run: RunResult },
    Failed { error: String },
}
impl AccountControlAttempt {
    pub(crate) fn from_result(result: Result<RunResult>) -> Self {
        match result {
            Ok(run) => Self::Recorded { run },
            Err(error) => Self::Failed { error: format!("{error:#}") },
        }
    }
    pub fn run(&self) -> Option<&RunResult> {
        match self { Self::Recorded { run } => Some(run), Self::Failed { .. } => None }
    }
    pub fn can_continue(&self) -> bool {
        self.run().is_some_and(|run| run.kind == "result"
            && run.stop_reason == StopReason::Exited && run.terminated && run.cleanup_verified
            && !run.timed_out && !run.truncated)
    }
}
