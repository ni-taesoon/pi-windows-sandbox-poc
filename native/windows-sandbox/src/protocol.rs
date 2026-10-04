use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub workspace: String,
    pub writable_roots: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub network: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunRequest {
    pub schema_version: u32,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: HashMap<String, String>,
    pub stdin: String,
    pub timeout_ms: u32,
    pub max_output_bytes: usize,
    pub parent_pid: u32,
    pub policy_hash: String,
    pub policy: Policy,
}
impl RunRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(self.schema_version == 1, "unsupported schema");
        ensure!(
            !self.argv.is_empty() && !self.argv[0].is_empty(),
            "missing executable"
        );
        ensure!(
            self.timeout_ms > 0 && self.timeout_ms <= 3_600_000,
            "invalid timeout"
        );
        ensure!(
            self.max_output_bytes > 0 && self.max_output_bytes <= 16 * 1024 * 1024,
            "invalid output limit"
        );
        ensure!(self.stdin.len() <= 1024 * 1024, "stdin too large");
        ensure!(self.parent_pid > 0, "missing parent pid");
        ensure!(
            self.policy_hash.len() == 64 && self.policy_hash.bytes().all(|c| c.is_ascii_hexdigit()),
            "invalid policy digest"
        );
        ensure!(
            self.policy.network == "disabled",
            "only offline policy supported"
        );
        for s in self
            .argv
            .iter()
            .chain(std::iter::once(&self.cwd))
            .chain(self.env.keys())
            .chain(self.env.values())
            .chain(std::iter::once(&self.policy.workspace))
            .chain(self.policy.writable_roots.iter())
            .chain(self.policy.deny_read.iter())
            .chain(self.policy.deny_write.iter())
        {
            ensure!(!s.contains('\0'), "NUL in process parameter");
        }
        ensure!(
            self.env.keys().all(|k| !k.is_empty() && !k.contains('=')),
            "invalid environment name"
        );
        let mut keys: Vec<_> = self.env.keys().map(|k| k.to_uppercase()).collect();
        keys.sort();
        ensure!(
            !keys.windows(2).any(|w| w[0] == w[1]),
            "duplicate environment key"
        );
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RunResult {
    pub stop_reason: StopReason,
    #[serde(rename = "type")]
    pub kind: String,
    pub exit_code: u32,
    pub stdout_base64: String,
    pub stderr_base64: String,
    pub timed_out: bool,
    pub truncated: bool,
    pub terminated: bool,
    pub cleanup_verified: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StopReason {
    Exited,
    Timeout,
    OutputLimit,
    ParentDeath,
}
#[cfg(test)]
mod tests {
    fn valid_request() -> super::RunRequest {
        serde_json::from_value(serde_json::json!({"schemaVersion":1,"argv":["C:\\Windows\\System32\\cmd.exe"],"cwd":"C:\\work","env":{},"stdin":"","timeoutMs":1000,"maxOutputBytes":1024,"parentPid":42,"policyHash":"0".repeat(64),"policy":{"workspace":"C:\\work","writableRoots":[],"denyRead":[],"denyWrite":[],"network":"disabled"}})).unwrap()
    }
    #[test]
    fn bounded_request_validation() {
        let mut req = valid_request();
        assert!(req.validate().is_ok());
        req.timeout_ms = 0;
        assert!(req.validate().is_err());
        req.timeout_ms = 1000;
        req.policy.network = "enabled".into();
        assert!(req.validate().is_err());
        req.policy.network = "disabled".into();
        req.env.insert("Path".into(), "a".into());
        req.env.insert("PATH".into(), "b".into());
        assert!(req.validate().is_err());
    }
    #[test]
    fn stop_reasons_are_explicit() {
        for (reason, name) in [
            (super::StopReason::Exited, "exited"),
            (super::StopReason::Timeout, "timeout"),
            (super::StopReason::OutputLimit, "outputLimit"),
            (super::StopReason::ParentDeath, "parentDeath"),
        ] {
            assert_eq!(serde_json::to_value(reason).unwrap(), name);
        }
    }
    #[test]
    fn production_gate_is_closed() {
        assert!(!crate::NATIVE_VALIDATED);
    }
    #[test]
    fn unknown_fields_rejected() {
        assert!(serde_json::from_str::<super::Policy>(r#"{"workspace":"C:\\w","writableRoots":[],"denyRead":[],"denyWrite":[],"network":"disabled","escape":true}"#).is_err());
    }
}
