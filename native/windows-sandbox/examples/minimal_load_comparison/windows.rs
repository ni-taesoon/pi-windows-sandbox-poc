use super::output;
use anyhow::{ensure, Context, Result};
use base64::Engine;
use pi_windows_sandbox::{
    acl, broker, network, process::Handle,
    protocol::{Policy, RunRequest, RunResult, StopReason}, setup, token, winutil,
};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{fs::{MetadataExt, OpenOptionsExt}, io::AsRawHandle},
    path::{Path, PathBuf}, process::{Child, Command, Stdio}, ptr::null_mut,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Security::Cryptography::*, Security::*, Storage::FileSystem::*,
    System::Threading::GetCurrentProcessId,
};
const ROOT: &str = r"C:\PiSandboxLab";
fn path(name: &str) -> PathBuf { Path::new(ROOT).join(name) }
unsafe fn user_sid_bytes(t: isize) -> Result<Vec<u8>> {
    let mut len = 0;
    GetTokenInformation(t, TokenUser, null_mut(), 0, &mut len);
    ensure!(
        len as usize >= std::mem::size_of::<TOKEN_USER>() && len <= 4096,
        "token user size unavailable"
    );
    let mut buffer = vec![
        0usize;
        (len as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()
    ];
    ensure!(
        GetTokenInformation(t, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) != 0,
        "token user query failed"
    );
    let sid = (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid;
    ensure!(IsValidSid(sid) != 0, "invalid token SID");
    Ok(std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize).to_vec())
}
fn owner() -> Result<String> {
    unsafe {
        let t = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        winutil::string_from_sid_bytes(&user_sid_bytes(t.raw())?).map_err(anyhow::Error::msg)
    }
}
fn hash(bytes: &[u8]) -> Result<String> {
    let mut output = [0u8; 32];
    let mut len = 32;
    ensure!(
        unsafe {
            CryptHashCertificate2(
                winutil::to_wide("SHA256").as_ptr(),
                0,
                null_mut(),
                bytes.as_ptr(),
                bytes.len().try_into()?,
                output.as_mut_ptr(),
                &mut len,
            )
        } != 0
            && len == 32,
        "SHA256 failed"
    );
    Ok(output.iter().map(|b| format!("{b:02x}")).collect())
}
fn fresh_write(p: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(p)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

// Retained handles deny write/delete sharing through both fresh-process runs.
// Only fixed trusted inputs are read. The target OS DLL is never inspected/copied.
fn pin_file(p: &Path, pins: &mut Vec<File>, digest: &mut BTreeMap<String, String>) -> Result<()> {
    let metadata = std::fs::symlink_metadata(p)?;
    ensure!(metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "trusted input must be a regular non-reparse file");
    ensure!(!acl::path_has_standard_user_mutation_allow(p)?, "mutable trusted input");
    let mut file = OpenOptions::new().access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ).open(p)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } != 0
        && info.nNumberOfLinks == 1
        && info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0,
        "trusted input identity unavailable or hardlinked");
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    digest.insert(p.display().to_string(), hash(&bytes)?);
    pins.push(file);
    Ok(())
}
fn trusted_preflight() -> Result<Vec<File>> {
    ensure!(std::env::current_exe()?.to_string_lossy().eq_ignore_ascii_case(
        &path(r"trusted\minimal_load_comparison.exe").to_string_lossy()),
        "run only the staged fixed driver");
    let mut pins = Vec::new();
    for p in [PathBuf::from(r"C:\"), path(""), path("trusted"), path("work")] {
        let m = std::fs::symlink_metadata(&p)?;
        ensure!(m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "invalid lab ancestor");
        if p != Path::new(r"C:\") {
            ensure!(!acl::path_has_standard_user_mutation_allow(&p)?, "mutable lab ancestor");
        }
        pins.push(OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(&p)?);
    }
    Ok(pins)
}
fn pin_inputs(pins: &mut Vec<File>) -> Result<BTreeMap<String, String>> {
    let mut inputs = BTreeMap::new();
    for name in ["minimal_load_comparison.exe", "pi-windows-sandbox.exe", "minimal_load.exe"] {
        pin_file(&path("trusted").join(name), pins, &mut inputs)?;
    }
    Ok(inputs)
}
fn request() -> Result<RunRequest> {
    // Identical to the existing offline lab policy. Only the fixed target differs.
    let policy = Policy {
        workspace: path("work").display().to_string(),
        writable_roots: vec![path("work").display().to_string()],
        deny_read: vec![], deny_write: vec![], network: "disabled".into(),
    };
    Ok(RunRequest {
        schema_version: 1,
        argv: vec![path(r"trusted\minimal_load.exe").display().to_string()],
        cwd: path("work").display().to_string(),
        env: HashMap::from([
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("TEMP".into(), path("work").display().to_string()),
            ("TMP".into(), path("work").display().to_string()),
        ]),
        stdin: String::new(), timeout_ms: 15000, max_output_bytes: 4096,
        parent_pid: unsafe { GetCurrentProcessId() },
        policy_hash: hash(&serde_json::to_vec(&policy)?)?, policy,
    })
}
fn require_elevated() -> Result<()> {
    unsafe {
        let token = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0;
        ensure!(GetTokenInformation(token.raw(), TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32, &mut size) != 0
            && elevation.TokenIsElevated != 0, "already-elevated disposable runner required");
    }
    Ok(())
}
struct ControlChild(Child);
impl Drop for ControlChild {
    fn drop(&mut self) { let _ = self.0.kill(); }
}
fn capture(reader: impl Read + Send + 'static, cap: usize) -> std::sync::mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let captured = (|| {
            let mut bytes = Vec::new();
            reader.take((cap + 1) as u64).read_to_end(&mut bytes)?;
            Ok(bytes)
        })();
        let _ = send.send(captured);
    });
    receive
}
fn run_control(req: &RunRequest) -> Result<RunResult> {
    // This is a predeclared trusted diagnostic control, never an execution fallback.
    // The exact same immutable executable, empty stdin, environment and cwd are used.
    req.validate()?;
    let mut child = ControlChild(Command::new(&req.argv[0]).args(&req.argv[1..])
        .env_clear().envs(&req.env).current_dir(&req.cwd)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let stdout = capture(child.0.stdout.take().context("control stdout unavailable")?, req.max_output_bytes);
    let stderr = capture(child.0.stderr.take().context("control stderr unavailable")?, req.max_output_bytes);
    let deadline = Instant::now() + Duration::from_millis(u64::from(req.timeout_ms));
    let (status, timed_out) = loop {
        if let Some(status) = child.0.try_wait()? { break (status, false); }
        if Instant::now() >= deadline {
            child.0.kill().context("control timeout termination failed")?;
            let cleanup_deadline = Instant::now() + Duration::from_secs(5);
            let killed_status = loop {
                if let Some(status) = child.0.try_wait()? { break status; }
                ensure!(Instant::now() < cleanup_deadline, "control cleanup unverified");
                std::thread::sleep(Duration::from_millis(10));
            };
            break (killed_status, true);
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout.recv_timeout(Duration::from_secs(2)).context("control stdout completion unverified")??;
    let stderr = stderr.recv_timeout(Duration::from_secs(2)).context("control stderr completion unverified")??;
    let truncated = stdout.len() + stderr.len() > req.max_output_bytes;
    Ok(RunResult {
        kind: "result".into(),
        stop_reason: if timed_out { StopReason::Timeout } else if truncated { StopReason::OutputLimit } else { StopReason::Exited },
        exit_code: status.code().context("control exit code unavailable")? as u32,
        stdout_base64: base64::engine::general_purpose::STANDARD.encode(stdout),
        stderr_base64: base64::engine::general_purpose::STANDARD.encode(stderr),
        timed_out, truncated, terminated: true, cleanup_verified: true,
    })
}
fn observation(run: &Result<RunResult>) -> Result<output::LoadObservation> {
    let run = run.as_ref().map_err(|error| anyhow::anyhow!("{error:#}"))?;
    ensure!(run.kind == "result" && run.stop_reason == StopReason::Exited
        && run.terminated && run.cleanup_verified && !run.timed_out && !run.truncated,
        "process completion/cleanup not verified");
    let stdout = base64::engine::general_purpose::STANDARD.decode(&run.stdout_base64)?;
    let stderr = base64::engine::general_purpose::STANDARD.decode(&run.stderr_base64)?;
    output::parse(run.exit_code, &stdout, &stderr)
}
fn run_pair(owner: &str, req: RunRequest, inputs: &BTreeMap<String, String>, pins: &mut Vec<File>) -> Result<()> {
    let mut ignored = BTreeMap::new();
    pin_file(&path(r"trusted\minimal-load-baseline.json"), pins, &mut ignored)?;
    let baseline: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path(r"trusted\minimal-load-baseline.json"))?)?;
    ensure!(baseline["ownerSid"] == owner && baseline["inputs"] == serde_json::to_value(inputs)?
        && baseline["policyHash"] == req.policy_hash, "baseline input/owner/policy mismatch");
    ensure!(std::fs::read_dir(path("work"))?.next().is_none(), "fresh empty work directory required");
    // A create_new marker prevents repeating either process in this lab, including after failure.
    fresh_write(&path(r"trusted\minimal-load-attempted"), b"one fixed comparison\n")?;
    let identity = setup::logon_offline_identity(&path("store"), owner)?;
    ensure!(baseline["accountSid"] == identity.sid(), "account SID changed");
    let account_sid = identity.sid().to_owned();
    drop(identity);
    network::verify_offline_protection(&account_sid)?;
    let control = run_control(&req);
    // A failed control is evidence, not permission to change policy or bypass the sandbox.
    let control_observation = observation(&control);
    fresh_write(&path(r"trusted\minimal-load-control.json"), &serde_json::to_vec_pretty(
        &serde_json::json!({"diagnosticOnly":true, "normalValidationEligible":false,
            "run":control.as_ref().ok(), "launchError":control.as_ref().err().map(|e|format!("{e:#}")),
            "observation":control_observation.as_ref().ok(),
            "observationError":control_observation.as_ref().err().map(|e|format!("{e:#}"))}))?)?;
    // Fail closed on uncertain control cleanup; never start another process in that case.
    ensure!(control.as_ref().is_ok_and(|r| r.terminated && r.cleanup_verified),
        "control cleanup unverified; sandbox not launched");
    network::verify_offline_protection(&account_sid)?;
    let sandbox = unsafe { broker::run_via_dedicated_helper(
        &path("store"), &path(r"trusted\pi-windows-sandbox.exe"), req.clone()) };
    let sandbox_observation = observation(&sandbox);
    let complete = control_observation.is_ok() && sandbox_observation.is_ok();
    let evidence = serde_json::json!({
        "schemaVersion":1, "scope":"LAB_ONLY", "diagnosticOnly":true,
        "status":if complete { "LOAD_OBSERVATIONS_RECORDED" } else { "INCOMPLETE" },
        "nativeValidated":false, "normalValidationEligible":false, "pythonValidationEligible":false,
        "normalContext":"already-elevated CI owner account",
        "sandboxContext":"existing dedicated restricted account and private desktop",
        "sameExecutable":req.argv[0], "environment":req.env, "cwd":req.cwd,
        "dll":r"C:\Windows\System32\bcrypt.dll", "policyHash":req.policy_hash,
        "inputs":inputs,
        "freshLoadComparisonEligible":complete
            && control_observation.as_ref().is_ok_and(|r| !r.preloaded)
            && sandbox_observation.as_ref().is_ok_and(|r| !r.preloaded),
        "normal":{"run":control.as_ref().ok(), "launchError":control.as_ref().err().map(|e|format!("{e:#}")),
            "observation":control_observation.as_ref().ok(), "observationError":control_observation.as_ref().err().map(|e|format!("{e:#}"))},
        "sandbox":{"run":sandbox.as_ref().ok(), "launchError":sandbox.as_ref().err().map(|e|format!("{e:#}")),
            "observation":sandbox_observation.as_ref().ok(), "observationError":sandbox_observation.as_ref().err().map(|e|format!("{e:#}"))},
        "limitations":["only fixed ordinary DLL loading was attempted", "preloaded modules make fresh initialization inconclusive", "not Python or sandbox security validation",
            "a difference does not identify which restriction caused it",
            "no independent target token/job observation", "no traffic enforcement test"]
    });
    fresh_write(&path(r"trusted\minimal-load-run.json"), &serde_json::to_vec_pretty(&evidence)?)?;
    ensure!(complete, "one or both DLL-load observations unavailable; retain per-process result");
    Ok(())
}
fn execute(owner: &str, mode: &str) -> Result<()> {
    let mut pins = trusted_preflight()?;
    let inputs = pin_inputs(&mut pins)?;
    let req = request()?;
    req.validate()?;
    if mode == "setup" {
        ensure!(!path("store").exists() && !path(r"trusted\minimal-load-baseline.json").exists(),
            "fresh lab required");
        network::require_product_namespace_absent()?;
        setup::provision_offline_account(&path("store"), owner)?;
        let prepared = (|| -> Result<()> {
            let identity = setup::logon_offline_identity(&path("store"), owner)?;
            network::verify_offline_protection(identity.sid())?;
            fresh_write(&path(r"trusted\minimal-load-baseline.json"), &serde_json::to_vec_pretty(
                &serde_json::json!({"ownerSid":owner, "accountSid":identity.sid(),
                    "inputs":inputs, "policyHash":req.policy_hash, "nativeValidated":false}))?)
        })();
        if prepared.is_err() {
            setup::disable_offline_account(&path("store"), owner)
                .context("post-setup failure; DISABLE recovery failed")?;
        }
        prepared?;
        println!("MINIMAL_LOAD_SETUP_ONLY");
        Ok(())
    } else { run_pair(owner, req, &inputs, &mut pins) }
}
pub fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 1 && ["setup", "run", "disable"].contains(&args[0].as_str()),
        "fixed usage: minimal_load_comparison setup|run|disable");
    require_elevated()?;
    let owner = owner()?;
    if args[0] == "disable" { return setup::disable_offline_account(&path("store"), &owner); }
    if args[0] == "setup" { return execute(&owner, "setup"); }
    // Account shutdown encloses every run-mode input check and both process attempts.
    let run = execute(&owner, "run");
    let disable = setup::disable_offline_account(&path("store"), &owner);
    let recovery = serde_json::json!({"runError":run.as_ref().err().map(|e|format!("{e:#}")),
        "accountDisabled":disable.is_ok(), "disableError":disable.as_ref().err().map(|e|format!("{e:#}"))});
    let saved = fresh_write(&path(r"trusted\minimal-load-recovery.json"), &serde_json::to_vec_pretty(&recovery)?);
    disable.context("DISABLE recovery failed; dispose the runner")?;
    saved?;
    run?;
    let mut summary: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path(r"trusted\minimal-load-run.json"))?)?;
    summary["accountDisabled"] = serde_json::json!(true);
    fresh_write(&path(r"trusted\minimal-load-summary.json"), &serde_json::to_vec_pretty(&summary)?)?;
    println!("{}", summary);
    Ok(())
}
