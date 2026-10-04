#[path = "output_contract.rs"]
mod output_contract;
use anyhow::{ensure, Context, Result};
use base64::Engine;
use pi_windows_sandbox::{
    acl, broker, network,
    process::Handle,
    protocol::{Policy, RunRequest, StopReason},
    setup, token, winutil,
};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use windows_sys::Win32::{
    Security::Cryptography::*,
    Security::*,
    Storage::FileSystem::*,
    System::{Diagnostics::ToolHelp::*, JobObjects::*, Threading::*},
};
const ROOT: &str = r"C:\PiSandboxLab";
const SCRIPT: &str = "print('PI_LAB_SCRIPT_ENTERED', flush=True)\nimport pathlib, time\nprint('PI_LAB_IMPORTS_READY', flush=True)\np = pathlib.Path('result.txt')\np.write_bytes(b'PI_WINDOWS_PYTHON_LAB_OK\\n')\nassert p.read_bytes() == b'PI_WINDOWS_PYTHON_LAB_OK\\n'\nprint('PI_WINDOWS_PYTHON_LAB_OK', flush=True)\ntime.sleep(3)\n";
const OUTPUT: &[u8] = b"PI_WINDOWS_PYTHON_LAB_OK\n";
fn path(s: &str) -> PathBuf {
    Path::new(ROOT).join(s)
}
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
// Reject reparse components; protect runtime against mutation and replacement for
// the entire launch by retaining no-write/no-delete-sharing handles on every file.
fn pin_tree(
    p: &Path,
    handles: &mut Vec<File>,
    digest: &mut BTreeMap<String, String>,
) -> Result<()> {
    let m = std::fs::symlink_metadata(p)?;
    ensure!(
        m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "reparse target {}",
        p.display()
    );
    ensure!(
        !acl::path_has_standard_user_mutation_allow(p)?,
        "standard user can mutate trusted target {}",
        p.display()
    );
    let mut f = OpenOptions::new()
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(if m.is_dir() {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        })
        .open(p)
        .with_context(|| format!("pin {}", p.display()))?;
    if m.is_dir() {
        for child in std::fs::read_dir(p)? {
            pin_tree(&child?.path(), handles, digest)?;
        }
    } else {
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;
        digest.insert(p.to_string_lossy().to_string(), hash(&bytes)?);
    }
    handles.push(f);
    Ok(())
}
fn trusted_preflight() -> Result<()> {
    ensure!(
        std::env::current_exe()?
            .to_string_lossy()
            .eq_ignore_ascii_case(&path(r"trusted\python_lab.exe").to_string_lossy()),
        "run only staged trusted lab executable"
    );
    for p in [
        PathBuf::from(r"C:\"),
        path(""),
        path("trusted"),
        path("runtime"),
        path("work"),
    ] {
        let metadata = std::fs::symlink_metadata(&p)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "invalid lab ancestor"
        );
        // Drive-root Users may have create-directory rights; no target parent may.
        if p != Path::new(r"C:\") {
            ensure!(
                !acl::path_has_standard_user_mutation_allow(&p)?,
                "unsafe lab ancestor {}",
                p.display()
            );
        }
    }
    ensure!(
        path(r"runtime\python.exe").is_file(),
        "missing staged Python"
    );
    ensure!(
        path(r"trusted\pi-windows-sandbox.exe").is_file(),
        "missing staged helper"
    );
    Ok(())
}
fn request() -> Result<RunRequest> {
    let policy = Policy {
        workspace: path("work").display().to_string(),
        writable_roots: vec![path("work").display().to_string()],
        deny_read: vec![],
        deny_write: vec![],
        network: "disabled".into(),
    };
    let policy_hash = hash(&serde_json::to_vec(&policy)?)?;
    Ok(RunRequest {
        schema_version: 1,
        argv: vec![
            path(r"runtime\python.exe").display().to_string(),
            "-I".into(),
            "-S".into(),
            "-B".into(),
            path(r"trusted\fixture.py").display().to_string(),
        ],
        cwd: path("work").display().to_string(),
        env: HashMap::from([
            ("SystemRoot".into(), r"C:\Windows".into()),
            ("TEMP".into(), path("work").display().to_string()),
            ("TMP".into(), path("work").display().to_string()),
        ]),
        stdin: String::new(),
        timeout_ms: 15000,
        max_output_bytes: 65536,
        parent_pid: unsafe { GetCurrentProcessId() },
        policy_hash,
        policy,
    })
}
fn pin_inputs() -> Result<(Vec<File>, BTreeMap<String, String>)> {
    let mut handles = vec![];
    let mut digest = BTreeMap::new();
    pin_tree(&path("runtime"), &mut handles, &mut digest)?;
    for name in ["python_lab.exe", "pi-windows-sandbox.exe", "fixture.py"] {
        pin_tree(&path("trusted").join(name), &mut handles, &mut digest)?;
    }
    Ok((handles, digest))
}
pub fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args != ["run"] {
        return dispatch();
    }
    // Recovery encloses every run-mode check, including malformed input/pins and
    // observer panic. Store ownership authentication scopes disable to our account.
    let owner = owner()?;
    let run = dispatch();
    let disable = setup::disable_offline_account(&path("store"), &owner);
    let recovery = serde_json::json!({"runError":run.as_ref().err().map(|e|format!("{e:#}")),
        "accountDisabled":disable.is_ok(), "disableError":disable.as_ref().err().map(|e|format!("{e:#}"))});
    let evidence = fresh_write(
        &path(r"trusted\recovery-evidence.json"),
        &serde_json::to_vec_pretty(&recovery)?,
    );
    if let Err(error) = disable {
        anyhow::bail!("run={run:?}; DISABLE RECOVERY FAILED: {error:#}");
    }
    evidence?;
    run?;
    let mut summary: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path(r"trusted\result-evidence.json"))?)?;
    summary["status"] = serde_json::json!("LAB_SMOKE_PASS");
    summary["accountDisabled"] = serde_json::json!(true);
    fresh_write(
        &path(r"trusted\summary-evidence.json"),
        &serde_json::to_vec_pretty(&summary)?,
    )?;
    println!("{}", summary);
    Ok(())
}
fn dispatch() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(
        args.len() == 1 && ["setup", "run", "disable"].contains(&args[0].as_str()),
        "fixed lab usage: python_lab setup|run|disable"
    );
    unsafe {
        let t = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0;
        ensure!(
            GetTokenInformation(
                t.raw(),
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of_val(&elevation) as u32,
                &mut size
            ) != 0
                && elevation.TokenIsElevated != 0,
            "already elevated disposable runner required; account recovery authority unavailable"
        );
    }
    let owner = owner()?;
    if args[0] == "disable" {
        return setup::disable_offline_account(&path("store"), &owner);
    }
    trusted_preflight()?;
    if args[0] == "setup" {
        ensure!(
            !path("store").exists() && !path(r"trusted\baseline.json").exists(),
            "fresh lab required"
        );
        network::require_product_namespace_absent()?;
        fresh_write(&path(r"trusted\fixture.py"), SCRIPT.as_bytes())?;
        let (_pins, inputs) = pin_inputs()?;
        let req = request()?;
        // Operator authorization must precede this mode. There is no elevation,
        // approval inference, account reuse, policy override, or command passthrough.
        setup::provision_offline_account(&path("store"), &owner)?;
        let result = (|| -> Result<()> {
            let identity = setup::logon_offline_identity(&path("store"), &owner)?;
            network::verify_offline_protection(identity.sid())?;
            fresh_write(
                &path(r"trusted\baseline.json"),
                &serde_json::to_vec_pretty(
                    &serde_json::json!({"ownerSid":owner,"accountSid":identity.sid(),"inputs":inputs,"policyHash":req.policy_hash,"nativeValidated":false}),
                )?,
            )?;
            Ok(())
        })();
        if result.is_err() {
            setup::disable_offline_account(&path("store"), &owner)
                .context("post-setup failure; DISABLE recovery failed")?;
        }
        result?;
        println!("LAB_SETUP_ONLY: fresh account and protected inputs prepared; no Python launched");
        return Ok(());
    }
    let (_pins, inputs) = pin_inputs()?;
    let mut baseline_handles = vec![];
    let mut ignored = BTreeMap::new();
    pin_tree(
        &path(r"trusted\baseline.json"),
        &mut baseline_handles,
        &mut ignored,
    )?;
    let baseline: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path(r"trusted\baseline.json"))?)?;
    ensure!(
        baseline["ownerSid"] == owner && baseline["inputs"] == serde_json::to_value(inputs)?,
        "owner/input identity changed"
    );
    ensure!(
        std::fs::read(path(r"trusted\fixture.py"))? == SCRIPT.as_bytes(),
        "fixed fixture mismatch"
    );
    ensure!(
        std::fs::read_dir(path("work"))?.next().is_none(),
        "work fixture must be empty; no retries on reused lab"
    );
    let identity = setup::logon_offline_identity(&path("store"), &owner)?;
    ensure!(
        baseline["accountSid"] == identity.sid(),
        "account SID changed"
    );
    let req = request()?;
    ensure!(
        baseline["policyHash"] == req.policy_hash,
        "policy digest changed"
    );
    let expected_sid = identity.sid().to_owned();
    drop(identity);
    // Snapshot precedes first helper. Fresh-only setup, operator-owned immutable
    // inputs and this one run are lab assumptions, not production race closure.
    ensure!(
        observe(&expected_sid)?.is_empty(),
        "preexisting dedicated-account process"
    );
    let done = Arc::new(AtomicBool::new(false));
    let finished = done.clone();
    let observed_sid = expected_sid.clone();
    let observer = std::thread::spawn(move || -> (Vec<Observed>, Option<String>) {
        let mut found = BTreeMap::new();
        while !finished.load(Ordering::SeqCst) {
            match observe(&observed_sid) {
                Ok(batch) => {
                    for item in batch {
                        found.entry(item.pid).or_insert(item);
                    }
                }
                Err(error) => return (found.into_values().collect(), Some(format!("{error:#}"))),
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        (found.into_values().collect(), None)
    });
    // Read-only effective rule check immediately before the unsafe broker call.
    let launched = (|| -> Result<_> {
        network::verify_offline_protection(&expected_sid)?;
        unsafe {
            broker::run_via_dedicated_helper(
                &path("store"),
                &path(r"trusted\pi-windows-sandbox.exe"),
                req,
            )
        }
    })();
    done.store(true, Ordering::SeqCst);
    // Never propagate an observer error/panic before preserving the broker
    // outcome. Partial samples are diagnostic only, not substitute identity proof.
    let (observations, observer_error) = match observer.join() {
        Ok(report) => report,
        Err(_) => (
            Vec::new(),
            Some("observer.phase=join; status=panic".to_owned()),
        ),
    };
    // Account recovery still encloses this entire dispatch in main().
    let raw = serde_json::json!({"scope":"LAB_ONLY", "nativeValidated":false,"loaderTraceDiagnostic":cfg!(feature = "lab-loader-trace"),"accountSid":expected_sid,"run":launched.as_ref().ok(),"launchError":launched.as_ref().err().map(|e|format!("{e:#}")),"exitCodeHex":launched.as_ref().ok().map(|r|format!("0x{:08X}",r.exit_code)),"observerError":observer_error.as_deref(),"observed":observations.iter().map(|o| serde_json::json!({"pid":o.pid,"parentPid":o.parent_pid,"image":o.image,"sid":o.sid,"restricted":o.restricted,"inJob":o.in_job,"exited":o.exited()})).collect::<Vec<_>>()});
    fresh_write(
        &path(r"trusted\run-evidence.json"),
        &serde_json::to_vec_pretty(&raw)?,
    )?;
    if let Some(error) = observer_error {
        anyhow::bail!("independent observer failed: {error}");
    }
    if cfg!(feature = "lab-loader-trace") {
        anyhow::bail!("LOADER_TRACE_DIAGNOSTIC_ONLY: broker evidence saved; normal validation requires a fresh run without this feature");
    }
    let result = launched?;
    ensure!(
        result.exit_code == 0
            && result.stop_reason == StopReason::Exited
            && result.terminated
            && result.cleanup_verified
            && !result.timed_out
            && !result.truncated,
        "Python/broker failed"
    );
    let stdout = base64::engine::general_purpose::STANDARD
        .decode(&result.stdout_base64)
        .context("invalid Python stdout encoding")?;
    ensure!(
        output_contract::matches_stdout(&stdout),
        "fixed Python stdout contract not completed"
    );
    ensure!(
        observations.iter().any(|o| o
            .image
            .eq_ignore_ascii_case(&path(r"runtime\python.exe").display().to_string())
            && o.restricted
            && o.in_job
            && o.exited()),
        "independent OS Python token/job/exit observation missing"
    );
    let output_path = path(r"work\result.txt");
    let mut output = OpenOptions::new()
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&output_path)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(
        unsafe { GetFileInformationByHandle(output.as_raw_handle() as isize, &mut info) } != 0
            && info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
                == 0
            && info.nNumberOfLinks == 1,
        "output must be a regular single-link file"
    );
    let mut bytes = Vec::new();
    output.read_to_end(&mut bytes)?;
    ensure!(bytes == OUTPUT, "Python output mismatch");
    let evidence = serde_json::json!({"status":"PYTHON_EXECUTION_OBSERVED","nativeValidated":false,"outputSha256":hash(&bytes)?,
        "outputIdentity":{"volume":info.dwVolumeSerialNumber,"fileIndexHigh":info.nFileIndexHigh,"fileIndexLow":info.nFileIndexLow},
        "accountSid":expected_sid,"limitations":["not adversarial validation","job observation proves job membership, not exact outer job identity","same-account startup race remains a production blocker","no traffic enforcement test"]});
    fresh_write(
        &path(r"trusted\result-evidence.json"),
        &serde_json::to_vec_pretty(&evidence)?,
    )?;
    Ok(())
}
#[derive(serde::Serialize)]
struct Observed {
    pid: u32,
    parent_pid: u32,
    image: String,
    sid: String,
    restricted: bool,
    in_job: bool,
    #[serde(skip)]
    handle: Handle,
}
impl Observed {
    fn exited(&self) -> bool {
        unsafe { WaitForSingleObject(self.handle.raw(), 0) == 0 }
    }
}
/// The wait is on the same retained handle, never a fresh PID lookup. A signaled
/// handle is only an exit-race clue; it does not authenticate a missing image.
unsafe fn observer_api(api: &'static str, ok: i32, process: &Handle) -> Result<()> {
    if ok == 0 {
        let code = std::io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        let wait = WaitForSingleObject(process.raw(), 0);
        anyhow::bail!("observer API failed: api={api}; win32={code}; retained_handle_wait={wait}");
    }
    Ok(())
}
fn observe(sid: &str) -> Result<Vec<Observed>> {
    unsafe {
        let snapshot = Handle::from_raw(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;
        let mut entry: PROCESSENTRY32W = std::mem::zeroed();
        entry.dwSize = std::mem::size_of_val(&entry) as u32;
        ensure!(
            Process32FirstW(snapshot.raw(), &mut entry) != 0,
            "process snapshot unavailable"
        );
        let mut found = vec![];
        loop {
            let raw = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
                0,
                entry.th32ProcessID,
            );
            if raw != 0 {
                let handle = Handle::from_raw(raw)?;
                let mut t = 0;
                if OpenProcessToken(handle.raw(), TOKEN_QUERY, &mut t) != 0 {
                    let t = Handle::from_raw(t)?;
                    let actual = winutil::string_from_sid_bytes(&user_sid_bytes(t.raw())?)
                        .map_err(anyhow::Error::msg)?;
                    if actual == sid {
                        let mut image = vec![0u16; 32768];
                        let mut len = image.len() as u32;
                        observer_api(
                            "image-query/QueryFullProcessImageNameW",
                            QueryFullProcessImageNameW(
                                handle.raw(),
                                0,
                                image.as_mut_ptr(),
                                &mut len,
                            ),
                            &handle,
                        )?;
                        let mut job = 0;
                        observer_api(
                            "job-query/IsProcessInJob",
                            IsProcessInJob(handle.raw(), 0, &mut job),
                            &handle,
                        )?;
                        found.push(Observed {
                            pid: entry.th32ProcessID,
                            parent_pid: entry.th32ParentProcessID,
                            image: String::from_utf16(&image[..len as usize])?,
                            sid: actual,
                            restricted: IsTokenRestricted(t.raw()) != 0,
                            in_job: job != 0,
                            handle,
                        });
                    }
                }
            }
            if Process32NextW(snapshot.raw(), &mut entry) == 0 {
                break;
            }
        }
        Ok(found)
    }
}
