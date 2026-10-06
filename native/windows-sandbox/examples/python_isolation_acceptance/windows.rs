use anyhow::{ensure, Context, Result};
use pi_windows_sandbox::{acl, broker, network, process::Handle, setup, token, winutil,
    python_isolation::{self as lab, Assessment, Case, FixedRequest, Frame, Probe, Verdict}};
use std::{collections::BTreeMap, fs::{File, OpenOptions}, io::{Read, Write},
    os::windows::{fs::{MetadataExt, OpenOptionsExt}, io::AsRawHandle},
    path::{Path, PathBuf}, net::{SocketAddr, TcpListener, TcpStream}, ptr::null_mut,
    time::{Duration, Instant}};
use windows_sys::Win32::{Foundation::*, Security::*, Security::Authorization::*,
    Security::Cryptography::*, Storage::FileSystem::*, System::Threading::GetCurrentProcessId};
fn path(name: &str) -> PathBuf { Path::new(lab::ROOT).join(name) }
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

fn require_elevated() -> Result<()> {
    unsafe {
        let token = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed(); let mut size = 0;
        ensure!(GetTokenInformation(token.raw(), TokenElevation, (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32, &mut size) != 0 && elevation.TokenIsElevated != 0,
            "already elevated disposable Windows runner required");
    } Ok(())
}
fn pin_directory(p: &Path, mutable_fixture: bool, pins: &mut Vec<File>) -> Result<()> {
    let m = std::fs::symlink_metadata(p)?;
    ensure!(m.is_dir() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0, "reparse/non-directory ancestor");
    if p != Path::new(r"C:\") && !mutable_fixture {
        ensure!(!acl::path_has_standard_user_mutation_allow(p)?, "mutable trusted ancestor");
    }
    let file = OpenOptions::new().access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(p)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } != 0
        && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0, "directory handle identity unavailable");
    if mutable_fixture { verify_outside_acl(&file)?; }
    pins.push(file); Ok(())
}
fn verify_outside_acl(file: &File) -> Result<()> {
    unsafe {
        let mut descriptor = null_mut(); let mut dacl = null_mut();
        ensure!(GetSecurityInfo(file.as_raw_handle() as isize, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            null_mut(), null_mut(), &mut dacl, null_mut(), &mut descriptor) == 0, "outside ACL query failed");
        let result = (|| -> Result<()> {
            ensure!(!dacl.is_null() && IsValidAcl(dacl) != 0, "outside DACL absent/invalid");
            let mut world_modify = false;
            for index in 0..(*dacl).AceCount {
                let mut ace = null_mut(); ensure!(GetAce(dacl, index as u32, &mut ace) != 0, "outside ACE missing");
                let header = &*(ace as *const ACE_HEADER);
                ensure!(header.AceType == 0, "outside fixture requires simple allow ACEs only");
                let allow = &*(ace as *const ACCESS_ALLOWED_ACE);
                let sid = std::ptr::addr_of!(allow.SidStart).cast_mut().cast();
                ensure!(IsValidSid(sid) != 0, "outside ACE SID invalid");
                let sid = winutil::string_from_sid_bytes(std::slice::from_raw_parts(sid.cast::<u8>(), GetLengthSid(sid) as usize)).map_err(anyhow::Error::msg)?;
                // Owner/group ACEs are fixed by staging; arbitrary capability SIDs must not appear.
                ensure!(["S-1-1-0", "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545"].contains(&sid.as_str()) || sid == owner()?, "unexpected outside capability/account ACE");
                if sid == "S-1-5-32-545" {
                    ensure!(allow.Mask & !(FILE_GENERIC_READ | FILE_GENERIC_EXECUTE) == 0,
                        "builtin Users outside ACE must be read/execute only");
                }
                if sid == "S-1-1-0" {
                    let modify = FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
                    world_modify |= allow.Mask & modify == modify;
                    ensure!(allow.Mask & (WRITE_DAC | WRITE_OWNER) == 0, "outside fixture world ACL control forbidden");
                }
            }
            ensure!(world_modify, "outside fixture Everyone Modify control missing"); Ok(())
        })();
        LocalFree(descriptor as HLOCAL); result
    }
}
fn pin_file(p: &Path, pins: &mut Vec<File>, digest: &mut BTreeMap<String,String>) -> Result<()> {
    let m = std::fs::symlink_metadata(p)?;
    ensure!(m.is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 && m.len() <= 128*1024*1024,
        "immutable file shape/size invalid");
    ensure!(!acl::path_has_standard_user_mutation_allow(p)?, "mutable immutable input");
    let mut f = OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(p)?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(f.as_raw_handle() as isize, &mut info) } != 0
        && info.nNumberOfLinks == 1 && info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0,
        "immutable file reparse/hardlink/identity invalid");
    let mut bytes = Vec::new(); f.read_to_end(&mut bytes)?;
    digest.insert(p.display().to_string(), hash(&bytes)?); pins.push(f); Ok(())
}
#[derive(Default)]
struct RuntimeBudget { entries: usize, bytes: u64 }
fn pin_runtime(p: &Path, pins: &mut Vec<File>, digest: &mut BTreeMap<String,String>, depth: u32, budget: &mut RuntimeBudget) -> Result<()> {
    ensure!(depth <= 32, "runtime tree depth exceeded");
    budget.entries += 1;
    ensure!(budget.entries <= 20000, "runtime inventory bounds");
    pin_directory(p, false, pins)?;
    for entry in std::fs::read_dir(p)? {
        let p = entry?.path(); let m = std::fs::symlink_metadata(&p)?;
        ensure!(m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0, "runtime reparse forbidden");
        if m.is_dir() { pin_runtime(&p, pins, digest, depth+1, budget)?; }
        else {
            budget.entries += 1; budget.bytes = budget.bytes.checked_add(m.len()).context("runtime size overflow")?;
            ensure!(budget.entries <= 20000 && budget.bytes <= 2*1024*1024*1024, "runtime count/aggregate size bounds");
            pin_file(&p, pins, digest)?;
        }
    } Ok(())
}
fn inputs() -> Result<(Vec<File>, BTreeMap<String,String>)> {
    ensure!(std::env::current_exe()?.to_string_lossy().eq_ignore_ascii_case(&path(r"trusted\python_isolation_acceptance.exe").to_string_lossy()), "fixed staged driver required");
    let mut pins = Vec::new();
    for p in [PathBuf::from(r"C:\"), path(""), path("trusted"), path("work"), path("fixtures"),
        path(r"work\denied-read"), path(r"work\denied-write")] { pin_directory(&p, false, &mut pins)?; }
    pin_directory(&path(r"fixtures\outside-world"), true, &mut pins)?;
    let mut digest = BTreeMap::new();
    for name in ["python_isolation_acceptance.exe", "pi-windows-sandbox.exe", "python-isolation-fixture.py",
        "python-isolation-stage.json", "python-isolation-runtime-manifest.json"] {
        pin_file(&path("trusted").join(name), &mut pins, &mut digest)?;
    }
    let mut runtime = BTreeMap::new(); pin_runtime(&path("runtime"), &mut pins, &mut runtime, 0, &mut RuntimeBudget::default())?;
    let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(path(r"trusted\python-isolation-runtime-manifest.json"))?)?;
    ensure!(manifest["schemaVersion"] == 1 && manifest["pythonVersion"] == "3.12.10"
        && manifest["inputs"] == serde_json::to_value(&runtime)?, "runtime manifest/inventory mismatch");
    ensure!(runtime.contains_key(lab::PYTHON), "fixed Python image missing");
    digest.extend(runtime);
    let stage: serde_json::Value = serde_json::from_slice(&std::fs::read(path(r"trusted\python-isolation-stage.json"))?)?;
    ensure!(stage["nativeValidated"] == false && stage["scope"] == "LAB_PYTHON_ISOLATION_ACCEPTANCE", "invalid stage scope/gate");
    for (key, name) in [("driverSha256",r"trusted\python_isolation_acceptance.exe"),
        ("helperSha256",r"trusted\pi-windows-sandbox.exe"), ("fixtureSha256",r"trusted\python-isolation-fixture.py"),
        ("pythonSha256",r"runtime\python.exe"), ("runtimeManifestSha256",r"trusted\python-isolation-runtime-manifest.json")] {
        ensure!(stage[key].as_str() == digest.get(&path(name).display().to_string()).map(String::as_str), "staged image hash mismatch: {key}");
    }
    Ok((pins,digest))
}
fn fixture_files() -> [(&'static str, &'static [u8]); 3] { [
    (r"work\input.txt", b"PYTHON_ISOLATION_INPUT\n"),
    (r"work\denied-read\secret.txt", b"SYNTHETIC_DENIED_READ\n"),
    (r"fixtures\outside-world\read.txt", b"SYNTHETIC_OUTSIDE_READ\n") ] }
fn verify_fixture() -> Result<()> {
    for (name, bytes) in fixture_files() {
        let p = path(name); let m = std::fs::symlink_metadata(&p)?;
        ensure!(m.is_file() && m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0, "synthetic fixture replaced");
        let f = OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE).open(&p)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(unsafe { GetFileInformationByHandle(f.as_raw_handle() as isize,&mut info) } != 0 && info.nNumberOfLinks == 1, "synthetic fixture hardlink");
        ensure!(std::fs::read(p)? == bytes, "synthetic fixture contents changed");
    }
    for (name, allowed) in [("work", vec!["denied-read","denied-write","input.txt"]),
        (r"work\denied-read",vec!["secret.txt"]), (r"work\denied-write",vec![]),
        (r"fixtures\outside-world",vec!["read.txt"])] {
        let mut names: Vec<String> = std::fs::read_dir(path(name))?.map(|e| Ok(e?.file_name().to_string_lossy().into_owned())).collect::<Result<_>>()?;
        names.sort(); let mut allowed = allowed; allowed.sort();
        ensure!(names == allowed, "fixture must be fresh: {name}");
    } Ok(())
}
struct Listener { socket: TcpListener, address: SocketAddr }
impl Listener {
    fn new(address: &str) -> Result<Self> {
        let address = address.parse()?; let socket = TcpListener::bind(address)?;
        socket.set_nonblocking(true)?; Ok(Self { socket, address })
    }
    fn drain(&self) -> Result<usize> {
        let mut count = 0;
        loop { match self.socket.accept() {
            Ok((_stream,_)) => { count += 1; ensure!(count <= 32, "listener accept bound exceeded"); },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(count), Err(e) => return Err(e.into())
        } }
    }
    fn control(&self) -> Result<()> {
        // Each owner control has its own source port and is accepted synchronously.
        // Any preexisting connection is drained/counts against the sandbox separately.
        let stream = TcpStream::connect_timeout(&self.address,Duration::from_secs(2))?;
        let peer = stream.local_addr()?; let deadline = Instant::now()+Duration::from_secs(2);
        loop { match self.socket.accept() {
            Ok((_accepted, source)) => { ensure!(source == peer,"unexpected connection mixed with owner control"); return Ok(()); },
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                ensure!(Instant::now() < deadline,"owner listener accept timeout"); std::thread::sleep(Duration::from_millis(5)); },
            Err(e) => return Err(e.into())
        } }
    }
}
struct Loopback { v4: Result<Listener>, v6: Result<Listener> }
impl Loopback {
    fn new() -> Self { Self { v4: Listener::new("127.0.0.1:43871"), v6: Listener::new("[::1]:43872") } }
    fn sample(&self) -> serde_json::Value {
        let observe = |listener: &Result<Listener>| match listener {
            Ok(l) => { let unexpected = l.drain(); let control = l.control();
                serde_json::json!({"unexpectedAccepts":unexpected.as_ref().ok(),"liveOwnerControl":control.is_ok(),
                    "error":unexpected.err().or_else(||control.err()).map(|e|format!("{e:#}"))}) },
            Err(e) => serde_json::json!({"unexpectedAccepts":null,"liveOwnerControl":false,"error":format!("{e:#}")}) };
        serde_json::json!({"tcp4":observe(&self.v4),"tcp6":observe(&self.v6)})
    }
}
fn healthy(v: &serde_json::Value) -> bool { ["tcp4","tcp6"].iter().all(|k|
    v[k]["liveOwnerControl"] == true && v[k]["unexpectedAccepts"] == 0 && v[k]["error"].is_null()) }
fn file_bytes_match(p: &Path, expected: &[u8]) -> bool {
    (|| -> Result<bool> {
        let mut file = OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(p)?;
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize,&mut info) } != 0
            && info.nNumberOfLinks == 1 && info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0,
            "output identity/reparse/hardlink check failed");
        let mut bytes = Vec::new(); (&mut file).take(expected.len() as u64 + 1).read_to_end(&mut bytes)?;
        Ok(bytes == expected)
    })().unwrap_or(false)
}
fn artifact_presence(p: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(p) {
        Ok(_) => Ok(true), // Any newly created object is a write-boundary violation.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
fn positive_output(case: Case) -> bool { case.boundary() && file_bytes_match(
    &path("work").join(format!("python-{}.txt",case.label())),lab::OUTPUT) }
fn run_suite(owner: &str, digest: &BTreeMap<String,String>, pins: &mut Vec<File>) -> Result<serde_json::Value> {
    let mut ignored = BTreeMap::new(); pin_file(&path(r"trusted\python-isolation-baseline.json"),pins,&mut ignored)?;
    let baseline: serde_json::Value = serde_json::from_slice(&std::fs::read(path(r"trusted\python-isolation-baseline.json"))?)?;
    let policy_hash = hash(&serde_json::to_vec(&lab::fixed_policy())?)?;
    ensure!(baseline["ownerSid"] == owner && baseline["inputs"] == serde_json::to_value(digest)?
        && baseline["policyHash"] == policy_hash,"baseline owner/inputs/policy mismatch");
    verify_fixture()?;
    fresh_write(&path(r"trusted\python-isolation-attempted"),b"one fixed Python isolation acceptance attempt\n")?;
    let identity = setup::logon_offline_identity(&path("store"),owner)?;
    ensure!(baseline["accountSid"] == identity.sid(),"account identity changed");
    network::verify_offline_protection(identity.sid())?; drop(identity);
    let listeners = Loopback::new(); let mut before = listeners.sample();
    let mut frames = Vec::new(); let mut assessments: Vec<(Case,Assessment)> = Vec::new(); let mut ordinary_ok = false;
    let run = unsafe { broker::run_fixed_python_acceptance(FixedRequest::new(lab::request(Case::StrictBoundary,
        GetCurrentProcessId(),policy_hash.clone()))?, &mut |frame: &Frame| {
        let after = listeners.sample();
        if frame.case == Case::OrdinaryOutside {
            ordinary_ok = lab::parse_script(frame).is_ok_and(|s| matches!(s.outside_write,Some(Probe::Success))
                && matches!(s.outside_read,Some(Probe::Success))) && lab::native_valid(frame)
                && file_bytes_match(&path(r"fixtures\outside-world\ordinary-write.txt"),b"SYNTHETIC_OUTSIDE_WRITE\n");
        }
        let mut assessment = lab::assess(frame,positive_output(frame.case),ordinary_ok,healthy(&before) && healthy(&after));
        let outside_artifact = if frame.case.boundary() {
            artifact_presence(&path(r"fixtures\outside-world").join(format!("{}-write.txt",frame.case.label())))
        } else { Ok(false) };
        let denied_artifact = if frame.case.boundary() {
            artifact_presence(&path(r"work\denied-write").join(format!("{}.txt",frame.case.label())))
        } else { Ok(false) };
        // Unexpected creation is a failure even if a later Python error prevented its JSON.
        if outside_artifact.as_ref().is_ok_and(|present| *present) { assessment.outside_write = Verdict::PolicyBoundaryFail; }
        else if outside_artifact.is_err() && assessment.outside_write != Verdict::PolicyBoundaryFail { assessment.outside_write = Verdict::Inconclusive; }
        if denied_artifact.as_ref().is_ok_and(|present| *present) { assessment.explicit_denies = Verdict::PolicyBoundaryFail; }
        else if denied_artifact.is_err() && assessment.explicit_denies != Verdict::PolicyBoundaryFail { assessment.explicit_denies = Verdict::Inconclusive; }
        if frame.case.boundary() && ["tcp4","tcp6"].iter().any(|k| after[k]["unexpectedAccepts"].as_u64().is_some_and(|n|n>0)) {
            assessment.loopback_only = Verdict::PolicyBoundaryFail;
        }
        let record = serde_json::json!({"schemaVersion":1,"scope":"LAB_PYTHON_ISOLATION_ACCEPTANCE", "nativeValidated":false,
            "frame":frame,"script":lab::parse_script(frame).ok(),"scriptError":lab::parse_script(frame).err().map(|e|format!("{e:#}")),
            "assessment":assessment,"loopbackBefore":before,"loopbackAfter":after,
            "outputBytesMatch":positive_output(frame.case),"ordinaryOutsideControlHealthy":ordinary_ok,
            "outsideWriteArtifact":{"present":outside_artifact.as_ref().ok(),"error":outside_artifact.err().map(|e|format!("{e:#}"))},
            "deniedWriteArtifact":{"present":denied_artifact.as_ref().ok(),"error":denied_artifact.err().map(|e|format!("{e:#}"))}});
        fresh_write(&path("trusted").join(format!("python-isolation-{}.json",frame.case.name())),&serde_json::to_vec_pretty(&record)?)?;
        frames.push(record); assessments.push((frame.case,assessment)); before = after;
        Ok(())
    }) };
    let boundary_fail = assessments.iter().any(|(_,a)| a.outside_write == Verdict::PolicyBoundaryFail
        || a.explicit_denies == Verdict::PolicyBoundaryFail || a.loopback_only == Verdict::PolicyBoundaryFail);
    let core = !boundary_fail && ordinary_ok && run.is_ok() && assessments.iter().filter(|(c,_)| c.pinned()).count() == 3
        && assessments.iter().filter(|(c,_)| c.pinned()).all(|(c,a)| a.python_success && a.identity == Verdict::ObservedPass
            && if c.boundary() { a.outside_write == Verdict::ObservedPass && a.broad_read_truth == Verdict::ObservedPass
                && a.explicit_denies == Verdict::ObservedPass && a.loopback_only == Verdict::ObservedPass }
                else { a.descendant_cleanup == Verdict::ObservedPass });
    let summary = serde_json::json!({"schemaVersion":1,"scope":"LAB_PYTHON_ISOLATION_ACCEPTANCE","nativeValidated":false,
        "normalValidationEligible":false,"pythonValidationEligible":false,"fullPass":false,
        "status":if boundary_fail {"POLICY_BOUNDARY_FAIL"} else if core {"BOUNDED_OBSERVATIONS_RECORDED"} else {"INCONCLUSIVE"},
        "boundedCoreAcceptance":core,"parentDeath":"NOT_TESTED","frames":frames,"inputs":digest,"policyHash":policy_hash,
        "suiteError":run.err().map(|e|format!("{e:#}")),"accountDisabled":false,
        "limitations":["parent-death cleanup is NOT_TESTED; full-isolation acceptance is impossible in this revision",
            "loopback TCP4/TCP6 only; no DNS, UDP, external endpoint or all-outbound claim",
            "write restriction does not imply a read allowlist; synthetic outside read is reported separately",
            "strict and pinned token policies use the same CreateProcessAsUserW; ordinary baseline uses CreateProcessW",
            "fixed order/shared helper session are confounds; no token-factor causal attribution",
            "runtime inventory is per-run identity from official staging, not independent historical provenance",
            "fresh disposable-lab-only result: same-account startup/stdio handle race is not closed or audited for production",
            "preexisting dedicated-account processes are not independently enumerated; fresh setup is a lab prerequisite"]});
    fresh_write(&path(r"trusted\python-isolation-run.json"),&serde_json::to_vec_pretty(&summary)?)?;
    Ok(summary)
}
fn setup_lab(owner: &str) -> Result<()> {
    let (_pins,digest) = inputs()?;
    ensure!(!path("store").exists(),"fresh setup required"); network::require_product_namespace_absent()?;
    for (name,bytes) in fixture_files() { fresh_write(&path(name),bytes)?; }
    verify_fixture()?;
    setup::provision_offline_account(&path("store"),owner)?;
    let prepared = (|| -> Result<()> {
        let identity = setup::logon_offline_identity(&path("store"),owner)?;
        network::verify_offline_protection(identity.sid())?;
        fresh_write(&path(r"trusted\python-isolation-baseline.json"),&serde_json::to_vec_pretty(&serde_json::json!({
            "ownerSid":owner,"accountSid":identity.sid(),"inputs":digest,
            "policyHash":hash(&serde_json::to_vec(&lab::fixed_policy())?)?,"nativeValidated":false}))?)
    })();
    if prepared.is_err() { setup::disable_offline_account(&path("store"),owner).context("setup failed and disable recovery failed")?; }
    prepared
}
pub fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    ensure!(args.len() == 1 && ["setup","run","disable"].contains(&args[0].as_str()), "fixed usage: python_isolation_acceptance setup|run|disable");
    require_elevated()?; let owner = owner()?;
    if args[0] == "disable" { return setup::disable_offline_account(&path("store"),&owner); }
    if args[0] == "setup" { setup_lab(&owner)?; println!("PYTHON_ISOLATION_SETUP_ONLY"); return Ok(()); }
    // The recovery boundary encloses every run-mode check, including failed preflight.
    let run = (|| { let (mut pins,digest) = inputs()?; run_suite(&owner,&digest,&mut pins) })();
    let disable = setup::disable_offline_account(&path("store"),&owner);
    fresh_write(&path(r"trusted\python-isolation-recovery.json"),&serde_json::to_vec_pretty(&serde_json::json!({
        "accountDisabled":disable.is_ok(),"disableError":disable.as_ref().err().map(|e|format!("{e:#}")),
        "runError":run.as_ref().err().map(|e|format!("{e:#}"))}))?)?;
    disable.context("account disable unverified; dispose runner")?;
    let mut summary = run?; summary["accountDisabled"] = serde_json::json!(true);
    fresh_write(&path(r"trusted\python-isolation-summary.json"),&serde_json::to_vec_pretty(&summary)?)?;
    println!("{}",summary);
    ensure!(summary["boundedCoreAcceptance"] == true,"required bounded Python canary failed or inconclusive; preserved per-case evidence");
    Ok(())
}
