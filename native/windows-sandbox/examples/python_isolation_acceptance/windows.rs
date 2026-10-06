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
// This telemetry is read-only and role-normalized. It never modifies admission,
// accepts arbitrary paths, serializes SDDL, or exposes unknown trustee identities.
#[derive(Debug)]
struct DaclObservationError { stage: &'static str, winerror: Option<u32> }
type DaclResult<T> = std::result::Result<T,DaclObservationError>;
fn dacl_bad(stage: &'static str) -> DaclObservationError { DaclObservationError { stage,winerror:None } }
unsafe fn dacl_api(ok: i32,stage: &'static str) -> DaclResult<()> {
    if ok == 0 { let code=GetLastError(); return Err(DaclObservationError {stage,winerror:Some(code)}); }
    Ok(())
}
fn dacl_target(p: &Path,directory: bool,roles: &[(&str,token::LocalSid)]) -> DaclResult<serde_json::Value> {
    let file=OpenOptions::new().access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(p)
        .map_err(|error| DaclObservationError {stage:"open-fixed-target",winerror:error.raw_os_error().and_then(|e|u32::try_from(e).ok())})?;
    unsafe {
        let mut info: BY_HANDLE_FILE_INFORMATION=std::mem::zeroed();
        dacl_api(GetFileInformationByHandle(file.as_raw_handle() as isize,&mut info),"target-handle-information")?;
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
            || (!directory && info.nNumberOfLinks != 1) { return Err(dacl_bad("target-no-reparse-single-link-shape")); }
        let mut descriptor=null_mut();let mut dacl=null_mut();
        let code=GetSecurityInfo(file.as_raw_handle() as isize,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
            null_mut(),null_mut(),&mut dacl,null_mut(),&mut descriptor);
        if code != 0 { return Err(DaclObservationError {stage:"get-target-dacl",winerror:Some(code)}); }
        let result=(|| -> DaclResult<serde_json::Value> {
            if dacl.is_null() { return Ok(serde_json::json!({"nullDacl":true,"aces":[]})); }
            if IsValidAcl(dacl) == 0 { return Err(dacl_bad("validate-target-dacl")); }
            if (*dacl).AceCount > 64 { return Err(dacl_bad("target-ace-count-bound")); }
            let mut records=Vec::new();
            for index in 0..(*dacl).AceCount {
                let mut raw=null_mut();dacl_api(GetAce(dacl,index as u32,&mut raw),"get-target-ace")?;
                let header=&*(raw as *const ACE_HEADER);
                if header.AceSize < 8 { return Err(dacl_bad("target-ace-size")); }
                // ACCESS_ALLOWED/DENIED_ACE use the same mask/SID layout. Unknown
                // forms retain type/flags/mask only and are normalized to OTHER.
                let mask=std::ptr::read_unaligned((raw as *const u8).add(4).cast::<u32>());
                let mut role="OTHER";
                if header.AceType == 0 || header.AceType == 1 {
                    let sid: *mut std::ffi::c_void=(raw as *mut u8).add(8).cast();
                    if header.AceSize < 16 { return Err(dacl_bad("target-ace-sid-header")); }
                    let subs=*((sid as *const u8).add(1)) as usize;
                    if 8 + 8 + subs*4 > header.AceSize as usize { return Err(dacl_bad("target-ace-sid-bounds")); }
                    if IsValidSid(sid) == 0 { return Err(dacl_bad("validate-target-trustee")); }
                    for (label,known) in roles { if EqualSid(sid,known.as_ptr()) != 0 { role=*label;break; } }
                }
                records.push(serde_json::json!({"index":index,"type":header.AceType,"mask":mask,
                    "maskHex":format!("0x{mask:08x}"),"flags":header.AceFlags,"trusteeRole":role,
                    "fileDeleteChild":mask & FILE_DELETE_CHILD != 0}));
            }
            Ok(serde_json::json!({"nullDacl":false,"aces":records}))
        })();
        LocalFree(descriptor as HLOCAL);result
    }
}
fn fixed_target_dacls(owner: &str,account: &str,cap: Option<&str>,logon:Option<&str>) -> serde_json::Value {
    let mut definitions=vec![("OWNER",owner),("SANDBOX_ACCOUNT",account),("EVERYONE","S-1-1-0"),
        ("BUILTIN_USERS","S-1-5-32-545"),("ADMINISTRATORS","S-1-5-32-544"),("SYSTEM","S-1-5-18")];
    if let Some(cap)=cap { definitions.push(("CAPABILITY",cap)); }
    if let Some(logon)=logon { definitions.push(("LOGON",logon)); }
    let roles=definitions.into_iter().map(|(label,sid)|token::LocalSid::from_string(sid).map(|sid|(label,sid))).collect::<Result<Vec<_>>>();
    #[allow(unused_mut)]
    let mut targets=vec![("WORK_ROOT","work",true),("DENIED_WRITE_DIR",r"work\denied-write",true),
        ("DENIED_READ_DIR",r"work\denied-read",true),("DENIED_READ_FILE",r"work\denied-read\secret.txt",false),
        ("OUTSIDE_WORLD_DIR",r"fixtures\outside-world",true)];
    #[cfg(feature="lab-python-logon-sid-comparison")]
    targets.push(("OUTSIDE_LOGON_DIR",r"fixtures\outside-logon",true));
    serde_json::Value::Array(targets.into_iter().map(|(target,name,directory)| {
        let result=match &roles { Ok(roles)=>dacl_target(&path(name),directory,roles),Err(_)=>Err(dacl_bad("normalize-known-trustee-roles")) };
        match result {
            Ok(mut value)=> { value["target"]=serde_json::json!(target);value["status"]=serde_json::json!("OBSERVED");value["error"]=serde_json::Value::Null;value },
            Err(error)=>serde_json::json!({"target":target,"status":"INCONCLUSIVE","aces":[],
                "error":{"stage":error.stage,"winerror":error.winerror}}),
        }
    }).collect())
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
    #[cfg(feature="lab-python-logon-sid-comparison")]
    pin_directory(&path(r"fixtures\outside-logon"),false,&mut pins)?;
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    pin_directory(&path(r"fixtures\outside-private"),false,&mut pins)?;
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
    }
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    ensure!(std::fs::read_dir(path(r"fixtures\outside-private"))?.next().is_none(),"fresh empty private outside leaf required");
    Ok(())
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
#[cfg(feature="lab-python-codex-policy-acceptance")]
fn codex_artifacts() -> serde_json::Value {
    let inspect=|name:&str,directory:bool,expected:Option<&[u8]>| -> Result<serde_json::Value> {
        let mut file=OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(path(name))?;
        let mut info:BY_HANDLE_FILE_INFORMATION=unsafe{std::mem::zeroed()};
        ensure!(unsafe{GetFileInformationByHandle(file.as_raw_handle() as isize,&mut info)}!=0
            && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT==0
            && (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY!=0)==directory
            && (directory || info.nNumberOfLinks==1),"protected artifact identity/shape mismatch");
        // Keep this no-delete-shared identity handle alive through bounded bytes
        // or empty-directory observation. Never reopen a file by path for bytes.
        let content_matches=if let Some(expected)=expected {
            let mut bytes=Vec::new();(&mut file).take(expected.len() as u64+1).read_to_end(&mut bytes)?;
            bytes==expected
        } else {
            ensure!(directory,"missing fixed file content expectation");
            std::fs::read_dir(path(name))?.next().transpose()?.is_none()
        };
        Ok(serde_json::json!({"identity":{"volumeSerialNumber":info.dwVolumeSerialNumber,
            "fileIndexHigh":info.nFileIndexHigh,"fileIndexLow":info.nFileIndexLow},"contentMatches":content_matches}))
    };
    let owner_control=inspect(r"fixtures\outside-private\owner-control.txt",false,Some(b"CODEX_PRIVATE_OWNER_CONTROL\n"));
    let file=inspect(r"work\codex-protected-file.txt",false,Some(b"CODEX_PROTECTED_FILE\n"));
    let directory=inspect(r"work\codex-protected-dir",true,None);
    let names=[r"work\codex-protected-file-renamed.txt",r"work\codex-protected-dir-renamed",
        r"work\codex-protected-dir\codex-write.txt",r"work\codex-allowed-file.txt",r"work\codex-allowed-file-renamed.txt",
        r"work\codex-allowed-dir",r"work\codex-allowed-dir-renamed"];
    let absences:Vec<_>=names.iter().map(|name| {
        let presence=artifact_presence(&path(name));
        serde_json::json!({"path":name,"present":presence.as_ref().ok(),"error":presence.err().map(|e|format!("{e:#}"))})
    }).collect();
    let original_file_presence=artifact_presence(&path(r"work\codex-protected-file.txt"));
    let original_dir_presence=artifact_presence(&path(r"work\codex-protected-dir"));
    // Definite mutation survives missing/malformed Python output. Query errors
    // are inconclusive, never transformed into an access-denial pass.
    let violation=original_file_presence.as_ref().is_ok_and(|v|!*v)
        || original_dir_presence.as_ref().is_ok_and(|v|!*v)
        || file.as_ref().is_ok_and(|v|v["contentMatches"]==false)
        || directory.as_ref().is_ok_and(|v|v["contentMatches"]==false)
        || absences.iter().take(3).any(|v|v["present"]==true);
    let verified=file.as_ref().is_ok_and(|v|v["contentMatches"]==true)
        && directory.as_ref().is_ok_and(|v|v["contentMatches"]==true)
        && absences.iter().all(|v|v["present"]==false);
    serde_json::json!({"ownerControlIdentity":owner_control.as_ref().ok().map(|v|&v["identity"]),
        "ownerControlBytesMatch":owner_control.as_ref().ok().map(|v|&v["contentMatches"]),
        "protectedFileIdentity":file.as_ref().ok().map(|v|&v["identity"]),
        "protectedDirIdentity":directory.as_ref().ok().map(|v|&v["identity"]),
        "protectedFileBytesMatch":file.as_ref().ok().map(|v|&v["contentMatches"]),
        "protectedDirectoryEmpty":directory.as_ref().ok().map(|v|&v["contentMatches"]),"expectedAbsent":absences,
        "protectedMutationObserved":violation,"artifactsVerified":verified,
        "errors":[file.err().map(|e|format!("{e:#}")),directory.err().map(|e|format!("{e:#}")),
            owner_control.err().map(|e|format!("{e:#}"))]})
}
fn run_suite(owner: &str, digest: &BTreeMap<String,String>, pins: &mut Vec<File>) -> Result<serde_json::Value> {
    let mut ignored = BTreeMap::new(); pin_file(&path(r"trusted\python-isolation-baseline.json"),pins,&mut ignored)?;
    let baseline: serde_json::Value = serde_json::from_slice(&std::fs::read(path(r"trusted\python-isolation-baseline.json"))?)?;
    let policy_hash = hash(&serde_json::to_vec(&lab::fixed_policy())?)?;
    ensure!(baseline["labFeature"] == lab::compiled_feature()
        && baseline["wfpPolicy"] == network::wfp_policy_provenance()
        && baseline["expectedWfpFilterCount"] == serde_json::json!(network::expected_wfp_filter_count()),
        "baseline compiled lab/network provenance mismatch");
    ensure!(baseline["ownerSid"] == owner && baseline["inputs"] == serde_json::to_value(digest)?
        && baseline["policyHash"] == policy_hash,"baseline owner/inputs/policy mismatch");
    verify_fixture()?;
    fresh_write(&path(r"trusted\python-isolation-attempted"),b"one fixed Python isolation acceptance attempt\n")?;
    let identity = setup::logon_offline_identity(&path("store"),owner)?;
    ensure!(baseline["accountSid"] == identity.sid(),"account identity changed");
    network::verify_offline_protection(identity.sid())?; drop(identity);
    let listeners = Loopback::new(); let mut before = listeners.sample();
    let mut frames = Vec::new(); let mut assessments: Vec<(Case,Assessment)> = Vec::new(); let mut ordinary_ok = false;
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    let codex_fixtures=std::cell::RefCell::new(None::<serde_json::Value>);
    #[cfg(feature="lab-python-logon-sid-comparison")]
    let session_grant=std::cell::RefCell::new(None::<lab::session_grant::SessionGrant>);
    let run = unsafe { broker::run_fixed_python_acceptance(FixedRequest::new(lab::request(Case::initial(),
        GetCurrentProcessId(),policy_hash.clone()))?, &mut |frame: &Frame| {
        let after = listeners.sample();
        if frame.case == Case::OrdinaryOutside {
            ordinary_ok = lab::parse_script(frame).is_ok_and(|s| matches!(s.outside_write,Some(Probe::Success))
                && matches!(s.outside_read,Some(Probe::Success))) && lab::native_valid(frame)
                && file_bytes_match(&path(r"fixtures\outside-world\ordinary-write.txt"),b"SYNTHETIC_OUTSIDE_WRITE\n");
        }
        let mut assessment = lab::assess(frame,positive_output(frame.case),ordinary_ok,healthy(&before) && healthy(&after));
        let session_artifact_matches=frame.case.session() && frame.case.boundary()
            && file_bytes_match(&path(r"fixtures\outside-logon\session-write.txt"),lab::SESSION_OUTPUT);
        #[cfg(feature="lab-python-logon-sid-comparison")]
        let session_grant_verified=session_grant.borrow().as_ref().is_some_and(|grant|grant.is_applied());
        #[cfg(not(feature="lab-python-logon-sid-comparison"))]
        let session_grant_verified=false;
        assessment.session_grant=lab::session_grant_verdict(frame,session_artifact_matches,session_grant_verified);
        let outside_artifact = if frame.case.boundary() {
            artifact_presence(&path(r"fixtures\outside-world").join(format!("{}-write.txt",frame.case.label())))
        } else { Ok(false) };
        let outside_bytes_match=frame.case.boundary() && file_bytes_match(
            &path(r"fixtures\outside-world").join(format!("{}-write.txt",frame.case.label())),b"SYNTHETIC_OUTSIDE_WRITE\n");
        let denied_artifact = if frame.case.boundary() {
            artifact_presence(&path(r"work\denied-write").join(format!("{}.txt",frame.case.label())))
        } else { Ok(false) };
        // Unexpected creation is a failure even if a later Python error prevented its JSON.
        if outside_artifact.as_ref().is_ok_and(|present| *present) {
            assessment.outside_write = if frame.case.codex() {Verdict::KnownExceptionObserved} else {Verdict::PolicyBoundaryFail};
        }
        else if outside_artifact.is_err() && assessment.outside_write != Verdict::PolicyBoundaryFail { assessment.outside_write = Verdict::Inconclusive; }
        if frame.case.codex() && frame.case.boundary() && assessment.outside_write==Verdict::KnownExceptionObserved {
            if !outside_artifact.as_ref().is_ok_and(|present|*present) {assessment.outside_write=Verdict::Inconclusive;}
            // Keep an actual outside write labeled as the known exception, while
            // requiring exact independent artifact bytes for bounded acceptance.
            if !outside_bytes_match {assessment.python_success=false;}
        }
        if denied_artifact.as_ref().is_ok_and(|present| *present) { assessment.explicit_denies = Verdict::PolicyBoundaryFail; }
        else if denied_artifact.is_err() && assessment.explicit_denies != Verdict::PolicyBoundaryFail { assessment.explicit_denies = Verdict::Inconclusive; }
        if frame.case.boundary() && ["tcp4","tcp6"].iter().any(|k| after[k]["unexpectedAccepts"].as_u64().is_some_and(|n|n>0)) {
            assessment.loopback_only = Verdict::PolicyBoundaryFail;
        }
        #[cfg(feature="lab-python-codex-policy-acceptance")]
        let codex_evidence={
            let private=artifact_presence(&path(r"fixtures\outside-private\codex-write.txt"));
            let mut artifact=codex_artifacts();
            let receipt=codex_fixtures.borrow();
            let receipt=receipt.as_ref().context("Codex fixture receipt missing before first frame")?;
            let expected_identity=|role:&str|receipt["targets"].as_array().and_then(|targets|
                targets.iter().find(|target|target["target"]==role)).map(|target|&target["identity"]);
            let identity_matches=|actual:&str,role:&str|expected_identity(role).is_some_and(|expected|
                expected.is_object() && artifact[actual].is_object() && artifact[actual]==*expected);
            let identities_match=identity_matches("protectedFileIdentity","CODEX_PROTECTED_FILE")
                && identity_matches("protectedDirIdentity","CODEX_PROTECTED_DIR");
            let identity_changed=[("protectedFileIdentity","CODEX_PROTECTED_FILE"),("protectedDirIdentity","CODEX_PROTECTED_DIR")]
                .iter().any(|(actual,role)|artifact[*actual].is_object() && expected_identity(role).is_some_and(|expected|
                    expected.is_object() && artifact[*actual]!=*expected));
            let owner_control=artifact["ownerControlBytesMatch"]==true && identity_matches("ownerControlIdentity","PRIVATE_OWNER_CONTROL");
            artifact["identitiesMatchPreparedTargets"]=serde_json::json!(identities_match);
            if identity_changed {artifact["protectedMutationObserved"]=serde_json::json!(true);}
            if !identities_match {artifact["artifactsVerified"]=serde_json::json!(false);}
            let fixture_verified=["ownerControlWriteReadVerified","protectedTargetsVerified","targetHandlesReleased",
                "lateTargetsCreatedAfterAdmission","protectedDirectoryEmpty","parentDeleteChildBypassAbsent"]
                .iter().all(|key|receipt[*key]==true);
            if frame.case.codex() && frame.case.boundary() {
                if private.as_ref().is_ok_and(|v|*v) {assessment.private_outside_write=Verdict::PolicyBoundaryFail;}
                else if private.is_err() || !owner_control || !fixture_verified {assessment.private_outside_write=Verdict::Inconclusive;}
            }
            if frame.case.file_operations() {
                if artifact["protectedMutationObserved"]==true {assessment.file_operations=Verdict::PolicyBoundaryFail;}
                else if artifact["artifactsVerified"]!=true || !fixture_verified {assessment.file_operations=Verdict::Inconclusive;}
            }
            serde_json::json!({"fixtureReceiptVerified":fixture_verified,"ownerControlWriteReadVerified":owner_control,
                "privateWriteArtifact":{"present":private.as_ref().ok(),"error":private.err().map(|e|format!("{e:#}"))},
                "fileOperationsArtifacts":artifact})
        };
        #[cfg(not(feature="lab-python-codex-policy-acceptance"))]
        let codex_evidence=serde_json::Value::Null;
        let record = serde_json::json!({"schemaVersion":1,"scope":"LAB_PYTHON_ISOLATION_ACCEPTANCE", "nativeValidated":false,
            "labFeature":lab::compiled_feature(),"wfpPolicy":network::wfp_policy_provenance(),
            "expectedWfpFilterCount":network::expected_wfp_filter_count(),
            "codexEvidence":codex_evidence,"absoluteWorkspaceWriteAcceptance":false,
            "frame":frame,"script":lab::parse_script(frame).ok(),"scriptError":lab::parse_script(frame).err().map(|e|format!("{e:#}")),
            "assessment":assessment,"loopbackBefore":before,"loopbackAfter":after,
            "fixedTargetDacls":fixed_target_dacls(owner,&frame.account_sid,Some(&frame.capability_sid),
                frame.session_token.as_ref().map(|config|config.actual_logon_sid.as_str())),
            "sessionGrantArtifactBytesMatch":session_artifact_matches,"sessionGrantVerified":session_grant_verified,
            "sessionGrantBoundaryException":frame.case.session(),"strictWorkspaceOnlyAcceptance":false,
            "outputBytesMatch":positive_output(frame.case),"ordinaryOutsideControlHealthy":ordinary_ok,
            "outsideWriteArtifact":{"bytesMatch":outside_bytes_match,"present":outside_artifact.as_ref().ok(),"error":outside_artifact.err().map(|e|format!("{e:#}"))},
            "deniedWriteArtifact":{"present":denied_artifact.as_ref().ok(),"error":denied_artifact.err().map(|e|format!("{e:#}"))}});
        fresh_write(&path("trusted").join(format!("python-isolation-{}.json",frame.case.name())),&serde_json::to_vec_pretty(&record)?)?;
        frames.push(record); assessments.push((frame.case,assessment)); before = after;
        Ok(())
    },
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    &mut |identity:&lab::VerifiedCodexIdentity| {
        ensure!(codex_fixtures.borrow().is_none(),"single fixed Codex fixture preparation required");
        let prepared=lab::codex_fixtures::prepare(identity);
        let receipt=match prepared {
            Ok(receipt)=>receipt,
            Err(error)=>{
                fresh_write(&path(r"trusted\python-isolation-codex-fixtures.json"),&serde_json::to_vec_pretty(
                    &serde_json::json!({"schemaVersion":1,"status":"PREPARE_FAILED","error":format!("{error:#}")}))?)?;
                return Err(error);
            }
        };
        // Durable owner receipt precedes callback return, therefore helper resume.
        let bytes=serde_json::to_vec_pretty(&receipt)?;
        fresh_write(&path(r"trusted\python-isolation-codex-fixtures.json"),&bytes)?;
        ensure!(file_bytes_match(&path(r"trusted\python-isolation-codex-fixtures.json"),&bytes),
            "durable Codex fixture receipt readback mismatch");
        *codex_fixtures.borrow_mut()=Some(receipt);Ok(())
    },
    #[cfg(feature="lab-python-logon-sid-comparison")]
    &mut |identity:&lab::VerifiedSessionIdentity| {
        ensure!(session_grant.borrow().is_none(),"single session grant callback required");
        let prepared=lab::session_grant::SessionGrant::prepare(identity);
        match prepared {
            Ok(grant)=>*session_grant.borrow_mut()=Some(grant),
            Err(error)=>{
                fresh_write(&path(r"trusted\python-isolation-session-grant-created.json"),&serde_json::to_vec_pretty(
                    &serde_json::json!({"schemaVersion":1,"target":"OUTSIDE_LOGON_DIR","status":"PREPARE_FAILED","error":error}))?)?;
                return Err(error.into());
            }
        }
        let mut stored=session_grant.borrow_mut();let grant=stored.as_mut().context("session grant missing")?;
        let applied=grant.apply();
        fresh_write(&path(r"trusted\python-isolation-session-grant-created.json"),&serde_json::to_vec_pretty(
            &grant.receipt(if applied.is_ok(){"GRANT_VERIFIED"}else{"GRANT_INCONCLUSIVE"},applied.as_ref().err()))?)?;
        applied.map_err(anyhow::Error::from)
    }) };
    #[cfg(feature="lab-python-logon-sid-comparison")]
    let session_grant_cleanup={
        let mut stored=session_grant.borrow_mut();
        let receipt=if let Some(grant)=stored.as_mut(){
            if run.is_ok(){
                // Broker success includes every inner tree, helper exit, empty
                // outer Job and ordinary admission cleanup. No restoration on Err.
                let restored=unsafe{grant.restore_after_verified_cleanup()};
                grant.receipt(if restored.is_ok(){"ORIGINAL_LEAF_DACL_RESTORED"}else{"RESTORE_INCONCLUSIVE"},restored.as_ref().err())
            }else{grant.receipt("RETAINED_CLEANUP_UNCERTAIN",None)}
        }else{serde_json::json!({"schemaVersion":1,"target":"OUTSIDE_LOGON_DIR","status":"NOT_CREATED","originalLeafDaclRestored":false})};
        fresh_write(&path(r"trusted\python-isolation-session-grant-cleanup.json"),&serde_json::to_vec_pretty(&receipt)?)?;
        receipt
    };
    #[cfg(not(feature="lab-python-logon-sid-comparison"))]
    let session_grant_cleanup=serde_json::json!({"status":"NOT_ENABLED","originalLeafDaclRestored":false});
    let session_profile=lab::session_profile_acceptance(&assessments,ordinary_ok,run.is_ok(),session_grant_cleanup["originalLeafDaclRestored"]==true);
    let boundary_fail = lab::any_policy_boundary_failure(&assessments);
    let core = !boundary_fail && ordinary_ok && run.is_ok() && assessments.iter().filter(|(c,_)| c.pinned()).count() == 3
        && assessments.iter().filter(|(c,_)| c.pinned()).all(|(c,a)| a.python_success && a.identity == Verdict::ObservedPass
            && if c.boundary() { a.outside_write == Verdict::ObservedPass && a.broad_read_truth == Verdict::ObservedPass
                && a.explicit_denies == Verdict::ObservedPass && a.loopback_only == Verdict::ObservedPass }
                else { a.descendant_cleanup == Verdict::ObservedPass });
    let candidate=lab::candidate_acceptance(&assessments,ordinary_ok,run.is_ok());
    let candidate_core=candidate.bounded_core_acceptance;
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    let codex_fixture_verified=codex_fixtures.borrow().as_ref().is_some_and(|r|
        r["ownerControlWriteReadVerified"]==true && r["protectedTargetsVerified"]==true && r["targetHandlesReleased"]==true);
    #[cfg(not(feature="lab-python-codex-policy-acceptance"))]
    let codex_fixture_verified=false;
    let codex_core=lab::codex_policy_acceptance(&assessments,ordinary_ok,run.is_ok(),codex_fixture_verified);
    let known_exceptions:Vec<_>=frames.iter().filter(|v|v["frame"]["case"]=="codex-boundary").map(|v|
        serde_json::json!({"target":"OUTSIDE_WORLD_DIR","preexistingPermission":"Everyone Modify",
            "result":v["assessment"]["outsideWrite"],"scriptProbe":v["script"]["outsideWrite"],
            "artifact":v["outsideWriteArtifact"],"absoluteWorkspaceWriteAcceptance":false})).collect();
    let mut summary = serde_json::json!({"schemaVersion":1,"scope":"LAB_PYTHON_ISOLATION_ACCEPTANCE","nativeValidated":false,
        "normalValidationEligible":false,"pythonValidationEligible":false,"fullPass":false,
        "labFeature":lab::compiled_feature(),"wfpPolicy":network::wfp_policy_provenance(),
        "expectedWfpFilterCount":network::expected_wfp_filter_count(),
        "comparisonCompleted":run.is_ok() && assessments.len() == Case::ALL.len(),
        "candidateAttemptStatus":if !cfg!(feature="lab-python-policy-repair-comparison") {"NOT_ENABLED"}
            else if candidate.recorded == 0 {"NOT_ATTEMPTED"} else if candidate.recorded == 3 {"RECORDED"} else {"INCOMPLETE"},
        "candidatePythonSuccess":candidate.python_success,"candidateIdentityAcceptance":candidate.identity_acceptance,
        "candidateFilesystemAcceptance":candidate.filesystem_acceptance,"candidateLoopbackAcceptance":candidate.loopback_acceptance,
        "candidateCleanupAcceptance":candidate.cleanup_acceptance,"candidateBoundedCoreAcceptance":candidate_core,
        "sessionProfileAcceptance":session_profile,"strictWorkspaceOnlyAcceptance":false,
        "sessionGrantCleanup":session_grant_cleanup,
        "sessionProfileDefinition":"limited current-logon profile: capability plus actual helper Logon SID; declared outside-logon Modify exception; not workspace-only isolation",
        "sessionExceptionResult":"successful outside-logon write is AUTHORIZED_SESSION_GRANT_OBSERVED, never a strict workspace pass or an escape",
        "sessionArtifactCleanupLimitation":"only original leaf DACL is restored; child artifact ACL/ownership is not a production revocation guarantee; VM disposal remains required",
        "candidateAcceptanceDefinition":"candidate-only results never override a failed control or the overall comparison verdict; desktop unavailable and parent-death remain outside bounded core",
        "candidateTokenReadbackScope":"helper candidate token queried before CreateProcessAsUserW; Python root/child restricting SIDs are independently queried by the native observer",
        "composedRepairScope":"the two dedicated-account WFP connect filters remain unchanged for all cases; candidate is capability-only with upstream default-object DACL; the separately enabled session profile adds only the actual helper Logon SID and its declared fixed-leaf grant",
        "status":if boundary_fail {"POLICY_BOUNDARY_FAIL"} else if core && (!cfg!(feature="lab-python-policy-repair-comparison") || candidate_core) && (!cfg!(feature="lab-python-logon-sid-comparison") || session_profile) {"BOUNDED_OBSERVATIONS_RECORDED"} else {"INCONCLUSIVE"},
        "boundedCoreAcceptance":core && (!cfg!(feature="lab-python-policy-repair-comparison") || candidate_core)
            && (!cfg!(feature="lab-python-logon-sid-comparison") || session_profile),
        "boundedCoreAcceptanceDefinition":["Python root and fixed child token/image/exact-Job identity plus retained-handle cleanup",
            "at most one same-account exact System32 conhost in that Job; its restricting SIDs are reported separately",
            "positive Python files, outside-write denial, explicit denies and live-control loopback denials",
            "unavailable desktop observation is excluded from bounded core; any observed desktop-name mismatch fails",
            "desktop UOI_NAME checks the observed leaf only; window-station attachment is not independently observed"],
        "observerCorrection":"console-host infrastructure is classified separately from Python children; unavailable desktop no longer erases token/Job evidence",
        "parentDeath":"NOT_TESTED","frames":frames,"inputs":digest,"policyHash":policy_hash,
        "suiteError":run.err().map(|e|format!("{e:#}")),"accountDisabled":false,
        "limitations":["parent-death cleanup is NOT_TESTED; full-isolation acceptance is impossible in this revision",
            "loopback TCP4/TCP6 only; no DNS, UDP, external endpoint or all-outbound claim",
            "write restriction does not imply a read allowlist; synthetic outside read is reported separately",
            "strict and pinned token policies use the same CreateProcessAsUserW; ordinary baseline uses CreateProcessW",
            "fixed order/shared helper session are confounds; no token-factor causal attribution",
            "runtime inventory is per-run identity from official staging, not independent historical provenance",
            "fresh disposable-lab-only result: same-account startup/stdio handle race is not closed or audited for production",
            "preexisting dedicated-account processes are not independently enumerated; fresh setup is a lab prerequisite"]});
    #[cfg(feature="lab-python-codex-policy-acceptance")]
    {
        // New profile has its own declared contract. Do not expose inapplicable
        // historical candidate/session explanations as if those cases ran.
        for key in ["candidateAttemptStatus","candidatePythonSuccess","candidateIdentityAcceptance",
            "candidateFilesystemAcceptance","candidateLoopbackAcceptance","candidateCleanupAcceptance",
            "candidateBoundedCoreAcceptance","sessionProfileAcceptance","sessionGrantCleanup","sessionProfileDefinition",
            "sessionExceptionResult","sessionArtifactCleanupLimitation","candidateAcceptanceDefinition",
            "candidateTokenReadbackScope","composedRepairScope"] {summary.as_object_mut().unwrap().remove(key);}
        summary["limitations"]=serde_json::json!([
            "parent-death NOT_TESTED; full-isolation and absolute workspace-only acceptance remain false",
            "TCP4/TCP6 fixed loopback endpoints only; no all-outbound, UDP, DNS, or external-endpoint claim",
            "write restriction is not a read allowlist; synthetic outside read remains separate",
            "Everyone-Modify outside write is a declared observed exception, not silently repaired",
            "fresh disposable VM required; same-account startup/stdio races and preexisting processes are not independently closed or audited",
            "desktop leaf observation can be unavailable; window-station attachment is not independently observed",
            "late protected targets are lab fixtures only; no caller-configurable ACL API or production revocation guarantee",
            "unchanged original token constructor with separately identified Pi-owned fourteen-filter WFP enhancement"]);
        summary["status"]=serde_json::json!(if boundary_fail {"POLICY_BOUNDARY_FAIL"}
            else if codex_core {"BOUNDED_CODEX_POLICY_ACCEPTANCE"} else {"INCONCLUSIVE"});
        summary["boundedCoreAcceptance"]=serde_json::json!(codex_core);
        summary["codexPolicyAcceptance"]=serde_json::json!(codex_core);
        summary["absoluteWorkspaceWriteAcceptance"]=serde_json::json!(false);
        summary["knownExceptions"]=serde_json::json!(known_exceptions);
        summary["codexFixtureReceipt"]=serde_json::json!(codex_fixtures.borrow().clone());
        summary["tokenProfile"]=serde_json::json!("unchanged original pinned Codex WRITE_RESTRICTED: capability + account + actual helper Logon SID + Everyone");
        summary["networkProvenance"]=serde_json::json!("Pi-owned enhancement: existing fourteen WFP filters, including two dedicated-account ALE_AUTH_CONNECT blocks; not claimed as upstream Codex token behavior");
        summary["boundedCoreAcceptanceDefinition"]=serde_json::json!([
            "exact five fixed cases: ordinary Everyone-Modify control, original Codex boundary, file operations, child normal exit, child timeout",
            "work read/create/modify and disposable file/directory rename/delete; explicit deny-read/write; private outside write denied with separate owner write/read baseline",
            "late capability-denied file and empty directory resist write/rename/delete without retained target handles; host independently verifies remaining artifacts",
            "Everyone-Modify outside write is preserved as a known exception and never an absolute workspace-only pass",
            "root/child actual token image exact Job and retained-handle cleanup; fixed live-control TCP4/TCP6 only",
            "desktop unavailable and parent death excluded; observed desktop mismatch fails; fullPass/nativeValidated remain false"]);
    }
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
            "labFeature":lab::compiled_feature(),"wfpPolicy":network::wfp_policy_provenance(),
            "expectedWfpFilterCount":network::expected_wfp_filter_count(),
            "fixedTargetDacls":fixed_target_dacls(owner,identity.sid(),None,None),
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
