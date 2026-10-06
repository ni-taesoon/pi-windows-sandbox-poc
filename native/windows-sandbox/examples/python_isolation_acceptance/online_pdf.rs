//! Owner-side online PDF evidence. This module is exclusive to the default-off lab.
//! Nothing in this file grants the sandbox network access or executes artifact bytes.
use super::*;
use pi_windows_sandbox::process::Job;
use std::{sync::{mpsc, Arc}, thread::JoinHandle, time::{SystemTime, UNIX_EPOCH}};
use windows_sys::Win32::System::Threading::{CreateProcessW, OpenProcessToken, ResumeThread,
    TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW};

const RELAY_SCRIPT: &str = r"C:\PiSandboxLab\trusted\python-online-pdf-relay.py";
const READY: &str = r"trusted\python-online-pdf-relay-ready.json";
const EVENTS: &str = r"trusted\python-online-pdf-relay.log";
const CLEANUP: &str = r"trusted\python-online-pdf-relay-cleanup.json";
const PDF_VALIDATION: &str = r"trusted\python-online-pdf-validation.json";
const MAX_LIFETIME: Duration = Duration::from_secs(300);
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const ARTIFACT_LIMIT: u64 = 1024 * 1024;

fn unix_ms() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis().try_into()?)
}
fn absent(name: &str) -> Result<()> {
    match std::fs::symlink_metadata(path(name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
        Ok(_) => Err(anyhow::anyhow!("fresh online PDF receipt/artifact required: {name}")),
    }
}
// The caller already pins every ancestor. Keep this exact no-delete-shared leaf
// handle while checking identity, size and bytes; never reopen by name for content.
fn bounded_artifact(name: &str, limit: u64, writer_may_remain: bool) -> Result<(Vec<u8>, serde_json::Value)> {
    let shares = if writer_may_remain { FILE_SHARE_READ | FILE_SHARE_WRITE } else { FILE_SHARE_READ };
    let mut file = OpenOptions::new().access_mode(FILE_GENERIC_READ).share_mode(shares)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(path(name))?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut info) } != 0,
        "artifact handle identity unavailable");
    ensure!(info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
        && info.nNumberOfLinks == 1, "artifact reparse/directory/hardlink forbidden");
    let size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
    ensure!(size > 0 && size <= limit, "artifact size exceeds fixed bounds");
    let mut bytes = Vec::new(); (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 == size, "artifact changed or bounded read incomplete");
    let mut after: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    ensure!(unsafe { GetFileInformationByHandle(file.as_raw_handle() as isize, &mut after) } != 0
        && after.nNumberOfLinks == 1 && after.nFileSizeHigh == info.nFileSizeHigh
        && after.nFileSizeLow == info.nFileSizeLow
        && after.ftLastWriteTime.dwHighDateTime == info.ftLastWriteTime.dwHighDateTime
        && after.ftLastWriteTime.dwLowDateTime == info.ftLastWriteTime.dwLowDateTime,
        "artifact identity/size changed during bounded read");
    Ok((bytes, serde_json::json!({"volumeSerialNumber":info.dwVolumeSerialNumber,
        "fileIndexHigh":info.nFileIndexHigh,"fileIndexLow":info.nFileIndexLow,"singleLink":true,
        "reparsePoint":false,"byteCount":size})))
}
fn read_json(name: &str, limit: u64) -> Result<serde_json::Value> {
    let (bytes, _) = bounded_artifact(name, limit, false)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn exact_keys(value: &serde_json::Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| object.len() == expected.len()
        && expected.iter().all(|key| object.contains_key(*key)))
}

pub(crate) struct Relay {
    job: Option<Arc<Job>>, process: Option<Handle>, pid: u32, assigned: bool,
    started: Instant, started_unix_ms: u64, ready: serde_json::Value, health: serde_json::Value,
    cancel_watchdog: Option<mpsc::Sender<()>>, watchdog: Option<JoinHandle<Result<bool>>>,
    startup_error: Option<String>, cleanup_receipt: Option<serde_json::Value>,
}
impl Relay {
    pub(crate) fn start() -> Result<Self> {
        for name in [READY, EVENTS, CLEANUP, PDF_VALIDATION] { absent(name)?; }
        let mut relay = Self {job:None,process:None,pid:0,assigned:false,started:Instant::now(),
            started_unix_ms:unix_ms()?,ready:serde_json::Value::Null,health:serde_json::Value::Null,
            cancel_watchdog:None,watchdog:None,startup_error:None,cleanup_receipt:None};
        if let Err(error) = relay.launch() {
            relay.startup_error = Some(format!("{error:#}"));
            let cleanup = relay.cleanup();
            return Err(error.context(format!("relay launch failed; cleanupVerified={}", cleanup["cleanupVerified"])));
        }
        Ok(relay)
    }
    fn launch(&mut self) -> Result<()> {
        let job = Arc::new(Job::new()?); self.job = Some(Arc::clone(&job));
        let argv = [lab::PYTHON.to_owned(), "-I".into(), "-S".into(), "-B".into(), RELAY_SCRIPT.into()];
        let mut command = winutil::to_wide(&winutil::argv_to_command_line(&argv));
        let app = winutil::to_wide(lab::PYTHON);
        let cwd = winutil::to_wide(path("trusted"));
        // Explicit replacement environment: no proxy, PATH, PYTHON*, credentials,
        // pip settings or inherited configuration. Unicode double-NUL terminator.
        let mut environment: Vec<u16> = [r"SystemRoot=C:\Windows", r"WINDIR=C:\Windows"].iter()
            .flat_map(|entry| entry.encode_utf16().chain(std::iter::once(0))).collect();
        environment.push(0);
        let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
        startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        // No stdio redirection: STARTUPINFO stays zero-initialized apart from cb.
        // FALSE handle inheritance and CREATE_NO_WINDOW prevent inherited
        // interactive I/O; the fixed relay writes only owner-side receipts.
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        ensure!(unsafe { CreateProcessW(app.as_ptr(), command.as_mut_ptr(), std::ptr::null(),
            std::ptr::null(), 0, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
            environment.as_ptr().cast(), cwd.as_ptr(), &startup, &mut pi) } != 0,
            "owner relay CreateProcessW failed: {}", std::io::Error::last_os_error());
        self.pid = pi.dwProcessId;
        self.process = Some(unsafe { Handle::from_raw(pi.hProcess)? });
        let thread = unsafe { Handle::from_raw(pi.hThread)? };
        let process = self.process.as_ref().context("relay retained process absent")?;
        let mut raw_token = 0;
        ensure!(unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &mut raw_token) } != 0,
            "relay owner token query failed");
        let token = unsafe { Handle::from_raw(raw_token)? };
        let current = unsafe { Handle::from_raw(token::get_current_token_for_restriction()?)? };
        ensure!(unsafe { user_sid_bytes(token.raw())? == user_sid_bytes(current.raw())? },
            "relay process did not retain current owner SID");
        job.assign_suspended(process)?; self.assigned = true;
        let (send, receive) = mpsc::channel();
        let remaining = MAX_LIFETIME.saturating_sub(self.started.elapsed());
        self.watchdog = Some(std::thread::Builder::new().name("fixed-relay-deadline".into()).spawn(move || {
            match receive.recv_timeout(remaining) {
                Err(mpsc::RecvTimeoutError::Timeout) => { job.terminate()?; Ok(true) },
                _ => Ok(false),
            }
        })?);
        self.cancel_watchdog = Some(send);
        ensure!(unsafe { ResumeThread(thread.raw()) } != u32::MAX,
            "relay resume failed: {}", std::io::Error::last_os_error());
        drop(thread);
        loop {
            self.ensure_alive()?;
            match std::fs::symlink_metadata(path(READY)) {
                Ok(_) => match read_json(READY, 8192) {
                    Ok(ready) => { self.ready = ready; break; },
                    Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e|e.raw_os_error()==Some(32)) => {},
                    Err(error) => return Err(error),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
                Err(e) => return Err(e.into()),
            }
            ensure!(self.started.elapsed() < READY_TIMEOUT, "relay ready receipt timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
        self.validate_ready()?;
        self.health = self.health_probe()?;
        self.ensure_alive()?;
        Ok(())
    }
    fn validate_ready(&self) -> Result<()> {
        ensure!(exact_keys(&self.ready, &["schemaVersion","pid","host","port","packageFetchCount","startedUtc","startedUnixMs"])
            && self.ready["schemaVersion"] == 1 && self.ready["pid"] == self.pid
            && self.ready["host"] == "127.0.0.1" && self.ready["port"] == 43873
            && self.ready["packageFetchCount"] == 0, "relay ready schema/identity/endpoint mismatch");
        let started = utc_ms(self.ready["startedUtc"].as_str().context("relay startedUtc absent")?)?;
        ensure!(self.ready["startedUnixMs"].as_u64() == Some(started)
            && started >= self.started_unix_ms && started <= unix_ms()?, "relay ready timestamp outside launch window");
        Ok(())
    }
    fn health_probe(&self) -> Result<serde_json::Value> {
        let endpoint: SocketAddr = "127.0.0.1:43873".parse()?;
        let mut stream = TcpStream::connect_timeout(&endpoint, Duration::from_secs(2))?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        stream.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1:43873\r\nConnection: close\r\n\r\n")?;
        let mut bytes = Vec::new(); stream.take(8193).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 8192, "relay health response exceeded bounds");
        let split = bytes.windows(4).position(|b| b == b"\r\n\r\n").context("relay health HTTP header absent")?;
        let headers = std::str::from_utf8(&bytes[..split])?;
        ensure!(headers.starts_with("HTTP/1.0 200 ") || headers.starts_with("HTTP/1.1 200 "),
            "relay health status was not successful");
        ensure!(!headers.to_ascii_lowercase().contains("transfer-encoding:"), "chunked health response unsupported");
        let health: serde_json::Value = serde_json::from_slice(&bytes[split + 4..])?;
        ensure!(exact_keys(&health, &["schemaVersion","packageFetchCount"])
            && health["schemaVersion"] == 1 && health["packageFetchCount"] == 0, "owner health probe must not fetch payloads");
        Ok(health)
    }
    pub(crate) fn ensure_alive(&self) -> Result<()> {
        ensure!(self.started.elapsed() < MAX_LIFETIME, "owner relay fixed suite deadline exceeded");
        ensure!(self.assigned && self.process.as_ref().is_some_and(|p|
            unsafe { WaitForSingleObject(p.raw(), 0) } == WAIT_TIMEOUT), "owner relay exited or liveness unavailable");
        ensure!(self.job.as_ref().context("owner relay Job absent")?.active_processes()? == 1,
            "owner relay Job must contain exactly its fixed root");
        Ok(())
    }
    pub(crate) fn cleanup(&mut self) -> serde_json::Value {
        if let Some(receipt) = &self.cleanup_receipt { return receipt.clone(); }
        // Stop the independent 300-second watchdog before dropping our Job handle.
        if let Some(cancel) = self.cancel_watchdog.take() { let _ = cancel.send(()); }
        let watchdog = self.watchdog.take().map(|thread| match thread.join() {
            Ok(Ok(expired)) => serde_json::json!({"deadlineExpired":expired,"error":null}),
            Ok(Err(e)) => serde_json::json!({"deadlineExpired":true,"error":format!("{e:#}")}),
            Err(_) => serde_json::json!({"deadlineExpired":null,"error":"relay watchdog panicked"}),
        });
        let mut errors = Vec::<String>::new();
        if let Some(job) = &self.job { if let Err(e) = job.terminate() { errors.push(format!("terminate relay Job: {e:#}")); } }
        if !self.assigned { if let Some(process) = &self.process {
            if unsafe { TerminateProcess(process.raw(), 1) } == 0 {
                errors.push(format!("terminate suspended unassigned relay: {}", std::io::Error::last_os_error()));
            }
        }}
        let root_signaled = self.process.as_ref().map_or(true, |p|
            unsafe { WaitForSingleObject(p.raw(), 5000) } == WAIT_OBJECT_0);
        if !root_signaled { errors.push("retained relay root handle not signaled".into()); }
        let deadline = Instant::now() + Duration::from_secs(5);
        let active = loop {
            match self.job.as_ref().map(|job|job.active_processes()).transpose() {
                Ok(Some(0)) | Ok(None) => break Some(0),
                Ok(Some(n)) if Instant::now() >= deadline => break Some(n),
                Ok(Some(_)) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => {errors.push(format!("relay Job accounting unavailable: {e:#}")); break None;},
            }
        };
        let verified = root_signaled && active == Some(0) && errors.is_empty();
        let mut receipt = serde_json::json!({"schemaVersion":1,"scope":"LAB_PYTHON_ONLINE_PDF_ACCEPTANCE",
            "pid":self.pid,"ownerRelay":true,"assignedBeforeResume":self.assigned,
            "killOnJobClose":self.job.is_some(),"retainedRootHandleSignaled":root_signaled,
            "activeProcesses":active,"cleanupVerified":verified,"startupError":self.startup_error,
            "watchdog":watchdog,"elapsedMs":self.started.elapsed().as_millis(),"errors":errors,
            "nativeValidated":false,"durableReceiptVerified":true});
        let durable = (|| -> Result<()> {
            let bytes = serde_json::to_vec_pretty(&receipt)?;
            fresh_write(&path(CLEANUP), &bytes)?;
            ensure!(bounded_artifact(CLEANUP, 65536, false)?.0 == bytes, "relay cleanup durable readback mismatch");
            Ok(())
        })();
        if let Err(e) = durable {
            receipt["cleanupVerified"] = serde_json::json!(false);
            receipt["durableReceiptVerified"] = serde_json::json!(false);
            receipt["receiptError"] = serde_json::json!(format!("{e:#}"));
        }
        self.cleanup_receipt = Some(receipt.clone()); receipt
    }
}
impl Drop for Relay { fn drop(&mut self) { let _ = self.cleanup(); } }

// Strict UTC parser keeps wall-clock evidence independent of Python's report.
// Accepted forms are ISO 8601 UTC with Z or +00:00 and 0..9 fractional digits.
fn utc_ms(value: &str) -> Result<u64> {
    let utc = value.strip_suffix('Z').or_else(|| value.strip_suffix("+00:00"))
        .context("timestamp must explicitly use UTC")?;
    ensure!(utc.len() >= 19 && utc.as_bytes()[4] == b'-' && utc.as_bytes()[7] == b'-'
        && utc.as_bytes()[10] == b'T' && utc.as_bytes()[13] == b':' && utc.as_bytes()[16] == b':',
        "UTC timestamp shape invalid");
    let number = |a:usize,b:usize| -> Result<i64> {
        let bytes = utc.as_bytes().get(a..b).context("UTC field bounds")?;
        ensure!(bytes.iter().all(u8::is_ascii_digit), "UTC field is not decimal");
        Ok(std::str::from_utf8(bytes)?.parse()?)
    };
    let (year,month,day,hour,minute,second) = (number(0,4)?,number(5,7)?,number(8,10)?,
        number(11,13)?,number(14,16)?,number(17,19)?);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [31, if leap {29} else {28},31,30,31,30,31,31,30,31,30,31];
    ensure!((1970..=9999).contains(&year) && (1..=12).contains(&month) && day >= 1
        && day <= days[(month - 1) as usize] && hour < 24 && minute < 60 && second < 60,
        "UTC date/time bounds invalid");
    let fraction = if utc.len() == 19 { 0 } else {
        ensure!(utc.as_bytes()[19] == b'.' && (21..=29).contains(&utc.len()), "UTC fraction shape invalid");
        let digits = &utc.as_bytes()[20..];
        ensure!(digits.iter().all(u8::is_ascii_digit), "UTC fraction is not decimal");
        let mut milliseconds = 0;
        for index in 0..3 { milliseconds = milliseconds * 10 + digits.get(index).map_or(0, |v|i64::from(*v - b'0')); }
        milliseconds
    };
    // Civil date to days since 1970-01-01, Gregorian calendar.
    let y = year - i64::from(month <= 2); let era = y.div_euclid(400); let yoe = y - era * 400;
    let mp = month + if month > 2 {-3} else {9}; let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let epoch_days = era * 146097 + doe - 719468;
    Ok(((((epoch_days * 24 + hour) * 60 + minute) * 60 + second) * 1000 + fraction).try_into()?)
}

impl Relay {
    pub(crate) fn evidence(&self, frames: &[serde_json::Value]) -> serde_json::Value {
        let result = self.read_events(frames);
        match result {
            Ok(events) => serde_json::json!({"onlineFetchVerified":true,"ready":self.ready,"health":self.health,
                "events":events,"boundedOwnerObservation":true,"allLocalClientsAuthenticated":false,
                "offlineInstallClaim":false,"error":null}),
            Err(error) => serde_json::json!({"onlineFetchVerified":false,"ready":self.ready,"health":self.health,
                "allLocalClientsAuthenticated":false,"offlineInstallClaim":false,"error":format!("{error:#}")}),
        }
    }
    fn read_events(&self, frames: &[serde_json::Value]) -> Result<Vec<serde_json::Value>> {
        self.ensure_alive()?;
        let installs = frames.iter().filter(|r| r["frame"]["case"] == "online-install").collect::<Vec<_>>();
        ensure!(installs.len() == 1, "one actual install frame required");
        let frame: Frame = serde_json::from_value(installs[0]["frame"].clone())?;
        let script = lab::parse_script(&frame)?;
        let install = script.online_install.context("verified install script evidence missing")?;
        let window = frame.execution_window.context("native install execution window missing")?;
        ensure!(window.started_unix_ms >= self.started_unix_ms
            && install.started_unix_ms >= window.started_unix_ms
            && install.finished_unix_ms <= window.finished_unix_ms
            && window.finished_unix_ms <= unix_ms()?, "install window outside owner relay lifecycle");
        // Relay owns this append-only log. Its handle may remain open, but stable
        // size/last-write checks and the final complete-newline requirement apply.
        let (bytes, _) = bounded_artifact(EVENTS, 128 * 1024, true)?;
        validate_relay_events(&bytes, &self.ready, self.started_unix_ms, unix_ms()?,
            install.started_unix_ms, install.finished_unix_ms)
    }
}
fn validate_relay_events(bytes:&[u8], ready:&serde_json::Value, launch_ms:u64, now_ms:u64,
    install_started:u64, install_finished:u64)->Result<Vec<serde_json::Value>> {
        ensure!(bytes.ends_with(b"\n"), "partial relay event log");
        let text = std::str::from_utf8(&bytes)?;
        let mut events = Vec::new();
        let mut previous_mono = 0u64;
        let mut previous_ms = launch_ms;
        let mut requests = BTreeMap::<u64, (String, usize)>::new();
        let mut packages = std::collections::BTreeSet::<String>::new();
        let stages = ["package_request","upstream_fetch_started","upstream_hash_verified","wheel_served"];
        let mut health_count = 0;
        let mut ready_count = 0;
        for line in text.lines() {
            ensure!(!line.is_empty() && line.len() <= 2048 && events.len() < 64, "relay event bounds exceeded");
            let event: serde_json::Value = serde_json::from_str(line)?;
            let object = event.as_object().context("relay event must be an object")?;
            let name = event["event"].as_str().context("relay event name missing")?;
            let ms = event["unixMs"].as_u64().context("relay event unixMs missing")?;
            let mono = event["monotonicNs"].as_u64().context("relay event monotonicNs missing")?;
            ensure!(event["schemaVersion"] == 1 && utc_ms(event["utc"].as_str().context("relay UTC absent")?)? == ms
                && mono > previous_mono && ms >= previous_ms && ms <= now_ms, "relay event clock/order mismatch");
            previous_mono = mono; previous_ms = ms;
            let base = ["schemaVersion","event","utc","unixMs","monotonicNs"];
            if name == "relay_ready" {
                let extras = ["pid","host","port","packageFetchCount","startedUtc","startedUnixMs"];
                ensure!(events.is_empty() && object.len() == 11
                    && base.iter().chain(extras.iter()).all(|key|object.contains_key(*key))
                    && ready.as_object().is_some_and(|receipt|receipt.iter().all(|(key,value)|event[key]==*value))
                    && ready["startedUnixMs"].as_u64().is_some_and(|started|started <= ms)
                    && ms <= install_started, "relay ready event differs from authenticated owner receipt");
                ready_count += 1;
            } else if name == "health" {
                ensure!(object.len() == 6 && base.iter().all(|key|object.contains_key(*key))
                    && ready_count == 1 && event["packageFetchCount"] == 0 && requests.is_empty()
                    && ms <= install_started, "owner health must precede and perform no package fetch");
                health_count += 1;
                ensure!(health_count == 1, "unexpected additional health callers");
            } else {
                let stage = stages.iter().position(|candidate|*candidate == name)
                    .context("relay rejected, failed, or unexpected event prevents online evidence")?;
                ensure!(ready_count == 1 && health_count == 1 && ms >= install_started && ms <= install_finished,
                    "payload event outside actual sandbox install interval");
                let request_id = event["requestId"].as_u64().context("relay requestId missing")?;
                let package = event["package"].as_str().context("relay package absent")?;
                let pin = lab::PACKAGE_PINS.iter().find(|p|p.0 == package).context("unapproved relay package")?;
                ensure!(event["filename"] == pin.2 && (1..=3).contains(&request_id), "relay wheel identity mismatch");
                let extras: &[&str] = match stage { 0=>&[],1=>&["upstreamHost"],_=>&["bytes","sha256"] };
                ensure!(object.len() == 8 + extras.len() && base.iter().chain(["requestId","package","filename"].iter())
                    .chain(extras.iter()).all(|key|object.contains_key(*key)), "relay event schema mismatch");
                if stage == 0 {
                    ensure!(!requests.contains_key(&request_id) && packages.insert(package.to_owned()), "duplicate relay wheel/request");
                    requests.insert(request_id,(package.to_owned(),1));
                } else {
                    let request = requests.get_mut(&request_id).context("upstream fetch without sandbox package request")?;
                    ensure!(request.0 == package && request.1 == stage, "relay package lifecycle out of order");
                    request.1 += 1;
                }
                if stage == 1 { ensure!(event["upstreamHost"] == "files.pythonhosted.org", "unapproved upstream host"); }
                if stage >= 2 {
                    ensure!(event["bytes"] == pin.4 && event["sha256"] == pin.3, "actual fetched/served bytes do not match pins");
                }
            }
            events.push(event);
        }
        ensure!(ready_count == 1 && health_count == 1 && requests.len() == 3 && packages.len() == 3
            && requests.values().all(|(_,stage)|*stage == 4) && events.len() == 14,
            "three complete live fetch/hash/serve lifecycles required");
        Ok(events)
}

fn canonical_package(name: &str) -> String { name.to_ascii_lowercase().replace(['_', '.'], "-") }
fn installation_report() -> Result<serde_json::Value> {
    let (bytes, identity) = bounded_artifact(r"work\pdf-install-report.json", 256 * 1024, false)?;
    let report: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(report["version"] == "1", "pip report format mismatch");
    let entries = report["install"].as_array().context("pip install entries absent")?;
    ensure!(entries.len() == 3, "exactly three pip report entries required");
    let mut names = std::collections::BTreeSet::new();
    let mut observed = Vec::new();
    for entry in entries {
        let name = canonical_package(entry["metadata"]["name"].as_str().context("pip metadata name absent")?);
        let pin = lab::PACKAGE_PINS.iter().find(|pin|pin.0 == name).context("unexpected pip distribution")?;
        ensure!(names.insert(name.clone()), "duplicate pip distribution");
        ensure!(entry["metadata"]["version"] == pin.1 && entry["requested"] == true && entry["is_direct"] == true
            && entry["download_info"]["url"] == format!("http://127.0.0.1:43873/wheels/{}",pin.2)
            && entry["download_info"]["archive_info"]["hashes"]["sha256"] == pin.3,
            "pip report version/direct URL/hash mismatch");
        observed.push(serde_json::json!({"name":pin.0,"version":pin.1,"filename":pin.2,"sha256":pin.3}));
    }
    Ok(serde_json::json!({"identity":identity,"reportSha256":hash(&bytes)?,"packages":observed,
        "installReportVerified":true}))
}

pub(crate) fn artifact_evidence(frame: &Frame) -> serde_json::Value {
    let result = (|| -> Result<serde_json::Value> {
        let script = lab::parse_script(frame)?;
        if frame.case == Case::OnlineInstall {
            ensure!(script.online_install.is_some(), "online install script evidence missing");
            let mut report = installation_report()?; report["artifactsVerified"] = serde_json::json!(true); Ok(report)
        } else if frame.case == Case::OnlinePdf {
            let pdf = script.online_pdf.context("online PDF script evidence missing")?;
            let (bytes, identity) = bounded_artifact(r"work\sandbox-test.pdf", ARTIFACT_LIMIT, false)?;
            let digest = hash(&bytes)?;
            ensure!(bytes.len() as u64 == pdf.byte_count && digest == pdf.sha256,
                "PDF handle bytes disagree with sandbox artifact receipt");
            validate_pdf(&bytes)?;
            let receipt = serde_json::json!({"schemaVersion":1,"pdfValidated":true,"artifactsVerified":true,
                "path":r"C:\PiSandboxLab\work\sandbox-test.pdf","identity":identity,"byteCount":bytes.len(),
                "pdfSha256":digest,"pageCount":1,"expectedText":"Sandbox PDF test","structuralOnly":true,
                "rendered":false,"nativeValidated":false});
            let encoded = serde_json::to_vec_pretty(&receipt)?;
            fresh_write(&path(PDF_VALIDATION), &encoded)?;
            ensure!(bounded_artifact(PDF_VALIDATION, 65536, false)?.0 == encoded,
                "PDF validation receipt durable readback mismatch");
            Ok(receipt)
        } else { Err(anyhow::anyhow!("artifact evidence only applies to fixed online cases")) }
    })();
    match result {
        Ok(value) => value,
        Err(error) => {
            let failure = serde_json::json!({"schemaVersion":1,"artifactsVerified":false,"pdfValidated":false,
                "structuralOnly":true,"rendered":false,"error":format!("{error:#}")});
            // A failing PDF case gets a durable non-success receipt too. Never
            // overwrite a previous success or follow an existing target.
            if frame.case == Case::OnlinePdf {
                if let Ok(bytes) = serde_json::to_vec_pretty(&failure) { let _ = fresh_write(&path(PDF_VALIDATION), &bytes); }
            }
            failure
        }
    }
}

// Small fail-closed parser for this one fixed ReportLab document shape. It does
// not render PDFs, execute actions, load fonts, decompress streams, or accept a
// general PDF document. References are checked against the actual xref offsets.
#[derive(Debug)]
enum PdfValue { Name(String), Number(String), Reference(usize), Array(Vec<PdfValue>),
    Dictionary(BTreeMap<String,PdfValue>), Literal(String), Hex, Keyword }
impl PdfValue {
    fn name(&self) -> Option<&str> { if let Self::Name(value)=self {Some(value)} else {None} }
    fn literal(&self) -> Option<&str> { if let Self::Literal(value)=self {Some(value)} else {None} }
    fn reference(&self) -> Option<usize> { if let Self::Reference(value)=self {Some(*value)} else {None} }
    fn integer(&self) -> Option<usize> { if let Self::Number(value)=self {value.parse().ok()} else {None} }
    fn number(&self) -> Option<f64> { if let Self::Number(value)=self {value.parse().ok()} else {None} }
    fn dictionary(&self) -> Option<&BTreeMap<String,PdfValue>> {
        if let Self::Dictionary(value)=self {Some(value)} else {None}
    }
    fn array(&self) -> Option<&[PdfValue]> { if let Self::Array(value)=self {Some(value)} else {None} }
}
struct PdfParser<'a> { bytes:&'a [u8], at:usize, values:usize }
impl<'a> PdfParser<'a> {
    fn new(bytes:&'a [u8])->Self {Self{bytes,at:0,values:0}}
    fn space(&mut self) {
        loop {
            while self.bytes.get(self.at).is_some_and(|b|b.is_ascii_whitespace()) {self.at+=1;}
            if self.bytes.get(self.at)==Some(&b'%') {
                while self.bytes.get(self.at).is_some_and(|b|*b!=b'\n' && *b!=b'\r') {self.at+=1;}
            } else {break;}
        }
    }
    fn take(&mut self, expected:&[u8])->Result<()> {
        ensure!(self.bytes.get(self.at..self.at+expected.len())==Some(expected), "fixed PDF token mismatch");
        self.at+=expected.len();Ok(())
    }
    fn word(&mut self)->Result<String> {
        self.space();let begin=self.at;
        while self.bytes.get(self.at).is_some_and(|b|!b.is_ascii_whitespace()
            && !b"()<>[]{}/%".contains(b)) {self.at+=1;}
        ensure!(self.at>begin && self.at-begin<=128, "fixed PDF token bounds invalid");
        Ok(std::str::from_utf8(&self.bytes[begin..self.at])?.to_owned())
    }
    fn value(&mut self, depth:usize)->Result<PdfValue> {
        self.space();self.values+=1;
        ensure!(depth<=16 && self.values<=2048, "fixed PDF nesting/token bounds exceeded");
        match self.bytes.get(self.at).copied().context("PDF value absent")? {
            b'/' => {self.at+=1;Ok(PdfValue::Name(self.word()?))},
            b'[' => {
                self.at+=1;let mut values=Vec::new();
                loop {self.space();if self.bytes.get(self.at)==Some(&b']'){self.at+=1;break;}
                    ensure!(values.len()<64,"fixed PDF array bound exceeded");values.push(self.value(depth+1)?);}
                Ok(PdfValue::Array(values))
            },
            b'<' if self.bytes.get(self.at+1)==Some(&b'<') => {
                self.at+=2;let mut dictionary=BTreeMap::new();
                loop {
                    self.space();if self.bytes.get(self.at..self.at+2)==Some(b">>"){self.at+=2;break;}
                    self.take(b"/")?;let key=self.word()?;
                    ensure!(dictionary.len()<64 && !dictionary.contains_key(&key), "PDF duplicate/oversized dictionary");
                    dictionary.insert(key,self.value(depth+1)?);
                }
                Ok(PdfValue::Dictionary(dictionary))
            },
            b'<' => {
                self.at+=1;let begin=self.at;
                while self.bytes.get(self.at).is_some_and(|b|b.is_ascii_hexdigit() || b.is_ascii_whitespace()) {self.at+=1;}
                ensure!(self.at-begin<=256,"fixed PDF hex bounds");self.take(b">")?;Ok(PdfValue::Hex)
            },
            b'(' => {
                self.at+=1;let begin=self.at;let mut nesting=1;
                while nesting>0 {
                    let value=*self.bytes.get(self.at).context("unterminated PDF literal")?;self.at+=1;
                    match value {
                        b'\\' => {ensure!(self.at<self.bytes.len(),"PDF escape bounds");self.at+=1;},
                        b'(' => {nesting+=1;ensure!(nesting<=8,"PDF literal nesting bounds");},
                        b')' => nesting-=1,_=>{},
                    }
                    ensure!(self.at-begin<=4096,"PDF literal size bounds");
                }
                Ok(PdfValue::Literal(std::str::from_utf8(&self.bytes[begin..self.at-1])?.to_owned()))
            },
            _ => {
                let word=self.word()?;
                if word=="true" || word=="false" || word=="null" {return Ok(PdfValue::Keyword);}
                ensure!(word.parse::<f64>().is_ok_and(f64::is_finite), "unsupported fixed PDF value");
                let saved=self.at;
                if let Ok(object)=word.parse::<usize>() {
                    let reference=(||->Result<bool>{Ok(self.word()?=="0" && self.word()?=="R")})();
                    if matches!(reference,Ok(true)) {return Ok(PdfValue::Reference(object));}
                }
                self.at=saved;Ok(PdfValue::Number(word))
            },
        }
    }
}
struct PdfObject { dictionary:BTreeMap<String,PdfValue>, stream:Option<Vec<u8>> }
fn pdf_reference(dictionary:&BTreeMap<String,PdfValue>,key:&str)->Result<usize> {
    dictionary.get(key).and_then(PdfValue::reference).context("required fixed PDF reference absent")
}
fn validate_pdf(bytes:&[u8])->Result<()> {
    ensure!((512..=ARTIFACT_LIMIT as usize).contains(&bytes.len()) && bytes.starts_with(b"%PDF-1.4\n"),
        "fixed PDF header/size mismatch");
    let start=bytes.windows(10).rposition(|p|p==b"startxref\n").context("PDF startxref absent")?;
    let suffix=std::str::from_utf8(&bytes[start..])?.split_whitespace().collect::<Vec<_>>();
    ensure!(suffix.len()==3 && suffix[0]=="startxref" && suffix[2]=="%%EOF", "PDF final trailer bounds invalid");
    let xref=suffix[1].parse::<usize>()?;
    ensure!(xref>16 && xref<start && bytes.get(xref..xref+5)==Some(b"xref\n"), "PDF xref does not point to actual table");
    let mut parser=PdfParser::new(&bytes[xref..start]);
    ensure!(parser.word()?=="xref" && parser.word()?=="0", "fixed PDF requires one complete xref subsection");
    let count=parser.word()?.parse::<usize>()?;
    ensure!((8..=32).contains(&count),"fixed one-page Helvetica PDF object count outside bounds");
    ensure!(parser.word()?=="0000000000" && parser.word()?=="65535" && parser.word()?=="f", "PDF free xref sentinel invalid");
    let mut offsets=Vec::new();
    for _ in 1..count {
        let offset=parser.word()?;ensure!(offset.len()==10 && offset.bytes().all(|b|b.is_ascii_digit()), "xref offset shape");
        let offset=offset.parse::<usize>()?;
        ensure!(offset>16 && offset<xref && offsets.last().map_or(true,|previous|offset>*previous)
            && parser.word()?=="00000" && parser.word()?=="n", "PDF xref offset/generation/order invalid");
        offsets.push(offset);
    }
    ensure!(parser.word()?=="trailer","PDF trailer absent");
    let PdfValue::Dictionary(trailer)=parser.value(0)? else {return Err(anyhow::anyhow!("PDF trailer is not dictionary"));};
    parser.space();ensure!(parser.at==parser.bytes.len(),"PDF extra xref/trailer bytes");
    ensure!(trailer.get("Size").and_then(PdfValue::integer)==Some(count) && !trailer.contains_key("Prev")
        && !trailer.contains_key("XRefStm"),"PDF incremental/compressed xref forbidden");
    let root=pdf_reference(&trailer,"Root")?;
    let mut objects=BTreeMap::<usize,PdfObject>::new();
    for index in 1..count {
        let end=if index+1==count{xref}else{offsets[index]};
        let mut object=PdfParser::new(&bytes[offsets[index-1]..end]);
        ensure!(object.word()?.parse::<usize>()?==index && object.word()?=="0" && object.word()?=="obj",
            "PDF xref does not identify expected object");
        let PdfValue::Dictionary(dictionary)=object.value(0)? else {return Err(anyhow::anyhow!("fixed PDF object not dictionary"));};
        object.space();let mut stream=None;
        if object.bytes.get(object.at..object.at+6)==Some(b"stream") {
            ensure!(dictionary.len()==1 && !dictionary.contains_key("Filter"),"fixed PDF stream must be uncompressed");
            let length=dictionary.get("Length").and_then(PdfValue::integer).context("direct PDF stream length absent")?;
            ensure!(length<=4096,"fixed PDF stream too large");object.take(b"stream\n")?;
            let end=object.at.checked_add(length).context("PDF stream length overflow")?;
            stream=Some(object.bytes.get(object.at..end).context("PDF stream outside object bounds")?.to_vec());
            object.at=end;object.space();object.take(b"endstream")?;object.space();
        }
        object.take(b"endobj")?;object.space();ensure!(object.at==object.bytes.len(),"unexpected PDF object suffix");
        objects.insert(index,PdfObject{dictionary,stream});
    }
    let object=|index:usize|->Result<&PdfObject>{objects.get(&index).context("PDF reference outside xref table")};
    let typed=|kind:&str|->Vec<usize>{objects.iter().filter(|(_,o)|o.dictionary.get("Type").and_then(PdfValue::name)==Some(kind))
        .map(|(index,_)|*index).collect()};
    let pages=typed("Page");let trees=typed("Pages");let catalogs=typed("Catalog");let fonts=typed("Font");
    ensure!(pages.len()==1 && trees.len()==1 && catalogs==[root] && fonts.len()==1,
        "exact one page, page tree, catalog and font required");
    let metadata=&object(pdf_reference(&trailer,"Info")?)?.dictionary;
    for (key,expected) in [("Title","Sandbox PDF test"),("Author","Pi sandbox"),("Creator","Pi sandbox PDF acceptance")] {
        ensure!(metadata.get(key).and_then(PdfValue::literal)==Some(expected), "fixed benign PDF metadata mismatch");
    }
    let catalog=&object(root)?.dictionary;let tree_index=pdf_reference(catalog,"Pages")?;
    ensure!(tree_index==trees[0],"catalog page-tree reference mismatch");
    let tree=&object(tree_index)?.dictionary;
    let kids=tree.get("Kids").and_then(PdfValue::array).context("PDF page-tree Kids absent")?;
    ensure!(tree.get("Count").and_then(PdfValue::integer)==Some(1) && kids.len()==1
        && kids[0].reference()==Some(pages[0]),"PDF page-tree count/child mismatch");
    let page=&object(pages[0])?.dictionary;
    ensure!(pdf_reference(page,"Parent")?==tree_index,"PDF page parent mismatch");
    let media=page.get("MediaBox").and_then(PdfValue::array).context("PDF page MediaBox absent")?;
    ensure!(media.len()==4 && media.iter().zip([0.0,0.0,595.2756,841.8898])
        .all(|(actual,expected)|actual.number().is_some_and(|v|(v-expected).abs()<0.01)),"fixed A4 PDF page bounds mismatch");
    let resources=page.get("Resources").and_then(PdfValue::dictionary).context("PDF page resources absent")?;
    let font_resource=&object(pdf_reference(resources,"Font")?)?.dictionary;
    ensure!(font_resource.len()==1 && pdf_reference(font_resource,"F1")?==fonts[0],"PDF Helvetica font resource mismatch");
    let font=&object(fonts[0])?.dictionary;
    ensure!(font.get("BaseFont").and_then(PdfValue::name)==Some("Helvetica")
        && font.get("Subtype").and_then(PdfValue::name)==Some("Type1")
        && font.get("Name").and_then(PdfValue::name)==Some("F1"),"PDF expected Helvetica font absent");
    ensure!(objects.values().filter(|o|o.stream.is_some()).count()==1,"fixed PDF requires exactly one content stream");
    let content=object(pdf_reference(page,"Contents")?)?.stream.as_ref().context("PDF page content stream absent")?;
    let normalized=std::str::from_utf8(content)?.split_whitespace().collect::<Vec<_>>().join(" ");
    ensure!(normalized==concat!("1 0 0 1 0 0 cm BT /F1 12 Tf 14.4 TL ET ",
        "BT /F1 12 Tf 14.4 TL ET BT 1 0 0 1 72 720 Tm (Sandbox PDF test) Tj T* ET"),
        "PDF fixed uncompressed one-line text operators mismatch");
    // Reject active or external-content constructs even if a malformed producer
    // hides them in an otherwise unused dictionary. Literal metadata is inert.
    for object in objects.values() {
        for key in ["AA","OpenAction","JavaScript","JS","Launch","AcroForm","EmbeddedFiles","Encrypt"] {
            ensure!(!object.dictionary.contains_key(key),"active PDF construct forbidden");
        }
    }
    ensure!(!trailer.contains_key("Encrypt"),"encrypted PDF forbidden");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn success_log() -> (Vec<serde_json::Value>,serde_json::Value,u64) {
        let epoch=utc_ms("2026-10-06T00:00:00.000Z").unwrap();
        let ready=serde_json::json!({"schemaVersion":1,"pid":1234,"host":"127.0.0.1","port":43873,
            "packageFetchCount":0,"startedUtc":"2026-10-06T00:00:00.001Z","startedUnixMs":epoch+1});
        let event=|name:&str,offset:u64|serde_json::json!({"schemaVersion":1,"event":name,
            "utc":format!("2026-10-06T00:00:00.{offset:03}Z"),"unixMs":epoch+offset,"monotonicNs":offset*1_000_000});
        let mut first=event("relay_ready",2);
        for (key,value) in ready.as_object().unwrap() {first[key]=value.clone();}
        let mut health=event("health",3);health["packageFetchCount"]=serde_json::json!(0);
        let mut events=vec![first,health];
        for (index,pin) in lab::PACKAGE_PINS.iter().enumerate() {
            for (stage,name) in ["package_request","upstream_fetch_started","upstream_hash_verified","wheel_served"].iter().enumerate() {
                let mut item=event(name,20+(index*4+stage)as u64);
                item["requestId"]=serde_json::json!(index+1);item["package"]=serde_json::json!(pin.0);
                item["filename"]=serde_json::json!(pin.2);
                if stage==1 {item["upstreamHost"]=serde_json::json!("files.pythonhosted.org");}
                if stage>=2 {item["bytes"]=serde_json::json!(pin.4);item["sha256"]=serde_json::json!(pin.3);}
                events.push(item);
            }
        }
        (events,ready,epoch)
    }
    fn encoded(events:&[serde_json::Value])->Vec<u8> {
        let mut bytes=Vec::new();for event in events {bytes.extend(serde_json::to_vec(event).unwrap());bytes.push(b'\n');}bytes
    }
    #[test]
    fn successful_fourteen_event_live_log() {
        let (events,ready,epoch)=success_log();
        assert_eq!(validate_relay_events(&encoded(&events),&ready,epoch,epoch+200,epoch+10,epoch+100).unwrap().len(),14);
    }
    #[test]
    fn live_log_rejects_missing_duplicate_unexpected_and_out_of_window_events() {
        let (original,ready,epoch)=success_log();
        let rejects=|events:&[serde_json::Value]|assert!(validate_relay_events(&encoded(events),&ready,
            epoch,epoch+200,epoch+10,epoch+100).is_err());
        let mut changed=original.clone();changed.remove(0);rejects(&changed);
        let mut changed=original.clone();changed.remove(5);rejects(&changed);
        let mut changed=original.clone();changed.push(original.last().unwrap().clone());rejects(&changed);
        let mut changed=original.clone();changed[4]["event"]=serde_json::json!("fetch_failed");rejects(&changed);
        let mut changed=original.clone();changed[0]["pid"]=serde_json::json!(9999);rejects(&changed);
        let mut changed=original.clone();changed[4]["sha256"]=serde_json::json!("00");rejects(&changed);
        let mut changed=original.clone();changed[2]["unixMs"]=serde_json::json!(epoch+9);
        changed[2]["utc"]=serde_json::json!("2026-10-06T00:00:00.009Z");rejects(&changed);
        let mut changed=original.clone();changed[6]["package"]=original[2]["package"].clone();
        changed[6]["filename"]=original[2]["filename"].clone();rejects(&changed);
    }
    fn synthetic_pdf()->Vec<u8> { synthetic_pdf_with_extra(false) }
    fn synthetic_pdf_with_extra(extra:bool)->Vec<u8> {
        let content=concat!("1 0 0 1 0 0 cm  BT /F1 12 Tf 14.4 TL ET\n",
            "BT /F1 12 Tf 14.4 TL ET\nBT 1 0 0 1 72 720 Tm (Sandbox PDF test) Tj T* ET\n \n");
        let mut bodies=vec!["<< /F1 2 0 R >>".to_owned(),
            "<< /BaseFont /Helvetica /Encoding /WinAnsiEncoding /Name /F1 /Subtype /Type1 /Type /Font >>".to_owned(),
            "<< /Contents 7 0 R /MediaBox [0 0 595.2756 841.8898] /Parent 6 0 R /Resources << /Font 1 0 R >> /Type /Page >>".to_owned(),
            "<< /Pages 6 0 R /Type /Catalog >>".to_owned(),
            "<< /Title (Sandbox PDF test) /Author (Pi sandbox) /Creator (Pi sandbox PDF acceptance) >>".to_owned(),
            "<< /Count 1 /Kids [3 0 R] /Type /Pages >>".to_owned(),
            format!("<< /Length {} >>\nstream\n{content}endstream",content.len())];
        if extra {bodies.push("<< /Note (extra inert metadata) >>".to_owned());}
        let count=bodies.len()+1;
        let mut pdf=b"%PDF-1.4\n% fixed synthetic parser test\n".to_vec();let mut offsets=Vec::new();
        for (index,body) in bodies.iter().enumerate() {offsets.push(pdf.len());pdf.extend(format!("{} 0 obj\n{body}\nendobj\n",index+1).bytes());}
        let xref=pdf.len();pdf.extend(format!("xref\n0 {count}\n0000000000 65535 f \n").bytes());
        for offset in offsets {pdf.extend(format!("{offset:010} 00000 n \n").bytes());}
        pdf.extend(format!("trailer\n<< /Root 4 0 R /Info 5 0 R /Size {count} >>\nstartxref\n{xref}\n%%EOF\n").bytes());pdf
    }
    #[test]
    fn structural_pdf_requires_actual_xref_page_font_and_plain_text_stream() {
        let pdf=synthetic_pdf();assert!(validate_pdf(&pdf).is_ok());
        assert!(validate_pdf(&synthetic_pdf_with_extra(true)).is_ok());
        for (before,after) in [("/Count 1","/Count 2"),("Sandbox PDF test","Sandbox BAD test"),
            ("/Helvetica","/Courierxx"),("/Parent 6 0 R","/Parent 4 0 R"),("/Root 4 0 R","/Root 3 0 R"),("/Author (Pi sandbox)","/Author (Other user)"),
            ("/Info 5 0 R","/Info 2 0 R")] {
            let changed=String::from_utf8(pdf.clone()).unwrap().replace(before,after);
            assert!(validate_pdf(changed.as_bytes()).is_err(),"accepted mutation: {before}");
        }
        let mut bad_xref=pdf.clone();
        let xref_entry=bad_xref.windows(b"0000000000 65535 f".len()).position(|bytes|bytes==b"0000000000 65535 f").unwrap();
        bad_xref[xref_entry]=b'1';assert!(validate_pdf(&bad_xref).is_err());
        let mut trailing=pdf.clone();trailing.extend(b"unexpected");assert!(validate_pdf(&trailing).is_err());
    }
    #[test]
    fn utc_parser_checks_calendar_and_millisecond_shape() {
        assert_eq!(utc_ms("1970-01-01T00:00:00Z").unwrap(),0);
        assert_eq!(utc_ms("1970-01-01T00:00:01.234567+00:00").unwrap(),1234);
        assert!(utc_ms("2026-02-29T00:00:00Z").is_err());
        assert!(utc_ms("2024-02-29T00:00:00Z").is_ok());
        assert!(utc_ms("2026-10-06T00:00:00").is_err());
    }
}
