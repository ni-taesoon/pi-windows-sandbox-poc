//! Separate fixed laboratory transport. The product helper protocol is unchanged.
use super::*;
use crate::python_isolation::{self as lab, Case, FixedRequest, Frame, Recorded};
fn receive<T: for<'de> Deserialize<'de>>(pipe: &Pipe, deadline: Instant) -> Result<T> {
    let length = u32::from_le_bytes(pipe.read_bytes(4, deadline)?.try_into().unwrap()) as usize;
    ensure!(length <= lab::MAX_FRAME, "Python evidence frame too large");
    Ok(serde_json::from_slice(&pipe.read_bytes(length, deadline)?)?)
}
fn send<T: Serialize>(pipe: &Pipe, value: &T, deadline: Instant) -> Result<()> {
    ensure!(serde_json::to_vec(value)?.len() <= lab::MAX_FRAME, "Python frame bounds exceeded");
    pipe.send(value, deadline)
}
/// Run only the immutable suite in a freshly provisioned disposable offline lab.
/// # Safety
/// Caller must pin and authenticate the entire runtime/script/helper inventory and
/// fixture ancestors, verify offline controls, and persist each frame before ACK.
/// No caller-selected token, executable, arguments, policy paths or network targets.
pub unsafe fn run_fixed_python_acceptance(
    fixed: FixedRequest, record: &mut dyn FnMut(&Frame) -> Result<()>,
) -> Result<()> {
    ensure!(fixed.case() == Case::StrictBoundary, "fixed suite initial request required");
    let store_path = Path::new(r"C:\PiSandboxLab\store");
    let helper_exe = Path::new(r"C:\PiSandboxLab\trusted\pi-windows-sandbox.exe");
    let current = Handle::from_raw(token::get_current_token_for_restriction()?)?;
    let owner = winutil::string_from_sid_bytes(&token::get_user_sid_bytes(current.raw())?).map_err(anyhow::Error::msg)?;
    let account_lease = crate::admission::acquire_account_lease(&owner)?;
    let identity = setup::logon_offline_identity(store_path, &owner)?;
    let pipe = Pipe::create(&owner, identity.sid())?;
    let helper = setup::launch::launch_suspended_helper(store_path, &owner, helper_exe,
        &["internal-fixed-python-isolation-helper".into(), pipe.name.clone(), GetCurrentProcessId().to_string()], None)?;
    let job = Job::new()?;
    job.assign_suspended(&helper.process)?;
    protect_helper_object(helper.process.raw(), &owner)?;
    protect_helper_object(helper.thread.raw(), &owner)?;
    let parent_wait_handle = duplicate_parent_wait_handle(&helper.process)?;
    let mut base = 0;
    win("Python admission/OpenProcessToken", OpenProcessToken(helper.process.raw(), TOKEN_QUERY, &mut base))?;
    let base = Handle::from_raw(base)?;
    let lease = AdmittedLaunch::prepare_under_lease(&base, &helper.account_sid, fixed.into_request(), &account_lease)?;
    let payload = lease.helper_payload(parent_wait_handle);
    ensure!(ResumeThread(helper.thread.raw()) != u32::MAX, "resume Python helper failed");
    let startup = Instant::now() + Duration::from_secs(10);
    pipe.connect(helper.pid, startup)?;
    send(&pipe, &payload, startup)?;
    let mut last = None;
    for case in Case::ALL {
        let deadline = Instant::now() + Duration::from_secs(35);
        let frame: Frame = receive(&pipe, deadline)?;
        ensure!(frame.case == case && frame.account_sid == helper.account_sid
            && frame.capability_sid == payload.capability_sid && frame.private_desktop == payload.private_desktop,
            "Python frame order/identity mismatch");
        // Persist failed loader exits too; never replace strict evidence by pinned success.
        record(&frame)?;
        ensure!(frame.cleanup_verified(), "Python tree cleanup unverified; later cases NOT_ATTEMPTED");
        last = frame.run;
        send(&pipe, &Recorded { case }, deadline)?;
    }
    ensure!(WaitForSingleObject(helper.process.raw(), 5000) == WAIT_OBJECT_0, "Python helper exit unverified");
    job.terminate()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while job.active_processes()? != 0 {
        ensure!(Instant::now() < deadline, "Python outer Job cleanup unverified");
        std::thread::sleep(Duration::from_millis(5));
    }
    lease.finish_after_verified_cleanup(last.context("missing final Python result")?)?;
    Ok(())
}
pub fn fixed_python_isolation_helper_main(name: &str, expected_broker: u32) -> Result<()> {
    ensure!(expected_broker > 0, "missing trusted broker identity");
    let pipe = Pipe::open(name, expected_broker)?;
    let payload: HelperPayload = receive(&pipe, Instant::now() + Duration::from_secs(10))?;
    ensure!(FixedRequest::new(payload.request.clone())?.case() == Case::StrictBoundary, "fixed initial Python request required");
    unsafe {
        let parent = duplicate_received_parent_wait_handle(payload.parent_wait_handle)?;
        let base = Handle::from_raw(token::get_current_token_for_restriction()?)?;
        let actual = token::get_user_sid_bytes(base.raw())?;
        let account_sid = setup::local_offline_account_sid()?;
        ensure!(actual == winutil::sid_bytes_from_string(&account_sid)?, "helper is not dedicated Pi account");
        let cap = token::LocalSid::from_string(&payload.capability_sid)?;
        let strict = Handle::from_raw(token::create_strict_write_token_from(base.raw(), &[cap.as_ptr()])?)?;
        // Exact pinned constructor; never hybridize or relax ACLs to make a canary pass.
        let pinned = Handle::from_raw(token::create_workspace_write_token_with_caps_and_user_from(base.raw(), &[cap.as_ptr()], &[])?)?;
        use windows_sys::Win32::System::Diagnostics::Debug::{GetErrorMode, SetErrorMode, SEM_FAILCRITICALERRORS};
        SetErrorMode(GetErrorMode() | SEM_FAILCRITICALERRORS);
        ensure!(GetErrorMode() & SEM_FAILCRITICALERRORS != 0, "critical error mode failed");
        for case in Case::ALL {
            let fixed = FixedRequest::new(lab::request(case, payload.request.parent_pid, payload.request.policy_hash.clone()))?;
            let mut observer = lab::observer::Observer::new();
            let result = crate::process::run_fixed_python(if case.pinned() { pinned.raw() } else { strict.raw() },
                &payload.private_desktop, &fixed, &parent, &mut observer);
            let frame = Frame { case, account_sid: account_sid.clone(), capability_sid: payload.capability_sid.clone(),
                private_desktop: payload.private_desktop.clone(), launch_error: result.as_ref().err().map(|e| format!("{e:#}")),
                run: result.ok(), native: observer.evidence };
            send(&pipe, &frame, Instant::now() + Duration::from_secs(10))?;
            ensure!(frame.cleanup_verified(), "Python cleanup unverified; suite stopped");
            let ack: Recorded = receive(&pipe, Instant::now() + Duration::from_secs(10))?;
            ensure!(ack.case == case, "Python evidence acknowledgement mismatch");
        }
    }
    Ok(())
}
