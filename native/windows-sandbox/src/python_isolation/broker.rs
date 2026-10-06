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
    #[cfg(feature="lab-python-logon-sid-comparison")]
    prepare_session_grant: &mut dyn FnMut(&lab::VerifiedSessionIdentity) -> Result<()>,
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
    #[cfg(feature="lab-python-logon-sid-comparison")]
    ensure!(lab::observer::restricting_sids(base.raw())?.is_empty(),"session broker requires unrestricted authenticated helper base");
    #[cfg(feature="lab-python-logon-sid-comparison")]
    let actual_logon_sid=winutil::string_from_sid_bytes(&token::get_logon_sid_bytes(base.raw())?).map_err(anyhow::Error::msg)?;
    let lease = AdmittedLaunch::prepare_under_lease(&base, &helper.account_sid, fixed.into_request(), &account_lease)?;
    let payload = lease.helper_payload(parent_wait_handle);
    ensure!(ResumeThread(helper.thread.raw()) != u32::MAX, "resume Python helper failed");
    let startup = Instant::now() + Duration::from_secs(10);
    pipe.connect(helper.pid, startup)?;
    send(&pipe, &payload, startup)?;
    let mut last = None;
    #[cfg(feature="lab-python-logon-sid-comparison")]
    let mut recorded_cases=0usize;
    for case in Case::ALL {
        let deadline = Instant::now() + Duration::from_secs(35);
        let frame: Frame = receive(&pipe, deadline)?;
        ensure!(frame.case == case && frame.account_sid == helper.account_sid
            && frame.capability_sid == payload.capability_sid && frame.private_desktop == payload.private_desktop,
            "Python frame order/identity mismatch");
        #[cfg(feature="lab-python-logon-sid-comparison")]
        if case.session() && frame.run.is_some() {
            let config=frame.session_token.as_ref().context("session token readback missing")?;
            ensure!(config.actual_logon_sid==actual_logon_sid && config.matches_capability(&payload.capability_sid),
                "session token does not match authenticated helper logon");
        }
        // Persist failed loader exits too; never replace strict evidence by pinned success.
        record(&frame)?;
        ensure!(frame.cleanup_verified(), "Python tree cleanup unverified; later cases NOT_ATTEMPTED");
        last = frame.run;
        #[cfg(feature="lab-python-logon-sid-comparison")]
        {
            recorded_cases+=1;
            if case==Case::CandidateChildTimeout {
                ensure!(recorded_cases==10,"session grant requires ten durably recorded controls");
                // Withhold ACK 10 until the owner has applied and persisted this
                // one fixed grant. Earlier sandbox trees are already verified dead.
                prepare_session_grant(&lab::VerifiedSessionIdentity {account_sid:helper.account_sid.clone(),
                    logon_sid:actual_logon_sid.clone(),capability_sid:payload.capability_sid.clone()})?;
            }
        }
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
        #[cfg(feature="lab-python-policy-repair-comparison")]
        let mut candidate: Option<(Handle,lab::CandidateTokenConfiguration)> = None;
        #[cfg(feature="lab-python-policy-repair-comparison")]
        let mut acknowledged_controls=0usize;
        #[cfg(feature="lab-python-logon-sid-comparison")]
        let mut session:Option<(Handle,lab::SessionTokenConfiguration)>=None;
        for case in Case::ALL {
            // This branch is reached only after the existing seven control frames
            // were persisted by the owner and their ordered ACKs received below.
            #[cfg(feature="lab-python-policy-repair-comparison")]
            if case.candidate() && candidate.is_none() {
                ensure!(acknowledged_controls == 7 && case == Case::CandidateBoundary,
                    "candidate requires seven durable control acknowledgements");
                match token::create_lab_policy_repair_token_from(base.raw(),cap.as_ptr()) {
                    Ok((raw,configuration)) => candidate=Some((Handle::from_raw(raw)?,configuration)),
                    Err(error) => {
                        let frame=Frame {case,account_sid:account_sid.clone(),capability_sid:payload.capability_sid.clone(),
                            private_desktop:payload.private_desktop.clone(),run:None,
                            launch_error:Some(format!("candidate token construction failed before launch: {error:#}")),
                            native:lab::NativeEvidence::default(),candidate_token:None,session_token:None};
                        send(&pipe,&frame,Instant::now()+Duration::from_secs(10))?;
                        anyhow::bail!("candidate token unavailable; remaining candidate cases NOT_ATTEMPTED");
                    }
                }
            }
            #[cfg(feature="lab-python-logon-sid-comparison")]
            if case.session() && session.is_none() {
                ensure!(acknowledged_controls==10 && case==Case::SessionBoundary,"session candidate requires ten durable acknowledgements");
                match token::create_lab_logon_session_token_from(base.raw(),cap.as_ptr()) {
                    Ok((raw,config))=>session=Some((Handle::from_raw(raw)?,config)),
                    Err(error)=>{
                        let frame=Frame {case,account_sid:account_sid.clone(),capability_sid:payload.capability_sid.clone(),
                            private_desktop:payload.private_desktop.clone(),run:None,
                            launch_error:Some(format!("session token construction failed before launch: {error:#}")),
                            native:lab::NativeEvidence::default(),candidate_token:None,session_token:None};
                        send(&pipe,&frame,Instant::now()+Duration::from_secs(10))?;
                        anyhow::bail!("session token unavailable; remaining session cases NOT_ATTEMPTED");
                    }
                }
            }
            let fixed = FixedRequest::new(lab::request(case, payload.request.parent_pid, payload.request.policy_hash.clone()))?;
            let mut observer = lab::observer::Observer::new();
            let launch_token=if case.pinned() {pinned.raw()} else {strict.raw()};
            #[cfg(feature="lab-python-policy-repair-comparison")]
            let launch_token=if case.candidate() {candidate.as_ref().context("candidate token missing")?.0.raw()} else {launch_token};
            #[cfg(feature="lab-python-logon-sid-comparison")]
            let launch_token=if case.session(){session.as_ref().context("session token missing")?.0.raw()}else{launch_token};
            let result = crate::process::run_fixed_python(launch_token,
                &payload.private_desktop, &fixed, &parent, &mut observer);
            let frame = Frame { case, account_sid: account_sid.clone(), capability_sid: payload.capability_sid.clone(),
                private_desktop: payload.private_desktop.clone(), launch_error: result.as_ref().err().map(|e| format!("{e:#}")),
                run: result.ok(), native: observer.evidence,
                candidate_token: {
                    #[cfg(feature="lab-python-policy-repair-comparison")]
                    { if case.candidate() {Some(candidate.as_ref().context("candidate configuration missing")?.1.clone())} else {None} }
                    #[cfg(not(feature="lab-python-policy-repair-comparison"))]
                    { None }
                },
                session_token:{
                    #[cfg(feature="lab-python-logon-sid-comparison")]
                    {if case.session(){Some(session.as_ref().context("session configuration missing")?.1.clone())}else{None}}
                    #[cfg(not(feature="lab-python-logon-sid-comparison"))]
                    {None}
                },
            };
            send(&pipe, &frame, Instant::now() + Duration::from_secs(10))?;
            ensure!(frame.cleanup_verified(), "Python cleanup unverified; suite stopped");
            let ack: Recorded = receive(&pipe, Instant::now() + Duration::from_secs(10))?;
            ensure!(ack.case == case, "Python evidence acknowledgement mismatch");
            #[cfg(feature="lab-python-policy-repair-comparison")]
            { acknowledged_controls += 1; }
        }
    }
    Ok(())
}
