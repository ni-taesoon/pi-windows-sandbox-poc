#![cfg(feature = "lab-python-isolation-acceptance")]
use pi_windows_sandbox::{python_isolation::*, protocol::{RunResult,StopReason}};
use base64::Engine;
fn frame(case: Case) -> Frame {
    let s = ScriptEvidence { schema_version:1, mode:case, python:[3,12,10], marker:"PYTHON_ISOLATION_OK".into(),
        outside_read:Some(Probe::Success),outside_write:Some(Probe::PermissionDenied { winerror:5 }),
        input_ok:Some(true),output_ok:Some(true),denied_read:Some(Probe::PermissionDenied { winerror:5 }),
        denied_write:Some(Probe::PermissionDenied { winerror:5 }),tcp4:Some(Probe::PermissionDenied { winerror:10013 }),
        tcp6:Some(Probe::PermissionDenied { winerror:10013 }) };
    let mut f = Frame { case, account_sid:"S-1-5-21-1-2-3-1001".into(),capability_sid:"S-1-5-21-4-5-6-7".into(),
        private_desktop:"Winsta0\\PiSandboxDesktop-0123456789abcdef0123456789abcdef".into(),
        run:Some(RunResult {kind:"result".into(),exit_code:0,stdout_base64:String::new(),stderr_base64:String::new(),
            stop_reason:StopReason::Exited,timed_out:false,truncated:false,terminated:true,cleanup_verified:true}),
        launch_error:None,native:NativeEvidence::default() };
    let mut restrictors = vec![f.capability_sid.clone()];
    if case.pinned() { restrictors.extend([f.account_sid.clone(),"S-1-1-0".into(),"S-1-5-5-1-2".into()]); }
    restrictors.sort();
    f.native.root = Some(IdentityEvidence {pid:10,image:PYTHON.into(),user_sid:f.account_sid.clone(),
        restricting_sids:restrictors,desktop:f.private_desktop.clone(),exact_job_member:true,retained_handle_signaled:true});
    f.native.job_empty = true; f.native.unobserved_handles_signaled = true; set_script(&mut f,&s); f
}
fn set_script(f: &mut Frame,s: &ScriptEvidence) { f.run.as_mut().unwrap().stdout_base64 =
    base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(s).unwrap()); }
#[test] fn exact_requests_only() {
    for case in Case::ALL { assert!(FixedRequest::new(request(case,123,"0".repeat(64))).is_ok()); }
    for mutate in [0,1,2,3,4,5,6,7,8] {
        let mut r = request(Case::PinnedBoundary,123,"0".repeat(64));
        match mutate { 0=>r.argv[0] = "python.exe".into(),1=>r.argv.push("evil.py".into()),2=>r.env.insert("PYTHONPATH".into(),"evil".into()).map(|_|()).unwrap_or(()),
            3=>r.policy.writable_roots.push("C:\\".into()),4=>r.stdin="print(1)".into(),5=>r.timeout_ms+=1,
            6=>r.argv[5]="descendant-hold".into(),7=>r.policy.deny_read.clear(),_=>r.max_output_bytes+=1 }
        assert!(FixedRequest::new(r).is_err());
    }
}
#[test] fn unknown_modes_fields_and_missing_probes_rejected() {
    assert!(serde_json::from_str::<Case>("\"custom\"").is_err());
    let mut f=frame(Case::PinnedBoundary); let mut s=parse_script(&f).unwrap(); s.tcp6=None;set_script(&mut f,&s);
    assert!(parse_script(&f).is_err());
    let mut value=serde_json::to_value(s).unwrap();value["networkEndpoint"]=serde_json::json!("example.com");
    assert!(serde_json::from_value::<ScriptEvidence>(value).is_err());
}
#[test] fn positive_python_is_independent_of_policy_failure() {
    let mut f=frame(Case::PinnedBoundary);let mut s=parse_script(&f).unwrap();s.outside_write=Some(Probe::Success);set_script(&mut f,&s);
    let result=assess(&f,true,true,true);assert!(result.python_success);
    assert_eq!(result.outside_write,Verdict::PolicyBoundaryFail);assert!(!result.full_pass);
    assert_eq!(result.parent_death,Verdict::NotTested);
}
#[test] fn broad_read_is_separate_from_write_restriction() {
    let f=frame(Case::StrictBoundary);let result=assess(&f,true,true,true);
    assert_eq!(result.outside_write,Verdict::ObservedPass);assert_eq!(result.outside_read,Some(Probe::Success));
    assert_eq!(result.broad_read_truth,Verdict::ObservedPass);assert!(!result.full_pass);
    assert_eq!(assess(&f,true,false,true).outside_write,Verdict::Inconclusive);
}
#[test] fn refused_timeout_and_missing_controls_are_inconclusive() {
    for code in [10061,10060,12345] {
        let mut f=frame(Case::PinnedBoundary);let mut s=parse_script(&f).unwrap();s.tcp4=Some(Probe::Inconclusive { winerror:Some(code) });set_script(&mut f,&s);
        assert_eq!(assess(&f,true,true,true).loopback_only,Verdict::Inconclusive);
    }
    let f=frame(Case::PinnedBoundary);assert_eq!(assess(&f,true,true,false).loopback_only,Verdict::Inconclusive);
    assert!(!(Probe::PermissionDenied {winerror:10061}).explicit_denial());
}
#[test] fn explicit_deny_success_is_failure() {
    let mut f=frame(Case::PinnedBoundary);let mut s=parse_script(&f).unwrap();s.denied_read=Some(Probe::Success);set_script(&mut f,&s);
    assert_eq!(assess(&f,true,true,true).explicit_denies,Verdict::PolicyBoundaryFail);
}
#[test] fn native_evidence_cannot_be_replaced_by_script_markers() {
    let mut f=frame(Case::PinnedBoundary);assert!(native_valid(&f));
    f.native.root.as_mut().unwrap().exact_job_member=false;assert!(!native_valid(&f));
    assert_eq!(assess(&f,true,true,true).identity,Verdict::Inconclusive);
    f.native.root.as_mut().unwrap().exact_job_member=true;
    f.native.root.as_mut().unwrap().restricting_sids.clear();assert!(!native_valid(&f));
    let f=frame(Case::PinnedBoundary);assert!(!assess(&f,false,true,true).python_success);
}
#[test] fn exited_root_does_not_prove_descendant_cleanup() {
    let mut f=frame(Case::PinnedChildNormalExit);let mut s=parse_script(&frame(Case::PinnedBoundary)).unwrap();
    s.mode=f.case;s.marker="CHILD_STARTED".into();s.input_ok=None;s.output_ok=None;s.outside_read=None;s.outside_write=None;
    s.denied_read=None;s.denied_write=None;s.tcp4=None;s.tcp6=None;set_script(&mut f,&s);
    assert!(parse_script(&f).is_ok());assert!(!native_valid(&f));
    let mut child=f.native.root.as_ref().unwrap().clone();child.pid=11;child.retained_handle_signaled=false;
    f.native.descendants.push(child);assert!(!native_valid(&f));
    f.native.descendants[0].retained_handle_signaled=true;assert!(native_valid(&f));
    assert_eq!(assess(&f,false,true,true).descendant_cleanup,Verdict::ObservedPass);
}
#[test] fn strict_startup_failure_is_preserved_and_cannot_pass_python() {
    let mut f=frame(Case::StrictBoundary);let r=f.run.as_mut().unwrap();r.exit_code=0xc0000142;r.stdout_base64=String::new();
    assert!(f.cleanup_verified());assert!(parse_script(&f).is_err());assert!(!assess(&f,false,true,true).python_success);
}
#[test] fn default_product_gate_stays_closed() { assert!(!pi_windows_sandbox::NATIVE_VALIDATED); }

#[test] fn continuation_requires_authoritative_cleanup_and_signaled_handles() {
    let mut f=frame(Case::StrictBoundary);assert!(f.cleanup_verified());
    f.native.job_empty=false;assert!(!f.cleanup_verified());f.native.job_empty=true;
    f.native.root.as_mut().unwrap().retained_handle_signaled=false;assert!(!f.cleanup_verified());
    f.native.root.as_mut().unwrap().retained_handle_signaled=true;
    let mut child=f.native.root.as_ref().unwrap().clone();child.pid=11;child.retained_handle_signaled=false;
    f.native.descendants.push(child);assert!(!f.cleanup_verified());f.native.descendants.clear();
    f.native.unobserved_handles_signaled=false;assert!(!f.cleanup_verified());
    f.native.unobserved_handles_signaled=true;f.native.root=None;
    // Fast loader failure can lack complete identity, but cannot contradict cleanup.
    assert!(f.cleanup_verified());assert!(!native_valid(&f));
}
