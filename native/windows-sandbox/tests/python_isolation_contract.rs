#![cfg(feature = "lab-python-isolation-acceptance")]
use pi_windows_sandbox::{python_isolation::*, protocol::{RunResult,StopReason}};
use base64::Engine;
fn frame(case: Case) -> Frame {
    let s = ScriptEvidence {
        #[cfg(feature="lab-python-online-pdf")]
        online_install:None,
        #[cfg(feature="lab-python-online-pdf")]
        online_pdf:None, schema_version:1, mode:case, python:[3,12,10], marker:"PYTHON_ISOLATION_OK".into(),
        outside_read:Some(Probe::Success),outside_write:Some(Probe::PermissionDenied { winerror:Some(5), errno:None, error_type:None }),
        input_ok:Some(true),output_ok:Some(true),denied_read:Some(Probe::PermissionDenied { winerror:Some(5), errno:None, error_type:None }),
        denied_write:Some(Probe::PermissionDenied { winerror:Some(5), errno:None, error_type:None }),tcp4:Some(Probe::PermissionDenied { winerror:Some(10013), errno:None, error_type:None }),
        tcp6:Some(Probe::PermissionDenied { winerror:Some(10013), errno:None, error_type:None }),session_grant_write:None,private_outside_write:None,file_operations:None };
    let mut f = Frame {
        #[cfg(feature="lab-python-online-pdf")]
        execution_window:None, case, account_sid:"S-1-5-21-1-2-3-1001".into(),capability_sid:"S-1-5-21-4-5-6-7".into(),
        private_desktop:"Winsta0\\PiSandboxDesktop-0123456789abcdef0123456789abcdef".into(),
        run:Some(RunResult {kind:"result".into(),exit_code:0,stdout_base64:String::new(),stderr_base64:String::new(),
            stop_reason:StopReason::Exited,timed_out:false,truncated:false,terminated:true,cleanup_verified:true}),
        launch_error:None,native:NativeEvidence::default(),candidate_token:None,session_token:None,codex_token:None };
    let mut restrictors = vec![f.capability_sid.clone()];
    if case.pinned() { restrictors.extend([f.account_sid.clone(),"S-1-1-0".into(),"S-1-5-5-1-2".into()]); }
    restrictors.sort();
    f.native.root = Some(IdentityEvidence {pid:10,image:PYTHON.into(),user_sid:f.account_sid.clone(),
        restricting_sids:restrictors,desktop:DesktopEvidence::Observed {name:f.private_desktop.rsplit('\\').next().unwrap().into()},exact_job_member:true,retained_handle_signaled:true});
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
        let mut f=frame(Case::PinnedBoundary);let mut s=parse_script(&f).unwrap();s.tcp4=Some(Probe::Inconclusive { winerror:Some(code),errno:None,error_type:None });set_script(&mut f,&s);
        assert_eq!(assess(&f,true,true,true).loopback_only,Verdict::Inconclusive);
    }
    let f=frame(Case::PinnedBoundary);assert_eq!(assess(&f,true,true,false).loopback_only,Verdict::Inconclusive);
    assert!(!(Probe::PermissionDenied { winerror:Some(10061), errno:None, error_type:None }).explicit_denial());
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
#[test] fn diagnostics_preserve_root_errors_when_descendant_observation_fails() {
    let mut d=NativeDiagnostics::default();d.expected_root_pid=100;d.expected_root_thread_id=101;
    d.root_error("api=GetThreadDesktop(identity); win32=5".into());
    d.root_error("process identity/liveness unavailable".into());
    d.descendant_error("unexpected process tree expansion".into());
    assert_eq!(d.root_first_error.as_deref(),Some("api=GetThreadDesktop(identity); win32=5"));
    assert_eq!(d.root_last_error.as_deref(),Some("process identity/liveness unavailable"));
    assert_eq!(d.descendant_first_error.as_deref(),Some("unexpected process tree expansion"));
    let serialized=serde_json::to_value(d).unwrap();assert_eq!(serialized["expectedRootPid"],100);
}
#[test] fn diagnostic_snapshots_members_and_strings_are_bounded() {
    let mut d=NativeDiagnostics::default();
    for pid in 0..32 {
        d.snapshot(JobPidSnapshot {assigned:3,returned:3,pids:vec![pid,pid+100,pid+200],query_error:None});
        d.member(JobMemberEvidence {pid,image:Some("x".repeat(2048)),query_error:None});
    }
    d.root_error("x".repeat(4096));
    assert_eq!(d.job_pid_snapshots.len(),8);assert_eq!(d.job_members.len(),8);assert!(d.truncated);
    assert_eq!(d.job_pid_snapshots[0].pids,vec![0,100,200]);
    assert!(d.root_first_error.unwrap().len()<=512);
    assert!(d.job_members.iter().all(|m|m.image.is_none()));
}
#[test] fn errno_only_permission_requires_exact_explicit_evidence() {
    for errno in [1,13] {
        let p=Probe::PermissionDenied {winerror:None,errno:Some(errno),error_type:Some("PermissionError".into())};
        assert!(p.file_denial());assert!(p.socket_denial());
        let mut f=frame(Case::PinnedBoundary);let mut s=parse_script(&f).unwrap();s.denied_read=Some(p);set_script(&mut f,&s);
        assert_eq!(assess(&f,true,true,true).explicit_denies,Verdict::ObservedPass);
    }
    for (winerror,errno,kind) in [(None,None,Some("PermissionError")),(None,Some(13),None),
        (None,Some(13),Some("OSError")),(Some(10061),Some(13),Some("PermissionError")),
        (None,Some(2),Some("FileNotFoundError"))] {
        let p=Probe::PermissionDenied {winerror,errno,error_type:kind.map(str::to_owned)};
        assert!(!p.explicit_denial());
    }
    let old:Probe=serde_json::from_str(r#"{"outcome":"INCONCLUSIVE","winerror":null}"#).unwrap();
    assert!(!old.explicit_denial());
}
#[test] fn dacl_telemetry_is_fixed_bounded_and_read_only() {
    let driver=include_str!("../examples/python_isolation_acceptance/windows.rs");
    let telemetry=driver.split("// This telemetry is read-only").nth(1).unwrap().split("fn pin_file(").next().unwrap();
    for target in ["WORK_ROOT","DENIED_WRITE_DIR","DENIED_READ_DIR","DENIED_READ_FILE","OUTSIDE_WORLD_DIR"] {
        assert!(telemetry.contains(target));
    }
    for forbidden in ["SetSecurityInfo(","SetNamedSecurityInfo","ConvertSidToStringSid","string_from_sid_bytes","to_sddl"] {
        assert!(!telemetry.contains(forbidden));
    }
    assert!(telemetry.contains("AceCount > 64"));assert!(telemetry.contains("FILE_FLAG_OPEN_REPARSE_POINT"));
    assert!(telemetry.contains("trusteeRole"));assert!(telemetry.contains("fileDeleteChild"));
    assert!(driver.contains("fixed_target_dacls(owner,identity.sid(),None,None)"));
    assert!(driver.contains("fixed_target_dacls(owner,&frame.account_sid,Some(&frame.capability_sid),"));
}
#[test] fn job_diagnostics_precede_bounded_cardinality_rejection() {
    let observer=include_str!("../src/python_isolation/observer.rs");
    assert!(observer.find("diagnostics.snapshot(").unwrap()<observer.find("pids.assigned <= 3 && pids.count <= 3").unwrap());
    assert!(observer.contains("PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE"));
    assert!(!observer.contains("PROCESS_ALL_ACCESS"));assert!(!observer.contains("PROCESS_VM_READ"));
    assert!(!observer.contains("descendant_error.take().or_else"));
}
#[test] fn unavailable_desktop_preserves_token_job_identity_without_claiming_desktop() {
    let mut f=frame(Case::PinnedBoundary);
    f.native.root.as_mut().unwrap().desktop=DesktopEvidence::Unavailable {error:"api=GetThreadDesktop(identity); win32=0".into()};
    assert!(native_valid(&f));
    let a=assess(&f,true,true,true);assert_eq!(a.identity,Verdict::ObservedPass);
    assert_eq!(a.desktop,Verdict::Inconclusive);assert!(!a.full_pass);
    let root=serde_json::to_value(f.native.root.as_ref().unwrap()).unwrap();
    assert_eq!(root["desktop"]["status"],"UNAVAILABLE");assert!(root["desktop"]["name"].is_null());
    f.native.root.as_mut().unwrap().desktop=DesktopEvidence::Observed {name:"Default".into()};
    assert_eq!(assess(&f,true,true,true).desktop,Verdict::PolicyBoundaryFail);
}
#[test] fn single_owned_exact_job_system_conhost_is_separate_infrastructure() {
    let mut f=frame(Case::PinnedBoundary);
    let mut host=f.native.root.as_ref().unwrap().clone();host.pid=20;host.image=CONHOST.into();
    host.restricting_sids=vec![]; // Report actual host restrictors; do not invent Python equivalence.
    host.desktop=DesktopEvidence::Unavailable {error:"infrastructure desktop not queried".into()};
    f.native.console_hosts.push(host.clone());assert!(native_valid(&f));assert!(f.cleanup_verified());
    f.native.console_hosts[0].retained_handle_signaled=false;assert!(!f.cleanup_verified());assert!(!native_valid(&f));
    f.native.console_hosts[0]=host.clone();f.native.console_hosts[0].user_sid="S-1-5-18".into();assert!(!native_valid(&f));
    f.native.console_hosts[0]=host.clone();f.native.console_hosts[0].image=r"C:\PiSandboxLab\work\conhost.exe".into();assert!(!native_valid(&f));
    f.native.console_hosts[0]=host.clone();f.native.console_hosts[0].exact_job_member=false;assert!(!native_valid(&f));
    f.native.console_hosts[0]=host.clone();f.native.console_hosts.push(host);assert!(!native_valid(&f));
}
#[test] fn console_host_never_substitutes_for_fixed_python_descendant() {
    let mut f=frame(Case::PinnedChildNormalExit);
    let mut host=f.native.root.as_ref().unwrap().clone();host.pid=20;host.image=CONHOST.into();
    f.native.console_hosts.push(host.clone());assert!(!native_valid(&f));
    f.native.descendants.push(host);assert!(!native_valid(&f));
    let mut child=f.native.root.as_ref().unwrap().clone();child.pid=30;
    f.native.descendants[0]=child;assert!(native_valid(&f));
    f.native.descendants[0].restricting_sids.clear();assert!(!native_valid(&f));
}
#[test] fn observer_allowance_is_exactly_classified_and_assertion_change_is_disclosed() {
    let observer=include_str!("../src/python_isolation/observer.rs");
    assert!(observer.contains("image.eq_ignore_ascii_case(CONHOST)"));
    assert!(observer.contains("self.console_hosts.is_empty()"));
    assert!(observer.contains("unexpected additional Python descendant"));
    assert!(observer.contains("self.unclassified.push((pid,handle))"));
    let driver=include_str!("../examples/python_isolation_acceptance/windows.rs");
    assert!(driver.contains("boundedCoreAcceptanceDefinition"));
    assert!(driver.contains("unavailable desktop observation is excluded"));
    assert!(driver.contains("lab::any_policy_boundary_failure(&assessments)"));
}
#[test] fn desktop_query_clears_stale_error_and_null_never_becomes_observed() {
    let observer=include_str!("../src/python_isolation/observer.rs");
    let query=observer.split("unsafe fn inspect_desktop(tid: u32)").nth(1).unwrap()
        .split("unsafe fn restricting_sids").next().unwrap();
    assert!(query.contains("SetLastError(0);\n    let desktop=GetThreadDesktop(tid);\n    api((desktop != 0) as i32,\"GetThreadDesktop(identity)\")?;"));
    assert!(observer.contains("Err(error) => DesktopEvidence::Unavailable {error:format!(\"{error:#}\")}"));
    let mut f=frame(Case::PinnedBoundary);
    f.native.root.as_mut().unwrap().desktop=DesktopEvidence::Unavailable {error:"api=GetThreadDesktop(identity); win32=0".into()};
    assert_eq!(desktop_verdict(&f),Verdict::Inconclusive);
}
fn candidate_configuration(capability: &str) -> CandidateTokenConfiguration {
    CandidateTokenConfiguration {profile:"CAP_ONLY_UPSTREAM_DEFAULT_DACL_V1".into(),restricting_sids:vec![capability.into()],
        default_dacl_aces:vec![DefaultDaclAce {role:DefaultDaclRole::Logon,mask:0x10000000,flags:0},
            DefaultDaclAce {role:DefaultDaclRole::OwnerRights,mask:0x00020000,flags:0}]}
}
#[test] fn candidate_configuration_accepts_only_one_cap_and_exact_upstream_dacl() {
    let cap="S-1-5-21-1-2-3-4";let mut c=candidate_configuration(cap);assert!(c.matches_capability(cap));
    c.restricting_sids.push("S-1-1-0".into());assert!(!c.matches_capability(cap));
    c=candidate_configuration(cap);c.default_dacl_aces[1].mask=0x10000000;assert!(!c.matches_capability(cap));
    c=candidate_configuration(cap);c.default_dacl_aces[0].flags=3;assert!(!c.matches_capability(cap));
    c=candidate_configuration(cap);c.default_dacl_aces[0].role=DefaultDaclRole::OwnerRights;assert!(!c.matches_capability(cap));
}
#[cfg(all(not(feature="lab-python-policy-repair-comparison"),not(feature="lab-python-codex-policy-acceptance")))]
#[test] fn base_feature_has_no_candidate_cases() {
    assert_eq!(Case::ALL.len(),7);assert!(!Case::ALL.iter().any(|case|case.candidate()));
    assert!(serde_json::from_str::<Case>("\"candidate-boundary\"").is_err());
    assert!(!candidate_acceptance(&[],true,true).bounded_core_acceptance);
}
#[cfg(feature="lab-python-policy-repair-comparison")]
#[test] fn composed_feature_appends_three_fixed_cases_without_reordering_controls() {
    let names=Case::ALL.map(Case::name);
    assert_eq!(&names[..7],&["ordinary-outside","strict-boundary","strict-child-normal-exit","strict-child-timeout",
        "pinned-boundary","pinned-child-normal-exit","pinned-child-timeout"]);
    assert_eq!(&names[7..10],&["candidate-boundary","candidate-child-normal-exit","candidate-child-timeout"]);
    assert!(compiled_feature()=="lab-python-policy-repair-comparison" || compiled_feature()=="lab-python-logon-sid-comparison");
    for case in &Case::ALL[7..10] {
        assert!(case.candidate());assert!(!case.pinned());assert_eq!(case.label(),"candidate");
        assert!(FixedRequest::new(request(*case,123,"0".repeat(64))).is_ok());
    }
}
#[cfg(feature="lab-python-policy-repair-comparison")]
#[test] fn candidate_requires_readback_and_actual_capability_only_child_token() {
    let mut f=frame(Case::CandidateBoundary);assert!(!native_valid(&f));
    f.candidate_token=Some(candidate_configuration(&f.capability_sid));assert!(native_valid(&f));
    f.native.root.as_mut().unwrap().restricting_sids.push("S-1-1-0".into());assert!(!native_valid(&f));
    f.native.root.as_mut().unwrap().restricting_sids.pop();
    f.candidate_token.as_mut().unwrap().default_dacl_aces[0].mask=0;assert!(!native_valid(&f));
}
#[cfg(feature="lab-python-policy-repair-comparison")]
#[test] fn candidate_success_never_overwrites_a_pinned_boundary_failure() {
    let passing=assess(&frame(Case::StrictBoundary),true,true,true);
    let mut assessments=Vec::new();
    let mut failed=passing.clone();failed.outside_write=Verdict::PolicyBoundaryFail;
    assessments.push((Case::PinnedBoundary,failed));
    for case in [Case::CandidateBoundary,Case::CandidateChildNormalExit,Case::CandidateChildTimeout] {
        let mut a=passing.clone();if case.descendant() {a.descendant_cleanup=Verdict::ObservedPass;}
        assessments.push((case,a));
    }
    assert!(candidate_acceptance(&assessments,true,true).bounded_core_acceptance);
    assert!(any_policy_boundary_failure(&assessments));
    assert!(!candidate_acceptance(&assessments,true,false).bounded_core_acceptance);
    assessments.pop();assert!(!candidate_acceptance(&assessments,true,true).bounded_core_acceptance);
}
#[test] fn candidate_constructor_changes_only_new_strict_default_dacl_after_acknowledgements() {
    let token=include_str!("../src/python_isolation/token_candidate.rs");
    assert!(token.contains("create_strict_write_token_from(base,&[capability])"));
    assert!(token.contains("get_logon_sid_bytes(base)"));
    assert!(token.contains("set_default_dacl(derived,logon.as_mut_ptr().cast(),&[])"));
    assert!(token.contains("CloseHandle(derived)"));
    for forbidden in ["create_workspace_write_token", "AdjustTokenPrivileges(", "CreateRestrictedToken(",
        "SetSecurityInfo(","SetNamedSecurityInfo", "Impersonate", "allow_null_device"] {assert!(!token.contains(forbidden));}
    let broker=include_str!("../src/python_isolation/broker.rs");
    assert!(broker.contains("acknowledged_controls == 7 && case == Case::CandidateBoundary"));
    assert!(broker.find("ensure!(ack.case == case").unwrap()<broker.find("acknowledged_controls += 1").unwrap());
    assert!(broker.contains("candidate token construction failed before launch"));
    let manifest=include_str!("../Cargo.toml");
    assert!(manifest.contains("lab-python-policy-repair-comparison = [\"lab-python-isolation-acceptance\"]"));
    assert!(manifest.contains("default = []"));
}
fn session_configuration(capability:&str)->SessionTokenConfiguration{
    SessionTokenConfiguration {profile:"CAP_PLUS_ACTUAL_LOGON_UPSTREAM_DEFAULT_DACL_V1".into(),base_restricting_sid_count:0,
        actual_logon_sid:"S-1-5-5-1-2".into(),restricting_sids:vec![capability.into(),"S-1-5-5-1-2".into()],
        default_dacl_aces:candidate_configuration(capability).default_dacl_aces}
}
#[test] fn session_configuration_is_exactly_capability_plus_actual_logon(){
    let cap="S-1-5-21-1-2-3-4";let mut config=session_configuration(cap);assert!(config.matches_capability(cap));
    config.restricting_sids.push("S-1-1-0".into());assert!(!config.matches_capability(cap));
    config=session_configuration(cap);config.restricting_sids.push("S-1-5-21-8-9-10-1000".into());assert!(!config.matches_capability(cap));
    config=session_configuration(cap);config.base_restricting_sid_count=1;assert!(!config.matches_capability(cap));
    config=session_configuration(cap);config.actual_logon_sid="S-1-1-0".into();assert!(!config.matches_capability(cap));
}
#[cfg(feature="lab-python-logon-sid-comparison")]
#[test] fn session_feature_appends_only_three_cases_after_ten_controls(){
    assert_eq!(Case::ALL.len(),13);
    assert_eq!(Case::ALL[9],Case::CandidateChildTimeout);
    assert_eq!(Case::ALL[10..].iter().map(|case|case.name()).collect::<Vec<_>>(),
        vec!["session-boundary","session-child-normal-exit","session-child-timeout"]);
    assert_eq!(compiled_feature(),"lab-python-logon-sid-comparison");
    for case in &Case::ALL[10..]{assert!(case.session());assert!(!case.candidate());assert!(!case.pinned());
        assert!(FixedRequest::new(request(*case,123,"0".repeat(64))).is_ok());}
    assert_eq!(fixed_policy().writable_roots,vec![WORK]);
    assert!(!fixed_policy().writable_roots.contains(&OUTSIDE_LOGON.into()));
}
#[cfg(feature="lab-python-logon-sid-comparison")]
#[test] fn session_native_readback_and_authorized_exception_are_distinct_from_escape(){
    let mut f=frame(Case::SessionBoundary);assert!(!native_valid(&f));
    f.session_token=Some(session_configuration(&f.capability_sid));
    f.native.root.as_mut().unwrap().restricting_sids=f.session_token.as_ref().unwrap().restricting_sids.clone();
    f.native.root.as_mut().unwrap().restricting_sids.sort();assert!(native_valid(&f));
    let mut script=parse_script(&frame(Case::PinnedBoundary)).unwrap();script.mode=Case::SessionBoundary;
    script.session_grant_write=Some(Probe::Success);set_script(&mut f,&script);
    assert_eq!(session_grant_verdict(&f,true,true),Verdict::AuthorizedSessionGrantObserved);
    assert_eq!(session_grant_verdict(&f,false,true),Verdict::Inconclusive);
    assert_eq!(session_grant_verdict(&f,true,false),Verdict::Inconclusive);
    f.native.root.as_mut().unwrap().restricting_sids.push("S-1-1-0".into());assert!(!native_valid(&f));
}
#[cfg(feature="lab-python-logon-sid-comparison")]
#[test] fn session_profile_requires_exception_and_restoration_without_erasing_controls(){
    let mut a=assess(&frame(Case::StrictBoundary),true,true,true);
    a.session_grant=Verdict::AuthorizedSessionGrantObserved;
    let mut values=vec![(Case::SessionBoundary,a.clone())];
    a.descendant_cleanup=Verdict::ObservedPass;
    values.push((Case::SessionChildNormalExit,a.clone()));values.push((Case::SessionChildTimeout,a.clone()));
    assert!(session_profile_acceptance(&values,true,true,true));
    assert!(!session_profile_acceptance(&values,true,true,false));
    assert!(!any_policy_boundary_failure(&values));assert!(!a.full_pass);
    let mut pinned=a;pinned.outside_write=Verdict::PolicyBoundaryFail;values.insert(0,(Case::PinnedBoundary,pinned));
    assert!(session_profile_acceptance(&values,true,true,true));assert!(any_policy_boundary_failure(&values));
}
#[test] fn session_constructor_uses_original_unrestricted_base_and_no_world_or_user(){
    let constructor=include_str!("../src/python_isolation/token_candidate.rs").split("pub(crate) unsafe fn create_lab_logon_session_token_from").nth(1).unwrap();
    assert!(constructor.find("base_sids.is_empty()").unwrap()<constructor.find("create_token_with_caps_impl(").unwrap());
    assert!(constructor.contains("create_token_with_caps_impl(base,&[capability],&[logon_ptr],false)"));
    assert!(constructor.contains("get_logon_sid_bytes(base)"));
    assert!(constructor.contains("set_default_dacl(derived,logon_ptr,&[])"));
    assert!(!constructor.contains("get_user_sid_bytes"));assert!(!constructor.contains("world_sid"));
    let broker=include_str!("../src/python_isolation/broker.rs");
    assert!(broker.contains("recorded_cases==10"));assert!(broker.contains("acknowledged_controls==10 && case==Case::SessionBoundary"));
    assert!(broker.find("record(&frame)?").unwrap()<broker.find("prepare_session_grant(&lab::VerifiedSessionIdentity").unwrap());
    assert!(broker.find("prepare_session_grant(&lab::VerifiedSessionIdentity").unwrap()<broker.find("send(&pipe, &Recorded").unwrap());
    assert!(broker.contains("config.actual_logon_sid==actual_logon_sid"));
}
#[test] fn session_grant_is_one_fixed_pinned_leaf_and_restoration_has_no_drop_side_effect(){
    let grant=include_str!("../src/python_isolation/session_grant.rs");
    for needed in ["Path::new(OUTSIDE_LOGON)","trusted-leaf-owner","fresh-empty-logon-leaf-required","create_directory_guard",
        "self.original.aces","exact-logon-grant-readback","restore-original-leaf-readback","attempted=true",
        "grants.len()!=1","grants[0].mask!=MODIFY","originalLeafDaclRestored","trusteeRole"]{assert!(grant.contains(needed),"{needed}");}
    assert!(!grant.contains("impl Drop for SessionGrant"));assert!(!grant.contains("SetNamedSecurityInfo"));
    assert!(!grant.contains("remove_file"));assert!(!grant.contains("ConvertSidToStringSid"));
    assert_eq!(grant.matches("SetSecurityInfo(self.leaf.as_raw_handle()").count(),2);
    let driver=include_str!("../examples/python_isolation_acceptance/windows.rs");
    assert!(driver.contains("if run.is_ok(){"));assert!(driver.contains("RETAINED_CLEANUP_UNCERTAIN"));
    assert!(driver.contains("grant.restore_after_verified_cleanup()"));
    assert!(driver.contains("\"strictWorkspaceOnlyAcceptance\":false"));
    assert!(driver.contains("AUTHORIZED_SESSION_GRANT_OBSERVED"));
    assert!(driver.contains("child artifact ACL/ownership is not a production revocation guarantee"));
}

#[cfg(feature="lab-python-codex-policy-acceptance")]
fn codex_frame(case:Case)->Frame {
    let mut f=frame(Case::PinnedBoundary);
    let mut s=parse_script(&f).unwrap();f.case=case;s.mode=case;
    if case.codex() {
        f.codex_token=Some(CodexTokenConfiguration {profile:"ORIGINAL_PINNED_CODEX_WRITE_RESTRICTED_V1".into(),
            actual_logon_sid:"S-1-5-5-1-2".into(),restricting_sids:f.native.root.as_ref().unwrap().restricting_sids.clone()});
    }
    if case.boundary() {
        s.outside_write=Some(Probe::Success);
        s.private_outside_write=Some(denied_mutation());
    } else {
        s.input_ok=None;s.output_ok=None;s.denied_read=None;s.denied_write=None;s.tcp4=None;s.tcp6=None;
        if case==Case::OrdinaryOutside {
            f.native.root.as_mut().unwrap().restricting_sids.clear();s.outside_write=Some(Probe::Success);
        } else {s.outside_read=None;s.outside_write=None;}
        if case.file_operations() {s.file_operations=Some(passing_file_operations());}
        if case.descendant() {
            s.marker="CHILD_STARTED".into();let mut child=f.native.root.as_ref().unwrap().clone();child.pid=11;
            f.native.descendants.push(child);
        }
        if case.timeout() {let run=f.run.as_mut().unwrap();run.stop_reason=StopReason::Timeout;run.timed_out=true;}
    }
    set_script(&mut f,&s);f
}
fn denied_mutation()->Probe {Probe::PermissionDenied {winerror:Some(5),errno:Some(13),error_type:Some("PermissionError".into())}}
fn passing_file_operations()->FileOperations {FileOperations {
    allowed_file_rename:Probe::Success,allowed_file_delete:Probe::Success,
    allowed_dir_rename:Probe::Success,allowed_dir_delete:Probe::Success,
    protected_file_read:Probe::Success,protected_file_write:denied_mutation(),
    protected_file_rename:denied_mutation(),protected_file_delete:denied_mutation(),
    protected_dir_write:denied_mutation(),protected_dir_rename:denied_mutation(),protected_dir_delete:denied_mutation(),
}}
#[cfg(all(feature="lab-python-codex-policy-acceptance",not(feature="lab-python-online-pdf")))]
#[test] fn codex_profile_is_exactly_five_cases_and_rejects_old_suite_requests() {
    assert_eq!(Case::ALL.map(Case::name),["ordinary-outside","codex-boundary","codex-file-operations",
        "codex-child-normal-exit","codex-child-timeout"]);
    assert_eq!(Case::initial(),Case::CodexBoundary);
    assert_eq!(compiled_feature(),"lab-python-codex-policy-acceptance");
    assert!(Case::CodexFileOperations.file_operations());assert!(!Case::CodexFileOperations.descendant());
    for case in [Case::StrictBoundary,Case::PinnedBoundary,Case::PinnedChildNormalExit,Case::PinnedChildTimeout] {
        assert!(FixedRequest::new(request(case,123,"0".repeat(64))).is_err());
    }
    let cargo=include_str!("../Cargo.toml");
    assert!(cargo.contains("lab-python-codex-policy-acceptance = [\"lab-python-isolation-acceptance\"]"));
    assert!(include_str!("../src/lib.rs").contains("Codex policy acceptance cannot be combined"));
}
#[cfg(feature="lab-python-codex-policy-acceptance")]
#[test] fn codex_known_world_exception_can_pass_declared_contract_but_not_absolute_gate() {
    let values=Case::ALL.into_iter().filter(|case|!case.online()).map(|case|(case,assess(&codex_frame(case),true,true,true))).collect::<Vec<_>>();
    let boundary=&values[1].1;
    assert_eq!(boundary.outside_write,Verdict::KnownExceptionObserved);
    assert!(!boundary.full_pass);assert!(!pi_windows_sandbox::NATIVE_VALIDATED);
    assert!(codex_policy_acceptance(&values,true,true,true));
    assert!(!codex_policy_acceptance(&values,false,true,true));
    assert!(!codex_policy_acceptance(&values,true,false,true));
    assert!(!codex_policy_acceptance(&values,true,true,false));
    assert!(!codex_policy_acceptance(&values[..4],true,true,true));
    let mut duplicated=values.clone();duplicated[4]=duplicated[3].clone();
    assert!(!codex_policy_acceptance(&duplicated,true,true,true));
    // The old pinned interpretation remains an actual POLICY_BOUNDARY_FAIL.
    let mut old=frame(Case::PinnedBoundary);let mut script=parse_script(&old).unwrap();
    script.outside_write=Some(Probe::Success);set_script(&mut old,&script);
    assert_eq!(assess(&old,true,true,true).outside_write,Verdict::PolicyBoundaryFail);
}
#[cfg(feature="lab-python-codex-policy-acceptance")]
#[test] fn codex_native_identity_requires_actual_logon_and_original_four_restrictors() {
    let mut f=codex_frame(Case::CodexBoundary);assert!(native_valid(&f));
    f.codex_token.as_mut().unwrap().actual_logon_sid="S-1-5-5-9-9".into();assert!(!native_valid(&f));
    f=codex_frame(Case::CodexBoundary);f.native.root.as_mut().unwrap().restricting_sids.pop();assert!(!native_valid(&f));
    f=codex_frame(Case::CodexBoundary);f.codex_token=None;assert!(!native_valid(&f));
}
#[cfg(feature="lab-python-codex-policy-acceptance")]
#[test] fn codex_private_missing_unknown_or_successful_probe_cannot_pass() {
    for probe in [None,Some(Probe::Success),Some(Probe::Inconclusive {winerror:Some(32),errno:Some(13),error_type:Some("PermissionError".into())})] {
        let mut f=codex_frame(Case::CodexBoundary);let mut s=parse_script(&f).unwrap();s.private_outside_write=probe;set_script(&mut f,&s);
        let a=assess(&f,true,true,true);assert_ne!(a.private_outside_write,Verdict::ObservedPass);
    }
    let mut value=serde_json::to_value(passing_file_operations()).unwrap();
    value["protectedDirDelete"]=serde_json::json!({"outcome":"NOT_TRIED"});
    assert!(serde_json::from_value::<FileOperations>(value).is_err());
    let mut f=codex_frame(Case::CodexFileOperations);let mut s=parse_script(&f).unwrap();s.file_operations=None;
    set_script(&mut f,&s);assert!(parse_script(&f).is_err());
    let mut value=serde_json::to_value(passing_file_operations()).unwrap();value.as_object_mut().unwrap().remove("protectedFileRename");
    assert!(serde_json::from_value::<FileOperations>(value).is_err());
}
#[test] fn destructive_probe_needs_access_denial_not_sharing_missing_or_nonempty() {
    assert!(denied_mutation().mutation_denial());
    let errno=Probe::PermissionDenied {winerror:None,errno:Some(13),error_type:Some("PermissionError".into())};
    assert!(errno.mutation_denial());
    for code in [2,3,32,145,10013] {
        let p=Probe::PermissionDenied {winerror:Some(code),errno:Some(13),error_type:Some("PermissionError".into())};
        assert!(!p.mutation_denial());let mut operations=passing_file_operations();operations.protected_dir_delete=p;
        assert_eq!(operations.verdict(),Verdict::Inconclusive);
    }
    let mut operations=passing_file_operations();assert_eq!(operations.verdict(),Verdict::ObservedPass);
    operations.protected_file_rename=Probe::Success;assert_eq!(operations.verdict(),Verdict::PolicyBoundaryFail);
    operations.protected_file_delete=Probe::Inconclusive {winerror:Some(2),errno:Some(2),error_type:Some("FileNotFoundError".into())};
    assert_eq!(operations.verdict(),Verdict::PolicyBoundaryFail);
}
#[test] fn codex_late_preparation_is_authenticated_post_admission_pre_resume() {
    let broker=include_str!("../src/python_isolation/broker.rs");
    let prepare=broker.find("prepare_codex_fixtures(&lab::VerifiedCodexIdentity").unwrap();
    assert!(broker.find("AdmittedLaunch::prepare_under_lease").unwrap()<prepare);
    assert!(broker.find("let payload = lease.helper_payload").unwrap()<prepare);
    assert!(prepare<broker.find("ResumeThread(helper.thread.raw())").unwrap());
    assert!(broker.contains("token::get_user_sid_bytes(base.raw())? == winutil::sid_bytes_from_string(&helper.account_sid)?"));
    assert!(broker.contains("config.actual_logon_sid==actual_logon_sid && config.matches"));
    let driver=include_str!("../examples/python_isolation_acceptance/windows.rs");
    assert!(driver.contains("python-isolation-codex-fixtures.json"));
    assert!(driver.contains("protectedMutationObserved"));assert!(driver.contains("KnownExceptionObserved} else {Verdict::PolicyBoundaryFail}"));
    assert!(driver.contains("\"absoluteWorkspaceWriteAcceptance\""));
}
#[test] fn codex_protected_targets_are_late_fixed_and_no_handle_survives_the_receipt() {
    let fixtures=include_str!("../src/python_isolation/codex_fixtures.rs");
    assert!(fixtures.contains("pub fn prepare(identity: &VerifiedCodexIdentity) -> Result<Value>"));
    assert!(fixtures.contains("acl::add_deny_write_ace(target.path(), roles.capability_sid.as_ptr())?"));
    assert!(fixtures.contains("ace.sid == capability && ace.mask == DENY_WRITE"));
    assert!(fixtures.contains("coverage(snapshot, capability, DENY, scope, false) == DENY_WRITE"));
    assert!(fixtures.contains("require_inherited"));assert!(fixtures.contains("verify_no_delete_child"));
    assert!(fixtures.find("drop(guard);").unwrap()<fixtures.rfind("empty_protected_directory()?").unwrap());
    assert!(fixtures.find("All file/directory/guard handles are released here").unwrap()
        <fixtures.find("receipt[\"targetHandlesReleased\"]").unwrap());
    for forbidden in ["pub fn new(","SetNamedSecurityInfo", "remove_file(","remove_dir(","impl Drop for Fixture", "GetNamedSecurityInfo"] {
        assert!(!fixtures.contains(forbidden));
    }
    let driver=include_str!("../examples/python_isolation_acceptance/windows.rs");
    let inspect=driver.split("fn codex_artifacts()").nth(1).unwrap().split("fn run_suite(").next().unwrap();
    assert!(!inspect.contains("std::fs::read("));
    assert!(inspect.contains("(&mut file).take(expected.len() as u64+1).read_to_end"));
    assert!(driver.contains("identitiesMatchPreparedTargets"));
    assert!(driver.contains("artifact[actual]==*expected"));
    assert!(driver.contains("if identity_changed {artifact[\"protectedMutationObserved\"]"));
    assert!(driver.contains("durable Codex fixture receipt readback mismatch"));
}

#[cfg(feature="lab-python-online-pdf")]
fn online_frame(case:Case)->Frame {
    let mut f=codex_frame(case);
    let bytes=base64::engine::general_purpose::STANDARD.decode(&f.run.as_ref().unwrap().stdout_base64).unwrap();
    let mut script:ScriptEvidence=serde_json::from_slice(&bytes).unwrap();
    let installed=PACKAGE_PINS.iter().map(|p|InstalledPackage {name:p.0.into(),version:p.1.into()}).collect();
    let origins=std::collections::BTreeMap::from([
        ("reportlab".into(),format!(r"{PDF_DEPS}\reportlab\__init__.py")),
        ("PIL".into(),format!(r"{PDF_DEPS}\PIL\__init__.py")),
        ("charset_normalizer".into(),format!(r"{PDF_DEPS}\charset_normalizer\__init__.py")),
        ("PIL._imaging".into(),format!(r"{PDF_DEPS}\PIL\_imaging.cp312-win_amd64.pyd")),
    ]);
    f.execution_window=Some(ExecutionWindow {started_unix_ms:1_000_000,finished_unix_ms:1_005_000});
    if case==Case::OnlineInstall {
        script.online_install=Some(OnlineInstallEvidence {started_unix_ms:1_000_100,finished_unix_ms:1_004_900,
            pip_exit_code:0,target:PDF_DEPS.into(),report_path:r"C:\PiSandboxLab\work\pdf-install-report.json".into(),
            target_was_fresh:true,report_verified:true,installed,module_origins:origins,pip_output:"mock only".into(),
            pip_output_truncated:false});
    } else {
        script.online_pdf=Some(OnlinePdfEvidence {path:r"C:\PiSandboxLab\work\sandbox-test.pdf".into(),byte_count:1500,
            sha256:"a".repeat(64),page_count:1,expected_text:"Sandbox PDF test".into(),page_compression:0,invariant:true,
            installed,module_origins:origins});
    }
    set_script(&mut f,&script);f
}
#[cfg(feature="lab-python-online-pdf")]
#[test] fn online_profile_appends_only_two_immutable_original_token_cases() {
    assert_eq!(Case::ALL.map(Case::name),["ordinary-outside","codex-boundary","codex-file-operations",
        "codex-child-normal-exit","codex-child-timeout","online-install","online-pdf"]);
    assert_eq!(compiled_feature(),"lab-python-online-pdf");
    assert_eq!(Case::initial(),Case::CodexBoundary);
    assert!(include_str!("../Cargo.toml").contains("lab-python-online-pdf = [\"lab-python-codex-policy-acceptance\"]"));
    for (case,timeout,deadline) in [(Case::OnlineInstall,120000,140),(Case::OnlinePdf,30000,50)] {
        assert!(case.codex());assert!(!case.descendant());assert!(!case.boundary());assert!(case.online());
        let r=request(case,123,"0".repeat(64));assert_eq!(r.timeout_ms,timeout);assert_eq!(case.frame_deadline_seconds(),deadline);
        assert_eq!(r.argv,[PYTHON,"-I","-S","-B",ONLINE_SCRIPT,case.name()]);
        assert!(r.env.keys().all(|k|["SystemRoot","TEMP","TMP"].contains(&k.as_str())));
        assert!(FixedRequest::new(r.clone()).is_ok());
        let mut altered=r.clone();altered.argv[4]=SCRIPT.into();assert!(FixedRequest::new(altered).is_err());
        let mut altered=r.clone();altered.argv.push("https://example.invalid/script.py".into());assert!(FixedRequest::new(altered).is_err());
        let mut altered=r;altered.env.insert("PIP_INDEX_URL".into(),"https://example.invalid".into());assert!(FixedRequest::new(altered).is_err());
        let frame=online_frame(case);assert!(parse_script(&frame).is_ok());assert!(native_valid(&frame));
        assert!(!assess(&frame,false,true,true).full_pass);
    }
    assert_eq!(Case::CodexBoundary.budget_ms(),15000);assert_eq!(Case::CodexBoundary.frame_deadline_seconds(),35);
    assert_eq!(Case::CodexChildTimeout.budget_ms(),8000);
}
#[cfg(feature="lab-python-online-pdf")]
#[test] fn online_imports_reports_versions_timing_and_freshness_fail_closed() {
    for change in 0..10 {
        let mut f=online_frame(Case::OnlineInstall);let mut s=parse_script(&f).unwrap();let i=s.online_install.as_mut().unwrap();
        match change {
            0=>i.pip_exit_code=1,1=>i.target_was_fresh=false,2=>i.report_verified=false,
            3=>i.installed[0].version="0.0.0".into(),4=>i.installed.push(i.installed[0].clone()),
            5=>{i.module_origins.insert("PIL".into(),r"C:\PiSandboxLab\runtime\Lib\site-packages\PIL\__init__.py".into());},
            6=>{i.module_origins.insert("PIL._imaging".into(),format!(r"{PDF_DEPS}\PIL\_imaging.py"));},
            7=>i.started_unix_ms=999_999,8=>i.finished_unix_ms=1_005_001,
            _=>{i.module_origins.insert("reportlab".into(),format!(r"{PDF_DEPS}\..\host\reportlab.py"));},
        }
        set_script(&mut f,&s);assert!(parse_script(&f).is_err(),"change {change}");
    }
    let mut f=online_frame(Case::OnlineInstall);f.execution_window=None;assert!(parse_script(&f).is_err());
    let mut f=online_frame(Case::OnlineInstall);f.native.root.as_mut().unwrap().exact_job_member=false;
    assert!(parse_script(&f).is_ok());assert!(!native_valid(&f));
}
#[cfg(feature="lab-python-online-pdf")]
#[test] fn online_pdf_receipt_cannot_substitute_for_host_structural_and_fetch_evidence() {
    let values=Case::ALL.map(|case|{
        let f=if case.online(){online_frame(case)}else{codex_frame(case)};
        (case,assess(&f,true,true,true))
    });
    let core=codex_policy_acceptance(&values,true,true,true);assert!(core);
    assert!(online_pdf_acceptance(&values,core,true,true,true,true,true));
    for missing in 0..6 {
        let mut gates=[true;6];gates[missing]=false;
        assert!(!online_pdf_acceptance(&values,gates[0],gates[1],gates[2],gates[3],gates[4],gates[5]));
    }
    let mut values=values;values[6].1.identity=Verdict::Inconclusive;
    assert!(!online_pdf_acceptance(&values,true,true,true,true,true,true));
    assert!(!online_pdf_acceptance(&values[..6],true,true,true,true,true,true));
    for change in 0..6 {
        let mut f=online_frame(Case::OnlinePdf);let mut s=parse_script(&f).unwrap();let p=s.online_pdf.as_mut().unwrap();
        match change {0=>p.page_count=2,1=>p.expected_text="user document".into(),2=>p.byte_count=1,
            3=>p.sha256="bad".into(),4=>p.invariant=false,_=>p.page_compression=1}
        set_script(&mut f,&s);assert!(parse_script(&f).is_err());
    }
}
#[cfg(feature="lab-python-online-pdf")]
#[test] fn online_fixture_uses_public_pip_in_root_and_separate_isolated_pdf() {
    let source=include_str!("../../../scripts/python-online-pdf-fixture.py");
    for flag in ["--no-index","--require-hashes","--only-binary=:all:","--no-deps","--no-cache-dir",
        "--no-compile","--disable-pip-version-check","--retries","--timeout","--target","--report"] {
        assert!(source.contains(flag));
    }
    assert!(source.contains("runpy.run_module(\"pip\", run_name=\"__main__\", alter_sys=True)"));
    assert!(source.contains("\"PIP_CONFIG_FILE\": os.devnull"));assert!(source.contains("os.environ.clear()"));
    assert!(!source.contains("pip._internal"));assert!(!source.contains("subprocess"));
    assert!(!source.contains("trusted-host"));assert!(!source.contains("CERT_NONE"));
    assert!(source.contains("PDF.open(\"xb\")"));assert!(source.contains("\"PIL._imaging\""));
    assert!(source.contains("pagesize=A4, pdfVersion=(1, 4), pageCompression=0, invariant=1"));
    assert!(!include_str!("../../../scripts/python-isolation-fixture.py").contains("online-install"));
}
