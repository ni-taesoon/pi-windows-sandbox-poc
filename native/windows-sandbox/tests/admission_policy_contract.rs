//! Portable transaction/postcondition tests. These perform no Windows ACL edits
//! and do not claim native isolation or AccessCheck validation.
use pi_windows_sandbox::{
    admission_plan::{
        apply_and_verify, ordered_indices, verify_deny_coverage, AceKind, CoverageFailure,
        EditKind, FailurePhase, SimpleAce, CONTAINER_INHERIT, INHERITED, INHERIT_ONLY,
        NO_PROPAGATE, OBJECT_INHERIT,
    },
    policy_masks::WRITE_DENY,
};
use std::cell::RefCell;

const INHERIT: u8 = OBJECT_INHERIT | CONTAINER_INHERIT;
const READ_DENY: u32 = 0x0012_0089 | WRITE_DENY;

fn deny(mask: u32, flags: u8) -> SimpleAce {
    SimpleAce { kind: AceKind::Deny, flags, mask, account_sid: true }
}

fn allow(mask: u32) -> SimpleAce {
    SimpleAce { kind: AceKind::Allow, flags: 0, mask, account_sid: false }
}

#[test]
fn stable_grants_first_preserves_each_phases_pinned_order() {
    use EditKind::{Deny, Grant};
    assert_eq!(ordered_indices(&[Deny, Grant, Deny, Grant, Grant]), vec![1, 3, 4, 0, 2]);
    assert_eq!(ordered_indices(&[Grant, Grant]), vec![0, 1]);
    assert_eq!(ordered_indices(&[Deny, Deny]), vec![0, 1]);
    assert_eq!(ordered_indices(&[]), Vec::<usize>::new());
}

#[test]
fn all_grants_finish_before_denies_and_all_denies_finish_before_verification() {
    use EditKind::{Deny, Grant};
    let events = RefCell::new(Vec::new());
    let kinds = [Deny, Grant, Deny, Grant];
    let result: Result<(), _> = apply_and_verify(
        &kinds,
        |index| { events.borrow_mut().push(("apply", index)); Ok::<_, &str>(()) },
        |index| { events.borrow_mut().push(("verify", index)); Ok(()) },
        |index| { events.borrow_mut().push(("rollback", index)); Ok(()) },
    );
    assert!(result.is_ok());
    assert_eq!(*events.borrow(), vec![
        ("apply", 1), ("apply", 3), ("apply", 0), ("apply", 2),
        ("verify", 0), ("verify", 2),
    ]);
}

#[test]
fn overlapping_grant_model_cannot_erase_final_account_denies() {
    // Model the observed inheritance hazard without a native security mutation:
    // any ancestor grant erases the current child deny. The final callbacks
    // inspect the resulting ACLs, rather than trusting a successful edit call.
    let final_acls = RefCell::new(vec![Vec::new(), Vec::new()]);
    let result = apply_and_verify(
        &[EditKind::Deny, EditKind::Deny, EditKind::Grant],
        |index| {
            if index == 2 {
                for acl in final_acls.borrow_mut().iter_mut() {
                    *acl = vec![allow(0x0013_01ff)];
                }
            } else {
                final_acls.borrow_mut()[index].insert(0, deny(WRITE_DENY, INHERIT));
            }
            Ok(())
        },
        |index| verify_deny_coverage(&final_acls.borrow()[index], WRITE_DENY, true),
        |_| panic!("successful admission must not roll back"),
    );
    assert!(result.is_ok());
}

#[test]
fn grant_only_and_empty_policy_keep_existing_apply_behavior() {
    let events = RefCell::new(Vec::new());
    for kinds in [vec![], vec![EditKind::Grant, EditKind::Grant]] {
        let result = apply_and_verify(
            &kinds,
            |index| { events.borrow_mut().push(index); Ok::<_, &str>(()) },
            |_| panic!("no denied target to verify"),
            |_| panic!("successful grants must not roll back"),
        );
        assert!(result.is_ok());
    }
    assert_eq!(*events.borrow(), vec![0, 1]);
}

#[test]
fn apply_failure_rolls_back_including_partially_touched_current_target() {
    use EditKind::{Deny, Grant};
    let events = RefCell::new(Vec::new());
    let failure = apply_and_verify(
        &[Deny, Grant, Deny, Grant],
        |index| {
            events.borrow_mut().push(("account_write", index));
            if index == 3 { return Err("capability write failed after account write"); }
            events.borrow_mut().push(("capability_write", index));
            Ok(())
        },
        |_| panic!("apply failure must not verify/admit"),
        |index| { events.borrow_mut().push(("rollback", index)); Ok(()) },
    ).unwrap_err();
    assert_eq!(failure.phase, FailurePhase::Apply);
    assert_eq!(failure.index, 3);
    assert!(!failure.rollback_failed);
    assert_eq!(*events.borrow(), vec![
        ("account_write", 1), ("capability_write", 1), ("account_write", 3),
        ("rollback", 3), ("rollback", 1),
    ]);
}

#[test]
fn late_deny_apply_failure_reverses_actual_order_not_original_indices() {
    let rolled_back = RefCell::new(Vec::new());
    let failure = apply_and_verify(
        &[EditKind::Deny, EditKind::Grant, EditKind::Deny, EditKind::Grant],
        |index| if index == 2 { Err("deny write failed") } else { Ok(()) },
        |_| panic!("failed apply cannot admit"),
        |index| { rolled_back.borrow_mut().push(index); Ok(()) },
    ).unwrap_err();
    assert_eq!(failure.phase, FailurePhase::Apply);
    assert_eq!(*rolled_back.borrow(), vec![2, 0, 3, 1]);
}

#[test]
fn postcondition_failure_rolls_back_every_applied_target_in_reverse() {
    let events = RefCell::new(Vec::new());
    let failure = apply_and_verify(
        &[EditKind::Deny, EditKind::Grant, EditKind::Deny, EditKind::Grant],
        |index| { events.borrow_mut().push(("apply", index)); Ok(()) },
        |index| {
            events.borrow_mut().push(("verify", index));
            if index == 2 { Err("final denied directory lost coverage") } else { Ok(()) }
        },
        |index| { events.borrow_mut().push(("rollback", index)); Ok(()) },
    ).unwrap_err();
    assert_eq!(failure.phase, FailurePhase::Verify);
    assert_eq!(failure.index, 2);
    assert!(!failure.rollback_failed);
    assert_eq!(*events.borrow(), vec![
        ("apply", 1), ("apply", 3), ("apply", 0), ("apply", 2),
        ("verify", 0), ("verify", 2),
        ("rollback", 2), ("rollback", 0), ("rollback", 3), ("rollback", 1),
    ]);
}

#[test]
fn rollback_failure_is_surfaced_and_does_not_skip_remaining_rollbacks() {
    for fail_during_apply in [false, true] {
        let rolled_back = RefCell::new(Vec::new());
        let failure = apply_and_verify(
            &[EditKind::Deny, EditKind::Grant],
            |index| if fail_during_apply && index == 0 { Err("apply failed") } else { Ok(()) },
            |_| Err("coverage failed"),
            |index| {
                rolled_back.borrow_mut().push(index);
                if index == 0 { Err("rollback failed") } else { Ok(()) }
            },
        ).unwrap_err();
        assert!(failure.rollback_failed);
        assert_eq!(*rolled_back.borrow(), vec![0, 1]);
    }
}

#[test]
fn duplicate_pins_are_all_rolled_back_after_failed_final_verification() {
    // Separate policy entries can pin the same object. Retain every attempted
    // index rather than deduplicating it or stopping after its first revocation.
    let pinned_objects = [7, 7, 7];
    let rolled_back = RefCell::new(Vec::new());
    let failure = apply_and_verify(
        &[EditKind::Deny, EditKind::Grant, EditKind::Deny],
        |_| Ok::<_, &str>(()),
        |_| Err("final duplicate-target coverage failed"),
        |index| {
            rolled_back.borrow_mut().push((index, pinned_objects[index]));
            if index == 2 { Err("first rollback failed") } else { Ok(()) }
        },
    ).unwrap_err();
    assert_eq!(failure.phase, FailurePhase::Verify);
    assert!(failure.rollback_failed);
    assert_eq!(*rolled_back.borrow(), vec![(2, 7), (0, 7), (1, 7)]);
}

#[test]
fn final_check_detects_later_write_invalidating_an_earlier_deny() {
    let aces = RefCell::new(Vec::new());
    let rolled_back = RefCell::new(Vec::new());
    let failure = apply_and_verify(
        &[EditKind::Deny, EditKind::Deny],
        |index| {
            *aces.borrow_mut() = if index == 0 {
                vec![deny(WRITE_DENY, INHERIT)]
            } else {
                vec![allow(WRITE_DENY)]
            };
            Ok(())
        },
        |_| verify_deny_coverage(&aces.borrow(), WRITE_DENY, true),
        |index| { rolled_back.borrow_mut().push(index); Ok(()) },
    ).unwrap_err();
    assert_eq!(failure.phase, FailurePhase::Verify);
    assert_eq!(failure.index, 0);
    assert_eq!(failure.error, CoverageFailure::AllowBeforeCoverage);
    assert_eq!(*rolled_back.borrow(), vec![1, 0]);
}

#[test]
fn explicit_effective_account_denies_cover_files_and_directories() {
    for mask in [WRITE_DENY, READ_DENY] {
        assert_eq!(verify_deny_coverage(&[deny(mask, 0)], mask, false), Ok(()));
        assert_eq!(verify_deny_coverage(&[deny(mask, INHERIT)], mask, true), Ok(()));
        assert_eq!(verify_deny_coverage(&[deny(mask, INHERIT), allow(u32::MAX)], mask, true), Ok(()));
    }
}

#[test]
fn deny_fragments_may_union_before_any_allow() {
    let fragment = 0x0000_0002;
    let aces = [deny(fragment, INHERIT), deny(WRITE_DENY & !fragment, INHERIT), allow(u32::MAX)];
    assert_eq!(verify_deny_coverage(&aces, WRITE_DENY, true), Ok(()));
    let intervening_allow = [aces[0], aces[2], aces[1]];
    assert_eq!(verify_deny_coverage(&intervening_allow, WRITE_DENY, true), Err(CoverageFailure::AllowBeforeCoverage));
}

#[test]
fn missing_mask_or_account_coverage_is_rejected() {
    assert!(verify_deny_coverage(&[], WRITE_DENY, true).is_err());
    assert!(verify_deny_coverage(&[allow(0x0013_01ff)], WRITE_DENY, true).is_err());
    assert!(verify_deny_coverage(&[deny(WRITE_DENY & !0x2, INHERIT)], WRITE_DENY, true).is_err());
    assert!(verify_deny_coverage(&[deny(WRITE_DENY, INHERIT)], READ_DENY, true).is_err());
    let mut other_sid = deny(WRITE_DENY, INHERIT);
    other_sid.account_sid = false;
    assert!(verify_deny_coverage(&[other_sid], WRITE_DENY, true).is_err());
}

#[test]
fn inherit_only_inherited_or_incomplete_directory_propagation_is_rejected() {
    for flags in [0, OBJECT_INHERIT, CONTAINER_INHERIT, INHERIT | NO_PROPAGATE,
        INHERIT | INHERIT_ONLY, INHERIT | INHERITED] {
        assert!(verify_deny_coverage(&[deny(WRITE_DENY, flags)], WRITE_DENY, true).is_err(), "flags={flags}");
    }
    for flags in [INHERIT_ONLY, INHERITED] {
        assert!(verify_deny_coverage(&[deny(WRITE_DENY, flags)], WRITE_DENY, false).is_err());
    }
}

#[test]
fn allow_before_deny_cannot_be_mistaken_for_effective_deny_coverage() {
    for account_sid in [false, true] {
        let mut first = allow(WRITE_DENY);
        first.account_sid = account_sid;
        for directory in [false, true] {
            assert_eq!(verify_deny_coverage(&[first, deny(WRITE_DENY, INHERIT)], WRITE_DENY, directory), Err(CoverageFailure::AllowBeforeCoverage));
        }
    }
    // An inherit-only allow still matters to a directory's future descendants.
    let mut first = allow(WRITE_DENY);
    first.flags = INHERIT | INHERIT_ONLY;
    assert!(verify_deny_coverage(&[first, deny(WRITE_DENY, INHERIT)], WRITE_DENY, true).is_err());
    assert_eq!(verify_deny_coverage(&[first, deny(WRITE_DENY, 0)], WRITE_DENY, false), Ok(()));
}

#[test]
fn complex_flags_and_nonconcrete_masks_fail_closed_even_after_coverage() {
    let covered = deny(WRITE_DENY, INHERIT);
    let mut unsupported = allow(1);
    unsupported.kind = AceKind::Unsupported;
    assert_eq!(verify_deny_coverage(&[covered, unsupported], WRITE_DENY, true), Err(CoverageFailure::UnsupportedAce));
    unsupported = allow(1);
    unsupported.flags = 0x20;
    assert_eq!(verify_deny_coverage(&[covered, unsupported], WRITE_DENY, true), Err(CoverageFailure::UnsupportedFlags));
    for mask in [0, 0x8000_0000, 0x0200_0000] {
        assert_eq!(verify_deny_coverage(&[covered], mask, true), Err(CoverageFailure::NonConcreteRequiredMask));
    }
    assert_eq!(verify_deny_coverage(&[deny(WRITE_DENY | 0x1000_0000, INHERIT)], WRITE_DENY, true), Err(CoverageFailure::NonConcreteAccountDeny));
}

#[test]
fn native_admission_uses_pinned_final_check_before_constructing_launch() {
    let source = include_str!("../src/admission.rs");
    let transaction = source.find("admission_plan::apply_and_verify(").unwrap();
    let success = source[transaction..].find("Ok(Self {").unwrap() + transaction;
    let body = &source[transaction..success];
    assert!(body.contains("verify_final_deny(&targets[index], account_sid.as_ptr())"));
    assert!(body.contains("edit_acl(target, cap.as_ptr(), target.mode, target.mask)"));
    assert!(body.contains("let account = edit_acl(target, account_sid.as_ptr(), REVOKE_ACCESS, 0)"));
    assert!(body.contains("let capability = edit_acl(target, cap.as_ptr(), REVOKE_ACCESS, 0)"));
    assert!(body.contains("rollback_failed={}"));
    let check = source.split("fn verify_final_deny(").nth(1).unwrap().split("fn enumerate(").next().unwrap();
    assert!(check.contains("target.handle.as_raw_handle() as HANDLE"));
    assert!(check.contains("!dacl.is_null() && IsValidAcl(dacl) != 0"));
    assert!(check.contains("IsValidSid(ace_sid.cast())"));
    assert!(check.contains("EqualSid(ace_sid.cast(), sid)"));
    assert!(check.contains("verify_deny_coverage(&aces, target.mask, target.is_directory)"));
    assert!(source.contains("const WRITE_ALLOW: u32 = FILE_GENERIC_WRITE | DELETE | FILE_DELETE_CHILD;"));
    assert!(source.contains("const WRITE_DENY: u32 = crate::policy_masks::WRITE_DENY;"));
    let broker = include_str!("../src/broker.rs");
    let helper_launch = broker.split("pub unsafe fn run_via_dedicated_helper(").nth(1).unwrap().split("pub fn helper_main(").next().unwrap();
    assert!(helper_launch.find("AdmittedLaunch::prepare_under_lease").unwrap() < helper_launch.find("ResumeThread").unwrap());
}
