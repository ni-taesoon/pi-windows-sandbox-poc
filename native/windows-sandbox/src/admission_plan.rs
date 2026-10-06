//! Portable ordering, rollback and ACL postconditions for experimental admission.
//! This module neither selects targets nor edits security descriptors.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EditKind {
    Grant,
    Deny,
}

/// Preserve the pinned enumeration order within each phase. No grant may follow
/// a deny, including grants on an overlapping ancestor that propagate to children.
pub fn ordered_indices(kinds: &[EditKind]) -> Vec<usize> {
    [EditKind::Grant, EditKind::Deny]
        .into_iter()
        .flat_map(|kind| {
            kinds
                .iter()
                .enumerate()
                .filter_map(move |(index, current)| (*current == kind).then_some(index))
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePhase {
    Apply,
    Verify,
}

#[derive(Debug)]
pub struct TransactionFailure<E> {
    pub phase: FailurePhase,
    pub index: usize,
    pub error: E,
    pub rollback_failed: bool,
}

/// The apply callback owns all account/capability writes for one pinned target.
/// Roll back even a failing apply: its first write or inheritance propagation may
/// already have succeeded. Verify every grant and deny only after all writes.
pub fn apply_and_verify<E>(
    kinds: &[EditKind],
    mut apply: impl FnMut(usize) -> Result<(), E>,
    mut verify: impl FnMut(usize) -> Result<(), E>,
    mut rollback: impl FnMut(usize) -> Result<(), E>,
) -> Result<(), TransactionFailure<E>> {
    let mut attempted = Vec::with_capacity(kinds.len());
    let result = (|| {
        for index in ordered_indices(kinds) {
            attempted.push(index);
            apply(index).map_err(|error| (FailurePhase::Apply, index, error))?;
        }
        for index in 0..kinds.len() {
            verify(index).map_err(|error| (FailurePhase::Verify, index, error))?;
        }
        Ok(())
    })();
    if let Err((phase, index, error)) = result {
        let mut rollback_failed = false;
        for index in attempted.into_iter().rev() {
            // Do not short-circuit cleanup after a rollback failure.
            rollback_failed |= rollback(index).is_err();
        }
        return Err(TransactionFailure {
            phase,
            index,
            error,
            rollback_failed,
        });
    }
    Ok(())
}

pub const OBJECT_INHERIT: u8 = 0x01;
pub const CONTAINER_INHERIT: u8 = 0x02;
pub const NO_PROPAGATE: u8 = 0x04;
pub const INHERIT_ONLY: u8 = 0x08;
pub const INHERITED: u8 = 0x10;
const KNOWN_FLAGS: u8 =
    OBJECT_INHERIT | CONTAINER_INHERIT | NO_PROPAGATE | INHERIT_ONLY | INHERITED;
const NON_CONCRETE_ACCESS: u32 = 0xf000_0000 | 0x0200_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AceKind {
    Allow,
    Deny,
    Unsupported,
}

/// Only structurally validated simple ACEs may be supplied by the native reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimpleAce {
    pub kind: AceKind,
    pub flags: u8,
    pub mask: u32,
    /// Matches the SID being checked: account for denies, account or capability
    /// in separate grant checks. Unrelated trustees are never grant evidence.
    pub account_sid: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrantCoverageFailure {
    NonConcreteRequiredMask,
    ForbiddenRequiredMask,
    UnsupportedAce,
    UnsupportedFlags,
    NonConcreteTargetAllow,
    ForbiddenTargetAllow,
    UnexpectedTargetAllow(u32),
    MissingMask(u32),
    MissingInheritedMask(u32),
}

/// Verify only the selected trustee's grant ACEs, without rewriting other SIDs
/// or treating their permissions as proof of coverage. This is a structural
/// postcondition, not AccessCheck: an overlapping direct deny may intentionally
/// override a valid grant. Inherited grants may provide coverage, but every
/// selected allow (even inherit-only) must be free of parent DELETE_CHILD and
/// any concrete right outside the intended grant, including WRITE_DAC/WRITE_OWNER.
pub fn verify_grant_coverage(
    aces: &[SimpleAce],
    required_mask: u32,
    directory: bool,
) -> Result<(), GrantCoverageFailure> {
    use crate::policy_masks::FILE_DELETE_CHILD;
    if required_mask == 0 || required_mask & NON_CONCRETE_ACCESS != 0 {
        return Err(GrantCoverageFailure::NonConcreteRequiredMask);
    }
    if required_mask & FILE_DELETE_CHILD != 0 {
        return Err(GrantCoverageFailure::ForbiddenRequiredMask);
    }
    let mut missing = required_mask;
    let mut missing_inherited = required_mask;
    for ace in aces.iter().filter(|ace| ace.account_sid) {
        if ace.kind == AceKind::Unsupported {
            return Err(GrantCoverageFailure::UnsupportedAce);
        }
        if ace.flags & !KNOWN_FLAGS != 0 {
            return Err(GrantCoverageFailure::UnsupportedFlags);
        }
        if ace.kind != AceKind::Allow {
            continue;
        }
        if ace.mask & NON_CONCRETE_ACCESS != 0 {
            return Err(GrantCoverageFailure::NonConcreteTargetAllow);
        }
        if ace.mask & FILE_DELETE_CHILD != 0 {
            return Err(GrantCoverageFailure::ForbiddenTargetAllow);
        }
        let unexpected = ace.mask & !required_mask;
        if unexpected != 0 {
            return Err(GrantCoverageFailure::UnexpectedTargetAllow(unexpected));
        }
        if ace.flags & INHERIT_ONLY == 0 {
            missing &= !ace.mask;
        }
        if ace.flags & (OBJECT_INHERIT | CONTAINER_INHERIT)
            == (OBJECT_INHERIT | CONTAINER_INHERIT)
            && ace.flags & NO_PROPAGATE == 0
        {
            missing_inherited &= !ace.mask;
        }
    }
    if missing != 0 {
        return Err(GrantCoverageFailure::MissingMask(missing));
    }
    if directory && missing_inherited != 0 {
        return Err(GrantCoverageFailure::MissingInheritedMask(missing_inherited));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverageFailure {
    NonConcreteRequiredMask,
    UnsupportedAce,
    UnsupportedFlags,
    NonConcreteAccountDeny,
    AllowBeforeCoverage,
    MissingMask(u32),
}

/// A conservative postcondition, not a general Windows AccessCheck emulator.
/// Require explicit, effective account denies covering the concrete policy mask
/// before any potentially applicable allow. Directory denies must also propagate
/// to both files and subdirectories without an inheritance-depth limit.
pub fn verify_deny_coverage(
    aces: &[SimpleAce],
    required_mask: u32,
    directory: bool,
) -> Result<(), CoverageFailure> {
    if required_mask == 0 || required_mask & NON_CONCRETE_ACCESS != 0 {
        return Err(CoverageFailure::NonConcreteRequiredMask);
    }
    let mut missing = required_mask;
    for ace in aces {
        if ace.kind == AceKind::Unsupported {
            return Err(CoverageFailure::UnsupportedAce);
        }
        if ace.flags & !KNOWN_FLAGS != 0 {
            return Err(CoverageFailure::UnsupportedFlags);
        }
        let effective = ace.flags & INHERIT_ONLY == 0;
        let inheritable = ace.flags & (OBJECT_INHERIT | CONTAINER_INHERIT) != 0;
        if ace.kind == AceKind::Allow
            && (effective || (directory && inheritable))
            && missing != 0
        {
            // We do not infer group membership or permissions from an allow mask.
            return Err(CoverageFailure::AllowBeforeCoverage);
        }
        if ace.kind != AceKind::Deny || !ace.account_sid {
            continue;
        }
        if ace.mask & NON_CONCRETE_ACCESS != 0 {
            return Err(CoverageFailure::NonConcreteAccountDeny);
        }
        if !effective || ace.flags & INHERITED != 0 {
            continue;
        }
        if directory
            && (ace.flags & (OBJECT_INHERIT | CONTAINER_INHERIT)
                != (OBJECT_INHERIT | CONTAINER_INHERIT)
                || ace.flags & NO_PROPAGATE != 0)
        {
            continue;
        }
        missing &= !ace.mask;
    }
    if missing != 0 {
        return Err(CoverageFailure::MissingMask(missing));
    }
    Ok(())
}
