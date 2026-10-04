//! Portable source-order/API contracts only; no account mutation or OS proof.
const ACCOUNTS: &str = include_str!("../src/setup/accounts.rs");
const SETUP: &str = include_str!("../src/setup.rs");
const WFP: &str = include_str!("../src/network/wfp.rs");
const BROKER: &str = include_str!("../src/broker.rs");
#[test]
fn local_sam_sid_replaces_ambiguous_lookup() {
    assert!(ACCOUNTS.contains("NetUserGetInfo("));
    assert!(ACCOUNTS.contains("USER_INFO_23"));
    assert!(ACCOUNTS.contains("NetApiBufferSize"));
    assert!(ACCOUNTS.contains("NetApiBufferFree"));
    assert!(!ACCOUNTS.contains("LookupAccountNameW"));
    assert!(BROKER.contains("setup::local_offline_account_sid()?"));
    assert!(!BROKER.contains("resolve_sid(&format!"));
}
#[test]
fn fresh_creation_does_not_adopt_existing_identity_or_guess_recovery() {
    let create = &ACCOUNTS[ACCOUNTS.find("fn create_disabled_account").unwrap()
        ..ACCOUNTS.find("struct LocalAccountState").unwrap()];
    assert!(
        create.find("status == NERR_Success").unwrap()
            < create.find("local_account_state()").unwrap()
    );
    assert!(create.contains("state.marker == marker"));
    assert!(create.contains("disabledFlagRequested"));
    assert!(create.contains("not-attempted-without-owned-identity"));
    assert!(!ACCOUNTS.contains("NetUserDel"));
    assert!(!ACCOUNTS.contains("usri1003_password"));
}
#[test]
fn durable_disabled_record_and_effective_protection_precede_activation() {
    let provision = &SETUP[SETUP.find("pub fn provision_offline_account").unwrap()
        ..SETUP.find("/// Read-only broker logon seam").unwrap()];
    let store = provision.find(".write(&record)").unwrap();
    let install = provision
        .find("network::install_offline_protection")
        .unwrap();
    let verify = provision
        .find("network::verify_offline_protection")
        .unwrap();
    let activate = provision
        .find("accounts::set_disabled(&sid, false)")
        .unwrap();
    assert!(store < install && install < verify && verify < activate);
    assert!(provision.contains("ownership.rollback()"));
    assert!(provision.contains("ownership.disarm()"));
    let disable = &SETUP[SETUP.find("pub fn disable_offline_account").unwrap()
        ..SETUP.find("/// Validated broker identity").unwrap()];
    assert!(disable.find("store::read").unwrap() < disable.find("accounts::set_disabled").unwrap());
}
#[test]
fn wfp_uses_sid_trustee_not_name_resolution() {
    assert!(WFP.contains("TrusteeForm: TRUSTEE_IS_SID"));
    assert!(WFP.contains("UserMatchCondition::for_sid"));
    assert!(!WFP.contains("BuildExplicitAccessWithNameW"));
    assert!(!WFP.contains("for_account("));
}
#[test]
fn rollback_is_marker_and_sid_bound_with_verified_state() {
    let recovery = &ACCOUNTS[ACCOUNTS.find("pub fn rollback").unwrap()
        ..ACCOUNTS.find("impl Drop for FreshAccount").unwrap()];
    assert!(recovery.contains("current.sid == self.sid && current.marker == self.marker"));
    assert!(recovery.contains("rollback-disabled-verified"));
    assert!(recovery.contains("set_disabled(&self.sid, true)"));
    assert!(ACCOUNTS.contains("phase=verify-owned-account-flags"));
    assert!(ACCOUNTS.contains("observed.sid == expected_sid"));
}
