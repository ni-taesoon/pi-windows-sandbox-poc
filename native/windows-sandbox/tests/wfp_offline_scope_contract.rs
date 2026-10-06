//! Portable source contracts only. These never open WFP, change accounts or
//! security, launch a canary, or establish Windows enforcement.
use std::collections::BTreeSet;

const SPECS: &str = include_str!("../src/network/wfp/filter_specs.rs");
const WFP: &str = include_str!("../src/network/wfp.rs");
const NETWORK: &str = include_str!("../src/network.rs");
const SETUP: &str = include_str!("../src/setup.rs");
const FEATURE: &str = "#[cfg(feature = \"lab-python-policy-repair-comparison\")]";

struct Spec<'a> {
    body: &'a str,
    gated: bool,
}

fn specs() -> Vec<Spec<'static>> {
    SPECS
        .match_indices("    FilterSpec {")
        .map(|(start, _)| {
            let end = start + SPECS[start..].find("\n    },").unwrap();
            Spec {
                body: &SPECS[start..end],
                gated: SPECS[..start].trim_end().ends_with(FEATURE),
            }
        })
        .collect()
}

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).unwrap().1.split_once(end).unwrap().0
}

fn compact(source: &str) -> String {
    source.chars().filter(|c| !c.is_whitespace()).collect()
}

#[test]
fn baseline_twelve_filter_identities_and_conditions_are_unchanged() {
    let expected = [
        ("019df13a98ac549490c7bc57bf9d03c6", "icmp_connect_v4", "ALE_AUTH_CONNECT_V4", "Protocol(IPPROTO_ICMPasu8)"),
        ("b1be2f634bb85f208e9d50568b9111da", "icmp_connect_v6", "ALE_AUTH_CONNECT_V6", "Protocol(IPPROTO_ICMPV6asu8)"),
        ("b2c5988ccae05fa595ea2a2812f3a936", "icmp_assign_v4", "ALE_RESOURCE_ASSIGNMENT_V4", "Protocol(IPPROTO_ICMPasu8)"),
        ("613631e435675560a65b3250a37c6a80", "icmp_assign_v6", "ALE_RESOURCE_ASSIGNMENT_V6", "Protocol(IPPROTO_ICMPV6asu8)"),
        ("986b7c9a948155d3a38118aec1d3bb7d", "dns_53_v4", "ALE_AUTH_CONNECT_V4", "RemotePort(53)"),
        ("459baa3c8428543c866b82f8e83f6317", "dns_53_v6", "ALE_AUTH_CONNECT_V6", "RemotePort(53)"),
        ("d87eec83adef59028b9bcc984c69223a", "dns_853_v4", "ALE_AUTH_CONNECT_V4", "RemotePort(853)"),
        ("a6bc42b6e8e6571cbf30f8b8c8de9327", "dns_853_v6", "ALE_AUTH_CONNECT_V6", "RemotePort(853)"),
        ("4ef2d385623d52f08b4785d3fa784292", "smb_445_v4", "ALE_AUTH_CONNECT_V4", "RemotePort(445)"),
        ("719955415f8d5e08a41ad3db97996788", "smb_445_v6", "ALE_AUTH_CONNECT_V6", "RemotePort(445)"),
        ("297960ba54915f4b9a0738180fe01d9c", "smb_139_v4", "ALE_AUTH_CONNECT_V4", "RemotePort(139)"),
        ("41ead4a054375f08804e96069d25f225", "smb_139_v6", "ALE_AUTH_CONNECT_V6", "RemotePort(139)"),
    ];
    let baseline: Vec<_> = specs().into_iter().filter(|spec| !spec.gated).collect();
    assert_eq!(baseline.len(), expected.len());
    for (spec, (key, name, layer, condition)) in baseline.iter().zip(expected) {
        assert_eq!(between(spec.body, "GUID::from_u128(0x", ")"), key);
        assert_eq!(between(spec.body, "name: \"", "\""), format!("pi_sandbox_wfp_{name}"));
        assert_eq!(between(spec.body, "layer_key: FWPM_LAYER_", ","), layer);
        let conditions = compact(between(spec.body, "conditions: &[", "]"));
        assert_eq!(conditions.trim_end_matches(','), format!("ConditionSpec::User,ConditionSpec::{condition}"));
    }
}

#[test]
fn only_two_unique_user_only_connect_specs_are_feature_gated() {
    let all = specs();
    assert_eq!(all.len(), 14);
    assert_eq!(SPECS.matches(FEATURE).count(), 2);
    let keys: BTreeSet<_> = all.iter().map(|s| between(s.body, "GUID::from_u128(0x", ")")).collect();
    let names: BTreeSet<_> = all.iter().map(|s| between(s.body, "name: \"", "\"")).collect();
    assert_eq!(keys.len(), all.len());
    assert_eq!(names.len(), all.len());
    let added: Vec<_> = all.iter().filter(|spec| spec.gated).collect();
    for (spec, (key, version)) in added.iter().zip([
        ("ef7656ccacb451bcb3ad27be82cb009a", "4"),
        ("3d9c33a833525ce2af92d71c8f66eb26", "6"),
    ]) {
        assert_eq!(between(spec.body, "GUID::from_u128(0x", ")"), key);
        assert_eq!(between(spec.body, "name: \"", "\""), format!("pi_sandbox_wfp_offline_connect_v{version}"));
        assert_eq!(between(spec.body, "layer_key: FWPM_LAYER_", ","), format!("ALE_AUTH_CONNECT_V{version}"));
        assert_eq!(compact(between(spec.body, "conditions: &[", "]")), "ConditionSpec::User");
    }
    assert_eq!(added.len(), 2);
    for spec in all {
        let conditions = between(spec.body, "conditions: &[", "]");
        assert_eq!(conditions.matches("ConditionSpec::User").count(), 1);
        assert!(!conditions.trim().is_empty());
    }
}

#[test]
fn installation_and_condition_builder_fail_closed_before_writes() {
    let install = between(WFP, "pub fn install_wfp_filters_for_sid", "pub(super) fn expected_filter_count");
    let scope = install.find("validate_user_scope(spec.conditions)?").unwrap();
    let sid = install.find("UserMatchCondition::for_sid(sid)?").unwrap();
    let open = install.find("Engine::open").unwrap();
    assert!(scope < sid && sid < open);
    let builder = between(WFP, "fn build_conditions(", "fn validate_user_scope(");
    assert!(builder.contains("Result<Vec<FWPM_FILTER_CONDITION0>>"));
    assert!(builder.find("validate_user_scope(specs)?").unwrap() < builder.find("Ok(specs").unwrap());
    let guard = compact(between(WFP, "fn validate_user_scope(", "fn delete_filter_if_present("));
    assert!(guard.contains("matches!(condition,ConditionSpec::User)"));
    assert!(guard.contains(".count()==1,"));
    let user = between(WFP, "fn for_sid(sid: &str)", "impl Drop for UserMatchCondition");
    assert!(user.contains("!sid.is_empty() && sid.starts_with(\"S-1-5-21-\")"));
    assert!(user.contains("sid == crate::setup::local_offline_account_sid()?"));
    assert!(user.find("LocalSid::from_string(sid)?").unwrap() < user.find("BuildSecurityDescriptorW(").unwrap());
    assert!(user.contains("TrusteeForm: TRUSTEE_IS_SID"));
    assert!(user.contains("TrusteeType: TRUSTEE_IS_USER"));
    assert!(user.contains("!condition.blob.data.is_null() && condition.blob.size > 0"));
}

#[test]
fn install_verify_collision_check_and_remove_share_the_compiled_specs() {
    for (start, end) in [
        ("pub fn install_wfp_filters_for_sid", "pub(super) fn expected_filter_count"),
        ("pub(crate) fn remove_wfp_filters", "struct Engine"),
        ("pub fn require_namespace_absent", "fn same_guid"),
    ] {
        assert!(between(WFP, start, end).contains("for spec in FILTER_SPECS"));
    }
    let verify = WFP.split_once("pub fn verify_wfp_filters_for_sid").unwrap().1;
    assert!(verify.contains("for spec in FILTER_SPECS"));
    for required in [
        "validate_user_scope(spec.conditions)?", "FwpmFilterGetByKey0",
        "same_guid(&f.filterKey, &spec.key)", "same_guid(&f.layerKey, &spec.layer_key)",
        "same_guid(&f.subLayerKey, &SUBLAYER_KEY)", "same_guid(&*f.providerKey, &PROVIDER_KEY)",
        "f.flags == FWPM_FILTER_FLAG_PERSISTENT", "f.action.r#type == FWP_ACTION_BLOCK",
        "f.numFilterConditions as usize == spec.conditions.len()", "!f.filterCondition.is_null()",
        "build_conditions(spec.conditions, &user)?", "actual.matchType == expected.matchType",
        "(*a.sd).size == (*e.sd).size", "WFP condition value mismatch",
    ] {
        assert!(verify.contains(required), "missing readback: {required}");
    }
    let add = between(WFP, "fn add_filter(", "fn build_conditions(");
    for required in ["build_conditions(spec.conditions, user_condition)?", "flags: FWPM_FILTER_FLAG_PERSISTENT", "r#type: FWP_ACTION_BLOCK", "weight: empty_value()", "subLayerKey: SUBLAYER_KEY"] {
        assert!(add.contains(required));
    }
    assert!(WFP.contains("serviceName: null_mut()"));
    assert!(WFP.contains("weight: 0x8000"));
    assert!(WFP.contains("GUID::from_u128(0xfdf5f7962e035500b81b83e9e8b69f8d)"));
    assert!(WFP.contains("GUID::from_u128(0xa112309bf79e58a7bf97348979bad2fb)"));
    for required in ["FwpmTransactionBegin0", "FwpmTransactionCommit0", "FwpmTransactionAbort0", "if !self.committed"] {
        assert!(WFP.contains(required));
    }
}

#[test]
fn metadata_is_read_only_and_failure_cannot_activate_the_account() {
    assert!(NETWORK.contains("pub fn expected_wfp_filter_count() -> usize"));
    assert!(NETWORK.contains("wfp::expected_filter_count()"));
    assert!(WFP.contains("FILTER_SPECS.len()"));
    let metadata = between(NETWORK, "pub fn wfp_policy_provenance", "pub(crate) fn install_offline_protection");
    assert!(metadata.contains("cfg!(feature = \"lab-python-policy-repair-comparison\")"));
    assert!(metadata.contains("lab-owned-account-connect-block-v1"));
    assert!(metadata.contains("baseline-port-icmp-v1"));
    let provision = between(SETUP, "pub fn provision_offline_account", "/// Read-only broker logon seam");
    assert!(provision.find("network::install_offline_protection").unwrap() < provision.find("network::verify_offline_protection").unwrap());
    assert!(provision.find("network::verify_offline_protection").unwrap() < provision.find("accounts::set_disabled(&sid, false)").unwrap());
    assert!(provision.contains("ownership.rollback()"));
    let disable = between(SETUP, "pub fn disable_offline_account", "/// Validated broker identity");
    assert!(disable.contains("accounts::set_disabled(&record.account_sid, true)"));
    assert!(!disable.contains("remove_wfp_filters"));
}
