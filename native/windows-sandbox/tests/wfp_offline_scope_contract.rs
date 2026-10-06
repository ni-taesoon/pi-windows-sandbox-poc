//! Portable source contracts only. These never open WFP, change accounts or
//! security, launch a canary, or establish Windows enforcement.
use std::collections::BTreeSet;

const SPECS: &str = include_str!("../src/network/wfp/filter_specs.rs");
const WFP: &str = include_str!("../src/network/wfp.rs");
const NETWORK: &str = include_str!("../src/network.rs");
const SETUP: &str = include_str!("../src/setup.rs");
const FEATURE: &str = r#"#[cfg(any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance"))]"#;
const OFFLINE_V4_FEATURE: &str = r#"#[cfg(all(not(feature = "lab-python-online-pdf"), any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance")))]"#;
const ONLINE_FEATURE: &str = r#"#[cfg(feature = "lab-python-online-pdf")]"#;
const FIREWALL: &str = include_str!("../src/network/firewall.rs");

struct Spec<'a> {
    body: &'a str,
    gate: String,
}

fn specs() -> Vec<Spec<'static>> {
    SPECS
        .match_indices("    FilterSpec {")
        .map(|(start, _)| {
            let end = start + SPECS[start..].find("\n    },").unwrap();
            Spec {
                body: &SPECS[start..end],
                gate: {
                    let prefix = SPECS[..start].trim_end();
                    if prefix.ends_with(']') {
                        compact(&prefix[prefix.rfind("#[cfg(").unwrap()..])
                    } else {
                        String::new()
                    }
                },
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
    let baseline: Vec<_> = specs().into_iter().filter(|spec| spec.gate.is_empty()).collect();
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
fn original_offline_connect_specs_keep_identity_and_only_v4_is_replaced_online() {
    let all = specs();
    assert_eq!(all.len(), 17);
    assert_eq!(all.iter().filter(|s| s.gate == compact(FEATURE)).count(), 1);
    assert_eq!(all.iter().filter(|s| s.gate == compact(OFFLINE_V4_FEATURE)).count(), 1);
    assert_eq!(all.iter().filter(|s| s.gate == compact(ONLINE_FEATURE)).count(), 3);
    let keys: BTreeSet<_> = all.iter().map(|s| between(s.body, "GUID::from_u128(0x", ")")).collect();
    let names: BTreeSet<_> = all.iter().map(|s| between(s.body, "name: \"", "\"")).collect();
    assert_eq!(keys.len(), all.len());
    assert_eq!(names.len(), all.len());
    let added: Vec<_> = all.iter().filter(|spec| !spec.gate.is_empty() && spec.gate != compact(ONLINE_FEATURE)).collect();
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
        "FWP_UINT32 => a.uint32 == e.uint32", "FWPM_TXN_READ_ONLY",
        "verify_exact_profile_inventory(engine.handle)?",
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
    assert!(metadata.contains("lab-python-policy-repair-comparison"));
    assert!(metadata.contains("codex-policy-with-lab-fixed-online-pypi-relay-v1"));
    assert!(metadata.find("lab-python-online-pdf").unwrap()
        < metadata.find("lab-python-codex-policy-acceptance").unwrap());
    assert!(metadata.contains("codex-policy-with-lab-owned-account-connect-block-v1"));
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

fn compiled_specs(offline: bool, online: bool) -> Vec<Spec<'static>> {
    assert!(!online || offline, "online feature depends on offline Codex lab feature");
    specs().into_iter().filter(|spec| {
        if spec.gate.is_empty() { true }
        else if spec.gate == compact(ONLINE_FEATURE) { online }
        else if spec.gate == compact(OFFLINE_V4_FEATURE) { offline && !online }
        else { assert_eq!(spec.gate, compact(FEATURE)); offline }
    }).collect()
}

#[test]
fn compiled_profiles_have_exact_counts_without_changing_offline_defaults() {
    assert_eq!(compiled_specs(false, false).len(), 12);
    assert_eq!(compiled_specs(true, false).len(), 14);
    assert_eq!(compiled_specs(true, true).len(), 16);
    let online = compiled_specs(true, true);
    assert!(!online.iter().any(|s| s.body.contains("pi_sandbox_wfp_offline_connect_v4")));
    assert!(online.iter().any(|s| s.body.contains("pi_sandbox_wfp_offline_connect_v6")));
    assert!(!WFP.contains("FWP_ACTION_PERMIT"));
}

#[test]
fn exact_online_complement_uses_three_unique_owned_account_blocks() {
    let expected = [
        ("4627aa81d7235ea982f4f277f26a3d2b", "not_relay_address", "RemoteAddressV4Not(0x7f000001)"),
        ("0b6d9a1f41265a698c9c60a6040d9f42", "not_tcp", "ProtocolNot(6)"),
        ("78f5d091c6135d34a8b178068f1372a7", "not_relay_port", "RemotePortNot(43873)"),
    ];
    let online: Vec<_> = specs().into_iter().filter(|s| s.gate == compact(ONLINE_FEATURE)).collect();
    assert_eq!(online.len(), expected.len());
    for (spec, (key, name, condition)) in online.iter().zip(expected) {
        assert_eq!(between(spec.body, "GUID::from_u128(0x", ")"), key);
        assert_eq!(between(spec.body, "name: \"", "\""), format!("pi_sandbox_wfp_online_pdf_{name}_v4"));
        assert_eq!(between(spec.body, "layer_key: FWPM_LAYER_", ","), "ALE_AUTH_CONNECT_V4");
        assert_eq!(compact(between(spec.body, "conditions: &[", "]")).trim_end_matches(','),
            format!("ConditionSpec::User,ConditionSpec::{condition}"));
    }
}

#[test]
fn online_builder_uses_documented_host_order_sortable_not_equal_values() {
    for (variant, field, kind, member, binding) in [
        ("RemoteAddressV4Not", "IP_REMOTE_ADDRESS", "UINT32", "uint32", "address"),
        ("ProtocolNot", "IP_PROTOCOL", "UINT8", "uint8", "protocol"),
        ("RemotePortNot", "IP_REMOTE_PORT", "UINT16", "uint16", "port"),
    ] {
        let arm = between(WFP, &format!("ConditionSpec::{variant}({binding}) =>"), "\n            },");
        let arm = compact(arm);
        assert!(arm.contains(&format!("fieldKey:FWPM_CONDITION_{field},")));
        assert!(arm.contains("matchType:FWP_MATCH_NOT_EQUAL,"));
        assert!(arm.contains(&format!("r#type:FWP_{kind},")));
        assert!(arm.contains(&format!("{member}:*{binding}")));
        assert!(!arm.contains(".to_be()"));
        assert!(!arm.contains(".swap_bytes()"));
    }
    assert_eq!(u32::from_be_bytes([127, 0, 0, 1]), 0x7f000001);
    assert_ne!(0x7f000001u32.swap_bytes(), 0x7f000001);
}

// Pure model of the literal compiled specs. It uses the source conditions, not
// a second hand-written allowlist, and never opens sockets or calls WFP.
fn blocked(specs: &[Spec<'_>], owned: bool, v6: bool, address: u32, protocol: u8, port: u16) -> bool {
    specs.iter().any(|spec| {
        let layer = between(spec.body, "layer_key: FWPM_LAYER_", ",");
        if layer != if v6 { "ALE_AUTH_CONNECT_V6" } else { "ALE_AUTH_CONNECT_V4" } {
            return false;
        }
        compact(between(spec.body, "conditions: &[", "]"))
            .split("ConditionSpec::").skip(1).all(|raw| {
                let condition = raw.trim_end_matches(',');
                if condition == "User" { return owned; }
                let (name, value) = condition.split_once('(').unwrap();
                let value = value.trim_end_matches(')');
                let value = match value {
                    "IPPROTO_ICMPasu8" => 1,
                    "IPPROTO_ICMPV6asu8" => 58,
                    value if value.starts_with("0x") => u32::from_str_radix(&value[2..], 16).unwrap(),
                    value => value.parse::<u32>().unwrap(),
                };
                match name {
                    "Protocol" => protocol as u32 == value,
                    "RemotePort" => port as u32 == value,
                    "RemoteAddressV4Not" => address != value,
                    "ProtocolNot" => protocol as u32 != value,
                    "RemotePortNot" => port as u32 != value,
                    _ => panic!("unexpected condition {condition}"),
                }
            })
    })
}

#[test]
fn only_exact_ipv4_tcp_relay_tuple_escapes_the_block_union() {
    let online = compiled_specs(true, true);
    assert!(!blocked(&online, true, false, 0x7f000001, 6, 43873));
    for port in 0..=u16::MAX {
        assert_eq!(blocked(&online, true, false, 0x7f000001, 6, port), port != 43873);
    }
    for protocol in 0..=u8::MAX {
        assert_eq!(blocked(&online, true, false, 0x7f000001, protocol, 43873), protocol != 6);
        assert!(blocked(&online, true, true, 0, protocol, 43873));
        assert!(!blocked(&online, false, false, 0x01010101, protocol, 443));
        assert!(!blocked(&online, false, true, 0, protocol, 443));
    }
    for address in [0, 1, 0x0100007f, 0x7f000000, 0x7f000002, 0x7fffffff, 0x01010101, 0xffffffff] {
        assert!(blocked(&online, true, false, address, 6, 43873));
    }
    for bit in 0..32 { assert!(blocked(&online, true, false, 0x7f000001 ^ (1 << bit), 6, 43873)); }
    let offline = compiled_specs(true, false);
    assert!(blocked(&offline, true, false, 0x7f000001, 6, 43873));
    assert!(blocked(&offline, true, true, 0, 6, 43873));
}

#[test]
fn firewall_exception_is_fresh_tcp_remote_port_complement_only() {
    let install = between(NETWORK, "pub(crate) fn install_offline_protection", "/// Read-only configuration");
    assert!(install.find("require_product_namespace_absent()?").unwrap()
        < install.find("firewall::ensure_offline_network_blocks").unwrap());
    let ports = between(FIREWALL, "let tcp_blocked_ports =", "for (name, description, protocol, remote_ports)");
    assert!(ports.contains("cfg!(feature = \"lab-python-online-pdf\")"));
    assert!(ports.contains("Some(\"1-43872,43874-65535\")"));
    assert!(ports.contains("None"));
    let loopback = compact(between(FIREWALL, "for (name, description, protocol, remote_ports)", "// Pi offline mode"));
    assert!(loopback.contains("NET_FW_IP_PROTOCOL_TCP.0,tcp_blocked_ports,"));
    assert!(loopback.contains("NET_FW_IP_PROTOCOL_UDP.0,None,"));
    assert!(loopback.contains("direction:NET_FW_RULE_DIR_OUT,"));
    assert!(loopback.contains("remote_addresses:Some(LOOPBACK_REMOTE_ADDRESSES),remote_ports,"));
    let other = between(FIREWALL, "// Pi offline mode", "fn ensure_local_policy_rules_take_effect");
    assert_eq!(other.matches("remote_ports: None").count(), 3);
    let existing = between(FIREWALL, "Ok(existing) =>", "Err(err) if");
    assert!(existing.contains("verify_rule(&existing, spec)?"));
    assert!(!existing.contains("configure_rule("));
    assert!(!existing.contains("SetRemotePorts"));
    let fresh = between(FIREWALL, "let new_rule: INetFwRule3", "Err(err) =>");
    assert!(fresh.find("configure_rule(&new_rule, spec)?").unwrap() < fresh.find("rules.Add(&new_rule)").unwrap());
}

#[test]
fn online_inventory_rejects_unknown_duplicate_or_missing_product_filters_read_only() {
    let inventory = WFP.split_once("fn verify_exact_profile_inventory").unwrap().1;
    for required in [
        "FwpmFilterCreateEnumHandle0(engine, &template", "FwpmFilterEnum0",
        "providerKey: &mut provider_key", "layerKey: layer", "count < requested",
        "count as usize == expected_count",
        "same_guid(unsafe { &*filter.providerKey }, &PROVIDER_KEY)",
        "same_guid(&filter.subLayerKey, &SUBLAYER_KEY)",
        "same_guid(&filter.filterKey, &spec.key)", "seen.insert(",
        "seen.len() == FILTER_SPECS.len()", "FwpmFilterDestroyEnumHandle0", "FwpmFreeMemory0",
    ] { assert!(inventory.contains(required), "missing exact inventory check: {required}"); }
    assert!(!inventory.contains("FwpmFilterCreateEnumHandle0(engine, null()"));
    assert!(!inventory.contains("FwpmFilterAdd0"));
    assert!(!inventory.contains("FwpmFilterDeleteByKey0"));
}
