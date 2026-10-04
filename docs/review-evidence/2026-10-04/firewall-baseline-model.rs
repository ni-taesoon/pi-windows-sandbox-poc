//! Portable firewall readback contract, used by the Windows COM adapter.
//! These tests verify admission decisions, not Windows packet enforcement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RuleScope {
    pub name: String,
    pub description: String,
    pub direction: i32,
    pub protocol: i32,
    pub action: i32,
    pub enabled: bool,
    pub profiles: i32,
    pub user: String,
    pub application: String,
    pub service: String,
    pub local_addresses: String,
    pub remote_addresses: String,
    pub local_ports: String,
    pub remote_ports: String,
    pub interfaces_empty: bool,
    pub interface_types: String,
    pub package: String,
    pub owner: String,
    pub remote_user: String,
    pub remote_machine: String,
    pub secure_flags: i32,
    pub edge_traversal: i32,
}

// Baseline decision extracted unchanged from configure_rule's SID-only readback.
pub(crate) fn validate(actual: &RuleScope, expected: &RuleScope, offline_sid: &str) -> Result<(), &'static str> {
    struct Spec<'a> { offline_sid: &'a str }
    let spec = Spec { offline_sid };
    let actual_str = &actual.user;
    let _ = expected;
    if !actual_str.contains(spec.offline_sid) { return Err("user scope mismatch"); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> RuleScope {
        RuleScope {
            name: "pi_sandbox_offline_block_loopback_tcp".into(),
            description: "Pi Sandbox Offline - Block Loopback TCP".into(),
            direction: 2, protocol: 6, action: 0, enabled: true, profiles: i32::MAX,
            user: "O:LSD:(A;;CC;;;S-1-5-21-1001)".into(),
            application: "".into(), service: "".into(), local_addresses: "*".into(),
            remote_addresses: "127.0.0.0/8,::/127".into(), local_ports: "*".into(),
            remote_ports: "*".into(), interfaces_empty: true, interface_types: "All".into(),
            package: "".into(), owner: "".into(), remote_user: "".into(),
            remote_machine: "".into(), secure_flags: 0, edge_traversal: 0,
        }
    }
    #[test]
    fn accepts_exact_readback() {
        let scope = expected();
        assert_eq!(validate(&scope, &scope, "S-1-5-21-1001"), Ok(()));
    }
    #[test]
    fn rejects_unexpected_application() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.application = "C:\\only-one.exe".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected application: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_service() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.service = "OnlyOneService".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected service: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_local_addresses() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.local_addresses = "192.0.2.1".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected local_addresses: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_local_ports() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.local_ports = "443".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected local_ports: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_remote_ports() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_ports = "443".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected remote_ports: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_interfaces_empty() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.interfaces_empty = false;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected interfaces_empty: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_interface_types() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.interface_types = "Wireless".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected interface_types: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_package() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.package = "S-1-15-2-1".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected package: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_owner() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.owner = "S-1-5-21-99".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected owner: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_remote_user() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_user = "O:LSD:(A;;CC;;;S-1-5-21-99)".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected remote_user: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_remote_machine() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_machine = "O:LSD:(A;;CC;;;S-1-5-21-99)".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected remote_machine: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_secure_flags() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.secure_flags = 1;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected secure_flags: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_edge_traversal() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.edge_traversal = 1;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected edge_traversal: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_enabled() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.enabled = false;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected enabled: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_action() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.action = 1;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected action: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_protocol() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.protocol = 17;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected protocol: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_direction() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.direction = 1;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected direction: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_profiles() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.profiles = 1;
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected profiles: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_remote_addresses() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_addresses = "127.0.0.1".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected remote_addresses: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_description() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.description = "Unrelated owner rule".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected description: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_name() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.name = "another-rule".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected name: {actual:?}");
    }
    #[test]
    fn rejects_unexpected_user() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.user = "O:LSD:(A;;CC;;;S-1-5-21-10010)".into();
        assert!(validate(&actual, &expected, "S-1-5-21-1001").is_err(),
            "accepted unexpected user: {actual:?}");
    }
}
