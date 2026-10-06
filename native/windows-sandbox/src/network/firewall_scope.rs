//! Portable firewall readback contract, used by the Windows COM adapter.
//! These tests verify admission decisions, not Windows packet enforcement.
#[path = "address_sets.rs"]
mod address_sets;

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

// Every field except remote_addresses remains exact. The one numeric IP selector
// is compared by its full parsed union; invalid or changed sets fail closed.
pub(crate) fn validate(actual: &RuleScope, expected: &RuleScope) -> Result<(), &'static str> {
    macro_rules! exact { ($($field:ident),+ $(,)?) => { $(actual.$field == expected.$field)&&+ }; }
    let other_fields_exact = exact!(
        name,
        description,
        direction,
        protocol,
        action,
        enabled,
        profiles,
        user,
        application,
        service,
        local_addresses,
        local_ports,
        remote_ports,
        interfaces_empty,
        interface_types,
        package,
        owner,
        remote_user,
        remote_machine,
        secure_flags,
        edge_traversal
    );
    if !other_fields_exact
        || !address_sets::equivalent(&actual.remote_addresses, &expected.remote_addresses)
    {
        return Err("firewall rule differs from the complete expected scope; refusing to adopt or modify it");
    }
    Ok(())
}

/// Diagnostic field names are compile-time constants, never COM-returned values.
/// This function does not participate in admission or normalize any field.
pub(crate) fn mismatched_fields(actual: &RuleScope, expected: &RuleScope) -> Vec<&'static str> {
    let mut fields = Vec::new();
    macro_rules! compare { ($($field:ident),+ $(,)?) => { $(
        if actual.$field != expected.$field { fields.push(stringify!($field)); }
    )+ }; }
    compare!(
        name,
        description,
        direction,
        protocol,
        action,
        enabled,
        profiles,
        user,
        application,
        service,
        local_addresses,
        remote_addresses,
        local_ports,
        remote_ports,
        interfaces_empty,
        interface_types,
        package,
        owner,
        remote_user,
        remote_machine,
        secure_flags,
        edge_traversal
    );
    fields
}

/// Safe metadata only: string byte lengths, or scalar integers/booleans.
/// Never format RuleScope or any raw COM string into a diagnostic.
pub(crate) fn mismatch_metadata(actual: &RuleScope, expected: &RuleScope) -> Vec<String> {
    let mut summaries = Vec::new();
    macro_rules! strings { ($($field:ident),+ $(,)?) => { $(
        if actual.$field != expected.$field {
            summaries.push(format!("{}:actual_bytes={},expected_bytes={}",stringify!($field),actual.$field.len(),expected.$field.len()));
        }
    )+ }; }
    macro_rules! scalars { ($($field:ident),+ $(,)?) => { $(
        if actual.$field != expected.$field {
            summaries.push(format!("{}:actual={},expected={}",stringify!($field),actual.$field,expected.$field));
        }
    )+ }; }
    strings!(
        name,
        description,
        user,
        application,
        service,
        local_addresses,
        remote_addresses,
        local_ports,
        remote_ports,
        interface_types,
        package,
        owner,
        remote_user,
        remote_machine
    );
    scalars!(
        direction,
        protocol,
        action,
        enabled,
        profiles,
        interfaces_empty,
        secure_flags,
        edge_traversal
    );
    summaries
}

#[cfg(test)]
mod tests {
    use super::*;
    fn expected() -> RuleScope {
        RuleScope {
            name: "pi_sandbox_offline_block_loopback_tcp".into(),
            description: "Pi Sandbox Offline - Block Loopback TCP".into(),
            direction: 2,
            protocol: 6,
            action: 0,
            enabled: true,
            profiles: i32::MAX,
            user: "O:LSD:(A;;CC;;;S-1-5-21-1001)".into(),
            application: "".into(),
            service: "".into(),
            local_addresses: "*".into(),
            remote_addresses: "127.0.0.0/8,::/127".into(),
            local_ports: "*".into(),
            remote_ports: "*".into(),
            interfaces_empty: true,
            interface_types: "All".into(),
            package: "".into(),
            owner: "".into(),
            remote_user: "".into(),
            remote_machine: "".into(),
            secure_flags: 0,
            edge_traversal: 0,
        }
    }
    #[test]
    fn accepts_exact_readback() {
        let scope = expected();
        assert_eq!(validate(&scope, &scope), Ok(()));
    }
    #[test]
    fn fixed_online_relay_complement_requires_exact_readback() {
        let mut online = expected();
        online.remote_ports = "1-43872,43874-65535".into();
        assert_eq!(validate(&online, &online), Ok(()));
        for ports in [
            "*", "", "1-65535", "1-43871,43874-65535", "1-43872,43875-65535",
            "43873", "1-43872", "43874-65535", "1-43872,43873-65535",
        ] {
            let mut actual = online.clone();
            actual.remote_ports = ports.into();
            assert!(validate(&actual, &online).is_err(), "accepted changed relay complement {ports}");
        }
        // The new profile cannot adopt the old wildcard rule or vice versa.
        assert!(validate(&expected(), &online).is_err());
        assert!(validate(&online, &expected()).is_err());
        for field in ["user", "protocol", "direction", "remote_addresses"] {
            let mut actual = online.clone();
            match field {
                "user" => actual.user = "O:LSD:(A;;CC;;;S-1-5-21-9999)".into(),
                "protocol" => actual.protocol = 17,
                "direction" => actual.direction = 1,
                "remote_addresses" => actual.remote_addresses = "127.0.0.1".into(),
                _ => unreachable!(),
            }
            assert!(validate(&actual, &online).is_err(), "accepted changed {field}");
        }
    }
    #[test]
    fn rejects_unexpected_application() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.application = "C:\\only-one.exe".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected application: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_service() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.service = "OnlyOneService".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected service: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_local_addresses() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.local_addresses = "192.0.2.1".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected local_addresses: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_local_ports() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.local_ports = "443".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected local_ports: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_remote_ports() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_ports = "443".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected remote_ports: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_interfaces_empty() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.interfaces_empty = false;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected interfaces_empty: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_interface_types() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.interface_types = "Wireless".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected interface_types: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_package() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.package = "S-1-15-2-1".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected package: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_owner() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.owner = "S-1-5-21-99".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected owner: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_remote_user() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_user = "O:LSD:(A;;CC;;;S-1-5-21-99)".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected remote_user: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_remote_machine() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_machine = "O:LSD:(A;;CC;;;S-1-5-21-99)".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected remote_machine: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_secure_flags() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.secure_flags = 1;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected secure_flags: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_edge_traversal() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.edge_traversal = 1;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected edge_traversal: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_enabled() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.enabled = false;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected enabled: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_action() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.action = 1;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected action: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_protocol() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.protocol = 17;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected protocol: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_direction() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.direction = 1;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected direction: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_profiles() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.profiles = 1;
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected profiles: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_remote_addresses() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_addresses = "127.0.0.1".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected remote_addresses: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_description() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.description = "Unrelated owner rule".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected description: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_name() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.name = "another-rule".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected name: {actual:?}"
        );
    }
    #[test]
    fn rejects_unexpected_user() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.user = "O:LSD:(A;;CC;;;S-1-5-21-10010)".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "accepted unexpected user: {actual:?}"
        );
    }
    #[test]
    fn diagnostics_identify_all_fields_without_string_values() {
        let expected = expected();
        let mut actual = expected.clone();
        let secret = "DO_NOT_LOG_RAW_C:\\runner\\token-S-1-5-21-987654321";
        macro_rules! change_strings { ($($field:ident),+ $(,)?) => { $(actual.$field=secret.into();)+ }; }
        change_strings!(
            name,
            description,
            user,
            application,
            service,
            local_addresses,
            remote_addresses,
            local_ports,
            remote_ports,
            interface_types,
            package,
            owner,
            remote_user,
            remote_machine
        );
        actual.direction = 1;
        actual.protocol = 17;
        actual.action = 1;
        actual.enabled = false;
        actual.profiles = 1;
        actual.interfaces_empty = false;
        actual.secure_flags = 1;
        actual.edge_traversal = 1;
        assert_eq!(
            mismatched_fields(&actual, &expected),
            vec![
                "name",
                "description",
                "direction",
                "protocol",
                "action",
                "enabled",
                "profiles",
                "user",
                "application",
                "service",
                "local_addresses",
                "remote_addresses",
                "local_ports",
                "remote_ports",
                "interfaces_empty",
                "interface_types",
                "package",
                "owner",
                "remote_user",
                "remote_machine",
                "secure_flags",
                "edge_traversal"
            ]
        );
        let details = mismatch_metadata(&actual, &expected);
        assert_eq!(details.len(), 22);
        let text = details.join(";");
        assert!(!text.contains(secret));
        assert!(!text.contains("S-1-5"));
        assert!(!text.contains("runner"));
        assert!(!text.contains("Pi Sandbox"));
        assert!(text.contains("enabled:actual=false,expected=true"));
        assert!(text.contains("protocol:actual=17,expected=6"));
        assert!(text.contains(&format!(
            "owner:actual_bytes={},expected_bytes=0",
            secret.len()
        )));
        assert!(validate(&actual, &expected).is_err());
    }
    #[test]
    fn exact_match_has_no_diagnostic_fields() {
        let expected = expected();
        assert!(mismatched_fields(&expected, &expected).is_empty());
        assert!(mismatch_metadata(&expected, &expected).is_empty());
        assert!(validate(&expected, &expected).is_ok());
    }
    #[test]
    fn accepts_equivalent_dotted_remote_mask_but_no_other_field_change() {
        let expected = expected();
        let mut actual = expected.clone();
        actual.remote_addresses = "127.0.0.0/255.0.0.0,::/127".into();
        assert!(validate(&actual, &expected).is_ok());
        actual.local_addresses = "0.0.0.0/0,::/0".into();
        assert!(
            validate(&actual, &expected).is_err(),
            "local selector must remain exact"
        );
    }
}
