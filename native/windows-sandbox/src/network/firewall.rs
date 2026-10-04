// Derived from OpenAI Codex (Apache-2.0).
// Source: codex-rs/windows-sandbox-rs/src/setup_provisioning/firewall.rs
// Pinned revision: a956835d020762cb2b570053af06f643a11c0ecc
// Modified for Pi: standalone modules and product-owned identity; see repository-root third_party/codex/PROVENANCE.md.

use anyhow::Result;
use std::io::Write;

use windows::core::Interface;
use windows::core::BSTR;
use windows::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::Foundation::S_OK;
use windows::Win32::Foundation::VARIANT_TRUE;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule3;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwRules;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwRule;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_ACTION_BLOCK;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_IP_PROTOCOL_ANY;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_IP_PROTOCOL_TCP;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_IP_PROTOCOL_UDP;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_MODIFY_STATE;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_MODIFY_STATE_OK;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIRECTION;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIR_IN;
use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_RULE_DIR_OUT;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    NET_FW_PROFILE2_ALL, NET_FW_PROFILE2_DOMAIN, NET_FW_PROFILE2_PRIVATE, NET_FW_PROFILE2_PUBLIC,
};
use windows::Win32::System::Com::CoCreateInstance;
use windows::Win32::System::Com::CoInitializeEx;
use windows::Win32::System::Com::CoUninitialize;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::COINIT_APARTMENTTHREADED;

use crate::firewall_scope::{self, RuleScope};
use crate::setup::SetupErrorCode;
use crate::setup::SetupFailure;

// Stable lookup names. Existing rules are validated read-only, never adopted by name.
// It intentionally does not change between installs.
const OFFLINE_BLOCK_RULE_NAME: &str = "pi_sandbox_offline_block_outbound";
const OFFLINE_BLOCK_INBOUND_RULE_NAME: &str = "pi_sandbox_offline_block_inbound";
const OFFLINE_BLOCK_LOOPBACK_TCP_RULE_NAME: &str = "pi_sandbox_offline_block_loopback_tcp";
const OFFLINE_BLOCK_LOOPBACK_UDP_RULE_NAME: &str = "pi_sandbox_offline_block_loopback_udp";

// Friendly text shown in the firewall UI.
const OFFLINE_BLOCK_RULE_FRIENDLY: &str = "Pi Sandbox Offline - Block Non-Loopback Outbound";
const OFFLINE_BLOCK_INBOUND_RULE_FRIENDLY: &str = "Pi Sandbox Offline - Block Non-Loopback Inbound";
const OFFLINE_BLOCK_LOOPBACK_TCP_RULE_FRIENDLY: &str = "Pi Sandbox Offline - Block Loopback TCP";
const OFFLINE_BLOCK_LOOPBACK_UDP_RULE_FRIENDLY: &str = "Pi Sandbox Offline - Block Loopback UDP";

const LOOPBACK_REMOTE_ADDRESSES: &str = "127.0.0.0/8,::/127";
const NON_LOOPBACK_REMOTE_ADDRESSES: &str = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";

struct BlockRuleSpec<'a> {
    internal_name: &'a str,
    friendly_desc: &'a str,
    direction: NET_FW_RULE_DIRECTION,
    protocol: i32,
    local_user_spec: &'a str,
    remote_addresses: Option<&'a str>,
    remote_ports: Option<&'a str>,
}

// Firewall COM also supports the service's existing MTA. Balance only our own initialization.
struct FirewallComApartment {
    initialized: bool,
}

impl FirewallComApartment {
    fn initialize() -> Result<Self> {
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_err() && hr != RPC_E_CHANGED_MODE {
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallComInitFailed,
                format!("CoInitializeEx failed: {hr:?}"),
            )));
        }
        Ok(Self {
            initialized: hr.is_ok(),
        })
    }
}

impl Drop for FirewallComApartment {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { CoUninitialize() };
        }
    }
}

pub fn ensure_offline_network_blocks(offline_sid: &str, log: &mut dyn Write) -> Result<()> {
    offline_network_blocks(offline_sid, log, true)
}
/// Read-only effective policy/rule inspection. Never creates or repairs a rule.
pub fn verify_offline_network_blocks(offline_sid: &str) -> Result<()> {
    offline_network_blocks(offline_sid, &mut std::io::sink(), false)
}
fn offline_network_blocks(offline_sid: &str, log: &mut dyn Write, install: bool) -> Result<()> {
    let local_user_spec = format!("O:LSD:(A;;CC;;;{offline_sid})");

    let _apartment = FirewallComApartment::initialize()?;

    unsafe {
        (|| -> Result<()> {
            let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
                .map_err(|err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperFirewallPolicyAccessFailed,
                        format!("CoCreateInstance NetFwPolicy2 failed: {err:?}"),
                    ))
                })?;
            ensure_local_policy_rules_take_effect(&policy)?;
            let rules = policy.Rules().map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallPolicyAccessFailed,
                    format!("INetFwPolicy2::Rules failed: {err:?}"),
                ))
            })?;

            for (name, description, protocol) in [
                (
                    OFFLINE_BLOCK_LOOPBACK_TCP_RULE_NAME,
                    OFFLINE_BLOCK_LOOPBACK_TCP_RULE_FRIENDLY,
                    NET_FW_IP_PROTOCOL_TCP.0,
                ),
                (
                    OFFLINE_BLOCK_LOOPBACK_UDP_RULE_NAME,
                    OFFLINE_BLOCK_LOOPBACK_UDP_RULE_FRIENDLY,
                    NET_FW_IP_PROTOCOL_UDP.0,
                ),
            ] {
                check_or_install_block_rule(
                    &rules,
                    &BlockRuleSpec {
                        internal_name: name,
                        friendly_desc: description,
                        direction: NET_FW_RULE_DIR_OUT,
                        protocol,
                        local_user_spec: &local_user_spec,
                        remote_addresses: Some(LOOPBACK_REMOTE_ADDRESSES),
                        remote_ports: None,
                    },
                    log,
                    install,
                )?;
            }

            // Pi offline mode has no local-binding exception: prevent a host
            // peer from reaching a sandbox listener over loopback as well.
            check_or_install_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: "pi_sandbox_offline_block_loopback_inbound",
                    friendly_desc: "Pi Sandbox Offline - Block Loopback Inbound",
                    direction: NET_FW_RULE_DIR_IN,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    remote_addresses: Some(LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
                install,
            )?;

            // Block all outbound IP protocols for this user.
            check_or_install_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: OFFLINE_BLOCK_RULE_NAME,
                    friendly_desc: OFFLINE_BLOCK_RULE_FRIENDLY,
                    direction: NET_FW_RULE_DIR_OUT,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    remote_addresses: Some(NON_LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
                install,
            )?;
            check_or_install_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: OFFLINE_BLOCK_INBOUND_RULE_NAME,
                    friendly_desc: OFFLINE_BLOCK_INBOUND_RULE_FRIENDLY,
                    direction: NET_FW_RULE_DIR_IN,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    remote_addresses: Some(NON_LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
                install,
            )?;
            Ok(())
        })()
    }
}

fn ensure_local_policy_rules_take_effect(policy: &INetFwPolicy2) -> Result<()> {
    // Pi hardening: rule installation cannot count as protection with a disabled
    // firewall profile. Never silently turn on a host security setting.
    for profile in [
        NET_FW_PROFILE2_DOMAIN,
        NET_FW_PROFILE2_PRIVATE,
        NET_FW_PROFILE2_PUBLIC,
    ] {
        if unsafe { policy.get_FirewallEnabled(profile) }? != VARIANT_TRUE {
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallPolicyIneffective,
                format!("firewall profile {profile:?} is disabled"),
            )));
        }
    }

    let mut modify_state = NET_FW_MODIFY_STATE::default();
    let result = unsafe {
        (Interface::vtable(policy).LocalPolicyModifyState)(
            Interface::as_raw(policy),
            &mut modify_state,
        )
    };
    validate_local_policy_modify_result(result, modify_state)
}

fn validate_local_policy_modify_result(
    result: windows::core::HRESULT,
    modify_state: NET_FW_MODIFY_STATE,
) -> Result<()> {
    if result.is_err() {
        // The COM query itself failed, so Windows never gave us a policy answer.
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallPolicyAccessFailed,
            format!("INetFwPolicy2::LocalPolicyModifyState failed: {result:?}"),
        )));
    }

    if result != S_OK {
        // S_FALSE means the answer only holds for some active profiles, not all of them.
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallPolicyIneffective,
            format!(
                "local firewall policy modifications do not apply to every current profile: LocalPolicyModifyState result={result:?}"
            ),
        )));
    }

    if modify_state == NET_FW_MODIFY_STATE_OK {
        return Ok(());
    }

    // Windows answered uniformly, and that answer says local rule edits are ineffective.
    Err(anyhow::Error::new(SetupFailure::new(
        SetupErrorCode::HelperFirewallPolicyIneffective,
        format!(
            "local firewall policy modifications will not take effect: LocalPolicyModifyState={modify_state:?}"
        ),
    )))
}

fn check_or_install_block_rule(
    rules: &INetFwRules,
    spec: &BlockRuleSpec<'_>,
    log: &mut dyn Write,
    install: bool,
) -> Result<()> {
    if install {
        return ensure_block_rule(rules, spec, log);
    }
    let rule: INetFwRule3 = unsafe { rules.Item(&BSTR::from(spec.internal_name))? }.cast()?;
    verify_rule(&rule, spec)
}

fn ensure_block_rule(
    rules: &INetFwRules,
    spec: &BlockRuleSpec<'_>,
    log: &mut dyn Write,
) -> Result<()> {
    let name = BSTR::from(spec.internal_name);
    let rule: INetFwRule3 = match unsafe { rules.Item(&name) } {
        Ok(existing) => {
            let existing: INetFwRule3 = existing.cast().map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleVerifyFailed,
                    format!("cast existing firewall rule to INetFwRule3 failed: {err:?}"),
                ))
            })?;
            // A matching name is not ownership. Never rewrite a colliding rule.
            // Only accept an already-exact rule, with no mutations on this path.
            verify_rule(&existing, spec)?;
            existing
        }
        Err(err) if err.code() == windows::core::HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
            let new_rule: INetFwRule3 =
                unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(
                    |err| {
                        anyhow::Error::new(SetupFailure::new(
                            SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                            format!("CoCreateInstance NetFwRule failed: {err:?}"),
                        ))
                    },
                )?;
            unsafe { new_rule.SetName(&name) }.map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                    format!("SetName failed: {err:?}"),
                ))
            })?;
            // Set all properties before adding the rule so we don't leave half-configured rules.
            configure_rule(&new_rule, spec)?;
            unsafe { rules.Add(&new_rule) }.map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                    format!("Rules::Add failed: {err:?}"),
                ))
            })?;
            new_rule
        }
        Err(err) => {
            return Err(anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallPolicyAccessFailed,
                format!("Rules::Item failed (not a missing rule): {err:?}"),
            )));
        }
    };
    // Verify again after Add; COM acceptance alone is not the scope contract.
    verify_rule(&rule, spec)?;

    let remote_addresses_log = spec.remote_addresses.unwrap_or("*");
    let remote_ports_log = spec.remote_ports.unwrap_or("*");

    log_line(
        log,
        &format!(
            "firewall rule configured name={} protocol={} RemoteAddresses={remote_addresses_log} RemotePorts={remote_ports_log} LocalUserAuthorizedList={}",
            spec.internal_name, spec.protocol, spec.local_user_spec
        ),
    )?;
    Ok(())
}

fn configure_rule(rule: &INetFwRule3, spec: &BlockRuleSpec<'_>) -> Result<()> {
    unsafe {
        rule.SetDescription(&BSTR::from(spec.friendly_desc))
            .map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                    format!("SetDescription failed: {err:?}"),
                ))
            })?;
        rule.SetDirection(spec.direction).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("SetDirection failed: {err:?}"),
            ))
        })?;
        rule.SetAction(NET_FW_ACTION_BLOCK).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("SetAction failed: {err:?}"),
            ))
        })?;
        rule.SetEnabled(VARIANT_TRUE).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("SetEnabled failed: {err:?}"),
            ))
        })?;
        rule.SetProfiles(NET_FW_PROFILE2_ALL.0).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("SetProfiles failed: {err:?}"),
            ))
        })?;
        configure_rule_network_scope(rule, spec)?;
        rule.SetLocalUserAuthorizedList(&BSTR::from(spec.local_user_spec))
            .map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                    format!("SetLocalUserAuthorizedList failed: {err:?}"),
                ))
            })?;
    }

    verify_rule(rule, spec)
}

fn expected_rule_scope(spec: &BlockRuleSpec<'_>) -> RuleScope {
    RuleScope {
        name: spec.internal_name.into(),
        description: spec.friendly_desc.into(),
        direction: spec.direction.0,
        protocol: spec.protocol,
        action: NET_FW_ACTION_BLOCK.0,
        enabled: true,
        profiles: NET_FW_PROFILE2_ALL.0,
        user: spec.local_user_spec.into(),
        application: String::new(),
        service: String::new(),
        local_addresses: "*".into(),
        remote_addresses: spec.remote_addresses.unwrap_or("*").into(),
        local_ports: "*".into(),
        remote_ports: spec.remote_ports.unwrap_or("*").into(),
        interfaces_empty: true,
        interface_types: "All".into(),
        package: String::new(),
        owner: String::new(),
        remote_user: String::new(),
        remote_machine: String::new(),
        secure_flags: 0,
        edge_traversal: 0,
    }
}

fn verify_rule(rule: &INetFwRule3, spec: &BlockRuleSpec<'_>) -> Result<()> {
    let actual = (|| -> windows::core::Result<RuleScope> {
        unsafe {
            let protocol = rule.Protocol()?;
            // Ports only apply to TCP/UDP; COM rejects port access for other protocols.
            let has_ports =
                protocol == NET_FW_IP_PROTOCOL_TCP.0 || protocol == NET_FW_IP_PROTOCOL_UDP.0;
            Ok(RuleScope {
                name: rule.Name()?.to_string(),
                description: rule.Description()?.to_string(),
                direction: rule.Direction()?.0,
                protocol,
                action: rule.Action()?.0,
                enabled: rule.Enabled()? == VARIANT_TRUE,
                profiles: rule.Profiles()?,
                user: rule.LocalUserAuthorizedList()?.to_string(),
                application: rule.ApplicationName()?.to_string(),
                service: rule.ServiceName()?.to_string(),
                local_addresses: rule.LocalAddresses()?.to_string(),
                remote_addresses: rule.RemoteAddresses()?.to_string(),
                local_ports: if has_ports {
                    rule.LocalPorts()?.to_string()
                } else {
                    "*".into()
                },
                remote_ports: if has_ports {
                    rule.RemotePorts()?.to_string()
                } else {
                    "*".into()
                },
                interfaces_empty: rule.Interfaces()?.is_empty(),
                interface_types: rule.InterfaceTypes()?.to_string(),
                package: rule.LocalAppPackageId()?.to_string(),
                owner: rule.LocalUserOwner()?.to_string(),
                remote_user: rule.RemoteUserAuthorizedList()?.to_string(),
                remote_machine: rule.RemoteMachineAuthorizedList()?.to_string(),
                secure_flags: rule.SecureFlags()?,
                edge_traversal: rule.EdgeTraversalOptions()?,
            })
        }
    })()
    .map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleVerifyFailed,
            format!("firewall scope read-back failed: {err:?}"),
        ))
    })?;
    firewall_scope::validate(&actual, &expected_rule_scope(spec)).map_err(|reason| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleVerifyFailed,
            format!("rule {}: {reason}", spec.internal_name),
        ))
    })
}

fn configure_rule_network_scope(rule: &INetFwRule3, spec: &BlockRuleSpec<'_>) -> Result<()> {
    unsafe {
        rule.SetProtocol(spec.protocol).map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("SetProtocol failed: {err:?}"),
            ))
        })?;
        let remote_addresses = spec.remote_addresses.unwrap_or("*");
        rule.SetRemoteAddresses(&BSTR::from(remote_addresses))
            .map_err(|err| {
                anyhow::Error::new(SetupFailure::new(
                    SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                    format!("SetRemoteAddresses failed: {err:?}"),
                ))
            })?;
        // This function is used only for a fresh, not-yet-added COM object.
        // Clear optional selectors explicitly, and verify every selector below.
        let unrestricted = (|| -> windows::core::Result<()> {
            rule.SetApplicationName(&BSTR::new())?;
            rule.SetServiceName(&BSTR::new())?;
            rule.SetLocalAddresses(&BSTR::from("*"))?;
            rule.SetInterfaces(&windows::core::VARIANT::default())?;
            rule.SetInterfaceTypes(&BSTR::from("All"))?;
            if spec.protocol == NET_FW_IP_PROTOCOL_TCP.0
                || spec.protocol == NET_FW_IP_PROTOCOL_UDP.0
            {
                rule.SetLocalPorts(&BSTR::from("*"))?;
                rule.SetRemotePorts(&BSTR::from(spec.remote_ports.unwrap_or("*")))?;
            }
            Ok(())
        })();
        unrestricted.map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("set unrestricted firewall selectors failed: {err:?}"),
            ))
        })?;
    }

    Ok(())
}

fn log_line(log: &mut dyn Write, msg: &str) -> Result<()> {
    writeln!(log, "{msg}")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::S_FALSE;
    use windows::Win32::NetworkManagement::WindowsFirewall::NET_FW_MODIFY_STATE_GP_OVERRIDE;
    #[test]
    fn rejects_partial_or_overridden_policy() {
        assert!(validate_local_policy_modify_result(S_OK, NET_FW_MODIFY_STATE_OK).is_ok());
        assert!(validate_local_policy_modify_result(S_FALSE, NET_FW_MODIFY_STATE_OK).is_err());
        assert!(
            validate_local_policy_modify_result(S_OK, NET_FW_MODIFY_STATE_GP_OVERRIDE).is_err()
        );
    }
}

pub fn require_namespace_absent() -> Result<()> {
    let _apartment = FirewallComApartment::initialize()?;
    unsafe {
        let policy: INetFwPolicy2 = CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)?;
        ensure_local_policy_rules_take_effect(&policy)?;
        let rules = policy.Rules()?;
        for name in [
            OFFLINE_BLOCK_RULE_NAME,
            OFFLINE_BLOCK_INBOUND_RULE_NAME,
            OFFLINE_BLOCK_LOOPBACK_TCP_RULE_NAME,
            OFFLINE_BLOCK_LOOPBACK_UDP_RULE_NAME,
            "pi_sandbox_offline_block_loopback_inbound",
        ] {
            match rules.Item(&BSTR::from(name)) {
                Ok(_) => anyhow::bail!("existing Pi firewall rule: {name}"),
                Err(error) => anyhow::ensure!(
                    error.code().0 as u32 == 0x80070002,
                    "cannot inspect firewall namespace: {error}"
                ),
            }
        }
    }
    Ok(())
}
