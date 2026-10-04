// Derived from OpenAI Codex (Apache-2.0).
// Source: codex-rs/windows-sandbox-rs/src/setup_provisioning/firewall.rs
// Pinned revision: a956835d020762cb2b570053af06f643a11c0ecc
// Modified for Pi: standalone modules and product-owned identity; see repository-root third_party/codex/PROVENANCE.md.

use anyhow::Result;
use std::io::Write;

use windows::core::Interface;
use windows::core::BSTR;
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

use crate::setup::SetupErrorCode;
use crate::setup::SetupFailure;

// This is the stable identifier we use to find/update the rule idempotently.
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
    offline_sid: &'a str,
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
                ensure_block_rule(
                    &rules,
                    &BlockRuleSpec {
                        internal_name: name,
                        friendly_desc: description,
                        direction: NET_FW_RULE_DIR_OUT,
                        protocol,
                        local_user_spec: &local_user_spec,
                        offline_sid,
                        remote_addresses: Some(LOOPBACK_REMOTE_ADDRESSES),
                        remote_ports: None,
                    },
                    log,
                )?;
            }

            // Pi offline mode has no local-binding exception: prevent a host
            // peer from reaching a sandbox listener over loopback as well.
            ensure_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: "pi_sandbox_offline_block_loopback_inbound",
                    friendly_desc: "Pi Sandbox Offline - Block Loopback Inbound",
                    direction: NET_FW_RULE_DIR_IN,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    offline_sid,
                    remote_addresses: Some(LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
            )?;

            // Block all outbound IP protocols for this user.
            ensure_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: OFFLINE_BLOCK_RULE_NAME,
                    friendly_desc: OFFLINE_BLOCK_RULE_FRIENDLY,
                    direction: NET_FW_RULE_DIR_OUT,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    offline_sid,
                    remote_addresses: Some(NON_LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
            )?;
            ensure_block_rule(
                &rules,
                &BlockRuleSpec {
                    internal_name: OFFLINE_BLOCK_INBOUND_RULE_NAME,
                    friendly_desc: OFFLINE_BLOCK_INBOUND_RULE_FRIENDLY,
                    direction: NET_FW_RULE_DIR_IN,
                    protocol: NET_FW_IP_PROTOCOL_ANY.0,
                    local_user_spec: &local_user_spec,
                    offline_sid,
                    remote_addresses: Some(NON_LOOPBACK_REMOTE_ADDRESSES),
                    remote_ports: None,
                },
                log,
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

fn ensure_block_rule(
    rules: &INetFwRules,
    spec: &BlockRuleSpec<'_>,
    log: &mut dyn Write,
) -> Result<()> {
    let name = BSTR::from(spec.internal_name);
    let rule: INetFwRule3 = match unsafe { rules.Item(&name) } {
        Ok(existing) => existing.cast().map_err(|err| {
            anyhow::Error::new(SetupFailure::new(
                SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                format!("cast existing firewall rule to INetFwRule3 failed: {err:?}"),
            ))
        })?,
        Err(_) => {
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
    };

    // Always re-apply fields to keep the setup idempotent.
    configure_rule(&rule, spec)?;

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

    // Read-back verification: ensure we actually wrote the expected SID scope.
    let actual = unsafe { rule.LocalUserAuthorizedList() }.map_err(|err| {
        anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleVerifyFailed,
            format!("LocalUserAuthorizedList (read-back) failed: {err:?}"),
        ))
    })?;
    let actual_str = actual.to_string();
    if !actual_str.contains(spec.offline_sid) {
        return Err(anyhow::Error::new(SetupFailure::new(
            SetupErrorCode::HelperFirewallRuleVerifyFailed,
            format!(
                "offline firewall rule user scope mismatch: expected SID {}, got {actual_str}",
                spec.offline_sid
            ),
        )));
    }
    Ok(())
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
        if let Some(remote_ports) = spec.remote_ports {
            rule.SetRemotePorts(&BSTR::from(remote_ports))
                .map_err(|err| {
                    anyhow::Error::new(SetupFailure::new(
                        SetupErrorCode::HelperFirewallRuleCreateOrAddFailed,
                        format!("SetRemotePorts failed: {err:?}"),
                    ))
                })?;
        }
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
