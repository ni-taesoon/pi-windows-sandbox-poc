// Derived from OpenAI Codex (Apache-2.0).
// Source: codex-rs/windows-sandbox-rs/src/wfp/filter_specs.rs
// Pinned revision: a956835d020762cb2b570053af06f643a11c0ecc
// Modified for Pi: standalone modules and product-owned identity; see repository-root third_party/codex/PROVENANCE.md.

use windows_sys::core::GUID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;
use windows_sys::Win32::Networking::WinSock::IPPROTO_ICMP;
use windows_sys::Win32::Networking::WinSock::IPPROTO_ICMPV6;

#[derive(Clone, Copy)]
pub(super) enum ConditionSpec {
    User,
    Protocol(u8),
    RemotePort(u16),
    #[cfg(feature = "lab-python-online-pdf")]
    RemoteAddressV4Not(u32),
    #[cfg(feature = "lab-python-online-pdf")]
    ProtocolNot(u8),
    #[cfg(feature = "lab-python-online-pdf")]
    RemotePortNot(u16),
}

#[derive(Clone, Copy)]
pub(super) struct FilterSpec {
    pub(super) key: GUID,
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) layer_key: GUID,
    pub(super) conditions: &'static [ConditionSpec],
}

pub(super) const FILTER_SPECS: &[FilterSpec] = &[
    FilterSpec {
        key: GUID::from_u128(0x019df13a98ac549490c7bc57bf9d03c6),
        name: "pi_sandbox_wfp_icmp_connect_v4",
        description: "Block sandbox-account ICMP connect v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMP as u8),
        ],
    },
    FilterSpec {
        key: GUID::from_u128(0xb1be2f634bb85f208e9d50568b9111da),
        name: "pi_sandbox_wfp_icmp_connect_v6",
        description: "Block sandbox-account ICMP connect v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
        ],
    },
    FilterSpec {
        key: GUID::from_u128(0xb2c5988ccae05fa595ea2a2812f3a936),
        name: "pi_sandbox_wfp_icmp_assign_v4",
        description: "Block sandbox-account ICMP resource assignment v4",
        layer_key: FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMP as u8),
        ],
    },
    FilterSpec {
        key: GUID::from_u128(0x613631e435675560a65b3250a37c6a80),
        name: "pi_sandbox_wfp_icmp_assign_v6",
        description: "Block sandbox-account ICMP resource assignment v6",
        layer_key: FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
        ],
    },
    // NAME_RESOLUTION_CACHE filters are intentionally omitted because ordinary
    // static filter shapes returned FWP_E_OUT_OF_BOUNDS during validation.
    FilterSpec {
        key: GUID::from_u128(0x986b7c9a948155d3a38118aec1d3bb7d),
        name: "pi_sandbox_wfp_dns_53_v4",
        description: "Block sandbox-account DNS TCP or UDP port 53 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(53)],
    },
    FilterSpec {
        key: GUID::from_u128(0x459baa3c8428543c866b82f8e83f6317),
        name: "pi_sandbox_wfp_dns_53_v6",
        description: "Block sandbox-account DNS TCP or UDP port 53 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(53)],
    },
    FilterSpec {
        key: GUID::from_u128(0xd87eec83adef59028b9bcc984c69223a),
        name: "pi_sandbox_wfp_dns_853_v4",
        description: "Block sandbox-account DNS-over-TLS port 853 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(853)],
    },
    FilterSpec {
        key: GUID::from_u128(0xa6bc42b6e8e6571cbf30f8b8c8de9327),
        name: "pi_sandbox_wfp_dns_853_v6",
        description: "Block sandbox-account DNS-over-TLS port 853 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(853)],
    },
    FilterSpec {
        key: GUID::from_u128(0x4ef2d385623d52f08b4785d3fa784292),
        name: "pi_sandbox_wfp_smb_445_v4",
        description: "Block sandbox-account SMB port 445 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(445)],
    },
    FilterSpec {
        key: GUID::from_u128(0x719955415f8d5e08a41ad3db97996788),
        name: "pi_sandbox_wfp_smb_445_v6",
        description: "Block sandbox-account SMB port 445 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(445)],
    },
    FilterSpec {
        key: GUID::from_u128(0x297960ba54915f4b9a0738180fe01d9c),
        name: "pi_sandbox_wfp_smb_139_v4",
        description: "Block sandbox-account SMB port 139 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(139)],
    },
    FilterSpec {
        key: GUID::from_u128(0x41ead4a054375f08804e96069d25f225),
        name: "pi_sandbox_wfp_smb_139_v6",
        description: "Block sandbox-account SMB port 139 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(139)],
    },
    // Disposable-lab comparison only. A required ALE_USER_ID condition scopes
    // all outbound connects (including loopback) to the owned local account.
    #[cfg(all(not(feature = "lab-python-online-pdf"), any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance")))]
    FilterSpec {
        key: GUID::from_u128(0xef7656ccacb451bcb3ad27be82cb009a),
        name: "pi_sandbox_wfp_offline_connect_v4",
        description: "Block sandbox-account outbound connect v4 (lab comparison)",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User],
    },
    #[cfg(any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance"))]
    FilterSpec {
        key: GUID::from_u128(0x3d9c33a833525ce2af92d71c8f66eb26),
        name: "pi_sandbox_wfp_offline_connect_v6",
        description: "Block sandbox-account outbound connect v6 (lab comparison)",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User],
    },
    // The online profile has NO permit/override filter. The union of these
    // three user-scoped blocks is the complement of the single relay tuple.
    // Every IPv6 connect remains covered by the original account-only block.
    #[cfg(feature = "lab-python-online-pdf")]
    FilterSpec {
        key: GUID::from_u128(0x4627aa81d7235ea982f4f277f26a3d2b),
        name: "pi_sandbox_wfp_online_pdf_not_relay_address_v4",
        description: "Block sandbox-account v4 outside fixed online PyPI relay address",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::RemoteAddressV4Not(0x7f000001),
        ],
    },
    #[cfg(feature = "lab-python-online-pdf")]
    FilterSpec {
        key: GUID::from_u128(0x0b6d9a1f41265a698c9c60a6040d9f42),
        name: "pi_sandbox_wfp_online_pdf_not_tcp_v4",
        description: "Block sandbox-account v4 outside fixed online PyPI relay TCP",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::ProtocolNot(6)],
    },
    #[cfg(feature = "lab-python-online-pdf")]
    FilterSpec {
        key: GUID::from_u128(0x78f5d091c6135d34a8b178068f1372a7),
        name: "pi_sandbox_wfp_online_pdf_not_relay_port_v4",
        description: "Block sandbox-account v4 outside fixed online PyPI relay port",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePortNot(43873)],
    },
];
