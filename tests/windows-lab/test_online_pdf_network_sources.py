"""Pure fixed-relay network contracts; no sockets, WFP, account or policy writes.

These validate source shape and its block-union model, not Windows enforcement.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
NATIVE = ROOT / "native/windows-sandbox"
SPECS = (NATIVE / "src/network/wfp/filter_specs.rs").read_text()
WFP = (NATIVE / "src/network/wfp.rs").read_text()
NETWORK = (NATIVE / "src/network.rs").read_text()
FIREWALL = (NATIVE / "src/network/firewall.rs").read_text()
SCOPE = (NATIVE / "src/network/firewall_scope.rs").read_text()


def compact(text):
    return re.sub(r"\s+", "", text)


def between(text, start, end):
    return text.split(start, 1)[1].split(end, 1)[0]


def source_specs():
    result = []
    for start in (m.start() for m in re.finditer(r"    FilterSpec \{", SPECS)):
        body = SPECS[start:SPECS.index("\n    },", start)]
        prefix = SPECS[:start].rstrip()
        gate = compact(prefix[prefix.rfind("#[cfg("):]) if prefix.endswith("]") else ""
        result.append({
            "key": between(body, "GUID::from_u128(0x", ")"),
            "name": between(body, 'name: "', '"'),
            "layer": between(body, "layer_key: FWPM_LAYER_", ","),
            "conditions": compact(between(body, "conditions: &[", "]")),
            "gate": gate,
        })
    return result


SHARED = compact('#[cfg(any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance"))]')
OFFLINE = compact('#[cfg(all(not(feature = "lab-python-online-pdf"), any(feature = "lab-python-policy-repair-comparison", feature = "lab-python-codex-policy-acceptance")))]')
ONLINE = compact('#[cfg(feature = "lab-python-online-pdf")]')


def profile(offline, online):
    assert not online or offline
    enabled = {"": True, SHARED: offline, OFFLINE: offline and not online, ONLINE: online}
    return [s for s in source_specs() if enabled[s["gate"]]]


def predicate(specs):
    """Compile actual literal source conditions into a pure block-union model."""
    filters = []
    for spec in specs:
        conditions = []
        for condition in spec["conditions"].split("ConditionSpec::")[1:]:
            condition = condition.rstrip(",")
            if condition == "User":
                conditions.append(("User", None))
            else:
                name, value = condition[:-1].split("(")
                value = {"IPPROTO_ICMPasu8": "1", "IPPROTO_ICMPV6asu8": "58"}.get(value, value)
                conditions.append((name, int(value, 0)))
        filters.append((spec["layer"], conditions))

    def blocked(owned=True, v6=False, address=0x7F000001, protocol=6, port=43873):
        layer = "ALE_AUTH_CONNECT_V6" if v6 else "ALE_AUTH_CONNECT_V4"
        for candidate, conditions in filters:
            if candidate != layer:
                continue
            matches = {
                "User": lambda _: owned,
                "Protocol": lambda value: protocol == value,
                "RemotePort": lambda value: port == value,
                "RemoteAddressV4Not": lambda value: address != value,
                "ProtocolNot": lambda value: protocol != value,
                "RemotePortNot": lambda value: port != value,
            }
            if all(matches[name](value) for name, value in conditions):
                return True
        return False
    return blocked


class FixedRelayNetworkSourceTests(unittest.TestCase):
    def test_profiles_preserve_offline_counts_keys_and_conditions(self):
        self.assertEqual([len(profile(False, False)), len(profile(True, False)), len(profile(True, True))], [12, 14, 16])
        all_specs = source_specs()
        self.assertEqual(len(all_specs), 17)
        self.assertEqual(len({s["key"] for s in all_specs}), 17)
        self.assertEqual(len({s["name"] for s in all_specs}), 17)
        for spec in all_specs:
            self.assertEqual(spec["conditions"].count("ConditionSpec::User"), 1)
        for version, key, gate in [("4", "ef7656ccacb451bcb3ad27be82cb009a", OFFLINE), ("6", "3d9c33a833525ce2af92d71c8f66eb26", SHARED)]:
            spec = next(s for s in all_specs if s["name"] == "pi_sandbox_wfp_offline_connect_v" + version)
            self.assertEqual((spec["key"], spec["conditions"], spec["gate"]), (key, "ConditionSpec::User", gate))
        self.assertNotIn("FWP_ACTION_PERMIT", WFP)

    def test_exact_relay_tuple_only_including_all_ports_and_protocols(self):
        blocked = predicate(profile(True, True))
        self.assertFalse(blocked())
        for port in range(65536):
            self.assertEqual(blocked(port=port), port != 43873)
        for protocol in range(256):
            self.assertEqual(blocked(protocol=protocol), protocol != 6)
            self.assertTrue(blocked(protocol=protocol, v6=True))
            self.assertFalse(blocked(protocol=protocol, owned=False))
        for address in [0, 1, 0x0100007F, 0x7F000000, 0x7F000002, 0x7FFFFFFF, 0x01010101, 0xFFFFFFFF] + [0x7F000001 ^ (1 << bit) for bit in range(32)]:
            self.assertTrue(blocked(address=address))
            self.assertFalse(blocked(address=address, owned=False))
        offline = predicate(profile(True, False))
        self.assertTrue(offline())
        self.assertTrue(offline(v6=True))

    def test_builder_has_exact_not_equal_match_data_types_and_host_values(self):
        for variant, field, kind, member, binding in [
            ("RemoteAddressV4Not", "IP_REMOTE_ADDRESS", "UINT32", "uint32", "address"),
            ("ProtocolNot", "IP_PROTOCOL", "UINT8", "uint8", "protocol"),
            ("RemotePortNot", "IP_REMOTE_PORT", "UINT16", "uint16", "port"),
        ]:
            arm = compact(between(WFP, f"ConditionSpec::{variant}({binding}) =>", "\n            },"))
            for required in [f"fieldKey:FWPM_CONDITION_{field},", "matchType:FWP_MATCH_NOT_EQUAL,", f"r#type:FWP_{kind},", f"{member}:*{binding}"]:
                self.assertIn(required, arm)
            self.assertNotIn(".to_be()", arm)
            self.assertNotIn(".swap_bytes()", arm)
        for condition in ["RemoteAddressV4Not(0x7f000001)", "ProtocolNot(6)", "RemotePortNot(43873)"]:
            self.assertIn(condition, SPECS)
        self.assertEqual(int.from_bytes(bytes([127, 0, 0, 1]), "big"), 0x7F000001)
        readback = WFP.split("pub fn verify_wfp_filters_for_sid", 1)[1]
        for check in ["actual.matchType == expected.matchType", "actual.conditionValue.r#type == expected.conditionValue.r#type", "FWP_UINT8 => a.uint8 == e.uint8", "FWP_UINT16 => a.uint16 == e.uint16", "FWP_UINT32 => a.uint32 == e.uint32"]:
            self.assertIn(check, readback)

    def test_inventory_is_read_only_provider_and_layer_scoped_bounded(self):
        readback = WFP.split("pub fn verify_wfp_filters_for_sid", 1)[1]
        inventory = WFP.split("fn verify_exact_profile_inventory", 1)[1]
        self.assertIn("FWPM_TXN_READ_ONLY", readback)
        for required in ["providerKey: &mut provider_key", "layerKey: layer", "actionMask: u32::MAX", "numFilterConditions: 0", "FwpmFilterCreateEnumHandle0(engine, &template", "FILTER_SPECS.len() as u32 + 1", "count < requested", "count as usize == expected_count", "seen.len() == FILTER_SPECS.len()", "FwpmFilterDestroyEnumHandle0", "FwpmFreeMemory0"]:
            self.assertIn(required, inventory)
        for forbidden in ["FwpmFilterCreateEnumHandle0(engine, null()", "FwpmFilterAdd0", "FwpmFilterDeleteByKey0"]:
            self.assertNotIn(forbidden, inventory)

    def test_fresh_setup_and_only_firewall_tcp_outbound_complement(self):
        install = between(NETWORK, "pub(crate) fn install_offline_protection", "/// Read-only configuration")
        self.assertLess(install.index("require_product_namespace_absent()?"), install.index("firewall::ensure_offline_network_blocks"))
        ports = between(FIREWALL, "let tcp_blocked_ports =", "for (name, description, protocol, remote_ports)")
        self.assertIn('cfg!(feature = "lab-python-online-pdf")', ports)
        self.assertIn('Some("1-43872,43874-65535")', ports)
        self.assertIn("None", ports)
        rules = compact(between(FIREWALL, "for (name, description, protocol, remote_ports)", "// Pi offline mode"))
        self.assertIn("NET_FW_IP_PROTOCOL_TCP.0,tcp_blocked_ports,", rules)
        self.assertIn("NET_FW_IP_PROTOCOL_UDP.0,None,", rules)
        self.assertIn("direction:NET_FW_RULE_DIR_OUT,", rules)
        other = between(FIREWALL, "// Pi offline mode", "fn ensure_local_policy_rules_take_effect")
        self.assertEqual(other.count("remote_ports: None"), 3)
        existing = between(FIREWALL, "Ok(existing) =>", "Err(err) if")
        self.assertIn("verify_rule(&existing, spec)?", existing)
        self.assertNotIn("configure_rule(", existing)
        self.assertNotIn("SetRemotePorts", existing)
        exact = between(SCOPE, "let other_fields_exact = exact!(", ");")
        self.assertIn("remote_ports", exact)

    def test_account_guards_precede_write_engine_and_provenance_is_explicit(self):
        install = between(WFP, "pub fn install_wfp_filters_for_sid", "pub(super) fn expected_filter_count")
        self.assertLess(install.index("validate_user_scope(spec.conditions)?"), install.index("UserMatchCondition::for_sid(sid)?"))
        self.assertLess(install.index("UserMatchCondition::for_sid(sid)?"), install.index("Engine::open"))
        self.assertLess(install.index("require_namespace_absent()?"), install.index("Engine::open"))
        self.assertIn("sid == crate::setup::local_offline_account_sid()?", WFP)
        provenance = between(NETWORK, "pub fn wfp_policy_provenance", "pub(crate) fn install_offline_protection")
        self.assertIn("codex-policy-with-lab-fixed-online-pypi-relay-v1", provenance)
        self.assertLess(provenance.index("lab-python-online-pdf"), provenance.index("lab-python-codex-policy-acceptance"))
        for previous in ["codex-policy-with-lab-owned-account-connect-block-v1", "lab-owned-account-connect-block-v1", "baseline-port-icmp-v1"]:
            self.assertIn(previous, provenance)


if __name__ == "__main__":
    unittest.main()
