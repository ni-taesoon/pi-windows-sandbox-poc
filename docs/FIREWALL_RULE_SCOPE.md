# Offline firewall rule readback contract

The product firewall names are lookup keys, not proof of ownership. Setup now
reads existing rules without editing them. A same-name rule is accepted only
when its complete supported scope matches the expected product rule. A scoped,
disabled, differently described, or otherwise mismatched rule aborts setup;
it is neither repaired nor deleted automatically. An administrator must inspect
and resolve a collision before retrying. Only `ERROR_FILE_NOT_FOUND` permits
creation; access errors and other lookup failures abort setup.

New rules are configured before insertion. Application/service restrictions,
local addresses, interface selection/types, and TCP/UDP local/remote ports are
explicitly initialized. Both new and existing rules are checked for name,
description, direction, protocol, block action, enabled state, all profiles,
exact local-user SDDL, application, service, local/remote addresses, applicable
ports, interfaces/types, package, local owner, remote users/machines, secure
flags, and edge-traversal options. Port getters/setters are only used for TCP/UDP;
ports cannot restrict a protocol-ANY rule.

Comparison is deliberately exact and fail-closed. Equivalent SDDL/address
canonicalization, interface-type case differences, or an unfamiliar COM
representation for an unrestricted field can cause setup to fail. Do not
weaken comparison to substring matches to make a host pass. Such cases need
Windows observations and narrowly justified normalization tests. No existing
rule is rewritten merely because its name matches.

`cargo test --manifest-path native/windows-sandbox/Cargo.toml firewall_scope`
runs the same portable readback validator used by the Windows adapter, with
mock property snapshots. It covers each checked property independently,
including a SID-prefix collision. These are admission-contract tests, not COM
integration tests or proof of packet blocking. Windows-native tests must still
verify creation, repeated setup, tampered same-name rules, missing/failed
getters, policy/GPO effects, IPv4/IPv6, TCP/UDP, and loopback enforcement. Check
that mismatched existing rules are unchanged after rejection. The production
validation gate remains false.

API references:
- [INetFwRule property contract](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)
- [INetFwRule interfaces](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrule-get_interfaces)
- [INetFwRules::Item lookup failures](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-inetfwrules-item)
