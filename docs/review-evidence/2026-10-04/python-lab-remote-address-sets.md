# Exact remote-address-set comparison

Diagnostic run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37194072370.
Source: `b09e8635d852c6ffeaf7a10641950e9ce8585a8b`.

The parent verified that only `remote_addresses` differed: actual byte length 26,
expected length 18. No raw actual property string was logged. The known compiled
loopback selector has an equivalent dotted-IPv4-mask spelling of length 26, making
normalization a likely explanation, not an observed representation. Fresh disabled
creation and rollback/final disabled readback passed; Python remained skipped.

The correction parses remote-address selectors into family-separated numeric
interval unions and accepts only equal complete sets. The other 21 firewall fields
remain exact. There is no expected-value substitution, rule broadening, profile
change or privilege expansion. A constant field/boolean-only message reports a
successful semantic equality check when the raw strings differ; raw addresses and
identity strings are not added to logs.

Supported syntax: numeric IPv4/IPv6 hosts, numeric CIDRs, contiguous dotted IPv4
netmasks, same-family inclusive ranges, and comma unions. Intervals are sorted and
merged with checked adjacency arithmetic. Wildcard represents the complete IPv4
and IPv6 universe only. Unknown symbolic selectors, zones, malformed/empty list
terms, noncontiguous masks, invalid bounds, mixed-family ranges, and excessive
input are rejected. Parsing is limited to 8,192 ASCII bytes and 128 terms.

The new dotted-mask equivalence test failed against the historical exact comparator
(RED) and passed with the new parser (GREEN). Historical source reconstruction was
verified against its frozen manifest hash before running that pure regression.
All 31 firewall/parser tests passed locally; changed-set and invalid-input cases
remain rejected. Windows-GNU example compilation passed. None of these tests prove
what the actual COM string was or that Windows sandbox Python has run. The next
approved fresh-VM attempt must establish actual readback acceptance and execution.
