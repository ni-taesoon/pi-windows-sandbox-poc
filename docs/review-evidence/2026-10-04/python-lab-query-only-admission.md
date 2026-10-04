# Query-only admission from the actual helper token

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37195431754.
Source: `289150d007ffe8fbbd70c0067042b0acdcf9dad2`.

The next Windows attempt identified the denied operation as
`helper-base-token/OpenProcessToken`, Win32 error 5. Setup and activation passed;
rollback and final explicit disable produced successful disabled-state readback.
Python was not executed. Raw identities and logs remain private.

## Minimal architecture correction

The broker now opens the actual suspended helper token with TOKEN_QUERY only.
Admission still verifies that token's account identity and uses its actual logon
SID for private-desktop access. It does not substitute the separately authenticated
broker-side logon token: matching account SIDs do not imply matching logon sessions.

Broker-only admission no longer constructs an unused restricted token across the
account boundary. Its explicit execution-path state carries no locally runnable
token, and direct `run()` rejects that state. Standalone admission retains its
existing restricted-token construction. The trusted dedicated helper still creates
and configures its own restricted derivative before launching any workload; the
capability, private desktop, parent-wait handoff and cleanup protocol are unchanged.

This removes an unnecessary cross-account rights request rather than granting
additional access. There is no token-DACL expansion, debug privilege enablement,
account privilege change, same-user fallback or production activation. A helper
restriction failure remains a failure with retained restrictive ACLs as designed.
The known fresh-account/same-account startup assumptions are not reclassified as
production guarantees.

Local validation: Windows-GNU example compilation and all 50 portable tests passed
(36 library, 4 broker contracts, 5 SAM contracts, 5 lab contracts). The new contract
checks QUERY-only opening, actual-helper desktop binding, preserved helper-side
restriction, and direct-execution refusal for helper-only admission. No native
Windows execution occurred locally; actual success requires the next approved
fresh-VM run.
