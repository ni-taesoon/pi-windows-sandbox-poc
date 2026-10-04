# Broker access failure: API-specific diagnostic follow-up

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37194790545.
Source: `99cf1944fe8ba639d18af22dbc977550ca346d0d`.

Firewall semantic verification and setup passed. The broker then returned generic
Windows access-denied error 5. Private evidence contains no returned run result and
zero sampled process observations; account-disable recovery succeeded. The empty
sample does not establish that a short-lived suspended helper never existed.
The old shared error wrapper did not identify which native API failed, so neither
a specific token-access failure nor an appropriate permission change is proven.

This diagnostic-only patch labels every broker Win32 wrapper call with a static
phase/API name and numeric error code. Major orchestration steps also receive
constant phase context. It does not change desired token rights, process/pipe
rights, object ACLs, operation order, account privileges or production gates.
No raw account identifiers, request values, handles, paths or authentication data
are included in the new diagnostic fields. Raw run evidence remains private.

## Source audit of token rights

Admission reads SID/logon information, creates a restricted derivative, and then
sets the derivative's default DACL and adjusts its change-notify privilege.
[Microsoft's CreateRestrictedToken documentation](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken)
specifies TOKEN_DUPLICATE for the input and the same access rights on the returned
handle. Consequently, reducing the current input to QUERY and DUPLICATE alone
would leave the existing derived-token adjustment calls without their required
access. The current derivation chain also needs ADJUST_DEFAULT and
ADJUST_PRIVILEGES. Shared standalone admission execution needs ASSIGN_PRIMARY;
the broker's helper-payload path does not itself execute that derived token.
This analysis is not proof of which access check failed. No mask reduction or
privilege expansion is included in this patch.

Local validation: three broker source-contract tests passed and Windows-GNU
example compilation passed. No Windows execution occurred locally. The next
approved fresh-VM attempt must identify the exact API before a behavioral fix.
