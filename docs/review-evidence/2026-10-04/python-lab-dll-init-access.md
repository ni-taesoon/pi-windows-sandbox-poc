# DLL initialization failure: read-only access diagnostics

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37197773872.
Source: `8f2a8954fdf15fe1ebb80068f94c26b53b3d864b`.

The preserved result exited with status `0xC0000142`, without timeout, stdout,
stderr or a script-entry marker. Independent OS evidence again identified the
restricted, job-contained Python process. Cleanup and account-disable recovery
passed. This establishes initialization failure before the fixed script, not the
particular DLL or underlying access check that caused it.

The next patch measures discretionary access without changing permissions. Inside
the trusted helper, base and restricted tokens are duplicated as impersonation
tokens for AccessCheck. Bounded owner/group/DACL descriptors are read from the
actual window station and the existing per-run private desktop. Object-specific
GENERIC_MAPPING values follow Microsoft's interactive-station/desktop tables.
Only individual intended object-access masks are tested; no access is granted.

The actual station must first match the expected station internally; otherwise
station/desktop comparisons are unavailable rather than applied to another object.
OpenDesktop requests the documented read/write-object prerequisites for a
READ_CONTROL handle, then performs descriptor reads only. No desktop/station switch,
security-descriptor setter, thread impersonation or privilege change is added.
Descriptors and identity strings remain inside the helper. Serialized diagnostics
contain only whitelisted object/access/API enums, numeric masks/errors, booleans,
and token-session equality. Unknown/unavailable checks are not reported as allowed.

The helper transmits diagnostics before workload launch; the broker records the
sanitized result. Both transport reads share the original response deadline.
The workload's token, private desktop, ACLs, argv, output contract and 15-second
limit remain unchanged. AccessCheck results are diagnostic evidence, not a complete
loader prediction or permission to broaden shared-station access. Any future access
grant must be separately justified and reviewed against the approved scope.

References:
- [AccessCheck](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck)
- [Window-station security and access rights](https://learn.microsoft.com/en-us/windows/win32/winstation/window-station-security-and-access-rights)
- [Desktop security and access rights](https://learn.microsoft.com/en-us/windows/win32/winstation/desktop-security-and-access-rights)
- [OpenDesktop prerequisites](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-opendesktopw)

Local validation: all 59 portable tests and Windows-GNU example compilation passed.
Three new source-contract tests cover read-only API scope, bounded/identity-free
telemetry and prelaunch framing/deadline preservation. Native AccessCheck execution
and successful Python fixture completion are still pending the next Windows run.
