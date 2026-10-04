# Existing loader evidence without changing execution

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37198638134.

Token sessions matched and the expected station was confirmed. Restricted station
checks allowed read attributes, global atoms and desktop enumeration; they denied
clipboard, desktop creation and attribute writing. Base checks allowed all six.
All six tested private-desktop accesses were allowed for both tokens. Python still
exited with DLL initialization failure before its entry marker. Those access
results do not prove which operation or DLL caused initialization to fail.

## Next bounded diagnostic

The workflow records the fixed run's start/end in a finally block, then reads
existing events after account recovery. No event provider, log or trace is enabled.
Queries are restricted to the Application Error, Windows Error Reporting,
SideBySide and Application Popup providers, at most 32 records each, inside a
maximum 120-second run window. XML is capped at 16 KiB per record; parser input is
capped at 2 MiB/128 records with declarations/entities rejected.

Positive event attribution currently supports only the known Application Error
1000 AppPath schema, requiring the exact staged Python path inside the run window.
Conflicting path fields are rejected. PID or basename alone never attributes a
record. Unsupported schemas/providers' records remain unattributed. Output contains
only whitelisted provider/channel, event ID, bounded encoded numeric status fields
and a validated module basename. Status text is not guessed to be decimal or hex.
Raw XML, messages, paths, account identifiers and other event fields are not saved.
Absence of attributable events does not establish success or absence of failure.

An offline PE reader inventories the staged python.exe and its bounded staged
Python-core/CRT dependency subset. It reads bytes only, never executes a PE or
resolves system DLLs. Files are limited to 32 MiB/eight selected images; PE offsets,
sections, import directories, descriptor counts and basename strings are checked.
Selected reparses are rejected before following them. Normal and RVA-form delay
imports are reported; unsupported forms fail as unavailable. Missing staged-root
entries are not labeled missing system dependencies. Static imports are neither
actual loaded-module evidence nor identification of the failing DLL.

Only the run window and sanitized PE/event JSON files join the explicit evidence
allowlist. No debugger, unrestricted baseline, security grant, timeout change,
package installation or loader-behavior change is added. Prior read-only access
checks and the fixed restricted Python execution remain unchanged.

Local validation: nine Python tests passed for synthetic PE parsing, malformed
bounds/names, exact event attribution, wrong windows/providers, ambiguous PID/path
cases, redaction and limits. Workflow YAML/guard/artifact checks passed. PowerShell
is unavailable locally, so the Windows wrapper is statically reviewed, not executed.
No actual loader cause has yet been established.
