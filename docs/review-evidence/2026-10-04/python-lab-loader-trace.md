# Explicit loader debugger diagnostic

Preceding run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37199692688.
Existing-event queries found no matching records; bounded PE import inventory did
not identify the failing DLL. The normal restricted Python process still exited
with initialization failure before its entry marker, with cleanup/recovery verified.

## Diagnostic scope and limits

The opt-in Cargo feature `lab-loader-trace` adds DEBUG_ONLY_THIS_PROCESS to the same
fixed restricted Python launch. It is disabled by default. Token, private desktop,
atomic job assignment, stdio bounds, parent liveness and 15-second wall-clock limit
remain in place. The temporary workflow build explicitly selects the feature.
No attaching to an existing process, debug privilege enablement, target-memory or
thread-context access, injection, station ACL change, or unrestricted baseline is
introduced.

The creating helper thread pumps WaitForDebugEvent and ContinueDebugEvent. The pump
cannot move between threads. It records only event types, sanitized image/DLL
basenames from transferred file handles, exception/exit/error codes and booleans.
Debug strings and target-memory image-name pointers are not read. Only transferred
image/DLL file handles are closed by the collector; OS-managed debug process/thread
handles are not adopted or closed. Existing PROCESS_INFORMATION handles retain
their separate ownership. A bounded file-header read obtains ntdll image extent;
no image bytes or addresses are emitted.

Only the first first-chance breakpoint within the observed ntdll image range is
consumed as the startup debugger breakpoint. This criterion is not absolute proof
of the breakpoint's origin, and the fixed trusted diagnostic scope matters. All
other exceptions are passed as DBG_EXCEPTION_NOT_HANDLED. Debugger presence and
suspension alter timing and may alter loader behavior; this is not a normal run.

Storage is bounded to 256 events, with a 4,096-event processing limit. Reaching the
processing limit stops the diagnostic as an output-limit failure. Job termination
continues pumping through process-exit continuation; the existing five-second
cleanup budget is also shared by error-path fallback. A continuation has at most
one retry. Inconclusive cleanup remains failure, with helper-exit/outer-job
containment retained. The code never detaches or disables debugger kill-on-exit.

The trace is sent to the broker before the workload result, under the existing
response deadline, and logged using sanitized fields. Trace failures retain partial
data where possible. The last loaded DLL is not treated as the culprit: loaded
images do not prove successful initialization, and a failed DllMain may produce
only the final exit status rather than a distinguishing exception.

## Normal validation remains required

Every trace-feature build marks its evidence diagnostic-only and refuses
LAB_SMOKE_PASS even if Python returns successfully. Remove the workflow's feature
selection and perform a fresh normal run before claiming fixed-fixture completion.
Production NATIVE_VALIDATED remains false throughout.

Local checks: all 63 portable tests passed; Windows-GNU examples compiled with and
without the feature. These include four new diagnostic-scope/cleanup source
contracts. No native debugger execution occurred locally.

References:
- [WaitForDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)
- [Debugger main loop](https://learn.microsoft.com/en-us/windows/win32/debug/writing-the-debugger-s-main-loop)
- [ContinueDebugEvent](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-continuedebugevent)
- [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
