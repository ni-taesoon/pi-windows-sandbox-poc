# Preserve broker evidence when the observer fails

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37197274910.
Source: `dcb848d0083f3641b12eecbd875b2a262dc4c4dd`.

The observer's process-image query failed before the driver wrote run evidence.
Only account-disable recovery and the observer error were preserved. No broker
exit status, Python markers or successful workload conclusion can be inferred from
that incomplete record. In particular, the earlier startup issue is not proven fixed.

The driver now joins the observer without early error propagation, preserving the
broker result, hexadecimal exit status, stdout/stderr and explicit observer error
before rejecting the run. Samples retained from prior completed observation rounds
are included when available. A thread panic is recorded as a static join failure.

Image/job query errors record a constant API/stage label, numeric Windows error,
and zero-time wait status from the same already-open process handle. The Windows
error is captured before the wait call. A signaled handle is only a possible exit-
race clue; it is not used to invent an image identity. There is no reopen-by-PID,
PID-reuse guess, or assumption that an unidentified process was Python.

Any observer error still blocks success, even if other evidence exists. Broker
failure, missing required restricted Python identity/job/exit proof, incomplete
fixed stdout or incorrect result file also remain failures. Timeout, restriction,
private desktop, ACLs and cleanup behavior are unchanged. Raw evidence stays private.

Local validation: seven lab source-contract tests and Windows-GNU example
compilation passed. No Windows execution occurred locally. The next approved
fresh-VM run must supply the missing broker outcome and observer diagnostics.
