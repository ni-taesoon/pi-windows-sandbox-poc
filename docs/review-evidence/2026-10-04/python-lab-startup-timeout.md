# Restricted Python launched; completion timed out

Actual run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37196523345.
Source: `ae24a024199050963b4567ea9c8b63d56bd7bbf1`.

Independent OS observation identified the staged Python process under the dedicated
account with a restricted token and job membership. The returned result timed out
at the existing 15-second deadline, with empty stdout/stderr and verified process
cleanup. Its observed exit was therefore not successful workload completion.
Account-disable recovery was verified. No validated result-file/success summary
was produced. Raw process identities and paths remain private.

Console-host processes were observed too, but that does not establish a console
failure. The evidence does not yet distinguish startup/loader blocking, invisible
critical-error UI, or another wait before the first Python progress output.

## Diagnostic-only change

In the one-shot dedicated helper, preserve the current error-mode bits and add only
SEM_FAILCRITICALERRORS. Child processes inherit this mode. The intention is to
return critical errors rather than wait on an inaccessible error dialog; this does
not claim such a dialog caused the measured timeout. WER behavior, console flags,
private desktop, token and ACL controls, output limits and 15-second deadline are
unchanged. No alignment-fault suppression or global setting change is introduced.

The fixed script emits flushed entry and import-complete markers before its
existing result-file work. Successful completion additionally requires the exact
three ordered output lines, accepting only consistent LF or CRLF encoding.
Partial markers, extra output, changed order and mixed line endings cannot pass.
Exit/cleanup, independent restricted-process observation and exact file-content/
identity checks remain mandatory. The private run record adds hexadecimal exit
status for easier diagnosis; the actual result bytes remain unchanged.

Official basis: [SetErrorMode](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)
documents SEM_FAILCRITICALERRORS and child inheritance, and recommends suppressing
critical-error dialogs to prevent hangs. The process-wide call is confined to the
one-shot helper, never applied to the owner/broker or standalone execution path.

Local validation: Windows-GNU example compilation and all 55 portable tests passed,
including exact stdout acceptance/rejection and helper-only error-mode scope.
There was no local Windows execution. The next approved native attempt must show
an actual error/phase result or successful fixture completion.
