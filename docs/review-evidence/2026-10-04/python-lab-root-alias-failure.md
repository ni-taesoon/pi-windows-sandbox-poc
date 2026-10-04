# Measured root alias refusal and narrow staging correction

Actual GitHub run: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37190848450.

The parent retrieved the actual Windows run evidence: MSVC build/link and the
previous mocked PowerShell selector regression passed. Staging then correctly
refused this root-level runtime entry:

- sourceRole: `python-runtime`
- path: `<PythonHome>\python3.exe` (runtime-relative description; host path omitted)
- LinkType: `SymbolicLink`
- attributes: `Archive, ReparsePoint`

Staging stopped before the synthetic-root ACL, account, setup, or sandbox Python
execution steps. This establishes the concrete source entry that blocked staging;
it does not establish successful sandbox execution or network enforcement.

## Narrow correction

The fixed command uses the approved, hash-checked `runtime\python.exe`. The unused
root-level `python3.exe` symbolic-link alias is now excluded from the selected
runtime and never copied, executed, followed, or target-resolved. The selector
records the exact exclusion in staging output and `stage-evidence.json`.

Only that exact root-level non-directory SymbolicLink is excluded. A root entry
masquerading as a directory is rejected. Nested `python3.exe` links, linked
`python.exe`, unknown reparse types, Lib/DLL links, other aliases and linked
ancestors retain rejection. The required interpreter and approved executable
hash checks remain unchanged. No interpreter files or library components needed
by the fixed command have been substituted, and no link target is assumed.

Regression additions cover alias exclusion without access to a mocked target
property, required interpreter rejection, nested same-name rejection, regular and
linked directory masquerades, and unrecognized reparse type rejection. These are
mocked selection tests, not sandbox proof. The new cases have not run locally
because PowerShell is unavailable; they run on the next fresh approved Windows VM.
Portable Rust source-contract results are recorded separately. No publication or
workflow dispatch was performed by this patch task.

The [original Actions run](https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37190848450) supports this technical summary. Raw runner logs, metadata, and their evidence manifests are retained privately and excluded from the current published source tree.
