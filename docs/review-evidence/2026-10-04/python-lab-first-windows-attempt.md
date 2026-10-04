# First actual Windows lab attempt: blocked in staging

Source: `07664a27f9b6d5fe9a54dd4c75ea098ececef39d`.
Run/job: https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37189834072/job/111399536076.

The observed GitHub Windows runner completed the real MSVC Rust 1.99 build/link
step in 27.24 seconds. The subsequent staging script failed at line 39 with
`Reparse-containing stage source refused.` These observations were retrieved
from the actual run by the parent task; this local patch does not rerun Windows.

The original code recursively examined both PythonHome and the entire native
build directory, but did not report which input/path caused refusal. Therefore
neither the source role nor the offending path/type is known from this attempt.
No claim about a particular Python junction, Cargo artifact, or alias is justified.

The failure occurred before creating `C:\PiSandboxLab`, changing its ACLs, creating
the dedicated account, installing product firewall/WFP objects, or launching the
sandbox Python fixture. This is real build/link evidence and a real staging
failure, not a successful sandbox execution or security validation.

## Follow-up patch, not yet Windows-executed

- Select only the helper and driver executable inputs plus their ancestors from
  the build tree. Unrelated build-tree entries are not copied and no longer cause
  a scan failure.
- Keep the complete selected Python runtime, without speculative component removal.
  Inspect ancestors and every runtime item before descending; refuse every copied
  reparse item rather than following/skipping it.
- Report source role, exact offending path, LinkType and file attributes in the
  refusal. Do not resolve the link target or print file contents.
- Copy only the validated breadth-first runtime selection, with per-item rechecks;
  no second wildcard recursive traversal. This still assumes a trusted quiescent
  source and is not an adversarial race-free copy claim.
- Add portable Rust source-contract checks and a mocked PowerShell selector
  regression. The mock validates selection/refusal logic, not the Windows OS.
  PowerShell is unavailable in this local Linux environment, so the mocked test
  has not been executed locally. It must run on the next approved Windows attempt.

No account/policy/runtime guard is disabled. If a required Python runtime item or
ancestor is actually a reparse point, the next run will still refuse with its exact
path. Any further packaging change needs that evidence and review first. Retry only
on a fresh approved disposable VM; production activation remains false.

## Evidence scope

The [original Actions run](https://github.com/ni-taesoon/pi-windows-sandbox-poc/actions/runs/37189834072) supports this technical summary. Raw runner logs, metadata, and their evidence manifests are retained privately and excluded from the current published source tree. No credential store was created or collected in this attempt.
