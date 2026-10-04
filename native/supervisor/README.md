# Windows job supervisor (source-only, unvalidated)

This is a non-elevated, dependency-free Win32 lifecycle helper, **not a sandbox or an installation/setup tool**. It does not create accounts, ACLs, firewall rules, or restricted tokens. Codex supplies those separate boundaries. Building this helper, its capability JSON, portable tests, and a clean exit code do not constitute native enforcement evidence. Keep the broker's native gate disabled until the complete Windows integration matrix passes on the exact binaries/configuration.

## Build

On Windows 10/11 x64, install an official Visual Studio C++ toolchain/Windows SDK and CMake, then run `./build.ps1` in a normal Developer PowerShell. No UAC elevation is needed or accepted at runtime. This source has **not been compiled against the Windows SDK here**. Linux can only run `sh tests/supervisor-contract/run.sh` from the repository root. That tests the actual portable C++ JSON parser and argument quoting; it does not test Win32 behavior.

## Trusted broker contract

```
pi-job-supervisor.exe --request-json '{"schemaVersion":1,"executable":"C:\\trusted\\codex.exe","argv":["-c","windows.sandbox=\"elevated\"","-c","prefer_mxc=false","-c","shell_environment_policy.inherit=\"all\"","sandbox","--sandbox-state-json","{...}","--","C:\\trusted\\node.exe","worker.cjs"],"cwd":"C:\\workspace","parentPid":1234}'
```

The example is a JSON contract illustration, not shell quoting guidance. Node must pass exactly two argv entries (`--request-json`, `JSON.stringify(request)`) using `spawn` with `shell:false`. Supply three valid pipe handles and a sanitized allowlist environment. Broker API keys and other secrets must not be present in the supervisor's environment, since CreateProcess intentionally inherits the broker-scrubbed environment. JSON arguments (and Windows process metadata) are not secret storage.

The only permitted launch prefix is the one above; it matches Codex CLI **0.160.0**, whose command is `sandbox`, not `sandbox windows`. The helper checks basename `codex.exe`, absolute drive paths, the exact switch sequence, required fields, duplicate/unknown fields, integer ranges, NULs, UTF-16 surrogate pairs and lengths. The broker must independently pin the actual Codex and helper binary path/hash, validate state JSON/policy and working directories, and keep both binaries out of sandbox-writeable directories. A basename is not executable authentication. This helper is not a privileged broker and does not accept setup commands or elevate anything.

Limits: request JSON <= 30,000 UTF-16 code units, <= 1,024 Codex args, child command line < 32,767 code units including room for NUL. The supervisor's own command line must also fit the Windows limit; the broker must reject oversized escaped outer JSON before spawn. UNC/device paths and drive-relative paths are deliberately unsupported. No shell concatenation is used; lpApplicationName is explicit and quoting follows the Windows CRT convention.

`-v` / `--version` returns `pi-job-supervisor 0.1.0`.

`--capabilities` returns:

```
{"protocol":1,"version":"0.1.0","atomicJobAssignment":true,"killOnJobClose":true,"parentDeathWatch":true,"nativeIntegrationValidated":false}
```

These booleans describe implemented source paths, not an attestation that calls work on the current OS or that Codex's alternate-account child belongs to the job.

## Lifetime behavior

- Reject elevated supervisor tokens. Verify requested parent PID is the actual launcher, open a non-inherited parent handle, reject reused/dead parent by creation time and liveness.
- Create an unnamed, non-inherited Job Object with KILL_ON_JOB_CLOSE and neither breakaway flag.
- Create the Codex root suspended using explicit stdin/stdout/stderr handle allowlisting and `PROC_THREAD_ATTRIBUTE_JOB_LIST`. The Windows 10+ job-list attribute assigns the job atomically during creation, **before ResumeThread**, and avoids the suspended-orphan race possible when the supervisor dies between CreateProcess and a later AssignProcessToJobObject call. No fallback to unassigned creation is allowed. Verify membership with IsProcessInJob before resuming.
- Wait for root exit, real parent death, or a console cancellation signal. On normal root exit, retrieve the original DWORD exit code, terminate the entire assigned job and query until ActiveProcesses is zero. A 30-second drain timeout is a supervisor failure, not success; closing the job still requests cleanup.
- Return the original root exit code only after successful drain. Parent death/cancel and helper failures return 125; `PI_SUPERVISOR_FAILURE:` on stderr identifies helper exceptions. Code 125 can also originate from Codex and is not a unique result discriminator. Outputs otherwise pass through byte-for-byte; diagnostic stderr may be appended on helper failure.
- Broker timeout/cancel may terminate this supervisor using its tracked process handle. The non-inherited job handle closes on abrupt death. Closing stdin is **not** a cancellation protocol. A crashed broker is detected independently from stdin EOF.

The helper intentionally does not implement the SDD's complete resource quotas, setup integrity, capability authentication, logon/token DACL protections, environment construction, or native policy attestation. Those remain separate release gates.

## Mandatory Windows integration probes (NOT RUN)

Use a disposable Windows VM with approved setup, the exact pinned Codex CLI/helper/Node builds, and an external trusted observer. Record versions/hashes, OS build, account mode, complete argv, process identities/creation times, and before/after observations. Never mark nativeEnforcement validated from a capability flag or operator assertion alone.

1. Compile with Windows SDK; version and capability contract; reject unknown/duplicate JSON fields, mismatched parent PID, elevation, invalid stdio and invalid/overlong args without launching any child.
2. Unicode/empty/quote/backslash argv and binary stdout/stderr round trips through the real Codex runner. Verify root exit codes including nonzero and high-bit DWORD values as represented by Node on Windows.
3. Actual `CreateProcessWithLogonW` dedicated-account runner: determine whether it and its sandbox child remain in the outer job. Observe live tree and termination from a trusted observer; a root-only IsProcessInJob result does not establish descendant membership. Exercise account transitions, nested jobs, and any supported launcher/service paths.
4. Launch a child/grandchild that continues writing timestamped heartbeats after its root returns. Through the exact Codex path, prove all heartbeat processes disappear and file writes stop after normal root exit, nonzero exit, broker cancel, broker crash, helper kill, console close and Windows logoff. Root and descendant must use captured creation identities to avoid PID reuse errors.
5. Kill the helper repeatedly at startup, especially while CreateProcess is in progress. Confirm no running **or suspended** orphan remains. Exercise parent exit during startup and incompatible inherited parent jobs; failures must launch nothing uncontained.
6. Attempt CREATE_BREAKAWAY_FROM_JOB, a nested job, detached processes, alternate logon, handle enumeration/duplication and hostile process DACL/token access. Verify no job/parent/process/token credential handles leak. This helper alone does not prove the Codex runner's account/object-access boundary.
7. Independently run filesystem deny, network offline IPv4/IPv6/DNS/UDP/loopback, tool routing, environment secret deny, provisioning integrity and output/timeout tests. Job cleanup is only one security property.

If the alternate-account launch is outside the outer job, this design is insufficient. Do not disable checks or allow breakaway to make it run. A trusted runner/upstream change that joins the outer job before starting untrusted code (or an equivalent verified lifetime mechanism) is required.

## Sources reviewed

- [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects), job inheritance, breakaway and kill-on-close.
- [Microsoft: Nested Jobs](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs), accounting and descendant job behavior.
- [Microsoft: CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw), explicit application name, command length and standard handles.
- [Microsoft: UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute), explicit handle list and job list.
- [Microsoft: atomic job assignment](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812), avoiding the suspended-process assignment race.
- [Codex 0.160.0 command runner](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/bin/command_runner/win.rs), preserves descendants on successful root completion.
- [Codex 0.160.0 elevated runner client](https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/elevated/runner_client.rs), CreateProcessWithLogonW launch requiring empirical job-retention verification.
