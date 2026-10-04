# Fixed Python smoke on a disposable Windows runner

**Implemented but not Windows-executed. No security validation claim.** Production
`NATIVE_VALIDATED` and the public `run` gate remain false. This separate Cargo
example has only `setup`, `run`, and `disable`; no request file, shell command,
model-provided argv, alternate interpreter path, policy override, or host fallback.

## Action-time approval scope

Before executing the staging script or any mode, obtain explicit approval naming
one fresh GitHub-hosted `windows-2022` disposable VM, the reviewed source revision
and built helper/driver hashes, and these changes:

- Create `C:\PiSandboxLab` and its `trusted`, `runtime`, `work`, and protected
  `store` directories. Replace ACLs/owners only inside this newly created tree.
  Copy the existing official runner Python installation and reviewed native builds
  into this tree. No install or download is part of this script.
- Create, activate, log on, and finally disable the fresh local `PiSandboxOffline`
  account; write its machine-DPAPI credential record in the protected store. No
  passwords or encrypted credential blobs belong in logs/artifacts.
- Create the five product `pi_sandbox_offline_*` Windows Firewall rules and fixed
  product WFP provider `fdf5f796-2e03-5500-b81b-83e9e8b69f8d`, sublayer
  `a112309b-f79e-58a7-bf97-348979bad2fb`, and filters listed in
  `src/network/wfp/filter_specs.rs`. Existing product objects cause refusal.
- Add and remove account/capability ACEs only on `C:\PiSandboxLab\work`, plus
  helper process/thread and private window-station/desktop object protection.
- Run exactly staged Python `-I -S -B C:\PiSandboxLab\trusted\fixture.py`, cwd
  `C:\PiSandboxLab\work`, through the dedicated-account broker. Its immutable
  source creates/reads only `result.txt` with `PI_WINDOWS_PYTHON_LAB_OK\n`, prints
  that marker, and sleeps three seconds for independent observation. Timeout 15s.
- Disable the owned account after the launch attempt and dispose the whole VM.
  Retain only enumerated non-secret evidence. No WFP removal, account deletion,
  UAC, antivirus, GPO, system-directory ACL, or network-setting weakening.

An approval switch or GitHub dispatch is an operator guard, **not** a substitute
for explicit action-time user approval. No networking probes, denied-read canary,
public-site traffic, package installs, application documents, or production use
are included. Obtain additional approval for any materially different target.

## Approved execution

Build the source and example on Windows with the frozen Cargo.lock:

```powershell
cargo build --locked --manifest-path native/windows-sandbox/Cargo.toml --examples
cargo build --locked --manifest-path native/windows-sandbox/Cargo.toml --bin pi-windows-sandbox
```

In the already-elevated disposable runner (never change UAC to make it work):

```powershell
./scripts/stage_windows_python_lab.ps1 -Phase Stage -ApprovedDisposableVm `
  -PythonHome $env:pythonLocation -BuildDirectory "$PWD/native/windows-sandbox/target/debug" `
  -ExpectedDriverSha256 $approvedDriverHash -ExpectedHelperSha256 $approvedHelperHash `
  -ExpectedPythonSha256 $approvedPythonHash -ApprovedSourceSha256 $approvedSourceHash
./scripts/stage_windows_python_lab.ps1 -Phase Setup -ApprovedDisposableVm
try {
  ./scripts/stage_windows_python_lab.ps1 -Phase Run -ApprovedDisposableVm
} finally {
  ./scripts/stage_windows_python_lab.ps1 -Phase Disable -ApprovedDisposableVm
}
```

Use hashes from reviewed build/runtime evidence for these variables; do not invent
hashes or treat calculating them immediately before execution as independent
review. The source hash is a recorded operator attestation: the stager does not
prove the compiler-to-source mapping or Python package provenance. A trusted,
quiescent frozen checkout, build logs, and the official runner image/toolcache
are explicit lab assumptions. Python executable version/source path and actual
Server 2022 build 20348 + win22 image scope are recorded and checked. Runtime
contents beyond python.exe are baselined and pinned, not independently attested.

`Setup` and `Run` are separate operator actions. Even a failed setup may leave a
fresh disabled account or product filters: dispose the VM, don't adopt them or
retry on that VM. Preserve the first error. If setup committed but later preflight
fails, run only the approved `Disable` recovery. An unknown account is never reset.

## Evidence and scope of a pass

The driver validates immutable compiled policy, recomputed policy digest, owner
and dedicated SIDs, exact fixture bytes, baseline hashes of the entire staged
Python runtime, helper and driver, and holds no-write/no-delete-sharing handles
on these files across launch. Fresh product namespace checks precede setup.
Read-only firewall effective-profile and exact rule checks plus WFP filter identity,
action, flags and condition checks immediately precede the unsafe broker call.
WFP SD bytes are conservatively compared; normalization may produce a refusal.
This is configuration inspection, not a traffic-enforcement measurement.

A separate OS observer snapshots processes, reads the Windows token SID and
restricted-token flag, process image and job membership, and retains process
handles through completion. It does not trust a SID or PID printed by Python.
Python must be observed with the dedicated SID, restricted token, staged image,
job membership and terminated handle. Snapshot sampling can miss short-lived
processes, so the fixed three-second fixture waits; missing evidence fails rather
than passes. Job membership does not establish exact broker job identity, and
unreadable unrelated host processes are skipped. Broker cleanup is independently
required by its returned result. The output file bytes must match and their
SHA-256 is reported on success.

Collect `trusted/stage-evidence.json`, `trusted/baseline.json`,
`trusted/run-evidence.json`, `trusted/recovery-evidence.json`, `trusted/result-evidence.json`, `trusted/summary-evidence.json`, build logs and driver stdout/stderr only. Do **not**
upload `store`, the whole root, an environment dump, or credential material.
A narrow `LAB_SMOKE_PASS` is never native validation. Same-account startup race,
complete deny/escape/descendant/network matrix, exact observer ancestry/job
binding, native server session/desktop behavior, and adversarial tests remain
production blockers. Real Windows failures must be diagnosed from retained
errors; never infer success from cross-compilation or source review.

## Manual lab workflow

`.github/workflows/windows-python-lab.yml` is manual `workflow_dispatch` only.
It requires the exact reviewed source commit and an approval checkbox defaulting
to false. The checkbox attests approval already obtained; never dispatch on
behalf of the user before that specific action-time approval. Official pinned
checkout/setup-python actions and official rustup build the checked source. The
trusted pipeline records compiler, lockfile, source, executable and runtime hashes
and passes those same-build pins into staging. This establishes traceability under
the trusted build assumption, not independently reproducible-build proof.

The workflow always attempts authenticated owned-account disable after a setup
attempt. Only named non-secret evidence files are retained for seven days; neither
credential store nor the synthetic root/runtime is uploaded. A failing step stays
failed. Missing success evidence is reported as missing, and no generated output
or skipped test can manufacture `LAB_SMOKE_PASS`. GitHub tears down the entire
hosted VM after the job; no workflow retry reuses an account or namespace.

The new upload action pin was verified from the official v4.6.2 release and its
linked commit: https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02.
