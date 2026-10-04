# Python smoke probe: prepared, not Windows-validated

The standalone stdlib script is `scripts/python-sandbox-probe.py`. It has not been executed inside a Windows sandbox. Linux unit tests validate logic, mocks, and temporary benign file handling only. They do not validate Windows containment.

No provisioning or launch helper is added. `nativeEnforcement` remains false, and the normal broker still refuses this backend. Do not flip that flag to run the probe. Use only the existing explicit reference experiment below after operator approval and the prerequisites in [Windows validation](WINDOWS_VALIDATION.md) and the [backend README](../packages/codex-backend/README.md).

## Prerequisites and authority

Use a disposable isolated Windows test machine without an existing Codex installation or real work data. A trusted operator must approve possible account, password, ACL, service, firewall and UAC changes from Codex. The Python script makes none of those changes, but the Codex launcher may provision or repair state automatically. There is no verified no-provisioning switch.

The operator supplies and reviews all absolute paths, Python interpreter and standard library, runtime configuration, environment, executable hashes/signatures, policy, test target address, and marker token. Use an absolute `python.exe`, never `python`, `py`, Windows Store aliases or PATH discovery. Keep Python, this script, application source, operator configuration and runtime installation outside sandbox write roots and protected from sandbox writes. Record Python's hash separately: the current backend's runtime verification covers its six known executables, not arbitrary Python runtimes. Do not add Python to that six-file manifest without reviewing its strict schema.

Prepare two dedicated disposable test directories: an allowed workspace and a separate, non-overlapping denied-write fixture outside every writable root. Neither may be a real user-data or system directory. Do not use junctions, symlinks, reparse points, hardlinked markers or 8.3 aliases. The operator must prevent concurrent replacement of these paths throughout testing; metadata preflight is not race-free containment.

1. Verify both directories exist on a writable volume and that the trusted host operator can exclusively create, read, and remove a uniquely named benign baseline file in each. Record this independently. Do not weaken sandbox ACLs to obtain a passing result.
2. Generate a new lowercase canonical UUID, called TOKEN below. In the denied fixture create a new regular file named `pi-python-canary-TOKEN.marker`, using exclusive creation, with exactly these ASCII bytes (LF, not CRLF): `pi-python-sandbox-canary-v1\nTOKEN\n`. Do not overwrite any existing file. Leave this marker readable by the sandbox while denying writes to the fixture. The script only reads this bounded, explicitly identified benign marker; no existing user-file contents are read.
3. If testing offline TCP, use only a controlled numeric IP and TCP port approved by the operator. Independently demonstrate that the listener is up and reachable from the host immediately before and after the run. Do not select an arbitrary Internet service. Omitting the target skips networking. The probe sends no application payload, though establishing a connection necessarily emits TCP traffic.
4. If a prerequisite or approval is missing, stop. Do not run this probe directly on the host as a fallback or infer Windows results from Linux tests.

## Create a request for the existing diagnostic CLI

The following is an operator-reviewed Node ES module recipe to create a new request JSON, not an automatic provisioning script. Replace every placeholder with the approved test values. Save/run it from the repository root only after review. Keep the generated request in a trusted directory, never a sandbox-writable location. The operator-owned `operator.json` remains separate; it must contain the verified runtime and exact activation acknowledgement described in the backend README. Do not generate or fake activation approval from model input.

```js
import { writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { createPolicy } from './packages/core/index.mjs';

// Replace these placeholders; do not target actual user or system data.
const workspace = String.raw`C:\APPROVED_TEST_WORKSPACE`;
const denied = String.raw`C:\APPROVED_DEDICATED_CANARY`;
const pythonExe = String.raw`C:\APPROVED_TRUSTED_PYTHON\python.exe`;
const script = String.raw`C:\APPROVED_TRUSTED_POC\scripts\python-sandbox-probe.py`;
const token = 'REPLACE_WITH_OPERATOR_MARKER_UUID';
const requestPath = String.raw`C:\APPROVED_TRUSTED_CONFIG\python-request.json`;
const policy = createPolicy({
  policyId: randomUUID(), revision: 1,
  ownerSid: 'REPLACE_WITH_VERIFIED_OPERATOR_SID',
  installId: 'disposable-python-probe',
  readMode: 'broadReadWithDeny',
  writeRoots: [workspace], readDeny: [], writeDeny: [denied],
  networkMode: 'offline', runtimeSetId: 'codex-0.160.0',
  limits: { timeoutMs: 30000, maxOutputBytes: 65536 },
  createdAt: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString()
});
const operation = {
  kind: 'exec', executable: pythonExe,
  argv: ['-I', '-B', script,
    '--workspace', workspace,
    '--denied-write-canary-dir', denied,
    '--canary-token', token,
    '--operator-approved-test-targets', '--cleanup-allowed'],
  cwd: workspace, stdin: { mode: 'closed' }
};
// Optional: append only a reviewed controlled numeric address and listening port.
// operation.argv.push('--network-host', APPROVED_IP, '--network-port', APPROVED_PORT);
writeFileSync(requestPath, JSON.stringify({ policy, operation }, null, 2), { flag: 'wx' });
```

`-I` isolates Python from user site packages and Python environment injection; `-B` avoids bytecode writes. It does not itself create a security boundary. Ensure the approved runtime's TEMP/TMP point to a prepared location permitted by this policy and PATH contains only trusted entries; do not inject credentials or model API keys.

Run from the repository root using the operator's absolute trusted Node executable and fully qualified configuration paths:

```text
C:\APPROVED_TRUSTED_NODE\node.exe packages/codex-backend/diagnose.mjs --explicit-windows-experiment C:\APPROVED_TRUSTED_CONFIG\operator.json C:\APPROVED_TRUSTED_CONFIG\python-request.json
```

The diagnostic's exact argv builder uses the pinned flattened Codex syntax:

```text
codex.exe -c windows.sandbox="elevated" -c prefer_mxc=false -c shell_environment_policy.inherit="all" sandbox --sandbox-state-json <compiled managed JSON> -- <absolute python.exe> -I -B <absolute script> <probe arguments>
```

Do not invoke that line directly to bypass the required supervisor. The existing diagnostic invokes the experimental supervisor and performs its fail-closed runtime/activation checks. Its stdout contains the Python JSON if Python actually starts; stderr contains separate launcher diagnostics and the experiment result. A setup failure, timeout, missing JSON, or termination before complete output is not a passing probe. Preserve both streams, launcher exit code, OS build, runtime hashes and observed identities as evidence.

## Meaning of output

Each check has `PASS`, `FAIL`, `INCONCLUSIVE` or `SKIP`. Overall status summarizes the checks that ran: a skipped network or lifetime check remains explicitly untested even if overall status is PASS. Exit codes are 0 for PASS/SKIP, 1 for FAIL, 2 for INCONCLUSIVE. Invalid CLI syntax also exits 2 through argparse.

- Workspace PASS: a uniquely named, exclusively created benign file was written and read back. `--cleanup-allowed` removes only that run's allowed artifact, under the operator's no-concurrent-modification prerequisite.
- Denied-write PASS: exclusive creation in the marked fixture returned an explicit permission error. Missing directories, unreadable/invalid markers, path collisions, a read-only-volume error, and unrelated failures are inconclusive. A missing/invalid marker prevents all probes. A successful denied creation is FAIL and leaves a uniquely named empty artifact for the operator to inspect/remove; the script never overwrites another file.
- TCP PASS: the supplied target returned an explicit permission denial. Timeout, refusal, DNS-related failure and unreachable networks are INCONCLUSIVE, not evidence of offline enforcement. Numeric addresses avoid a DNS lookup entirely. Any successful connection is FAIL. An unrelated pre-existing firewall rule can also deny a connection, so attribution requires independent baseline/evidence.
- Descendant lifetime is always SKIP. The probe creates no child and cannot attest its own termination. `nativeEnforcementAttested` and `cleanupVerified` remain false.

A PASS is only a narrow observation against approved fixtures, not a global security certification or evidence that all reads, writes, IPC or network paths are contained. Failure should stop broader validation rather than trigger host execution or policy relaxation.

## Separate lifetime procedure

Follow the existing Windows validation matrix with an external trusted observer. Record the supervisor, runner, Python and any separately approved long-lived canary child's PID plus creation time and actual Job membership. Check normal completion, cancellation, timeout and parent crash independently, then verify from outside the sandbox that every recorded descendant is gone. PID-only checks can confuse PID reuse. Retain evidence; this script does not automate child spawning, process termination, or lifecycle attestation. The reference backend still reports cleanup unverified.

## Safe local logic tests

From repository root, on Linux or Windows:

```sh
python3 -B scripts/python-sandbox-probe.py --self-test
python3 -B -m unittest discover -s tests/python-probe -p 'test_*.py' -v
```

Use the installed trusted interpreter's name/path for the local platform. These tests use mocks and temporary benign files, no actual network connections, Windows setup, ACL edits or sandbox execution. Sixteen tests passed on Linux during preparation on 2026-10-04. Actual Windows execution remains outstanding.
