# Disposable Windows lab preparation

Status: **preparation only; native execution blocked.** No Windows tests have run.
The production `NATIVE_VALIDATED=false` and public `run` rejection must remain unchanged.
This package does not add a validation override, driver, installer, elevation flow,
policy mutation, process launcher or network client.

## What is executable now

Python 3.10+ standard library only. From the source repository root:

```sh
python scripts/collect_windows_lab.py --source-root . > preparation.json
python -m unittest discover -s tests/windows-lab -v
```

Use a fresh output filename; shell redirection can overwrite existing files. The
collector itself only reads named source files and emits JSON on stdout. Optional
`--helper PATH`, `--policy PATH` and repeated `--evidence-file PATH` hash explicitly
selected, trusted local files without executing them or including their contents.
Do not point these flags at credentials or private user files. No executable is
searched through PATH and no subprocess is started. The interpreter's identity is
recorded, not Node/Rust/helper version claims obtained by running arbitrary programs.

Exit 0 means evidence collection succeeded, **not security validation passed**.
Input errors return 2 and a BLOCKED error record. Successful collection also remains
BLOCKED and all eight test records are NOT_RUN. Manifest mismatch is recorded and
blocks native work; it does not silently regenerate the manifest. The collector
checks only manifest-listed files, not source completeness or native build identity.
It rejects links/reparses, hardlinks, traversal and selected generated/private trees.
These are input hygiene checks on a trusted quiescent checkout, not race-free file
pins. Do not use the collector on attacker-mutated directories.

## Preflight and approval record (operator completes on the VM)

Record separately, without passwords, DPAPI material or environment dumps:

1. Exact disposable VM identity, Windows edition/build/architecture, isolation from
   work data, recovery snapshot identifier, and verified restoration procedure.
2. Source revision (if present), frozen source-manifest SHA-256 and clean/source
   review status; helper, separate driver, observer, Python and package hashes.
   Save trusted Windows build commands, compiler/toolchain versions, target triple,
   lockfile hash, build logs, signature status when available, and the mapping from
   that source identity to every executable. A matching hash alone proves no mapping.
3. Operator SID, elevation state, security-product/GPO inventory, secondary-logon
   availability, effective filtering configuration, existing product-object collision
   check, and path integrity. Do not disable antivirus, weaken GPO or broaden ACLs.
4. A specific approval identifying `PiSandboxOffline` account creation/activation,
   protected credential storage location, every fixture/parent ACL target, product
   firewall/WFP filters, UAC, and recovery changes. Approving this document or
   running the collector does not approve those security changes.
5. Approved dedicated writable directory, separate denied-write directory, separate
   denied-read fixture, immutable broker/helper/observer and policy locations outside
   writable roots. All data is synthetic. Record baseline hashes, file identity,
   DACL/owner and the minimum precondition access tests under the dedicated identity.
6. Numeric IPv4/IPv6 endpoints and ports owned by the operator, permitted test traffic,
   listener logging, and trusted host connectivity controls before and after each
   network case. No public site, credential, arbitrary DNS target, or surprise traffic.
7. Independent observer with trusted output storage and retained process handles;
   approved bounded timeouts, failure stop conditions, and no host fallback.

If any prerequisite is unavailable, record BLOCKED or INCONCLUSIVE as appropriate;
never manufacture PASS from skipped work. An approval ID is evidence to be checked
by the operator, never a credential or an automated permission bypass.

## Smallest future native launch path (not implemented here)

After source freeze/review, build a **separate lab-only Rust driver crate** outside the
production command. It must have a locked path dependency on the exact native crate,
fixed reviewed policy/fixture inputs, independent observer instrumentation and no
arbitrary command passthrough. Keep setup and run as separate operator actions.

- Elevated approved setup can compose `setup::provision_offline_account(store, owner)`.
  This creates/enables an account, stores DPAPI-protected credentials and installs
  filters; it is not a read-only preflight. Collision/partial failure needs explicit
  recovery; no reuse or deletion of unknown accounts/filter objects.
- Trusted owner run can compose the unsafe
  `broker::run_via_dedicated_helper(store, helper_exe, request)` only after independently
  satisfying every documented safety precondition: authenticated approved policy
  and digest, helper/build integrity, broker/store path protection, fresh effective
  offline controls and product principal identity. The unsafe API is not an
  authorization endpoint. The driver must refuse when those checks cannot be made.
- The broker owns suspended helper creation, outer job assignment, process/thread
  object protection, parent wait-handle duplication, admission and cleanup. Do not
  directly call `internal-experimental-helper`, pass raw handle values, run Python
  on the host as a substitute, call low-level `run_restricted` as a same-user fallback,
  or simply toggle `NATIVE_VALIDATED`.
- Before setup code is executed, driver review must establish verifiable offline
  control inspection and independent observer hooks. Current source APIs do not
  make these unsafe caller duties disappear. This package deliberately stops short
  of supplying an executable unsafe driver.

## Case matrix and evidence

Every case uses `schemas/windows-test-result.schema.json`: source manifest/policy
hashes, UTC start/end, exact benign argv, expected result, structured observed facts,
raw log references plus hashes, status and reproduction steps. The schema describes
records, not an evaluator or proof. A PASS is narrow to that case/target; it does not
promote native validation or prove the complete matrix in `WINDOWS_VALIDATION.md`.

### Python document creation

Use a pinned interpreter and pre-provisioned approved package environment. No online
package install as part of this case. From the verified restricted child, create a
unique benign document under its writable root with exclusive creation. Observer
checks file identity, nonempty valid format/content hash, successful exit/stdout/
stderr, sandbox principal and Job membership. The existing `python-sandbox-probe.py`
checks only narrow byte create/read-back, not document-library compatibility. Add a
separate approved document workload to the future driver to test that requirement.

### Denied path writes and reads

Use distinct synthetic targets. Establish that fixtures exist and have baseline
access in the intended pre-policy setup; observe policy installation separately.
For denied write, attempt exclusive new-file creation only. Explicit access denial
plus unchanged observer inventory/hash is narrow PASS; successful creation is FAIL
and immediately stops tests. Other errors (missing path, sharing violation, malformed
path) are INCONCLUSIVE. Do not retry with broader privileges.

For denied read, open one known existing benign fixture after admission. Explicit
access denial and a known-good baseline are narrow PASS; returned bytes mean FAIL
without logging bytes. Missing file, enumeration/preflight failure and wrong target
are INCONCLUSIVE. The existing probe has no denied-read case; do not claim it does.
Its denied-write marker must remain readable and cannot be reused as the denied-read
fixture: otherwise marker preflight fails before the access test.

### Offline network

Test one explicitly approved numeric controlled listener per address family. Use
host connectivity checks immediately before/after, listener correlation by run and
source identity, and effective WFP/firewall evidence. Sandbox connection success is
FAIL even if no application data was sent. Explicit access denial with valid controls
is narrow PASS for that attempted connect. Timeout, refusal, reset, unavailable IPv6,
missing listener logs, unverified filtering, or failed baseline is INCONCLUSIVE.
Never interpret a timeout as proof of isolation. The old probe's denial output is
an observation, not independent enforcement attestation. TCP alone does not cover
UDP/DNS/DoH/loopback/SMB/UNC; retain those as NOT_RUN in the wider matrix.

### Descendants and process cleanup

Observer obtains process handles, PIDs plus creation times, principal identity and
Job membership for helper, root, child and grandchild before triggering each case.
Use benign wait-only descendants with an observer-verified started signal and
bounded duration. Case A: root exits normally while descendants remain active.
Case B: approved termination of that lab broker only after all processes started.

Require every retained handle to become signaled within the declared cleanup
interval, Job active-process count zero when the observer can retain/query it, and
no unexpected breakaway process. Root exit, output closure, PID disappearance alone,
or self-reported `cleanupVerified` is insufficient. Distinguish PID reuse by creation
time. If observer lost required access or missed startup, INCONCLUSIVE; if a known
process remains alive after deadline, FAIL and stop. No ad-hoc global process kill.

### Security-state cleanup/recovery

Process cleanup and configuration cleanup are separate results. Record before/after
DACLs, owned account SID/state, filter IDs and protected store metadata without
credential contents. `disable_offline_account` is an explicit elevated recovery
operation; it does not remove persistent filters/accounts/stores. Admission failure
may intentionally retain restrictive ACLs. Never mark cleanup complete on disable
alone. Preserve evidence outside the disposable snapshot, then use the preapproved
VM restoration procedure and independently verify baseline restoration. Unknown
residual state is INCONCLUSIVE and prevents further tests.

## Stop conditions and coverage limits

Any outside write/read success, network success, surviving tracked descendant,
identity/path/hash mismatch, ownership conflict or policy relaxation stops the run.
Retain evidence; do not automatically repair security state. The operator's approved
recovery plan owns recovery. A failed negative case is a genuine failure even if
cleanup later succeeds.

This initial eight-case package does not cover every path alias/race, package
lifecycle, IPC/handle attack, policy error, inherited environment/secret exposure or
concurrent run. Those remain mandatory additional work from the main Windows matrix
before production activation. No result generated by this collector is Windows proof.

## Preparation-tool validation (2026-10-04)

18 Linux fixture/schema tests passed, including negative controls for paths, source drift,
missing evidence and non-execution. [Test log](review-evidence/2026-10-04/lab-preparation-tests.log).
After integration, the source collector was rerun against the refreshed manifest;
all listed hashes matched. Its outcome remains BLOCKED and all eight cases NOT_RUN.
This validates collection logic only, not the Windows system or any sandbox boundary.
