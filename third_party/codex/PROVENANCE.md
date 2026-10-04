# Source provenance and modifications

Upstream: https://github.com/openai/codex
Exact revision: `a956835d020762cb2b570053af06f643a11c0ecc`
Source: https://github.com/openai/codex/tree/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs
License: Apache-2.0; the complete upstream LICENSE and NOTICE are retained here.
`SOURCE_MANIFEST.json` maps every derived implementation/test file to original
paths and SHA-256 digests. Upstream NOTICE is retained without implying all its
listed third-party components are included in this extraction.

## Extraction modifications

- `token`, `token_user`, `acl` and their tests: copied reusable low-level source,
  provenance headers added; no upstream workspace dependency. Added strict token
  constructor using capability-only restricting SIDs (omitting Everyone, logon and
  account-user SIDs) and adding capability ACEs to the default object DACL;
  original low-level compatibility variants remain separately named. Converted one
  ACL let-chain to equivalent nested if for Rust 2021. Tests use crates.io
  pretty_assertions and tempfile. Applicable upstream copyright and Apache terms remain.
- `winutil`: group identity/comment changed to PiSandboxUsers; no Codex account reuse.
- `proc_thread_attr`: standalone extraction; product telemetry comment renamed;
  upstream atomic job-membership and explicit handle-list logic retained.
- `desktop`: adapted private desktop construction, no policy cache or legacy default
  desktop. Product-owned namespace, BCrypt nonce, owner/logon protected DACL.
- `process`: adapted CreateProcessAsUserW/attribute/job concepts into a small synchronous
  bounded runner; removed Codex logging, PTY, packaged-app and session coupling.
  Job breakaway, preserve-descendants and compatibility host fallbacks removed.
- `setup/accounts`: fresh PiSandboxOffline creation, elevation check, CSPRNG password,
  SID lookup and identity.rs-derived dedicated-account logon/token checks. New account
  activation and SID-bound disable rollback are scoped to the protected product record.
  No adoption/reset/enabling of upstream accounts.
- `setup/dpapi`: standalone upstream DPAPI source with product-scoped entropy and
  plaintext zeroization; protected storage added separately in new `setup/store.rs`.
- `setup/no_reparse_dir` and tests: upstream NtCreateFile no-reparse/pinning helpers,
  optional atomic security descriptor, product guard names, BCrypt entropy.
- `network/firewall`: standalone firewall source, all-profile enabled checks,
  product-owned rule identities; proxy relaxations removed.
- `network/wfp` and filter specs: offline-only source, product-owned provider/sublayer/
  filter GUIDs, IPv4/IPv6 AUTH_CONNECT and RESOURCE_ASSIGNMENT filters (not separate listen/receive layers).
- New `admission`: staged trusted library composition, pinned-handle account/capability
  ACLs serialized by a global product account lease, capability-only token/private
  desktop/job chain and fail-safe cleanup. Narrow write-deny masks exclude common
  read-control/synchronize rights. Hardlinks/complex ACLs/reparses are rejected.
- `setup/launch`: adapted elevated/runner_client.rs CreateProcessWithLogonW sequence
  into a standalone suspended-helper primitive; credentials stay local, product binary
  and ancestor paths are pinned/checked, workspace cwd and inherited env removed.
- New `broker`: bounded local named-pipe framing with mutual actual PID authentication,
  suspended own-helper Job assignment and OWNER RIGHTS process/thread hardening.
  Helper restricts its own token. This is new product integration, not upstream-tested
  behavior. Known pre-hardening same-account helper-process race remains a blocker.
  Global lease is not an orphan-process audit. Production CLI remains disabled.
- New `protocol`, `main`, `lib`, `setup/store`, `setup`/`network` entrypoints, Cargo manifest and README
  define the product boundary. No Codex executable is located, bundled, or invoked.

Source reuse is not a claim of equivalent security or compatibility. Integration and
Windows validation remain incomplete; production entrypoint stays fail-closed.
Dependencies come from crates.io and are captured in the standalone Cargo.lock.

## Review fixes (2026-10-04)

- Firewall rule readback now uses a new portable complete-scope validator. Existing
  mismatched rules are rejected without mutation; new selectors are explicitly set.
- Broker transfers a noninheritable SYNCHRONIZE-only process handle to its protected
  helper. The helper duplicates the received local handle and runs through a borrowed
  parent-handle path; no cross-account PID reopen is required in that path.
- New portable/source-contract regression tests and Windows-only handle tests are
  product additions. Windows tests were compiled, not executed; see
  `docs/REVIEW_FIX_EVIDENCE.md` for the distinction between real JS, modeled property
  validation, source assertions and unexecuted Windows tests.

## Fixed Python lab additions (2026-10-04)

New lab-only example, staging script, workflow and source-contract tests compose
the existing primitives without opening the public run endpoint. Derived firewall/WFP
modules add read-only exact configuration inspection and fresh-namespace checks.
The Windows ToolHelp feature supports independent process observations.
Source/contract checks and Windows cross-compilation are not native runtime proof.

## Local SAM identity and rollback correction

After measured Windows error 1332, local account identity uses NetUserGetInfo level23
instead of ambiguous name lookup. WFP user conditions use an explicit SID trustee.
Fresh transaction ownership markers and SID/state readback scope recovery; the
protected ready:false record is flushed before network setup or activation.
These changes do not protect against a malicious privileged account-replacement
race and are pending the next actual Windows attempt.

## Remote-address representation comparison

The new product-owned bounded address-set parser compares numeric IPv4/IPv6
unions exactly for firewall remote addresses. Other selector fields stay exact;
unknown syntax and unequal sets fail closed. This addresses a measured remote-address
readback mismatch without assuming its unlogged Windows spelling.

## Broker API diagnostics

Following a measured access-denied broker failure, product broker wrappers report
constant phase/API labels and numeric Win32 error codes. Desired access masks,
object security, operation order and fail-closed behavior are unchanged. New
source-contract coverage checks label completeness; no upstream validation claim
or additional permission grant is implied.
