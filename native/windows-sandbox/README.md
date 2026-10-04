# Standalone Windows sandbox source extraction (experimental)

This is a separate Cargo workspace. It builds `pi-windows-sandbox`, not Codex.
It has no Codex crate, model, authentication, session, CLI, or executable dependency.
Its upstream source is pinned; see [provenance](../../third_party/codex/PROVENANCE.md).

## What exists

- `token`: upstream restricted primary-token construction, privilege removal,
  restricting capability SIDs, logon-scoped default DACL, bounded token parsing.
- `acl`: upstream ACL inspection and explicit allow/deny read/write ACE operations.
- `desktop::PrivateDesktop::for_token`: new per-launch Pi private desktop with
  protected DACL and CSPRNG name, scoped to broker owner and sandbox logon SID.
- `process::run_restricted`: actual Win32 `CreateProcessAsUserW`, absolute executable,
  explicit environment and inherited stdio handle list, atomic job membership using
  `PROC_THREAD_ATTRIBUTE_JOB_LIST`, kill-on-close with no breakaway, output limits,
  timeout and parent liveness checks, tree termination, verified zero active job members.
- `setup::prepare_disabled_offline_account`: explicit elevated setup primitive for
  a fresh, DISABLED Pi offline account, DPAPI protection and account-scoped
  Windows Firewall/WFP setup. It refuses to adopt an existing account.
- `setup::provision_offline_account`: separate explicit experimental provisioning
  API creating a fresh protected credential store with atomic no-reparse object
  creation, enabled-account verification and disable-on-failure rollback. It binds
  the store to the authorized broker owner and validates dedicated account SID/groups.
  This is not exposed by the production CLI and must only run after setup authorization.
- `setup::logon_offline_identity`: validates protected store owner/DACL/record,
  decrypts credentials using product-scoped DPAPI entropy, validates the new token
  identity/groups, and returns an owned dedicated-account logon.
- `admission::AdmittedLaunch::from_identity`: staged trusted library composition of
  pinned-handle ACL admission, capability-only write-restricted token (without Everyone,
  logon or account-user restricting SIDs), per-launch private desktop and Job runner.
  A global product account lease serializes shared-account ACLs. Ordinary account
  access and capability write grants are distinct; read/write denies use the account
  SID, avoiding a potentially shared host logon SID. ACEs are revoked only after
  verified tree death; on unknown cleanup they remain for explicit recovery.
  Existing exact local path trees only, at most 10,000 objects/128 components;
  reparses, hardlinked files and complex ACEs are rejected.
- `broker::run_via_dedicated_helper`: experimental two-stage source composition.
  The normal owner broker starts this product's own pinned immutable helper with
  CreateProcessWithLogonW suspended, assigns an outer Job before resuming, hardens
  process/thread DACLs with OWNER RIGHTS, and authenticates local named-pipe peers
  by actual process IDs. The helper restricts a derivative of its own account token
  then invokes CreateProcessAsUserW. This removes the design requirement for an
  administrator runtime broker; privileged setup remains a separate explicit action.
  Credentials stay in the broker and are never passed through IPC.
- `protocol`: strict bounded JSON request and result definitions, with no LLM protocol.

These are real standalone native functions, not wrappers invoking another product.
Setup/account changes are not run by this repository's build, tests, or execution CLI.
The preparation-only API leaves the account disabled and does not persist credentials.
The separate provision API can activate its newly owned account after installing
protections; its protected ready record is still not a production-validation claim.
No setup or activation was executed during cloud development.

## What is deliberately unavailable

`status` reports `nativeValidated:false`. `run` parses/validates its request then
fails with `NATIVE_VALIDATION_REQUIRED`. There is no environment-variable override,
flag, automatic elevation, current-user fallback, or host execution fallback.

Policy digest authentication and user-facing authorization IPC, per-launch re-verification
of effective network controls, generalized policy planning (including globs/missing
targets), provisioning recovery/uninstall, same-account orphan-process auditing,
and integration into the public execution endpoint remain unfinished. Existing trusted-broker library seams are experimental and must
be reviewed/tested on Windows. Raw ACL functions alone are not a policy engine.
Changing a constant does not implement those missing boundaries.

The direct low-level run API requires CreateProcessAsUserW privileges when invoked
across accounts. The two-stage broker avoids this by restricting the helper's own token.
The helper launch/session/window-station path is still untested on Windows. No host
or elevated-runtime compatibility fallback is provided.

Known security blocker: CreateProcessWithLogonW cannot accept an initial process
security descriptor. A pre-existing same-account process might acquire a handle to
its suspended helper before the broker hardens the process/thread DACL. The global
lease prevents concurrent compliant brokers, but is not an orphan-process audit or
proof that no previous sandbox process exists. This must be resolved/validated before
production use. Post-create OWNER RIGHTS hardening alone is not claimed sufficient.

The capability-only token, serialized account ACLs and per-capability desktop/default
object DACL are deliberate product security-semantic changes from the upstream
compatibility path. They require new Windows evidence, especially object creation,
access checks, inherited ACLs, same-account attacks and nested-job lifecycle.

The low-level runner requires an already authenticated, restricted dedicated-account
primary token, verified offline protection and filesystem policy, and a live private
desktop. Its unsafe API documents those preconditions. Numeric parent PID and an
input policy hash are not authentication. They must be authenticated by the future
broker. Callers should own handles rather than accept arbitrary raw handles over IPC.

This extraction retains the upstream broad-read model with explicit read denies.
It does not claim strict filesystem confidentiality or protection from all same-host
side channels. ACL mutation requires explicit setup authorization and Windows validation.

## Build and validation

From this directory, using official Rust stable:

    cargo test --locked
    cargo check --locked --target x86_64-pc-windows-gnu --tests
    cargo build --locked --release --target x86_64-pc-windows-msvc

The first command on Linux tests only portable protocol/gate code. Cross-checking
Windows source is not running Windows security tests. A Windows linker/toolchain is
required for a runnable Windows executable. No binary is bundled in this source POC.

Before shipping, run dedicated-account isolation, explicit denied-read, reparse/hardlink,
network IPv4/IPv6/DNS/TCP/UDP/listen/loopback, alternate token path, breakaway/nested-job,
parent death, cancellation, timeout, output flood, setup partial failure and ACL
rollback/recovery tests on supported Windows hosts. Keep all capability gates false
until the missing integration and that matrix are complete.

## Wire format

`pi-windows-sandbox status` prints one JSON status object.
`internal-experimental-helper` is a dedicated-account, PID-authenticated pipe entry
used only by the experimental library; it is not a general shell/host execution mode.
`pi-windows-sandbox run` reads one UTF-8 JSON object from stdin (maximum 1 MiB),
then closes stdout with an NDJSON error and nonzero exit status while gated.
Fields: `schemaVersion:1`, `argv`, `cwd`, `env`, `stdin`, `parentPid`, `policyHash`,
`timeoutMs`, `maxOutputBytes`, `policy` containing `workspace`, `writableRoots`,
`denyRead`, `denyWrite`, `network:"disabled"`. Unknown fields are rejected.
Output result schema for the low-level library includes `type:"result"`, `exitCode`,
`stdoutBase64`, `stderrBase64`, `stopReason`, `timedOut`, `truncated`, `terminated`,
`cleanupVerified`. Base64 preserves raw subprocess bytes without lossy UTF-8 decoding.
Both streams are individually bounded by `maxOutputBytes`; truncation is explicit.
`stopReason` is `exited`, `timeout`, `outputLimit`, or `parentDeath`; only `exited`
is a normal command result. Forced termination never reports Windows STILL_ACTIVE.
