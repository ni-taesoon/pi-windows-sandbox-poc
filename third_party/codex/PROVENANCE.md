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
  filter GUIDs, upstream IPv4/IPv6 connect/listen/receive/resource-assignment coverage.
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
