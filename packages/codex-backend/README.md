# Pinned Codex reference adapter

This is an **external reference backend**, not a source-extracted independent sandbox. It invokes no model and requires no OpenAI API key. Native execution is OFF by default. The production-style `SandboxBroker` refuses `CodexReferenceBackend`: the required process-tree cleanup contract has not been demonstrated on Windows. The separately gated experiment now requires the experimental native job supervisor; adding that executable does not change broker admission.

## Verified upstream pin

- Codex **0.160.0**, tag `rust-v0.160.0`, source commit `a956835d020762cb2b570053af06f643a11c0ecc`.
- Official release: https://github.com/openai/codex/releases/tag/rust-v0.160.0
- GitHub release API queried during this implementation: https://api.github.com/repos/openai/codex/releases/tags/rust-v0.160.0
- Windows x64 raw asset SHA-256 digests, as returned by the official release API:
  - `codex-x86_64-pc-windows-msvc.exe`: `fdda5fa3cf3fb3d000b876720742857676293e4315e4b045fae6f8bd7e866d1d`
  - `codex-command-runner-x86_64-pc-windows-msvc.exe`: `dd13f8e95faba5cf539d870dd3b64c226b00d062a5b523e7e08c44fdc8235224`
  - `codex-windows-sandbox-setup-x86_64-pc-windows-msvc.exe`: `8f91d62aca2aca87b0ebf446848b817720415dd3080905ffc3085c17b70bd57a`

These hashes are for raw EXEs, not ZIP archives. No binary was downloaded, installed, or executed for this implementation. The experiment supports only these x64 artifacts renamed to `codex.exe`, `codex-command-runner.exe`, and `codex-windows-sandbox-setup.exe`, all in one protected trusted directory. This sibling layout is explicitly supported by upstream helper lookup. Other packaging layouts deliberately require adapter changes.

A content hash establishes identity, not Authenticode publisher trust. The operator must verify the source/signature/trust chain and supply hashes for their Node, PowerShell, and built supervisor. The trusted installation, application source, runtime manifest, operator configuration, and CODEX_HOME must be outside sandbox write roots and protected against sandbox writes. Hash checking has a check/use race; this PoC does not implement privileged immutable installation management.

## Exact CLI contract

The pinned version has **host-specific flattened syntax**, not the older `sandbox windows` subcommand:

```text
codex.exe -c windows.sandbox="elevated" -c prefer_mxc=false -c shell_environment_policy.inherit="all" sandbox --sandbox-state-json <JSON> -- <absolute executable> <argv...>
```

The JSON is built from the frozen broker policy, never accepted directly from a model. It contains:

```json
{
  "permission_profile": {
    "type": "managed",
    "file_system": {
      "type": "restricted",
      "entries": [
        {"path":{"type":"special","value":{"kind":"root"}},"access":"read"},
        {"path":{"type":"path","path":"c:\\work"},"access":"write"},
        {"path":{"type":"path","path":"c:\\secrets"},"access":"deny"}
      ]
    },
    "network": "restricted"
  },
  "codex_linux_sandbox_exe": null,
  "sandbox_cwd": "file:///c:/work",
  "use_legacy_landlock": false
}
```

`network` is `restricted` for offline and `enabled` for online. Read denies become `deny`, write denies become more-specific `read` entries. No automatic temporary write root is added. `sandbox_cwd` is a PathUri; entry paths are native Windows strings. The adapter rejects mismatched policy hashes and excessive Windows command-line lengths.

Managed JSON is essential: upstream supports `disabled`/`external` profiles that can take an unsandboxed spawn path. The adapter never generates those profiles. `prefer_mxc=false` prevents ambient MXC preference from replacing the intended restricted-token backend. Explicit `windows.sandbox="elevated"` does not silently fall back to legacy after an elevated launch failure.

- Exact command structs: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/cli/src/lib.rs
- Host dispatch: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/cli/src/main.rs
- Policy loading and Windows launch: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/cli/src/debug_sandbox.rs
- JSON SandboxState: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/codex-mcp/src/runtime.rs

## Stdio, failure, and cleanup

The CLI streams separate stdout/stderr and forwards stdin, including EOF. It returns the root command's exit code; setup/spawn errors print a diagnostic and exit 1. There is no structured CLI security attestation. Its Windows path sets `timeout_ms: None`, `tty: false`, and `stdin_open: true`; our transport applies its own timeout/output limits.

The upstream bridge allows up to five seconds for output draining. Ctrl-C requests termination, but killing the CLI is not proof that every descendant exited. Critically, on normal command exit upstream calls `job.preserve_descendants()`. Therefore a successful `codex` exit must never become `terminated: true` in this adapter.

The experimental supervisor wraps Codex in another non-breakaway job and waits for active-count zero after termination. Upstream spawns the runner via `CreateProcessWithLogonW` without an explicit breakaway flag; provisioning can use a service. Nested-job membership across that logon boundary remains an unrun Windows validation item. The supervisor source and ordinary exit code are not evidence that this works. The experiment always reports `terminated:false`, `cleanupVerified:false` until the native integration is independently validated and the broker integration is deliberately revised.

- Preserve descendants: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/bin/command_runner/win.rs#L668
- Runner launch: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/elevated/runner_client.rs#L392
- Stdio forwarding: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/stdio_bridge.rs

## Setup, state, and coexistence warning

A different CODEX_HOME is **not identity isolation**. Upstream uses fixed local account names `CodexSandboxOffline` and `CodexSandboxOnline`; provisioning can reset their passwords. It writes setup state/credentials beneath CODEX_HOME, grants or reconciles persistent ACLs, and configures account/network infrastructure. A separate CODEX_HOME can collide with an existing Codex installation.

Upstream supports explicit `codex sandbox setup --elevated --current-user --codex-home <directory>` (or `--user <user>` plus `--codex-home`). That is an operator action, not performed by this package. Matching preprovisioned state does **not** prove the next launch is side-effect-free: automatic setup, repair, refresh, and UAC can still happen. There is no verified `--no-provisioning` flag. Use only a disposable isolated Windows VM without another Codex installation. Do not run on a user's everyday machine.

The state-JSON invocation avoids the named-profile managed cloud-config bootstrap, so no model authentication is needed. Local/system/project config loading still occurs. Use a clean operator-controlled CODEX_HOME and trusted project/configuration; this is not a hermetic config loader. Never use a production logged-in Codex home. The sanitized process environment omits API keys and dangerous Node/Python injection variables, but this prototype does not attest every ambient Windows configuration layer.

- Fixed names: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/setup.rs
- Automatic setup: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/identity.rs
- Account password reset: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/windows-sandbox-rs/src/setup_provisioning/sandbox_users.rs
- Setup CLI: https://github.com/openai/codex/blob/a956835d020762cb2b570053af06f643a11c0ecc/codex-rs/cli/src/sandbox_setup.rs

## API and safe diagnosis

Exports: `CODEX_PIN`, `OFFICIAL_X64_SHA256`, `ACTIVATION_ACKNOWLEDGEMENT`, `CodexReferenceBackend`, `compileSandboxState`, `buildInvocation`, `buildSupervisorInvocation`, `verifyRuntime`, `runReferenceExperiment`, `spawnReference`.

Safe on any OS, no spawn or setup:

```sh
node packages/codex-backend/diagnose.mjs
node --test tests/codex-backend/reference.test.mjs
```

`new CodexReferenceBackend()` implements the broker shape but advertises no verified native capabilities and refuses `prepare`/`execute`.

A disposable-Windows-only developer experiment requires an operator-owned JSON file with `runtime` and `activation`. Runtime fields are `version: "0.160.0"`, absolute `codexExe`, `nodeExe`, `powershellExe`, `supervisorExe`, `supervisorVersion: "0.1.0"`, `codexHome`, `systemRoot`, `temp`, trusted `path` string, `userName`, and `files: [{path,sha256}]` covering all six executables. Activation must include `publisherTrustVerified: true`, `preprovisionedVersion: "0.160.0"`, and the exact exported acknowledgement string. These values are operator assertions, not automated native attestation.

```js
import {ACTIVATION_ACKNOWLEDGEMENT,runReferenceExperiment} from './packages/codex-backend/index.mjs';
const activation = {
  acknowledgement: ACTIVATION_ACKNOWLEDGEMENT,
  preprovisionedVersion: '0.160.0',
  publisherTrustVerified: true
};
// runtime is a reviewed operator-owned object; policy is made by createPolicy().
const result = await runReferenceExperiment({runtime,activation,policy,operation,
  onOutput: ({stream,data}) => process[stream].write(data)});
// Never reinterpret result.cleanupVerified === false as success of containment.
```

For CLI use, a separate request JSON contains `{policy, operation}`:

```text
node packages/codex-backend/diagnose.mjs --explicit-windows-experiment operator.json request.json
```

No automatic download, login, setup, account modification request, or native experiment was performed here. Build and validate the supervisor according to its own README before experimenting.

## File operations

Read/write/edit all launch a fixed Node worker inside the sandbox. The host only reads its own trusted worker source and runtime hashes; it does not read or mutate target files. Untrusted paths, file content, edit strings, and expected hashes arrive as JSON on stdin. File creation uses exclusive open; replacement/edit uses an opened handle and expected SHA-256, with exactly-one-match edit semantics. This is not a transactional concurrent editor: concurrent mutations and interruption can leave partial writes. Protecting against every reparse/TOCTOU pattern remains Windows-native validation work; lexical validation is not described as kernel enforcement.

Unit tests use injected fake transports. Passing them proves serialization, gates, and plumbing only. It does not prove restricted-token, ACL, offline network, named-pipe, job, cancellation, or cleanup behavior.
