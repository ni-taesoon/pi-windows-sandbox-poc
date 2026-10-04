# Standalone native backend

The bridge targets the source-built `pi-windows-sandbox.exe run` directly. No existing app/CLI, release executable, provisioning layout, or external supervisor is required by this package.

Execution is **disabled**: `NativeSandboxBackend` refuses preparation/execution until Windows enforcement and lifecycle acceptance testing is complete. Building the native crate does not activate the backend. `diagnose.mjs` is read-only and never spawns a process.

`buildInvocation` serializes the trusted policy, explicit runtime/environment, command, child stdin, limits and parent PID into the native runner's versioned JSON request. `spawnNative` is testable transport plumbing, not an activated backend. It bounds transport framing independently of decoded output, rejects pre-aborted work, and requires explicit process-tree cleanup attestations. Killing the runner or receiving EOF never establishes cleanup.

File-worker source is fixed trusted code; operation arguments travel as child stdin. It must only run within the validated native sandbox, never as a host fallback. Edits verify the original hash, reject invalid UTF-8, and reject multiple matches including overlaps before mutation. Managed runtime binaries must be hash-pinned and outside writable policy roots. Hash identity is not publisher trust.
