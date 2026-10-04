# Broker contract (PoC)

`index.mjs` is a dependency-free ESM implementation; `index.d.ts` describes the interface. Validation functions are the executable schema: they reject unknown fields; the type declarations describe operation and policy shapes. `createPolicy` validates, canonicalizes lexically, hashes, and deep-freezes an approved policy. This function **does not establish user approval or OS enforcement**. The trusted Electron main must supply approval and authenticated policy storage; renderers/model outputs must never be able to invoke it as authority.

## Native adapter obligations

The shipped default backend refuses every session. There is no production fake backend, unrestricted spawn, or direct file operation. All five operations go through the same `NativeBackend` contract. Capability booleans are a trusted adapter's statement, not attestation or a security boundary against malicious injected JavaScript. Do not load arbitrary adapters or workspace extensions.

A future native backend may report `nativeEnforcement: true` only after implementing and independently testing:

- authenticated owner-bound IPC and protected binaries/configuration;
- dedicated restricted tokens, ACL enforcement of broad reads with deny and approved writes, validated final file/volume identity, reparse/hardlink/TOCTOU handling;
- real offline network enforcement (or explicitly approved online mode);
- a protected cross-process owner/install lock, including crash recovery;
- Job membership and kill-on-close for all descendants, with no breakaway;
- per-execution revalidation of policy/security state and monotonic timeout enforcement;
- minimal native-owned environment, no inherited host environment or secrets, sandbox-only temp/home/package config and pinned runtime discovery;
- exec argv encoding without implicit shell, and a pinned PowerShell path with profiles disabled;
- file read bounds, atomic write-create/replace and exact single-match edit with expected hash conflict checks;
- cancellation that terminates the entire tree, settles execute, then returns `terminated:true`; `close` returns `cleaned:true` only after verified cleanup.

Capability queries, native preparation, cancellation grace, and close are each bounded by `cleanupTimeoutMs` (default 2000 ms). Preparation publishes a fenced session identity before calling the backend. Closing invalidates that identity and waits for outstanding preparation calls to settle before requesting native cleanup; an unresolved or late preparation call cannot reactivate the session or permit READY. `prepare` must return `{enforced:true, policyHash}`. `execute` must return `terminated:true` after every operation, including ordinary successful root exit. `cancel` admission from the broker is not termination confirmation; await the execute terminal result. If native cancellation or execution hangs, a bounded watchdog returns an unknown outcome and blocks the broker until native cleanup is verified. It never reports that a process was killed merely because a timeout elapsed. An OS-supervised native watchdog is still required for a reliable production deadline. An adapter throwing an exception may have left native processes alive: the broker blocks further work until verified cleanup.

String validation is conservative defense in depth only. It rejects relative paths, UNC/device/ADS paths, dot traversal, reserved device names, trailing dots/spaces, and short-name spellings. It cannot inspect NTFS, junctions, symlinks, hardlinks, ACLs, file identities, alternate aliases or races. Case folding assumes the supported Windows case-insensitive volume mode; a native adapter must reject other modes. The host broker performs no file I/O.

## Limits and replay

Only one session and one operation may be active per broker object. This is not a machine-wide lock. Native enforcement must serialize multiple broker processes. Outputs are base64-safe, aggregate byte-bounded and capped at 4096 retained chunks. Overflow requests cancellation and returns OUTPUT_LIMIT only after termination confirmation. Returned structured data is also budgeted. The native worker must bound allocation/read sizes before emitting data; a JavaScript callback cannot undo memory already allocated by an unsafe backend.

Request IDs are UUIDs, scoped to one session. Identical operation payloads share the same pending promise or frozen terminal result; conflicting payloads are rejected. Replay records are never evicted within a live session; the configured request limit requires closing and opening a new session. Records are memory-only. After process loss, persist unknown outcomes and refuse automatic retries in the native layer. New session IDs never resume old execution implicitly.

The broker refuses unknown fields and out-of-bounds values. No policy mutation, network upgrade, setup, repair, extension loading, or privilege escalation is exposed by this module. Failure handling never adds write roots or retries on the host.

## Running core tests

From the repository root: `node --test tests/core/*.test.mjs`.

The fake backend is test-local and performs no execution. These tests verify application contracts only. They are not Windows isolation or installer acceptance tests.
