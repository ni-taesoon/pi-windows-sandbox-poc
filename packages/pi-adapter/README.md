# Pi sandbox adapter

This is a broker client, **not a Windows security implementation**. It never opens model-requested files or spawns a command. A backend that proves the native boundary must authorize execution. The default unavailable backend must remain unavailable.

## Verified upstream contract

- Official repository: https://github.com/earendil-works/pi
- Inspected HEAD: `200387122ca450d6387f033949423114a270b96c`
- Optional peer: `@earendil-works/pi-coding-agent` **1.0.2**, Node >=22.19.0
- Source inspection: 2026-10-04. The SDK's `VERSION` is checked at runtime. Version matching is compatibility checking, not package authentication; use a reviewed lockfile/integrity record for production.
- Contract sources at that commit: `packages/coding-agent/src/core/sdk.ts`, `agent-session.ts`, `resource-loader.ts`, `extensions/types.ts`, `settings-manager.ts`, `session-manager.ts`, and `src/index.ts`.

`createAgentSession` accepts a name allowlist in `tools` and definitions in `customTools`; custom definitions replace same-name built-ins. The factory checks actual registered, active, and callable tools plus definition identity. It refuses unexpected tools and an unrecognized SDK version.

## Integration

```js
import * as sdk from '@earendil-works/pi-coding-agent';
import { createSandboxAgent } from './index.js';

// The trusted host explicitly supplies its model runtime and selected model.
// broker.createSession must first validate a prepared policy/backend.
const prepared = await broker.createSession(policy);
const agent = await createSandboxAgent({
  sdk, broker, modelRuntime, model,
  binding: { ...prepared, cwd: workspaceCwd },
});
await agent.prompt('Read the project and propose an edit.');
agent.dispose();
// The host owns broker session cleanup independently.
```

Use an approved workspace directory as `workspaceCwd`; the host supplies this separately from policy roots. Simple relative file paths are prefixed with this directory; traversal/alias syntax remains visible to broker rejection. Never expose raw `AgentSession` or attach the ordinary interactive/RPC frontend: its `executeBash` and other convenience paths can bypass tool definitions. The facade intentionally exposes only text prompt, abort, subscribe, and dispose. It disables prompt expansion and uses an empty resource loader and in-memory settings/session storage. No extensions, project AGENTS files, skills, MCP discovery, or saved sessions are loaded. The supplied SDK and model runtime remain trusted host code, not sandboxed code. Provider credentials belong there, never in tool arguments or child environment.

`createSandboxTools(broker, binding)` is also available for trusted integrations. Using definitions alone does **not** disable other tools: such integrations must replicate the allowlist, extension prohibition, registry verification, and withheld host APIs. Subagents must use the same factory with an authorized broker session, not Pi defaults.

## Tool differences and errors

- `read`: path plus optional **byte** offset/length, UTF-8 preferred, with actual result `encoding` metadata and hash when available. A range that splits a multibyte character or contains invalid UTF-8 returns lossless `base64` instead. Decode each range using its returned encoding; concatenate decoded bytes before interpreting text across chunks. Offsets, length limits and EOF keep their byte meanings; no replacement characters, dropped bytes or expanded ranges. Does not implement Pi's line-based pagination or image resizing.
- `write`: path/content and required mode (`create` or `replace`), optional expectedHash.
- `edit`: exact oldText/newText and required expectedHash. The broker/backend must enforce conflict handling; this PoC uses an optimistic expectedHash check and does not protect against concurrent uncooperative writers. This is not atomic compare-and-edit. The adapter never reads first on the host.
- `powershell`: command plus optional timeoutMs/maxOutputBytes. Explicit PowerShell semantics only; no per-call cwd/env authority.
- `bash`: always throws UNSUPPORTED before dispatch. No Bash-to-PowerShell translation or host fallback.
- `grep`, `find`, `ls`, arbitrary extension tools: absent from the SDK registry allowlist.

Adapter errors reject the tool promise so Pi records an error. Ordinary worker failures such as missing files or invalid UTF-8 edits return `FILE_OPERATION_FAILED` after confirmed termination and leave the session usable. A failed write may have partially changed a file; this error does not promise rollback. Unknown transport failures and unverified cleanup still block the broker. Outcome `unknown` never becomes success and is not automatically retried. AbortSignal triggers broker cancellation for the exact request ID and waits for the broker's execution result. Cancellation is not a guarantee that prior writes were undone. Final result binding is checked against request, session, and policy. Resource and output caps remain broker-enforced.

## Tests

`node --test tests/pi-adapter/*.test.js` from the repository root. Most tests use a fake broker and fake SDK; these prove routing/guard behavior only, not OS isolation. Any real-SDK optional smoke must be reported separately and must not make a model call or invoke host tools. Real Windows R01/R06 testing remains required.

Optional real SDK smoke (independently install the exact peer first):

```sh
PI_OFFLINE=1 PI_SDK_ENTRY=/absolute/path/to/pi-coding-agent/dist/index.js node --test tests/pi-adapter/real-sdk.test.js
```

The real 1.0.2 SDK initialization/registry/disposal smoke passed on Linux during this PoC build, with no model request or broker execution. It does not test Windows enforcement.
