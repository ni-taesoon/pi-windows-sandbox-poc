import { randomUUID } from "node:crypto";
import { StringDecoder } from "node:string_decoder";

export const PI_VERSION = "1.0.2";
export const PI_COMMIT = "200387122ca450d6387f033949423114a270b96c";
const NAMES = Object.freeze(["read", "write", "edit", "powershell", "bash"]);
const string = { type: "string" };
const integer = { type: "integer", minimum: 0 };
const hash = { type: "string", pattern: "^[a-f0-9]{64}$" };
const schema = (properties, required) => ({
  type: "object",
  properties,
  required,
  additionalProperties: false,
});
const specs = {
  read: schema(
    { path: string, offset: integer, length: { ...integer, minimum: 1 } },
    ["path"],
  ),
  write: schema(
    {
      path: string,
      content: string,
      mode: { enum: ["create", "replace"] },
      expectedHash: hash,
    },
    ["path", "content", "mode"],
  ),
  edit: schema(
    { path: string, expectedHash: hash, oldText: string, newText: string },
    ["path", "expectedHash", "oldText", "newText"],
  ),
  powershell: schema(
    {
      command: string,
      timeoutMs: { ...integer, minimum: 1 },
      maxOutputBytes: { ...integer, minimum: 1 },
    },
    ["command"],
  ),
  bash: schema({ command: string }, ["command"]),
};
function failure(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}
function validate(name, args) {
  const definition = specs[name];
  if (!args || typeof args !== "object" || Array.isArray(args))
    throw failure("INVALID_REQUEST", "Tool arguments must be an object");
  for (const key of Object.keys(args)) {
    const rule = definition.properties[key];
    if (!rule)
      throw failure("INVALID_REQUEST", `Unsupported ${name} field: ${key}`);
    const value = args[key];
    if (
      rule.type === "string" &&
      (typeof value !== "string" || value.includes("\0"))
    )
      throw failure("INVALID_REQUEST", `Invalid ${key}`);
    if (
      rule.type === "integer" &&
      (!Number.isSafeInteger(value) || value < rule.minimum)
    )
      throw failure("INVALID_REQUEST", `Invalid ${key}`);
    if (rule.enum && !rule.enum.includes(value))
      throw failure("INVALID_REQUEST", `Invalid ${key}`);
    if (rule.pattern && !new RegExp(rule.pattern).test(value))
      throw failure("INVALID_REQUEST", `Invalid ${key}`);
  }
  for (const key of definition.required)
    if (!Object.hasOwn(args, key))
      throw failure("INVALID_REQUEST", `Missing ${key}`);
}
function operation(name, args, cwd) {
  // Prefix simple relative paths only; do not canonicalize away traversal/alias evidence.
  if ("path" in args && !/^(?:[a-z]:|[\\/])/i.test(args.path))
    args = { ...args, path: `${cwd.replace(/[\\/]$/, "")}\\${args.path}` };
  if (name === "read") return { kind: "read", ...args, encoding: "utf8" };
  if (name === "write") {
    const { content, ...rest } = args;
    return { kind: "write", ...rest, data: content, encoding: "utf8" };
  }
  if (name === "edit") return { kind: "edit", ...args };
  const { command, ...limits } = args;
  return {
    kind: "shell",
    shellId: "powershell",
    script: command,
    cwd,
    ...limits,
  };
}
/** Tools have no host file/shell implementation or retry fallback. Broker is the security boundary. */
export function createSandboxTools(broker, binding) {
  if (
    !broker ||
    typeof broker.execute !== "function" ||
    typeof broker.cancel !== "function"
  )
    throw new TypeError("A broker is required");
  if (
    !binding?.sessionId ||
    !binding.policyRef?.hash ||
    typeof binding.cwd !== "string"
  )
    throw new TypeError("A prepared session binding and cwd are required");
  const { sessionId, cwd } = binding;
  const policyRef = Object.freeze({ ...binding.policyRef });
  return NAMES.map((name) =>
    Object.freeze({
      name,
      label: `Sandbox ${name}`,
      description:
        name === "bash"
          ? "Unavailable: Bash is unsupported by this Windows sandbox. Use powershell explicitly."
          : `Broker-only ${name}. Paths and execution are checked against the prepared policy. Read offsets/lengths are bytes; use returned encoding metadata (base64 for non-UTF-8 ranges); edit requires expectedHash.`,
      parameters: structuredClone(specs[name]),
      executionMode: "sequential",
      async execute(_toolCallId, args, signal) {
        validate(name, args);
        if (name === "bash")
          throw failure(
            "UNSUPPORTED",
            "Bash is unavailable. No host fallback is permitted.",
          );
        if (signal?.aborted)
          throw failure("CANCELLED", "Tool call cancelled before dispatch");
        const requestId = randomUUID();
        let cancelPromise;
        const cancel = () => {
          cancelPromise ??= Promise.resolve()
            .then(() => broker.cancel(sessionId, requestId))
            .catch(() => undefined);
        };
        const request = {
          protocol: { major: 1, minor: 0 },
          requestId,
          sessionId,
          method: "execute",
          policyRef,
          operation: operation(name, args, cwd),
        };
        // Dispatch before installing cancellation so cancel cannot precede broker admission.
        const execution = broker.execute(request);
        signal?.addEventListener("abort", cancel, { once: true });
        if (signal?.aborted) cancel();
        let result;
        try {
          result = await execution;
        } finally {
          signal?.removeEventListener("abort", cancel);
        }
        if (
          !result ||
          result.requestId !== requestId ||
          result.sessionId !== sessionId ||
          result.policyHash !== policyRef.hash
        )
          throw failure("INVALID_RESPONSE", "Broker response binding mismatch");
        if (result.outcome !== "success")
          throw failure(
            result.error?.code ?? "EXECUTION_UNKNOWN",
            result.error?.message ??
              "Execution outcome unknown; do not blindly retry",
          );
        if (signal?.aborted)
          throw failure(
            "CANCELLED",
            "Cancellation requested; consult broker for final execution status",
          );
        const decoders = {
          stdout: new StringDecoder("utf8"),
          stderr: new StringDecoder("utf8"),
        };
        const output =
          (result.outputs ?? [])
            .map((part) => {
              const decoder = decoders[part.stream];
              if (!decoder || part.encoding !== "base64")
                throw failure("INVALID_RESPONSE", "Invalid output chunk");
              return decoder.write(Buffer.from(part.data, "base64"));
            })
            .join("") +
          decoders.stdout.end() +
          decoders.stderr.end();
        const text = result.data
          ? JSON.stringify(result.data)
          : [
              output,
              result.exitCode === undefined
                ? ""
                : `Exit code: ${result.exitCode}`,
              result.truncated ? "[Output truncated]" : "",
            ]
              .filter(Boolean)
              .join("\n") || "Completed";
        return { content: [{ type: "text", text }], details: result };
      },
    }),
  );
}

/** No discovery, extensions, MCP, project context files, prompt files, or host skills. */
export function createEmptyResourceLoader(sdk) {
  const extensions = {
    extensions: [],
    errors: [],
    warnings: [],
    runtime: sdk.createExtensionRuntime(),
  };
  return Object.freeze({
    getExtensions: () => extensions,
    getSkills: () => ({ skills: [], diagnostics: [] }),
    getPrompts: () => ({ prompts: [], diagnostics: [] }),
    getThemes: () => ({ themes: [], diagnostics: [] }),
    getAgentsFiles: () => ({ agentsFiles: [] }),
    getSystemPrompt: () =>
      "Use sandbox tools only. Bash is unsupported. Never assume host access.",
    getSystemPromptSource: () => undefined,
    getAppendSystemPrompt: () => [],
    getAppendSystemPromptSources: () => [],
    extendResources: () => {
      throw failure("UNSUPPORTED", "Dynamic resources are disabled");
    },
    reload: async () => {},
  });
}

/** Trusted host supplies the pinned SDK and model runtime; the returned facade withholds host-capable SDK APIs. */
export async function createSandboxAgent({
  sdk,
  broker,
  binding,
  modelRuntime,
  model,
}) {
  if (sdk?.VERSION !== PI_VERSION)
    throw failure("VERSION_MISMATCH", `Requires Pi ${PI_VERSION}`);
  if (!modelRuntime || !model)
    throw new TypeError("Explicit trusted modelRuntime and model required");
  const tools = createSandboxTools(broker, binding);
  const result = await sdk.createAgentSession({
    cwd: binding.cwd,
    agentDir: binding.cwd,
    modelRuntime,
    model,
    tools: [...NAMES],
    customTools: tools,
    resourceLoader: createEmptyResourceLoader(sdk),
    sessionManager: sdk.SessionManager.inMemory(binding.cwd),
    settingsManager: sdk.SettingsManager.inMemory({ defaultTools: [...NAMES] }),
  });
  const session = result.session;
  function assertTools() {
    for (const method of [
      "getActiveToolNames",
      "getCallableToolNames",
      "getAllTools",
      "getToolDefinition",
    ]) {
      if (typeof session[method] !== "function")
        throw failure("VERSION_MISMATCH", `Pi lacks ${method}`);
    }
    for (const name of [
      ...session.getActiveToolNames(),
      ...session.getCallableToolNames(),
      ...session.getAllTools().map((t) => t.name),
    ]) {
      const expected = tools.find((t) => t.name === name);
      if (
        !expected ||
        session.getToolDefinition(name)?.execute !== expected.execute
      )
        throw failure("UNSUPPORTED", `Unsafe tool registry: ${name}`);
    }
    for (const tool of tools)
      if (session.getToolDefinition(tool.name)?.execute !== tool.execute)
        throw failure(
          "UNSUPPORTED",
          `Missing sandbox replacement: ${tool.name}`,
        );
  }
  try {
    assertTools();
  } catch (error) {
    await session.dispose?.();
    throw error;
  }
  return Object.freeze({
    async prompt(text) {
      if (typeof text !== "string")
        throw new TypeError("Text-only prompt required");
      assertTools();
      return session.prompt(text, { expandPromptTemplates: false });
    },
    abort: () => session.abort(),
    subscribe: (listener) => session.subscribe(listener),
    dispose: () => session.dispose(),
  });
}
