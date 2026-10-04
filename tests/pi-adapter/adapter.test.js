import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import {
  createSandboxTools,
  createSandboxAgent,
  PI_VERSION,
} from "../../packages/pi-adapter/index.js";
const binding = {
  sessionId: "00000000-0000-4000-8000-000000000001",
  policyRef: { id: "test", revision: 1, hash: "a".repeat(64) },
  cwd: "C:\\workspace",
};
function fakeBroker() {
  const calls = [],
    cancellations = [];
  return {
    calls,
    cancellations,
    cancel: async (...args) => cancellations.push(args),
    execute: async (request) => {
      calls.push(request);
      return {
        requestId: request.requestId,
        sessionId: request.sessionId,
        policyHash: request.policyRef.hash,
        outcome: "success",
        outputs: [
          {
            stream: "stdout",
            encoding: "base64",
            data: Buffer.from("hello").toString("base64"),
          },
        ],
        bytesSeen: 5,
        truncated: false,
      };
    },
  };
}
const tool = (broker, name) =>
  createSandboxTools(broker, binding).find((t) => t.name === name);
test("all supported operations carry immutable session policy binding", async () => {
  const broker = fakeBroker();
  for (const [name, args, kind] of [
    ["read", { path: "a.txt", offset: 1, length: 8 }, "read"],
    ["write", { path: "a.txt", content: "new", mode: "create" }, "write"],
    [
      "edit",
      {
        path: "a.txt",
        expectedHash: "b".repeat(64),
        oldText: "old",
        newText: "new",
      },
      "edit",
    ],
    ["powershell", { command: "Get-Location", timeoutMs: 500 }, "shell"],
  ]) {
    const result = await tool(broker, name).execute("model-call", args);
    assert.equal(result.content[0].text, "hello");
    assert.equal(broker.calls.at(-1).operation.kind, kind);
    assert.deepEqual(broker.calls.at(-1).policyRef, binding.policyRef);
    assert.equal(broker.calls.at(-1).method, "execute");
  }
  assert.equal(new Set(broker.calls.map((c) => c.requestId)).size, 4);
  assert.equal(broker.calls.at(-1).operation.shellId, "powershell");
});
test("Bash and authority-injection fields fail before broker", async () => {
  const broker = fakeBroker();
  await assert.rejects(tool(broker, "bash").execute("x", { command: "pwd" }), {
    code: "UNSUPPORTED",
  });
  await assert.rejects(
    tool(broker, "powershell").execute("x", {
      command: "pwd",
      env: { SECRET: "x" },
    }),
    { code: "INVALID_REQUEST" },
  );
  await assert.rejects(
    tool(broker, "write").execute("x", { path: "a", content: "x" }),
    { code: "INVALID_REQUEST" },
  );
  await assert.rejects(
    tool(broker, "edit").execute("x", {
      path: "a",
      oldText: "a",
      newText: "b",
    }),
    { code: "INVALID_REQUEST" },
  );
  assert.equal(broker.calls.length, 0);
});
test("no retry or success on broker denial, unknown result, or identity mismatch", async () => {
  for (const outcome of ["error", "unknown", "wrong-binding"]) {
    const broker = fakeBroker();
    const execute = broker.execute;
    broker.execute = async (request) => ({
      ...(await execute(request)),
      outcome: outcome === "wrong-binding" ? "success" : outcome,
      ...(outcome === "wrong-binding" ? { policyHash: "0".repeat(64) } : {}),
    });
    await assert.rejects(tool(broker, "read").execute("x", { path: "a" }));
    assert.equal(broker.calls.length, 1);
  }
});
test("pre-aborted calls do not dispatch", async () => {
  const broker = fakeBroker();
  await assert.rejects(
    tool(broker, "read").execute("x", { path: "a" }, AbortSignal.abort()),
    { code: "CANCELLED" },
  );
  assert.equal(broker.calls.length, 0);
});
test("abort forwards exact request ID and waits for broker outcome", async () => {
  const broker = fakeBroker(),
    controller = new AbortController();
  let finish;
  broker.execute = (request) => {
    broker.calls.push(request);
    return new Promise((resolve) => {
      finish = () =>
        resolve({
          requestId: request.requestId,
          sessionId: request.sessionId,
          policyHash: request.policyRef.hash,
          outcome: "success",
          outputs: [],
        });
    });
  };
  const pending = tool(broker, "read").execute(
    "x",
    { path: "a" },
    controller.signal,
  );
  controller.abort();
  await Promise.resolve();
  assert.deepEqual(broker.cancellations, [
    [binding.sessionId, broker.calls[0].requestId],
  ]);
  finish();
  await assert.rejects(pending, { code: "CANCELLED" });
});
function fakeSdk(extraTool) {
  let options, promptArgs;
  return {
    VERSION: PI_VERSION,
    createExtensionRuntime: () => ({}),
    SessionManager: { inMemory: (cwd) => ({ cwd }) },
    SettingsManager: { inMemory: (settings) => settings },
    async createAgentSession(input) {
      options = input;
      return {
        session: {
          getActiveToolNames: () => [
            ...input.tools,
            ...(extraTool ? [extraTool] : []),
          ],
          getCallableToolNames: () => input.tools,
          getAllTools: () => input.customTools,
          getToolDefinition: (name) =>
            input.customTools.find((t) => t.name === name),
          prompt: async (...args) => {
            promptArgs = args;
          },
          abort: async () => {},
          subscribe: () => () => {},
          dispose: () => {},
        },
      };
    },
    inspect: () => ({ options, promptArgs }),
  };
}
test("factory locks tool selection, suppresses discovery, exposes no raw session", async () => {
  const sdk = fakeSdk();
  const agent = await createSandboxAgent({
    sdk,
    broker: fakeBroker(),
    binding,
    modelRuntime: {},
    model: {},
  });
  assert.deepEqual(Object.keys(agent).sort(), [
    "abort",
    "dispose",
    "prompt",
    "subscribe",
  ]);
  await agent.prompt("/malicious @secret");
  assert.deepEqual(sdk.inspect().promptArgs, [
    "/malicious @secret",
    { expandPromptTemplates: false },
  ]);
  const loader = sdk.inspect().options.resourceLoader;
  assert.deepEqual(loader.getExtensions().extensions, []);
  assert.deepEqual(loader.getAgentsFiles().agentsFiles, []);
  assert.throws(() => loader.extendResources({}), { code: "UNSUPPORTED" });
});
test("unexpected active tool or SDK version refuses session", async () => {
  for (const sdk of [fakeSdk("find"), { ...fakeSdk(), VERSION: "0.0.0" }]) {
    await assert.rejects(
      createSandboxAgent({
        sdk,
        broker: fakeBroker(),
        binding,
        modelRuntime: {},
        model: {},
      }),
    );
  }
});
test("adapter contains no host file/process imports", async () => {
  const source = await readFile(
    new URL("../../packages/pi-adapter/index.js", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(
    source,
    /['"](?:node:)?(?:fs|child_process)(?:\/promises)?['"]|\b(?:spawn|execFile|readFile|writeFile)\s*\(/,
  );
});
test("relative paths are anchored without erasing traversal evidence", async () => {
  const broker = fakeBroker();
  await tool(broker, "read").execute("x", { path: "src\\file.txt" });
  assert.equal(broker.calls[0].operation.path, "C:\\workspace\\src\\file.txt");
  await tool(broker, "read").execute("x", { path: "..\\outside.txt" });
  assert.equal(
    broker.calls[1].operation.path,
    "C:\\workspace\\..\\outside.txt",
  );
});
test("adapter integrates with actual broker contract, using a fake native backend only", async () => {
  const { SandboxBroker, createPolicy } = await import(
    "../../packages/core/index.mjs"
  );
  const backend = {
    capabilities: () => ({
      nativeEnforcement: true,
      kinds: ["read", "write", "edit", "exec", "shell"],
      readModes: ["broadReadWithDeny"],
      networkModes: ["offline"],
    }),
    prepare: async ({ policy }) => ({
      enforced: true,
      policyHash: policy.policyHash,
    }),
    execute: async () => ({
      terminated: true,
      data: {
        encoding: "utf8",
        content: "fake only",
        eof: true,
        hash: "b".repeat(64),
      },
    }),
    cancel: async () => ({ terminated: true }),
    close: async () => ({ cleaned: true }),
  };
  const broker = new SandboxBroker({ backend });
  const policy = createPolicy({
    policyId: "00000000-0000-4000-8000-000000000002",
    revision: 1,
    ownerSid: "S-1-5-21-123",
    installId: "test",
    readMode: "broadReadWithDeny",
    writeRoots: ["C:\\workspace"],
    readDeny: [],
    writeDeny: [],
    networkMode: "offline",
    runtimeSetId: "test",
    limits: { timeoutMs: 1000, maxOutputBytes: 4096 },
    createdAt: new Date(Date.now() - 1000).toISOString(),
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  });
  const session = await broker.createSession(policy);
  const tools = createSandboxTools(broker, {
    ...session,
    cwd: "C:\\workspace",
  });
  const result = await tools
    .find((t) => t.name === "read")
    .execute("x", { path: "file.txt" });
  assert.equal(result.details.data.content, "fake only");
  await assert.rejects(
    tools
      .find((t) => t.name === "read")
      .execute("x", { path: "..\\outside.txt" }),
    { code: "POLICY_DENIED" },
  );
  await broker.closeSession(session.sessionId);
});

test("UTF-8 split chunks decode incrementally per output stream", async () => {
  const broker = fakeBroker(),
    execute = broker.execute;
  const bytes = Buffer.from("🙂");
  broker.execute = async (request) => ({
    ...(await execute(request)),
    outputs: [
      {
        stream: "stdout",
        encoding: "base64",
        data: bytes.subarray(0, 2).toString("base64"),
      },
      {
        stream: "stderr",
        encoding: "base64",
        data: Buffer.from("!").toString("base64"),
      },
      {
        stream: "stdout",
        encoding: "base64",
        data: bytes.subarray(2).toString("base64"),
      },
    ],
  });
  const result = await tool(broker, "read").execute("x", { path: "a" });
  assert.equal(result.content[0].text, "!🙂");
});
