import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { createPolicy, SandboxBroker } from "../../packages/core/index.mjs";
import {
  NATIVE_VALIDATED,
  NativeSandboxBackend,
  compileNativePolicy,
  buildInvocation,
  spawnNative,
  parseExperimentInputs,
  diagnosticExitCode,
  assertRuntimeOutsidePolicy,
} from "../../packages/native-backend/index.mjs";
const policy = () =>
  createPolicy({
    policyId: "fdc817d9-6d7e-4098-a186-d3aa99d0ab08",
    revision: 1,
    ownerSid: "S-1-5-21-123-1000",
    installId: "test",
    readMode: "broadReadWithDeny",
    writeRoots: ["C:\\work"],
    readDeny: ["C:\\secrets"],
    writeDeny: ["C:\\work\\.git"],
    networkMode: "offline",
    runtimeSetId: "native-0.1.0",
    limits: { timeoutMs: 1000, maxOutputBytes: 65536 },
    createdAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
  });
const runtime = {
  version: "0.1.0",
  runnerExe: "C:\\trusted\\pi-windows-sandbox.exe",
  nodeExe: "C:\\trusted\\node.exe",
  powershellExe:
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  systemRoot: "C:\\Windows",
  path: "C:\\trusted;C:\\Windows\\System32",
  temp: "C:\\work\\tmp",
  userName: "test",
  files: [],
};
const op = {
  kind: "exec",
  executable: runtime.nodeExe,
  argv: ["-e", 'console.log("hi")'],
  cwd: "C:\\work",
  stdin: { mode: "closed" },
};
test("standalone native policy explicitly includes offline and deny rules", () => {
  const p = compileNativePolicy(policy(), "C:\\work");
  assert.equal(p.network, "disabled");
  assert.deepEqual(p.denyRead, ["c:\\secrets"]);
  assert.deepEqual(p.denyWrite, ["c:\\work\\.git"]);
});
test("policy digest tampering is rejected", () =>
  assert.throws(
    () =>
      compileNativePolicy({ ...policy(), networkMode: "online" }, "C:\\work"),
    { code: "POLICY_DENIED" },
  ));
test("standalone invocation directly targets own runner without external CLI or supervisor", async () => {
  const r = await buildInvocation({
    policy: policy(),
    operation: op,
    runtime,
    parentPid: 123,
  });
  assert.equal(r.executable, "c:\\trusted\\pi-windows-sandbox.exe");
  assert.deepEqual(r.args, ["run"]);
  const req = JSON.parse(r.stdin);
  assert.equal(req.schemaVersion, 1);
  assert.equal(req.parentPid, 123);
  assert.equal(req.policyHash, policy().policyHash);
  assert.deepEqual(req.argv, ["c:\\trusted\\node.exe", ...op.argv]);
  assert.equal(req.stdin, "");
  assert.equal(req.env.OPENAI_API_KEY, undefined);
  assert.equal(req.env.NODE_OPTIONS, undefined);
  assert.equal(req.env.CODEX_HOME, undefined);
});
test("file content is child stdin data, never worker source or outer argv", async () => {
  const data = 'evil(); " & calc.exe';
  const r = await buildInvocation({
    policy: policy(),
    operation: {
      kind: "write",
      path: "C:\\work\\new.txt",
      data,
      encoding: "utf8",
      mode: "create",
    },
    runtime,
    workerSource: "fixed worker",
  });
  const req = JSON.parse(r.stdin);
  assert.equal(req.argv.at(-1), "fixed worker");
  assert.equal(
    req.argv.some((x) => x.includes(data)),
    false,
  );
  assert.equal(JSON.parse(req.stdin).data, data);
  assert.deepEqual(r.args, ["run"]);
});
test("shell is encoded for the child, never evaluated by a host shell", async () => {
  const r = await buildInvocation({
    policy: policy(),
    operation: {
      kind: "shell",
      shellId: "powershell",
      cwd: "C:\\work",
      script: 'Write-Output "a & b"',
    },
    runtime,
  });
  const req = JSON.parse(r.stdin);
  assert.equal(req.argv.at(-2), "-EncodedCommand");
  assert.equal(
    Buffer.from(req.argv.at(-1), "base64").toString("utf16le"),
    'Write-Output "a & b"',
  );
});
test("broker refuses unvalidated native engine even if a build exists", async () => {
  assert.equal(NATIVE_VALIDATED, false);
  const backend = new NativeSandboxBackend({ nativeValidated: true });
  assert.equal(backend.capabilities().nativeEnforcement, false);
  await assert.rejects(new SandboxBroker({ backend }).createSession(policy()), {
    code: "BACKEND_UNAVAILABLE",
  });
  await assert.rejects(backend.execute(), { code: "BACKEND_UNAVAILABLE" });
});
test("request cannot override operator runtime or activate enforcement", () => {
  for (const extra of [
    { runtime: {} },
    { nativeValidated: true },
    { activation: {} },
  ])
    assert.throws(
      () =>
        parseExperimentInputs(
          { runtime },
          { policy: policy(), operation: op, ...extra },
        ),
      { code: "INVALID_REQUEST" },
    );
  assert.equal(
    parseExperimentInputs({ runtime }, { policy: policy(), operation: op })
      .runtime,
    runtime,
  );
});
test("trusted runtime paths cannot reside inside writable roots", () =>
  assert.throws(
    () =>
      assertRuntimeOutsidePolicy(
        { ...runtime, nodeExe: "C:\\WORK\\node.exe" },
        policy(),
      ),
    { code: "POLICY_DENIED" },
  ));
test("oversized child command lines reject rather than truncate", async () =>
  await assert.rejects(
    buildInvocation({
      policy: policy(),
      operation: { ...op, argv: ["x".repeat(20000)] },
      runtime,
    }),
    { code: "INVALID_REQUEST" },
  ));
test("diagnostic error cannot become successful exit code", () => {
  assert.equal(
    diagnosticExitCode({ exitCode: 0, error: { code: "TIMEOUT" } }),
    1,
  );
  assert.equal(diagnosticExitCode({ exitCode: 0 }), 0);
});
const invocation = {
  executable: "fake",
  args: ["run"],
  cwd: "fake",
  env: {},
  stdin: "{}",
};
function fakeChild() {
  const child = new EventEmitter();
  for (const k of ["stdin", "stdout", "stderr"]) child[k] = new PassThrough();
  child.kill = () => {};
  child.unref = () => {};
  return child;
}
test("pre-aborted native transport does not spawn", async () => {
  let calls = 0;
  await assert.rejects(
    spawnNative(
      invocation,
      { signal: AbortSignal.abort(), timeoutMs: 100, maxOutputBytes: 100 },
      {
        spawnProcess: () => {
          calls++;
          return fakeChild();
        },
      },
    ),
    { code: "CANCELLED" },
  );
  assert.equal(calls, 0);
});
test("transport watchdog bounds child that never closes after kill", async () => {
  const child = fakeChild();
  let kills = 0;
  child.kill = () => {
    kills++;
  };
  const result = await spawnNative(
    invocation,
    { timeoutMs: 5, maxOutputBytes: 100 },
    { spawnProcess: () => child, drainTimeoutMs: 10 },
  );
  assert.equal(kills, 1);
  assert.equal(result.error.code, "CLEANUP_UNCONFIRMED");
  assert.equal(result.terminated, false);
  assert.equal(child.stdout.destroyed, true);
});
async function transportResult(
  event,
  maxOutputBytes = 100,
  processExitCode = 0,
) {
  const child = fakeChild(),
    outputs = [];
  const promise = spawnNative(
    invocation,
    {
      timeoutMs: 100,
      maxOutputBytes,
      onOutput: (chunk) => outputs.push(chunk),
    },
    { spawnProcess: () => child },
  );
  child.stdout.write(
    JSON.stringify({
      ...event,
      ...(Object.hasOwn(event, "stdout")
        ? { stdoutBase64: Buffer.from(event.stdout).toString("base64") }
        : {}),
      ...(Object.hasOwn(event, "stderr")
        ? { stderrBase64: Buffer.from(event.stderr).toString("base64") }
        : {}),
    }) + "\n",
  );
  child.emit("close", processExitCode, null);
  return { result: await promise, outputs };
}
const terminal = {
  type: "result",
  stopReason: "exited",
  exitCode: 0,
  stdoutBase64: "",
  stderrBase64: "",
  timedOut: false,
  truncated: false,
  terminated: true,
  cleanupVerified: true,
};
test("native error gate propagates without success or cleanup inference", async () => {
  const { result } = await transportResult(
    { type: "error", code: "NATIVE_VALIDATION_REQUIRED" },
    100,
    1,
  );
  assert.equal(result.error.code, "NATIVE_VALIDATION_REQUIRED");
  assert.equal(result.terminated, false);
});
test("JSON framing overhead does not consume native content budget", async () => {
  const { result, outputs } = await transportResult(
    { ...terminal, stdout: '"'.repeat(100) },
    100,
  );
  assert.equal(result.error, undefined);
  assert.equal(result.bytesSeen, 100);
  assert.equal(outputs[0].data.length, 100);
});
test("combined streams respect byte budget and require cleanup attestations", async () => {
  const { result, outputs } = await transportResult(
    { ...terminal, stdout: "123", stderr: "456" },
    4,
  );
  assert.equal(result.error.code, "OUTPUT_LIMIT");
  assert.equal(
    outputs.reduce((n, x) => n + x.data.length, 0),
    4,
  );
  assert.equal(
    (await transportResult({ ...terminal, cleanupVerified: false })).result
      .error.code,
    "CLEANUP_UNCONFIRMED",
  );
});

test("native stdout preserves non-UTF-8 bytes through base64", async () => {
  const bytes = Buffer.from([0xff, 0x00, 0xc3]);
  const { result, outputs } = await transportResult(
    { ...terminal, stdoutBase64: bytes.toString("base64") },
    3,
  );
  assert.equal(result.error, undefined);
  assert.deepEqual(outputs[0].data, bytes);
});
test("invalid or noncanonical base64 is rejected", async () => {
  for (const stdoutBase64 of ["!!!!", "Zg=", "Zh=="]) {
    const { result } = await transportResult({ ...terminal, stdoutBase64 });
    assert.equal(result.error.code, "BROKER_LOST");
  }
});
test("file result framing has a separate bound from one-byte read content", async () => {
  const req = await buildInvocation({
    policy: policy(),
    runtime,
    operation: {
      kind: "read",
      path: "C:\\work\\a",
      length: 1,
      maxOutputBytes: 1,
      encoding: "utf8",
    },
  });
  assert.equal(JSON.parse(req.stdin).maxOutputBytes, 1028);
  const child = fakeChild(),
    outputs = [];
  const pending = spawnNative(
    req,
    { timeoutMs: 100, maxOutputBytes: 1, onOutput: (x) => outputs.push(x) },
    { spawnProcess: () => child },
  );
  const response = {
    ok: true,
    data: { encoding: "base64", content: "YQ==", eof: true },
  };
  child.stdout.write(
    JSON.stringify({
      ...terminal,
      stdoutBase64: Buffer.from(JSON.stringify(response)).toString("base64"),
    }) + "\n",
  );
  child.emit("close", 0, null);
  const result = await pending;
  assert.equal(result.error, undefined);
  assert.deepEqual(result.data, { encoding: "utf8", content: "a", eof: true });
  assert.deepEqual(outputs, []);
});
test("tiny mutation output budget does not truncate write metadata", async () => {
  const req = await buildInvocation({
    policy: policy(),
    runtime,
    operation: {
      kind: "write",
      path: "C:\\work\\a",
      mode: "create",
      data: "a",
      encoding: "utf8",
      maxOutputBytes: 1,
    },
  });
  assert.equal(JSON.parse(req.stdin).maxOutputBytes, 1024);
});

test("native stop reasons cannot report normal success even with exit code zero", async () => {
  for (const [stopReason, code] of [
    ["parentDeath", "BROKER_LOST"],
    ["timeout", "TIMEOUT"],
    ["outputLimit", "OUTPUT_LIMIT"],
  ]) {
    const { result } = await transportResult({ ...terminal, stopReason });
    assert.equal(result.error.code, code);
    assert.equal(result.terminated, true);
  }
});
test("absent or unknown native stop reason fails closed", async () => {
  for (const stopReason of [undefined, null, "cancelled", "success"]) {
    const { result } = await transportResult({ ...terminal, stopReason });
    assert.equal(result.error.code, "BROKER_LOST");
  }
});
test("parent death cannot return successful structured file data", async () => {
  const req = await buildInvocation({
    policy: policy(),
    runtime,
    operation: {
      kind: "read",
      path: "C:\\work\\a",
      length: 1,
      maxOutputBytes: 1,
      encoding: "utf8",
    },
  });
  const child = fakeChild();
  const pending = spawnNative(
    req,
    { timeoutMs: 100, maxOutputBytes: 1 },
    { spawnProcess: () => child },
  );
  child.stdout.write(
    JSON.stringify({
      ...terminal,
      stopReason: "parentDeath",
      stdoutBase64: Buffer.from(
        JSON.stringify({
          ok: true,
          data: { encoding: "base64", content: "YQ==", eof: true },
        }),
      ).toString("base64"),
    }) + "\n",
  );
  child.emit("close", 0, null);
  const result = await pending;
  assert.equal(result.error.code, "BROKER_LOST");
  assert.equal(result.data, undefined);
});
