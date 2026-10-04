import test from "node:test";
import assert from "node:assert/strict";
import { createPolicy, SandboxBroker } from "../../packages/core/index.mjs";
import {
  CODEX_PIN,
  OFFICIAL_X64_SHA256,
  ACTIVATION_ACKNOWLEDGEMENT,
  CodexReferenceBackend,
  compileSandboxState,
  buildInvocation,
  runReferenceExperiment,
} from "../../packages/codex-backend/index.mjs";
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
    runtimeSetId: "codex-0.160.0",
    limits: { timeoutMs: 1000, maxOutputBytes: 65536 },
    createdAt: "2026-01-01T00:00:00Z",
    expiresAt: "2099-01-01T00:00:00Z",
  });
const runtime = {
  version: CODEX_PIN.version,
  supervisorVersion: "0.1.0",
  supervisorExe: "C:\\trusted\\pi-job-supervisor.exe",
  codexExe: "C:\\trusted\\codex.exe",
  nodeExe: "C:\\trusted\\node.exe",
  powershellExe:
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  systemRoot: "C:\\Windows",
  path: "C:\\trusted;C:\\Windows\\System32",
  codexHome: "C:\\codex-home",
  temp: "C:\\work\\tmp",
  userName: "test",
  files: [],
};
const op = {
  kind: "exec",
  executable: "C:\\trusted\\node.exe",
  argv: ["-e", 'console.log("hi")'],
  cwd: "C:\\work",
  stdin: { mode: "closed" },
};
const activation = {
  acknowledgement: ACTIVATION_ACKNOWLEDGEMENT,
  preprovisionedVersion: CODEX_PIN.version,
  publisherTrustVerified: true,
};
test("source pin and official x64 binary digest are exact", () => {
  assert.equal(CODEX_PIN.sourceCommit.length, 40);
  assert.equal(
    OFFICIAL_X64_SHA256["codex.exe"],
    "fdda5fa3cf3fb3d000b876720742857676293e4315e4b045fae6f8bd7e866d1d",
  );
});
test("managed state explicitly includes offline and deny rules", () => {
  const s = compileSandboxState(policy(), "C:\\work");
  assert.equal(s.permission_profile.type, "managed");
  assert.equal(s.permission_profile.network, "restricted");
  assert.equal(s.sandbox_cwd, "file:///c:/work");
  assert.ok(
    s.permission_profile.file_system.entries.some(
      (x) => x.access === "deny" && x.path.path === "c:\\secrets",
    ),
  );
  assert.ok(
    s.permission_profile.file_system.entries.some(
      (x) => x.access === "read" && x.path.path === "c:\\work\\.git",
    ),
  );
});
test("policy digest tampering is rejected", () =>
  assert.throws(
    () =>
      compileSandboxState({ ...policy(), networkMode: "online" }, "C:\\work"),
    (e) => e.code === "POLICY_DENIED",
  ));
test("host-specific command is flattened and backend mode forced", async () => {
  const r = await buildInvocation({ policy: policy(), operation: op, runtime });
  assert.deepEqual(r.args.slice(0, 7), [
    "-c",
    'windows.sandbox="elevated"',
    "-c",
    "prefer_mxc=false",
    "-c",
    'shell_environment_policy.inherit="all"',
    "sandbox",
  ]);
  assert.equal(r.args.includes("windows"), false);
  assert.equal(r.stdin, "");
  assert.equal(r.env.OPENAI_API_KEY, undefined);
  assert.equal(r.env.NODE_OPTIONS, undefined);
});
test("file content and path are only in stdin, never worker source", async () => {
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
  assert.equal(r.args.at(-1), "fixed worker");
  assert.equal(
    r.args.some((x) => x.includes(data)),
    false,
  );
  assert.equal(JSON.parse(r.stdin).data, data);
});
test("shell script is encoded as data argument, never host shell", async () => {
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
  assert.equal(r.args.at(-2), "-EncodedCommand");
  assert.equal(
    Buffer.from(r.args.at(-1), "base64").toString("utf16le"),
    'Write-Output "a & b"',
  );
});
test("actual native experiment refuses non-Windows before transport", async () => {
  let called = false;
  await assert.rejects(
    runReferenceExperiment(
      { runtime, policy: policy(), operation: op, activation },
      {
        platform: "linux",
        transport: () => {
          called = true;
        },
      },
    ),
    (e) => e.code === "BACKEND_UNAVAILABLE",
  );
  assert.equal(called, false);
});
test("actual native experiment refuses absent explicit operator activation", async () => {
  await assert.rejects(
    runReferenceExperiment(
      { runtime, policy: policy(), operation: op },
      {
        platform: "win32",
        verifyRuntime: async () => {
          throw Error("must not verify");
        },
      },
    ),
    (e) => e.code === "BACKEND_UNAVAILABLE",
  );
});
test("injected transport proves stdin/output plumbing, never cleanup guarantee", async () => {
  let captured;
  const output = [];
  const r = await runReferenceExperiment(
    {
      runtime,
      policy: policy(),
      operation: op,
      activation,
      onOutput: (x) => output.push(x),
    },
    {
      platform: "win32",
      verifyRuntime: async () => {},
      transport: async (req, hooks) => {
        captured = req;
        hooks.onOutput({ stream: "stdout", data: Buffer.from("ok") });
        return { exitCode: 0, terminated: true };
      },
    },
  );
  assert.equal(captured.executable, runtime.supervisorExe);
  assert.equal(JSON.parse(captured.args[1]).executable, runtime.codexExe);
  assert.equal(output[0].data.toString(), "ok");
  assert.equal(r.terminated, false);
  assert.equal(r.cleanupVerified, false);
});
test("broker refuses unverified direct CLI reference backend", async () => {
  const broker = new SandboxBroker({ backend: new CodexReferenceBackend() });
  await assert.rejects(
    broker.createSession(policy()),
    (e) => e.code === "BACKEND_UNAVAILABLE",
  );
});

test("request JSON cannot override operator runtime or activation", async () => {
  const { parseExperimentInputs } = await import(
    "../../packages/codex-backend/index.mjs"
  );
  assert.throws(
    () =>
      parseExperimentInputs(
        { runtime, activation },
        { policy: policy(), operation: op, runtime: { codexExe: "evil" } },
      ),
    (e) => e.code === "INVALID_REQUEST",
  );
  assert.throws(
    () =>
      parseExperimentInputs(
        { runtime, activation },
        { policy: policy(), operation: op, activation },
      ),
    (e) => e.code === "INVALID_REQUEST",
  );
  assert.equal(
    parseExperimentInputs(
      { runtime, activation },
      { policy: policy(), operation: op },
    ).runtime,
    runtime,
  );
});

test("uppercase unnormalized root cannot bypass protected runtime check", async () => {
  const p = policy();
  const raw = { ...p, writeRoots: ["C:\\WORK"] };
  await assert.rejects(
    runReferenceExperiment(
      {
        runtime: { ...runtime, codexHome: "C:\\work\\codex-home" },
        policy: raw,
        operation: op,
        activation,
      },
      {
        platform: "win32",
        verifyRuntime: async () => {
          throw Error("must reject first");
        },
      },
    ),
    (e) => e.code === "POLICY_DENIED",
  );
});

test("transport watchdog bounds a child that never closes after kill", async () => {
  const { EventEmitter } = await import("node:events");
  const { PassThrough } = await import("node:stream");
  const { spawnReference } = await import(
    "../../packages/codex-backend/index.mjs"
  );
  const child = new EventEmitter();
  for (const k of ["stdin", "stdout", "stderr"]) child[k] = new PassThrough();
  let kills = 0;
  child.kill = () => {
    kills++;
  };
  child.unref = () => {};
  const r = await spawnReference(
    { executable: "fake", args: [], cwd: "fake", env: {}, stdin: "" },
    { onOutput: () => {}, timeoutMs: 5, maxOutputBytes: 100 },
    { spawnProcess: () => child, drainTimeoutMs: 10 },
  );
  assert.equal(kills, 1);
  assert.equal(r.error.code, "CLEANUP_UNCONFIRMED");
  assert.equal(r.terminated, false);
  assert.equal(child.stdout.destroyed, true);
});

test("oversized Windows command lines reject rather than truncate", async () => {
  await assert.rejects(
    buildInvocation({
      policy: policy(),
      operation: { ...op, argv: ["x".repeat(20000)] },
      runtime,
    }),
    (e) => e.code === "INVALID_REQUEST",
  );
});

test("renaming an arbitrary binary cannot bypass official Codex digest pin", async () => {
  const { verifyRuntime } = await import(
    "../../packages/codex-backend/index.mjs"
  );
  await assert.rejects(
    verifyRuntime({ ...runtime, codexExe: "C:\\trusted\\arbitrary.exe" }),
    (e) => e.code === "VERSION_MISMATCH",
  );
});
