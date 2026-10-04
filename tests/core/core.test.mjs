import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  createPolicy,
  canonicalWindowsPath,
  validateEnvironment,
  validateOperation,
  SandboxBroker,
} from "../../packages/core/index.mjs";
const input = () => ({
  policyId: randomUUID(),
  revision: 1,
  ownerSid: "S-1-5-21-100",
  installId: "poc",
  readMode: "broadReadWithDeny",
  writeRoots: ["C:\\work"],
  readDeny: ["C:\\private"],
  writeDeny: ["C:\\work\\.git"],
  networkMode: "offline",
  runtimeSetId: "runtimes-v1",
  limits: { timeoutMs: 1000, maxOutputBytes: 1024 },
  createdAt: "2026-01-01T00:00:00Z",
  expiresAt: "2027-01-01T00:00:00Z",
});
// The only mock lives in tests. It performs no real I/O or process execution.
class FakeBackend {
  calls = 0;
  cancellations = 0;
  closes = 0;
  capabilities() {
    return {
      nativeEnforcement: true,
      kinds: ["read", "write", "edit", "exec", "shell"],
      readModes: ["broadReadWithDeny"],
      networkModes: ["offline", "online"],
    };
  }
  async prepare({ policy }) {
    return { enforced: true, policyHash: policy.policyHash };
  }
  async execute(ctx) {
    this.calls++;
    return this.run ? this.run(ctx) : { terminated: true, exitCode: 0 };
  }
  async cancel() {
    this.cancellations++;
    return { terminated: true };
  }
  async close() {
    this.closes++;
    return { cleaned: true };
  }
}
async function fixture(backend = new FakeBackend(), p = createPolicy(input())) {
  const broker = new SandboxBroker({
    backend,
    now: () => Date.parse("2026-10-04"),
  });
  const session = await broker.createSession(p);
  const request = {
    protocol: { major: 1, minor: 0 },
    method: "execute",
    requestId: randomUUID(),
    ...session,
    operation: { kind: "read", path: "C:\\work\\a.txt" },
  };
  return { backend, broker, request, p };
}
const code = (c) => (e) => e.code === c;
test("immutable deterministic policy, deny overrides and boundary-safe containment", () => {
  const i = input(),
    p = createPolicy(i);
  i.writeRoots.push("C:\\other");
  assert.equal(p.writeRoots.length, 1);
  assert.ok(Object.isFrozen(p.limits));
  assert.equal(
    createPolicy({ ...i, writeRoots: ["c:/work"] }).policyHash,
    p.policyHash,
  );
  assert.throws(
    () =>
      validateOperation(
        {
          kind: "write",
          path: "C:\\work-other\\x",
          data: "x",
          mode: "create",
          encoding: "utf8",
        },
        p,
      ),
    code("POLICY_DENIED"),
  );
  assert.throws(
    () => validateOperation({ kind: "read", path: "C:\\private\\secret" }, p),
    code("POLICY_DENIED"),
  );
  assert.throws(
    () =>
      validateOperation({ kind: "edit", path: "C:\\work\\.git\\config" }, p),
    code("POLICY_DENIED"),
  );
});
test("reject Windows lexical ambiguities", () => {
  for (const path of [
    "C:relative",
    "\\\\server\\share",
    "\\\\?\\C:\\work",
    "C:\\work\\..\\x",
    "C:\\work\\x:ads",
    "C:\\work\\NUL.txt",
    "C:\\work\\trailing.",
    "C:\\PROGRA~1\\x",
  ])
    assert.throws(() => canonicalWindowsPath(path), code("POLICY_DENIED"));
  assert.equal(canonicalWindowsPath("C:/Work/file"), "c:\\work\\file");
});
test("strict fields, environment allowlist and bounds", () => {
  const p = createPolicy(input());
  assert.throws(
    () => createPolicy({ ...input(), extra: true }),
    code("INVALID_REQUEST"),
  );
  assert.throws(
    () => validateEnvironment({ OPENAI_API_KEY: "secret" }),
    code("INVALID_REQUEST"),
  );
  assert.throws(
    () => validateEnvironment({ PATH: "C:\\evil" }),
    code("INVALID_REQUEST"),
  );
  assert.deepEqual(validateEnvironment({ PYTHONUTF8: "1" }), {
    PYTHONUTF8: "1",
  });
  assert.throws(
    () =>
      validateOperation(
        { kind: "read", path: "C:\\work\\a", maxOutputBytes: 2000 },
        p,
      ),
    code("INVALID_REQUEST"),
  );
});
test("default and unknown backend fail closed", async () => {
  await assert.rejects(
    new SandboxBroker().createSession(createPolicy(input())),
    code("BACKEND_UNAVAILABLE"),
  );
  await assert.rejects(
    new SandboxBroker({ backend: { capabilities: () => ({}) } }).createSession(
      createPolicy(input()),
    ),
    code("BACKEND_UNAVAILABLE"),
  );
});
test("all operations use backend and exact replay is executed once", async () => {
  const { backend, broker, request } = await fixture();
  for (const op of [
    { kind: "read", path: "C:\\work\\a" },
    {
      kind: "write",
      path: "C:\\work\\a",
      data: "x",
      mode: "create",
      encoding: "utf8",
    },
    {
      kind: "edit",
      path: "C:\\work\\a",
      oldText: "x",
      newText: "y",
      expectedHash: "a".repeat(64),
    },
    {
      kind: "exec",
      executable: "C:\\runtime\\node.exe",
      argv: [],
      cwd: "C:\\work",
      stdin: { mode: "closed" },
    },
    {
      kind: "shell",
      shellId: "powershell",
      script: "Write-Output hi",
      cwd: "C:\\work",
    },
  ]) {
    const r = { ...request, requestId: randomUUID(), operation: op };
    const a = broker.execute(r),
      b = broker.execute(r);
    assert.equal(a, b);
    assert.equal((await a).outcome, "success");
    assert.deepEqual(await broker.execute(r), await a);
  }
  assert.equal(backend.calls, 5);
  assert.throws(
    () => broker.execute({ ...request, requestId: [...[]][0] }),
    code("INVALID_REQUEST"),
  );
});
test("same ID conflicting payload and active session serialization", async () => {
  const { backend, broker, request, p } = await fixture();
  let release;
  backend.run = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const first = broker.execute(request);
  assert.throws(
    () =>
      broker.execute({
        ...request,
        operation: { ...request.operation, path: "C:\\work\\b" },
      }),
    code("REQUEST_CONFLICT"),
  );
  assert.throws(
    () => broker.execute({ ...request, requestId: randomUUID() }),
    code("BUSY"),
  );
  await assert.rejects(broker.createSession(p), code("BUSY"));
  release({ terminated: true });
  await first;
});
test("cancel is idempotent and admission differs from confirmed termination", async () => {
  const { backend, broker, request } = await fixture();
  backend.run = ({ signal }) =>
    new Promise((resolve) =>
      signal.addEventListener("abort", () => resolve({ terminated: true })),
    );
  const pending = broker.execute(request);
  assert.deepEqual(await broker.cancel(request.sessionId, request.requestId), {
    accepted: true,
    terminal: false,
  });
  await broker.cancel(request.sessionId, request.requestId);
  assert.equal((await pending).error.code, "CANCELLED");
  assert.equal(backend.cancellations, 1);
  assert.deepEqual(await broker.cancel(request.sessionId, request.requestId), {
    accepted: false,
    terminal: true,
  });
});
test("timeout and output limits stop backend, bounded terminal results", async () => {
  for (const mode of ["timeout", "output"]) {
    const { backend, broker, request } = await fixture();
    backend.run = async ({ signal, onOutput }) => {
      if (mode === "output") {
        onOutput({ stream: "stdout", data: "x".repeat(2048) });
        return { terminated: true };
      }
      return new Promise((resolve) =>
        signal.addEventListener("abort", () => resolve({ terminated: true })),
      );
    };
    const r = await broker.execute({
      ...request,
      operation: { ...request.operation, timeoutMs: 10 },
    });
    assert.equal(r.error.code, mode === "timeout" ? "TIMEOUT" : "OUTPUT_LIMIT");
    assert.equal(backend.cancellations, 1);
    assert.ok(
      r.outputs.reduce((n, o) => n + Buffer.from(o.data, "base64").length, 0) <=
        1024,
    );
  }
});
test("missing termination blocks subsequent work until verified close", async () => {
  const { backend, broker, request } = await fixture();
  backend.run = async () => ({ terminated: false });
  assert.equal((await broker.execute(request)).outcome, "unknown");
  assert.equal(broker.getStatus().state, "BLOCKED");
  assert.throws(
    () => broker.execute({ ...request, requestId: randomUUID() }),
    code("BUSY"),
  );
  backend.close = async () => ({ cleaned: false });
  await assert.rejects(
    broker.closeSession(request.sessionId),
    code("CLEANUP_UNCONFIRMED"),
  );
  assert.equal(broker.getStatus().state, "BLOCKED");
  backend.close = async () => ({ cleaned: true });
  await broker.closeSession(request.sessionId);
  assert.equal(broker.getStatus().state, "READY");
});
test("expired or mutated policy cannot start", async () => {
  const p = createPolicy(input());
  await assert.rejects(
    new SandboxBroker({
      backend: new FakeBackend(),
      now: () => Date.parse("2028-01-01"),
    }).createSession(p),
    code("POLICY_EXPIRED"),
  );
  await assert.rejects(
    new SandboxBroker({ backend: new FakeBackend() }).createSession({
      ...p,
      networkMode: "online",
    }),
    code("POLICY_DENIED"),
  );
});
test("request replay budget never evicts completed records", async () => {
  const i = input();
  i.limits.maxRequests = 1;
  const { broker, request } = await fixture(new FakeBackend(), createPolicy(i));
  await broker.execute(request);
  assert.throws(
    () => broker.execute({ ...request, requestId: randomUUID() }),
    code("REQUEST_LIMIT"),
  );
  assert.equal((await broker.execute(request)).outcome, "success");
});
test("concurrent close performs one native cleanup", async () => {
  const { broker, backend, request } = await fixture();
  await Promise.all([
    broker.closeSession(request.sessionId),
    broker.closeSession(request.sessionId),
  ]);
  assert.equal(backend.closes, 1);
});
test("hung execute and cancel reach bounded unknown result and block broker", async () => {
  const backend = new FakeBackend();
  backend.run = () => new Promise(() => {});
  backend.cancel = () => new Promise(() => {});
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 10,
    now: () => Date.parse("2026-10-04"),
  });
  const s = await broker.createSession(createPolicy(input()));
  const r = await broker.execute({
    protocol: { major: 1, minor: 0 },
    method: "execute",
    requestId: randomUUID(),
    ...s,
    operation: { kind: "read", path: "C:\\work\\a", timeoutMs: 5 },
  });
  assert.equal(r.outcome, "unknown");
  assert.equal(r.error.code, "CLEANUP_UNCONFIRMED");
  assert.equal(broker.getStatus().state, "BLOCKED");
});
test("hung close is bounded and never restores ready", async () => {
  const backend = new FakeBackend();
  backend.close = () => new Promise(() => {});
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 10,
    now: () => Date.parse("2026-10-04"),
  });
  const s = await broker.createSession(createPolicy(input()));
  await assert.rejects(
    broker.closeSession(s.sessionId),
    code("CLEANUP_UNCONFIRMED"),
  );
  assert.equal(broker.getStatus().state, "BLOCKED");
});

test("early explicit cancellation watchdog does not wait for wall timeout", async () => {
  const backend = new FakeBackend();
  backend.run = () => new Promise(() => {});
  backend.cancel = () => new Promise(() => {});
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 10,
    now: () => Date.parse("2026-10-04"),
  });
  const session = await broker.createSession(createPolicy(input()));
  const requestId = randomUUID();
  const result = broker.execute({
    protocol: { major: 1, minor: 0 },
    method: "execute",
    requestId,
    ...session,
    operation: { kind: "read", path: "C:\\work\\a" },
  });
  await broker.cancel(session.sessionId, requestId);
  assert.equal((await result).error.code, "CLEANUP_UNCONFIRMED");
  assert.equal(broker.getStatus().state, "BLOCKED");
});

test("malformed native data is an unknown result and blocks reuse", async () => {
  const { backend, broker, request } = await fixture();
  backend.run = async () => ({
    terminated: true,
    data: { unexpected: "raw backend payload" },
  });
  assert.equal((await broker.execute(request)).outcome, "unknown");
  assert.equal(broker.getStatus().state, "BLOCKED");
});

test("backend exceptions never imply confirmed cleanup, including known error names", async () => {
  for (const thrown of [null, { code: "POLICY_DENIED", message: "denied" }]) {
    const { backend, broker, request } = await fixture();
    backend.run = async () => {
      throw thrown;
    };
    const result = await broker.execute(request);
    assert.equal(result.outcome, "unknown");
    assert.equal(broker.getStatus().state, "BLOCKED");
  }
});

test("hanging capabilities is bounded, blocks admission and requires settled preparation before cleanup", async () => {
  const backend = new FakeBackend();
  let release;
  const capabilities = backend.capabilities();
  backend.capabilities = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 10,
    now: () => Date.parse("2026-10-04"),
  });
  await assert.rejects(
    broker.createSession(createPolicy(input())),
    code("CLEANUP_UNCONFIRMED"),
  );
  const sessionId = broker.getStatus().sessionId;
  assert.equal(broker.getStatus().state, "BLOCKED");
  await assert.rejects(
    broker.closeSession(sessionId),
    code("CLEANUP_UNCONFIRMED"),
  );
  assert.equal(backend.closes, 0);
  release(capabilities);
  await Promise.resolve();
  assert.equal(broker.getStatus().state, "BLOCKED");
  await broker.closeSession(sessionId);
  assert.equal(broker.getStatus().state, "READY");
});

test("hanging prepare and late success never activate a timed-out session", async () => {
  const backend = new FakeBackend();
  let release;
  backend.prepare = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 10,
    now: () => Date.parse("2026-10-04"),
  });
  const policy = createPolicy(input());
  await assert.rejects(
    broker.createSession(policy),
    code("CLEANUP_UNCONFIRMED"),
  );
  const sessionId = broker.getStatus().sessionId;
  await assert.rejects(
    broker.closeSession(sessionId),
    code("CLEANUP_UNCONFIRMED"),
  );
  release({ enforced: true, policyHash: policy.policyHash });
  await Promise.resolve();
  assert.equal(broker.getStatus().state, "BLOCKED");
  await broker.closeSession(sessionId);
  assert.equal(broker.getStatus().state, "READY");
});

test("close during prepare fences activation and waits for settle before native cleanup", async () => {
  const backend = new FakeBackend();
  let release, entered;
  const preparing = new Promise((resolve) => {
    entered = resolve;
  });
  backend.prepare = () =>
    new Promise((resolve) => {
      release = resolve;
      entered();
    });
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 100,
    now: () => Date.parse("2026-10-04"),
  });
  const policy = createPolicy(input());
  const creation = broker.createSession(policy);
  const rejectedCreation = assert.rejects(creation, code("CANCELLED"));
  await preparing;
  const closing = broker.closeSession(broker.getStatus().sessionId);
  assert.equal(broker.getStatus().state, "CLEANUP");
  assert.equal(backend.closes, 0);
  release({ enforced: true, policyHash: policy.policyHash });
  await rejectedCreation;
  await closing;
  assert.equal(backend.closes, 1);
  assert.equal(broker.getStatus().state, "READY");
  assert.equal(broker.getStatus().sessionId, null);
});

test("close during capability query prevents native prepare from starting", async () => {
  const backend = new FakeBackend();
  const capabilities = backend.capabilities();
  let release,
    prepareCalls = 0;
  backend.capabilities = () =>
    new Promise((resolve) => {
      release = resolve;
    });
  backend.prepare = async () => {
    prepareCalls++;
    return {};
  };
  const broker = new SandboxBroker({
    backend,
    cleanupTimeoutMs: 100,
    now: () => Date.parse("2026-10-04"),
  });
  const creation = broker.createSession(createPolicy(input()));
  const rejectedCreation = assert.rejects(creation, code("CANCELLED"));
  await Promise.resolve();
  const closing = broker.closeSession(broker.getStatus().sessionId);
  release(capabilities);
  await rejectedCreation;
  await closing;
  assert.equal(prepareCalls, 0);
  assert.equal(broker.getStatus().state, "READY");
});

test("redundant root separators remain absolute drive roots and cannot be write roots", () => {
  for (const root of ["C:\\\\", "C:////", "C:\\/\\"]) {
    assert.equal(canonicalWindowsPath(root), "c:\\");
    assert.throws(
      () => createPolicy({ ...input(), writeRoots: [root] }),
      code("POLICY_DENIED"),
    );
  }
});
test("read content budget excludes JSON and base64 overhead", async () => {
  for (const encoding of ["utf8", "base64"]) {
    const b = new FakeBackend();
    b.run = async () => ({
      terminated: true,
      data: {
        encoding,
        content:
          encoding === "utf8"
            ? '"'.repeat(32)
            : Buffer.alloc(32, 1).toString("base64"),
        eof: true,
      },
    });
    const { broker, request } = await fixture(b);
    const result = await broker.execute({
      ...request,
      operation: {
        ...request.operation,
        encoding,
        length: 32,
        maxOutputBytes: 32,
      },
    });
    assert.equal(result.outcome, "success");
    assert.equal(result.truncated, false);
  }
});
test("read content over decoded byte budget fails without truncating JSON", async () => {
  const b = new FakeBackend();
  b.run = async () => ({
    terminated: true,
    data: {
      encoding: "base64",
      content: Buffer.alloc(33).toString("base64"),
      eof: true,
    },
  });
  const { broker, request } = await fixture(b);
  const result = await broker.execute({
    ...request,
    operation: { ...request.operation, length: 32, maxOutputBytes: 32 },
  });
  assert.equal(result.error.code, "OUTPUT_LIMIT");
  assert.equal(result.data, undefined);
});

test("file operation errors require confirmed termination; unknown failures remain blocked", async () => {
  for (const [code, terminated, expected, state] of [
    ["FILE_OPERATION_FAILED", true, "FILE_OPERATION_FAILED", "SESSION_ACTIVE"],
    ["FILE_OPERATION_FAILED", false, "CLEANUP_UNCONFIRMED", "BLOCKED"],
    ["UNRECOGNIZED_WORKER_ERROR", true, "BROKER_LOST", "BLOCKED"],
  ]) {
    const { backend, broker, request } = await fixture();
    backend.run = async () => ({ terminated, error: { code } });
    const result = await broker.execute(request);
    assert.equal(result.error.code, expected);
    assert.equal(result.outcome, state === "BLOCKED" ? "unknown" : "error");
    assert.equal(broker.getStatus().state, state);
  }
});
