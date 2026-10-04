import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { spawnSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, win32 } from "node:path";
import { fileURLToPath } from "node:url";
import { SandboxBroker, createPolicy } from "../../packages/core/index.mjs";
import { spawnNative } from "../../packages/native-backend/index.mjs";
import { createSandboxTools } from "../../packages/pi-adapter/index.js";

const worker = fileURLToPath(
  new URL("../../packages/native-backend/file-worker.cjs", import.meta.url),
);
// These are Linux/disposable-worker + simulated native-envelope regressions, NOT
// Windows sandbox enforcement tests. Only this test backend executes on the host.
async function fixture(t, files = {}) {
  const dir = await mkdtemp(join(tmpdir(), "file-regression-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  for (const [name, bytes] of Object.entries(files))
    await writeFile(join(dir, name), bytes);
  const terminals = [];
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
    cancel: async () => ({ terminated: true }),
    close: async () => ({ cleaned: true }),
    async execute({ operation, ...context }) {
      const child = new EventEmitter();
      for (const name of ["stdin", "stdout", "stderr"])
        child[name] = new PassThrough();
      child.kill = () => {};
      child.unref = () => {};
      const pending = spawnNative(
        {
          executable: "test-only",
          args: [],
          cwd: dir,
          env: {},
          stdin: "{}",
          fileOperation: operation,
          captureOutputBytes: 65536,
        },
        {
          ...context,
          timeoutMs: 1000,
          maxOutputBytes: operation.maxOutputBytes,
        },
        { spawnProcess: () => child },
      );
      const result = spawnSync(process.execPath, [worker], {
        input: JSON.stringify({
          ...operation,
          path: join(dir, win32.basename(operation.path)),
        }),
      });
      assert.equal(result.error, undefined);
      child.stdout.write(
        JSON.stringify({
          type: "result",
          stopReason: "exited",
          exitCode: result.status,
          stdoutBase64: result.stdout.toString("base64"),
          stderrBase64: result.stderr.toString("base64"),
          timedOut: false,
          truncated: false,
          terminated: true,
          cleanupVerified: true,
        }) + "\n",
      );
      child.emit("close", 0, null);
      const terminal = await pending;
      terminals.push(terminal);
      return terminal;
    },
  };
  const broker = new SandboxBroker({
    backend,
    now: () => Date.parse("2026-10-04"),
  });
  const session = await broker.createSession(
    createPolicy({
      policyId: randomUUID(),
      revision: 1,
      ownerSid: "S-1-5-21-100",
      installId: "test",
      readMode: "broadReadWithDeny",
      writeRoots: ["C:\\work"],
      readDeny: [],
      writeDeny: [],
      networkMode: "offline",
      runtimeSetId: "test",
      limits: { timeoutMs: 1000, maxOutputBytes: 1024 },
      createdAt: "2026-01-01T00:00:00Z",
      expiresAt: "2099-01-01T00:00:00Z",
    }),
  );
  const execute = (operation) =>
    broker.execute({
      protocol: { major: 1, minor: 0 },
      method: "execute",
      requestId: randomUUID(),
      ...session,
      operation,
    });
  return {
    broker,
    execute,
    terminals,
    dir,
    tools: createSandboxTools(broker, { ...session, cwd: "C:\\work" }),
  };
}

test("UTF-8 byte ranges preserve every byte across multibyte boundaries and permit session reuse", async (t) => {
  const bytes = Buffer.from("A한🙂éZ");
  const f = await fixture(t, { text: bytes });
  const chunks = [];
  for (let offset = 0; offset < bytes.length; offset++) {
    const r = await f.execute({
      kind: "read",
      path: "C:\\work\\text",
      offset,
      length: 1,
      maxOutputBytes: 1,
      encoding: "utf8",
    });
    assert.equal(
      r.outcome,
      "success",
      `offset=${offset}: ${JSON.stringify({ terminal: f.terminals.at(-1), broker: r, state: f.broker.getStatus().state })}`,
    );
    assert.equal(f.terminals.at(-1).terminated, true);
    assert.equal(f.terminals.at(-1).cleanupVerified, true);
    assert.equal(r.data.encoding, bytes[offset] < 128 ? "utf8" : "base64");
    chunks.push(Buffer.from(r.data.content, r.data.encoding));
    assert.equal(r.data.eof, offset + 1 === bytes.length);
    assert.equal(f.broker.getStatus().state, "SESSION_ACTIVE");
  }
  assert.deepEqual(Buffer.concat(chunks), bytes);
});

test("Pi read exposes lossless encoding metadata for invalid UTF-8, then reuses the session", async (t) => {
  const bytes = Buffer.from([0xff, 0x00, 0xc3]);
  const f = await fixture(t, {
    binary: bytes,
    valid: Buffer.from("\ufeff한🙂"),
  });
  const read = f.tools.find((t) => t.name === "read");
  const result = await read.execute("binary", {
    path: "binary",
    length: bytes.length,
  });
  const data = JSON.parse(result.content[0].text);
  assert.equal(data.encoding, "base64");
  assert.deepEqual(Buffer.from(data.content, data.encoding), bytes);
  const valid = await read.execute("valid", { path: "valid" });
  assert.deepEqual(JSON.parse(valid.content[0].text), {
    encoding: "utf8",
    content: "\ufeff한🙂",
    eof: true,
  });
  assert.equal(f.broker.getStatus().state, "SESSION_ACTIVE");
});

test("missing file is FILE_OPERATION_FAILED with verified cleanup and next Pi read succeeds", async (t) => {
  const f = await fixture(t, { valid: "ok" });
  const read = f.tools.find((t) => t.name === "read");
  await assert.rejects(read.execute("missing", { path: "missing" }), {
    code: "FILE_OPERATION_FAILED",
  });
  assert.equal(f.terminals.at(-1).terminated, true);
  assert.equal(f.terminals.at(-1).cleanupVerified, true);
  assert.equal(f.broker.getStatus().state, "SESSION_ACTIVE");
  assert.equal(
    JSON.parse((await read.execute("valid", { path: "valid" })).content[0].text)
      .content,
    "ok",
  );
});

test("invalid UTF-8 edit is recoverable without mutation and subsequent read succeeds", async (t) => {
  const bytes = Buffer.from([0xff, 0x61]);
  const f = await fixture(t, { binary: bytes });
  const result = await f.execute({
    kind: "edit",
    path: "C:\\work\\binary",
    expectedHash: createHash("sha256").update(bytes).digest("hex"),
    oldText: "a",
    newText: "b",
  });
  assert.equal(result.outcome, "error");
  assert.equal(result.error.code, "FILE_OPERATION_FAILED");
  assert.deepEqual(await readFile(join(f.dir, "binary")), bytes);
  assert.equal(f.broker.getStatus().state, "SESSION_ACTIVE");
  const read = await f.execute({
    kind: "read",
    path: "C:\\work\\binary",
    encoding: "base64",
  });
  assert.equal(read.outcome, "success");
  assert.deepEqual(Buffer.from(read.data.content, read.data.encoding), bytes);
});
