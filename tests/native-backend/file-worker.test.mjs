import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
const worker = fileURLToPath(
  new URL("../../packages/native-backend/file-worker.cjs", import.meta.url),
);
// Test-only direct execution against disposable fixtures; no production host file fallback.
async function editFixture(bytes, oldText, newText) {
  const dir = await mkdtemp(join(tmpdir(), "native-worker-test-"));
  try {
    const path = join(dir, "fixture");
    await writeFile(path, bytes);
    const result = spawnSync(process.execPath, [worker], {
      input: JSON.stringify({
        kind: "edit",
        path,
        oldText,
        newText,
        expectedHash: createHash("sha256").update(bytes).digest("hex"),
      }),
      encoding: "utf8",
    });
    return {
      status: result.status,
      response: JSON.parse(result.stdout),
      bytes: await readFile(path),
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
test("invalid UTF-8 edit rejects without mutating any bytes", async () => {
  const bytes = Buffer.from([0xff, 0x61, 0x62]);
  const r = await editFixture(bytes, "a", "x");
  assert.equal(r.status, 1);
  assert.equal(r.response.ok, false);
  assert.deepEqual(r.bytes, bytes);
});
test("overlapping edit matches conflict before mutation", async () => {
  const bytes = Buffer.from("aaa");
  const r = await editFixture(bytes, "aa", "b");
  assert.equal(r.response.error.code, "FILE_CONFLICT");
  assert.deepEqual(r.bytes, bytes);
});
test("valid UTF-8 edits preserve a leading BOM", async () => {
  const r = await editFixture(Buffer.from("\ufeffhello"), "hello", "world");
  assert.equal(r.response.ok, true);
  assert.deepEqual(r.bytes, Buffer.from("\ufeffworld"));
});
