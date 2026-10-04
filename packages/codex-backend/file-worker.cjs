"use strict";
// Executed ONLY inside the reference sandbox. All caller data arrives on stdin.
const fs = require("node:fs/promises");
const { createHash } = require("node:crypto");
const sha = (b) => createHash("sha256").update(b).digest("hex");
async function main() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > 1048576) throw Error("INPUT_LIMIT");
    chunks.push(chunk);
  }
  const op = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!["read", "write", "edit"].includes(op.kind))
    throw Error("INVALID_REQUEST");
  let handle;
  try {
    handle = await fs.open(
      op.path,
      op.kind === "read"
        ? "r"
        : op.kind === "write" && op.mode === "create"
          ? "wx"
          : "r+",
    );
    const info = await handle.stat();
    if (!info.isFile()) throw Error("INVALID_REQUEST");
    if (op.kind === "read") {
      const buffer = Buffer.alloc(op.length);
      const { bytesRead } = await handle.read(buffer, 0, op.length, op.offset);
      return {
        data: buffer.subarray(0, bytesRead).toString(op.encoding),
        encoding: op.encoding,
        bytesRead,
      };
    }
    let data;
    if (op.kind === "edit" || op.mode === "replace") {
      if (info.size > 8388608) throw Error("FILE_LIMIT");
      const prior = await handle.readFile();
      if (sha(prior) !== op.expectedHash) throw Error("FILE_CONFLICT");
      if (op.kind === "edit") {
        const text = prior.toString("utf8");
        const at = text.indexOf(op.oldText);
        if (at < 0 || text.indexOf(op.oldText, at + op.oldText.length) !== -1)
          throw Error("FILE_CONFLICT");
        data = Buffer.from(
          text.slice(0, at) + op.newText + text.slice(at + op.oldText.length),
        );
      }
    }
    data ??= Buffer.from(op.data, op.encoding);
    // Positional I/O retains the opened file identity during the mutation.
    for (let at = 0; at < data.length; ) {
      const r = await handle.write(data, at, data.length - at, at);
      if (!r.bytesWritten) throw Error("WRITE_FAILED");
      at += r.bytesWritten;
    }
    await handle.truncate(data.length);
    await handle.sync();
    return { bytesWritten: data.length, sha256: sha(data) };
  } finally {
    await handle?.close();
  }
}
main()
  .then((data) => process.stdout.write(JSON.stringify({ ok: true, data })))
  .catch((error) => {
    process.stdout.write(
      JSON.stringify({
        ok: false,
        error: {
          code:
            error.message === "FILE_CONFLICT"
              ? "FILE_CONFLICT"
              : "FILE_OPERATION_FAILED",
        },
      }),
    );
    process.exitCode = 1;
  });
