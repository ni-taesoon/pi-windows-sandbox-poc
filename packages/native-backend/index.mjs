import { readFile, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { win32 } from "node:path";
import { fileURLToPath } from "node:url";
import {
  SandboxError,
  canonicalWindowsPath,
  createPolicy,
  validateOperation,
  isWithin,
} from "../core/index.mjs";

export const NATIVE_VERSION = "0.1.0";
// A successful compilation is not an enforcement validation. No operator/model flag overrides this.
export const NATIVE_VALIDATED = false;
export const VALIDATION_BLOCKER =
  "Extracted native engine requires the Windows enforcement and lifecycle acceptance matrix; native activation remains disabled.";
const fail = (code, message) => {
  throw new SandboxError(code, message);
};
const sha = (b) => createHash("sha256").update(b).digest("hex");
const workerPath = fileURLToPath(new URL("./file-worker.cjs", import.meta.url));

function checkedPolicy(policy) {
  const { policyHash, ...input } = policy;
  const checked = createPolicy(input);
  if (checked.policyHash !== policyHash)
    fail("POLICY_DENIED", "Policy digest mismatch");
  return checked;
}
export function compileNativePolicy(policy, cwd) {
  const checked = checkedPolicy(policy);
  if (checked.networkMode !== "offline")
    fail(
      "POLICY_UNSUPPORTED",
      "Native runner currently supports offline policy only",
    );
  return {
    workspace: canonicalWindowsPath(cwd),
    writableRoots: checked.writeRoots,
    denyRead: checked.readDeny,
    denyWrite: checked.writeDeny,
    network: "disabled",
  };
}

/** Build the standalone source-based runner protocol. Only trusted host configuration selects runtimes. */
export async function buildInvocation({
  policy,
  operation,
  runtime,
  workerSource,
  parentPid = process.pid,
}) {
  policy = checkedPolicy(policy);
  assertRuntimeOutsidePolicy(runtime, policy);
  const op = validateOperation(operation, policy);
  const cwd = op.cwd ?? policy.writeRoots[0];
  let argv,
    stdin = "";
  if (op.kind === "exec")
    argv = [canonicalWindowsPath(op.executable), ...op.argv];
  else if (op.kind === "shell")
    argv = [
      canonicalWindowsPath(runtime.powershellExe),
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(op.script, "utf16le").toString("base64"),
    ];
  else {
    workerSource ??= await readFile(workerPath, "utf8");
    argv = [canonicalWindowsPath(runtime.nodeExe), "-e", workerSource];
    stdin = JSON.stringify(op);
  }
  if (
    !Number.isSafeInteger(parentPid) ||
    parentPid < 1 ||
    parentPid > 0xffffffff
  )
    fail("INVALID_REQUEST", "Invalid parent process ID");
  if (argv.reduce((n, s) => n + 2 * s.length + 3, 0) > 30000)
    fail("INVALID_REQUEST", "Windows child command-line budget exceeded");
  const env = {
    SystemRoot: runtime.systemRoot,
    WINDIR: runtime.systemRoot,
    COMSPEC: win32.join(runtime.systemRoot, "System32", "cmd.exe"),
    PATH: runtime.path,
    TEMP: runtime.temp,
    TMP: runtime.temp,
    USERNAME: runtime.userName,
    ...(op.env ?? {}),
  };
  const fileOperation = ["read", "write", "edit"].includes(op.kind)
    ? op
    : undefined;
  // The worker's base64/JSON envelope has an independent transport budget.
  const captureOutputBytes = fileOperation
    ? (op.kind === "read" ? Math.ceil(op.length / 3) * 4 : 0) + 1024
    : op.maxOutputBytes;
  const request = {
    schemaVersion: 1,
    argv,
    cwd,
    env,
    stdin,
    parentPid,
    policyHash: policy.policyHash,
    timeoutMs: op.timeoutMs,
    maxOutputBytes: captureOutputBytes,
    policy: compileNativePolicy(policy, cwd),
  };
  const serialized = JSON.stringify(request);
  if (Buffer.byteLength(serialized) > 1048576)
    fail("INVALID_REQUEST", "Native request exceeds 1 MiB");
  return {
    executable: canonicalWindowsPath(runtime.runnerExe),
    args: ["run"],
    cwd,
    env,
    stdin: serialized,
    captureOutputBytes,
    fileOperation,
  };
}

export class NativeSandboxBackend {
  capabilities() {
    return {
      nativeEnforcement: false,
      kinds: [],
      readModes: [],
      networkModes: [],
      nativeValidated: NATIVE_VALIDATED,
      reason: VALIDATION_BLOCKER,
    };
  }
  async prepare() {
    fail("BACKEND_UNAVAILABLE", VALIDATION_BLOCKER);
  }
  async execute() {
    fail("BACKEND_UNAVAILABLE", VALIDATION_BLOCKER);
  }
  async cancel() {
    return { terminated: false };
  }
  async close() {
    return { cleaned: false };
  }
}

/** Hash identity is not publisher trust. No existing app or CLI binary is part of this runtime. */
export async function verifyRuntime(runtime) {
  if (runtime.version !== NATIVE_VERSION)
    fail("VERSION_MISMATCH", "Exact standalone runner version required");
  for (const key of [
    "runnerExe",
    "nodeExe",
    "powershellExe",
    "systemRoot",
    "temp",
  ])
    canonicalWindowsPath(runtime[key]);
  if (
    typeof runtime.userName !== "string" ||
    !runtime.userName ||
    runtime.userName.includes("\0")
  )
    fail("INVALID_REQUEST", "Operator-owned Windows username required");
  if (typeof runtime.path !== "string" || runtime.path.includes("\0"))
    fail("INVALID_REQUEST", "Operator-owned PATH required");
  if (!Array.isArray(runtime.files))
    fail(
      "BACKEND_UNAVAILABLE",
      "Operator-owned runtime hash manifest required",
    );
  for (const requiredPath of [
    runtime.runnerExe,
    runtime.nodeExe,
    runtime.powershellExe,
  ]) {
    if (
      !runtime.files.some(
        (f) =>
          canonicalWindowsPath(f.path) === canonicalWindowsPath(requiredPath),
      )
    )
      fail("BACKEND_UNAVAILABLE", "Missing runtime hash pin: " + requiredPath);
  }
  for (const file of runtime.files) {
    canonicalWindowsPath(file.path);
    if (!/^[a-f0-9]{64}$/.test(file.sha256))
      fail("INVALID_REQUEST", "Invalid runtime SHA-256");
    if (
      canonicalWindowsPath(await realpath(file.path)) !==
      canonicalWindowsPath(file.path)
    )
      fail("POLICY_DENIED", "Runtime path resolves elsewhere");
    if (sha(await readFile(file.path)) !== file.sha256)
      fail("VERSION_MISMATCH", "Runtime hash mismatch");
  }
}

export function assertRuntimeOutsidePolicy(runtime, policy) {
  policy = checkedPolicy(policy);
  for (const path of [
    runtime.runnerExe,
    runtime.nodeExe,
    runtime.powershellExe,
    ...(runtime.files ?? []).map((f) => f.path),
  ]) {
    if (
      policy.writeRoots.some((root) =>
        isWithin(canonicalWindowsPath(path), root),
      )
    )
      fail(
        "POLICY_DENIED",
        "Trusted runtime must be outside sandbox writable roots",
      );
  }
}
export function parseExperimentInputs(operator, request) {
  if (
    !operator ||
    typeof operator !== "object" ||
    Array.isArray(operator) ||
    Object.keys(operator).some((k) => !["runtime"].includes(k))
  )
    fail("INVALID_REQUEST", "Invalid operator configuration");
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).some((k) => !["policy", "operation"].includes(k))
  )
    fail("INVALID_REQUEST", "Request may contain only policy and operation");
  return {
    runtime: operator.runtime,
    policy: request.policy,
    operation: request.operation,
  };
}
export function diagnosticExitCode(result) {
  return result.error ? 1 : (result.exitCode ?? 1);
}

function decodeBase64(value) {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  )
    throw Error("Invalid base64");
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value) throw Error("Noncanonical base64");
  return bytes;
}

/** Future transport plumbing, NOT an activated SandboxBroker backend. Never infers cleanup from process close. */
export function spawnNative(
  invocation,
  { onOutput = () => {}, signal, timeoutMs, maxOutputBytes },
  { spawnProcess = spawn, drainTimeoutMs = 2000 } = {},
) {
  if (signal?.aborted)
    return Promise.reject(
      new SandboxError("CANCELLED", "Cancelled before native process spawn"),
    );
  return new Promise((resolve, reject) => {
    const child = spawnProcess(invocation.executable, invocation.args, {
      cwd: invocation.cwd,
      env: invocation.env,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let wire = [],
      wireBytes = 0,
      reason = null,
      done = false,
      watchdog,
      timer;
    // JSON escaping can expand one payload byte sixfold; transport overhead is separately bounded.
    const wireLimit =
      Math.ceil(((invocation.captureOutputBytes ?? maxOutputBytes) * 2) / 3) *
        4 +
      65536;
    const finish = (result, error) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      clearTimeout(watchdog);
      signal?.removeEventListener("abort", abort);
      if (error) reject(error);
      else resolve(result);
    };
    const startWatchdog = () => {
      if (watchdog || done) return;
      watchdog = setTimeout(() => {
        for (const stream of ["stdin", "stdout", "stderr"])
          child[stream]?.destroy();
        child.unref?.();
        finish({
          exitCode: null,
          terminated: false,
          cleanupVerified: false,
          error: { code: "CLEANUP_UNCONFIRMED" },
          stopReason: reason,
        });
      }, drainTimeoutMs);
    };
    const stop = (why) => {
      if (done) return;
      reason ??= why;
      try {
        child.kill();
      } catch {}
      startWatchdog();
    };
    const abort = () => stop("CANCELLED");
    timer = setTimeout(() => stop("TIMEOUT"), timeoutMs);
    for (const stream of ["stdout", "stderr"])
      child[stream].on("data", (data) => {
        if (done || reason) return;
        wireBytes += data.length;
        if (wireBytes > wireLimit) {
          stop("OUTPUT_LIMIT");
          return;
        }
        if (stream === "stdout") wire.push(Buffer.from(data));
      });
    child.stdin.on("error", () => {});
    child.once("error", (error) => finish(null, error));
    child.once("exit", startWatchdog);
    child.once("close", (exitCode, exitSignal) => {
      if (reason) {
        finish({
          exitCode,
          exitSignal,
          terminated: false,
          cleanupVerified: false,
          error: { code: reason },
        });
        return;
      }
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          Buffer.concat(wire),
        );
        const lines = text.trim().split("\n");
        if (lines.length !== 1)
          throw Error("Expected exactly one native terminal event");
        const result = JSON.parse(lines[0]);
        if (result.type === "error" && typeof result.code === "string") {
          finish({
            exitCode,
            terminated: false,
            cleanupVerified: false,
            error: { code: result.code },
          });
          return;
        }
        if (
          result.type !== "result" ||
          !Number.isInteger(result.exitCode) ||
          result.exitCode < 0 ||
          result.exitCode > 0xffffffff ||
          typeof result.stdoutBase64 !== "string" ||
          typeof result.stderrBase64 !== "string" ||
          typeof result.timedOut !== "boolean" ||
          typeof result.truncated !== "boolean" ||
          !["exited", "timeout", "outputLimit", "parentDeath"].includes(
            result.stopReason,
          )
        )
          throw Error("Invalid native result");
        if (result.terminated !== true || result.cleanupVerified !== true) {
          finish({
            exitCode: result.exitCode,
            terminated: false,
            cleanupVerified: false,
            error: { code: "CLEANUP_UNCONFIRMED" },
          });
          return;
        }
        const nativeError =
          result.stopReason === "parentDeath"
            ? "BROKER_LOST"
            : result.stopReason === "timeout" || result.timedOut
              ? "TIMEOUT"
              : result.stopReason === "outputLimit" || result.truncated
                ? "OUTPUT_LIMIT"
                : exitCode !== 0
                  ? "BROKER_LOST"
                  : null;
        const streams = {
          stdout: decodeBase64(result.stdoutBase64),
          stderr: decodeBase64(result.stderrBase64),
        };
        if (invocation.fileOperation) {
          const terminal = {
            exitCode: result.exitCode,
            terminated: true,
            cleanupVerified: true,
          };
          if (nativeError) {
            finish({
              ...terminal,
              error: {
                code: nativeError,
              },
            });
            return;
          }
          const response = JSON.parse(
            new TextDecoder("utf-8", { fatal: true }).decode(streams.stdout),
          );
          if (
            response.ok === false &&
            typeof response.error?.code === "string"
          ) {
            finish({ ...terminal, error: response.error });
            return;
          }
          if (response.ok !== true || !response.data || result.exitCode !== 0)
            throw Error("Invalid worker result");
          let data = response.data;
          if (invocation.fileOperation.kind === "read") {
            if (data.encoding !== "base64")
              throw Error("Invalid worker encoding");
            const content = decodeBase64(data.content);
            if (
              content.length >
              Math.min(invocation.fileOperation.length, maxOutputBytes)
            ) {
              finish({ ...terminal, error: { code: "OUTPUT_LIMIT" } });
              return;
            }
            // Offsets and limits are bytes, so a valid file can yield a range
            // starting/ending inside a UTF-8 code point. Preserve the exact range
            // as base64 when it cannot be decoded losslessly; never replace,
            // drop, or read past those bytes to manufacture valid text.
            if (invocation.fileOperation.encoding === "utf8") {
              try {
                const text = new TextDecoder("utf-8", {
                  fatal: true,
                  ignoreBOM: true,
                }).decode(content);
                data = { ...data, encoding: "utf8", content: text };
              } catch {
                data = { ...data, encoding: "base64" };
              }
            }
          }
          finish({ ...terminal, data });
          return;
        }
        let retained = 0,
          bytesSeen = 0;
        for (const stream of ["stdout", "stderr"]) {
          const data = streams[stream];
          bytesSeen += data.length;
          const count = Math.min(data.length, maxOutputBytes - retained);
          if (count) onOutput({ stream, data: data.subarray(0, count) });
          retained += count;
        }
        finish({
          exitCode: result.exitCode,
          terminated: true,
          cleanupVerified: true,
          bytesSeen,
          ...(nativeError
            ? { error: { code: nativeError } }
            : bytesSeen > maxOutputBytes
              ? { error: { code: "OUTPUT_LIMIT" } }
              : {}),
        });
      } catch {
        finish({
          exitCode,
          terminated: false,
          cleanupVerified: false,
          error: { code: "BROKER_LOST" },
        });
      }
    });
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    if (!reason) child.stdin.end(invocation.stdin);
    else child.stdin.destroy();
  });
}
