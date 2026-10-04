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

export const CODEX_PIN = Object.freeze({
  version: "0.160.0",
  tag: "rust-v0.160.0",
  sourceCommit: "a956835d020762cb2b570053af06f643a11c0ecc",
  source:
    "https://github.com/openai/codex/tree/a956835d020762cb2b570053af06f643a11c0ecc",
});
export const OFFICIAL_X64_SHA256 = Object.freeze({
  "codex.exe":
    "fdda5fa3cf3fb3d000b876720742857676293e4315e4b045fae6f8bd7e866d1d",
  "codex-command-runner.exe":
    "dd13f8e95faba5cf539d870dd3b64c226b00d062a5b523e7e08c44fdc8235224",
  "codex-windows-sandbox-setup.exe":
    "8f91d62aca2aca87b0ebf446848b817720415dd3080905ffc3085c17b70bd57a",
});
export const ACTIVATION_ACKNOWLEDGEMENT =
  "I approve using a disposable isolated Windows test machine, existing Codex provisioning, and possible account, ACL, service and firewall changes.";
export const CLEANUP_BLOCKER =
  "Codex 0.160.0 preserves descendants after normal root exit; CLI completion does not attest process-tree cleanup.";
const fail = (code, message) => {
  throw new SandboxError(code, message);
};
const sha = (b) => createHash("sha256").update(b).digest("hex");
const workerPath = fileURLToPath(new URL("./file-worker.cjs", import.meta.url));

export function compileSandboxState(policy, cwd) {
  const { policyHash, ...input } = policy;
  const checked = createPolicy(input);
  if (checked.policyHash !== policyHash)
    fail("POLICY_DENIED", "Policy digest mismatch");
  cwd = canonicalWindowsPath(cwd);
  const entries = [
    { path: { type: "special", value: { kind: "root" } }, access: "read" },
    ...checked.writeRoots.map((path) => ({
      path: { type: "path", path },
      access: "write",
    })),
    ...checked.writeDeny.map((path) => ({
      path: { type: "path", path },
      access: "read",
    })),
    ...checked.readDeny.map((path) => ({
      path: { type: "path", path },
      access: "deny",
    })),
  ];
  // PathUri is a URI; filesystem entries use RawFileSystemPath native strings.
  const sandbox_cwd =
    "file:///" +
    cwd
      .replaceAll("\\", "/")
      .split("/")
      .map((s, i) => (i === 0 ? s : encodeURIComponent(s)))
      .join("/");
  return {
    permission_profile: {
      type: "managed",
      file_system: { type: "restricted", entries },
      network: checked.networkMode === "offline" ? "restricted" : "enabled",
    },
    codex_linux_sandbox_exe: null,
    sandbox_cwd,
    use_legacy_landlock: false,
  };
}

export async function buildInvocation({
  policy,
  operation,
  runtime,
  workerSource,
}) {
  const op = validateOperation(operation, policy);
  let command,
    stdin = "";
  const cwd = op.cwd ?? policy.writeRoots[0];
  if (op.kind === "exec")
    command = [canonicalWindowsPath(op.executable), ...op.argv];
  else if (op.kind === "shell") {
    command = [
      canonicalWindowsPath(runtime.powershellExe),
      "-NoLogo",
      "-NoProfile",
      "-NonInteractive",
      "-EncodedCommand",
      Buffer.from(op.script, "utf16le").toString("base64"),
    ];
  } else {
    workerSource ??= await readFile(workerPath, "utf8");
    command = [canonicalWindowsPath(runtime.nodeExe), "-e", workerSource];
    stdin = JSON.stringify(op);
  }
  const state = compileSandboxState(policy, cwd);
  const invocation = {
    executable: runtime.codexExe,
    args: [
      "-c",
      'windows.sandbox="elevated"',
      "-c",
      "prefer_mxc=false",
      "-c",
      'shell_environment_policy.inherit="all"',
      "sandbox",
      "--sandbox-state-json",
      JSON.stringify(state),
      "--",
      ...command,
    ],
    cwd,
    stdin,
    env: {
      SystemRoot: runtime.systemRoot,
      WINDIR: runtime.systemRoot,
      COMSPEC: win32.join(runtime.systemRoot, "System32", "cmd.exe"),
      PATH: runtime.path,
      CODEX_HOME: runtime.codexHome,
      TEMP: runtime.temp,
      TMP: runtime.temp,
      USERNAME: runtime.userName,
      ...(op.env ?? {}),
    },
  };
  if (
    invocation.args.reduce(
      (n, s) => n + 2 * s.length + 3,
      invocation.executable.length,
    ) > 30000
  )
    fail("INVALID_REQUEST", "Windows command-line budget exceeded");
  return invocation;
}

/** Safe broker implementation: refuses the full contract until a native supervisor exists. */
export class CodexReferenceBackend {
  capabilities() {
    return {
      nativeEnforcement: false,
      kinds: [],
      readModes: [],
      networkModes: [],
      referenceOnly: true,
      reason: CLEANUP_BLOCKER,
      pin: CODEX_PIN,
    };
  }
  async prepare() {
    fail("BACKEND_UNAVAILABLE", CLEANUP_BLOCKER);
  }
  async execute() {
    fail("BACKEND_UNAVAILABLE", CLEANUP_BLOCKER);
  }
  async cancel() {
    return { terminated: false };
  }
  async close() {
    return { cleaned: false };
  }
}

/** Hash checks establish operator-selected file identity, NOT Authenticode/publisher trust. */
export async function verifyRuntime(runtime) {
  if (win32.basename(runtime.codexExe ?? "").toLowerCase() !== "codex.exe")
    fail(
      "VERSION_MISMATCH",
      "Pinned Codex binary must use the verified codex.exe layout",
    );
  if (runtime.version !== CODEX_PIN.version)
    fail("VERSION_MISMATCH", "Exact Codex version required");
  for (const key of [
    "codexExe",
    "nodeExe",
    "powershellExe",
    "codexHome",
    "systemRoot",
    "temp",
    "supervisorExe",
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
  if (!Array.isArray(runtime.files) || runtime.files.length < 3)
    fail(
      "BACKEND_UNAVAILABLE",
      "Operator hash manifest including executable and helpers required",
    );
  if (runtime.supervisorVersion !== "0.1.0")
    fail("VERSION_MISMATCH", "Exact supervisor source/build version required");
  const required = [
    runtime.supervisorExe,
    runtime.codexExe,
    win32.join(win32.dirname(runtime.codexExe), "codex-command-runner.exe"),
    win32.join(
      win32.dirname(runtime.codexExe),
      "codex-windows-sandbox-setup.exe",
    ),
    runtime.nodeExe,
    runtime.powershellExe,
  ];
  for (const requiredPath of required)
    if (
      !runtime.files.some(
        (f) =>
          canonicalWindowsPath(f.path) === canonicalWindowsPath(requiredPath),
      )
    )
      fail("BACKEND_UNAVAILABLE", "Missing runtime hash pin: " + requiredPath);
  for (const file of runtime.files) {
    canonicalWindowsPath(file.path);
    const basename = win32.basename(file.path).toLowerCase();
    if (
      OFFICIAL_X64_SHA256[basename] &&
      file.sha256 !== OFFICIAL_X64_SHA256[basename]
    )
      fail("VERSION_MISMATCH", "Official Codex release digest required");
    if (!/^[a-f0-9]{64}$/.test(file.sha256))
      fail("INVALID_REQUEST", "Invalid runtime SHA-256");
    const resolved = await realpath(file.path);
    if (canonicalWindowsPath(resolved) !== canonicalWindowsPath(file.path))
      fail("POLICY_DENIED", "Runtime path resolves elsewhere");
    if (sha(await readFile(file.path)) !== file.sha256)
      fail("VERSION_MISMATCH", "Runtime hash mismatch");
  }
}

/** Explicit experiment only; never used by SandboxBroker and never reports cleanup verified. */
export async function runReferenceExperiment(
  { runtime, policy, operation, activation, onOutput = () => {}, signal },
  dependencies = {},
) {
  const platform = dependencies.platform ?? process.platform;
  if (platform !== "win32")
    fail("BACKEND_UNAVAILABLE", "Native reference experiment requires Windows");
  if (
    activation?.acknowledgement !== ACTIVATION_ACKNOWLEDGEMENT ||
    activation?.preprovisionedVersion !== CODEX_PIN.version ||
    activation?.publisherTrustVerified !== true
  )
    fail(
      "BACKEND_UNAVAILABLE",
      "Explicit operator activation and publisher verification required",
    );
  const { policyHash, ...policyInput } = policy;
  policy = createPolicy(policyInput);
  if (policy.policyHash !== policyHash)
    fail("POLICY_DENIED", "Policy digest mismatch");
  if (
    Date.now() < Date.parse(policy.createdAt) ||
    Date.now() >= Date.parse(policy.expiresAt)
  )
    fail("POLICY_EXPIRED", "Policy is not currently valid");
  for (const file of runtime.files ?? [])
    if (
      policy.writeRoots.some((root) =>
        isWithin(canonicalWindowsPath(file.path), root),
      )
    )
      fail(
        "POLICY_DENIED",
        "Trusted runtime must be outside sandbox writable roots",
      );
  if (
    policy.writeRoots.some((root) =>
      isWithin(canonicalWindowsPath(runtime.codexHome), root),
    )
  )
    fail("POLICY_DENIED", "CODEX_HOME must be outside sandbox writable roots");
  await (dependencies.verifyRuntime ?? verifyRuntime)(runtime);
  const op = validateOperation(operation, policy);
  const request = await buildInvocation({
    policy,
    operation: op,
    runtime,
    workerSource: dependencies.workerSource,
  });
  const transport = dependencies.transport ?? spawnReference;
  const supervised = buildSupervisorInvocation(
    request,
    runtime,
    dependencies.parentPid ?? process.pid,
  );
  const result = await transport(supervised, {
    onOutput,
    signal,
    timeoutMs: op.timeoutMs,
    maxOutputBytes: op.maxOutputBytes,
  });
  return {
    ...result,
    terminated: false,
    cleanupVerified: false,
    referenceOnly: true,
    warning: CLEANUP_BLOCKER,
  };
}

export function buildSupervisorInvocation(
  invocation,
  runtime,
  parentPid = process.pid,
) {
  if (runtime.supervisorVersion !== "0.1.0")
    fail("VERSION_MISMATCH", "Supervisor 0.1.0 required");
  canonicalWindowsPath(runtime.supervisorExe);
  const request = {
    schemaVersion: 1,
    executable: invocation.executable,
    cwd: invocation.cwd,
    argv: invocation.args,
    parentPid,
  };
  const args = ["--request-json", JSON.stringify(request)];
  if (
    args.reduce((n, s) => n + 2 * s.length + 3, runtime.supervisorExe.length) >
    30000
  )
    fail("INVALID_REQUEST", "Supervisor Windows command-line budget exceeded");
  return { ...invocation, executable: runtime.supervisorExe, args };
}

export function parseExperimentInputs(operator, request) {
  if (
    !operator ||
    typeof operator !== "object" ||
    Array.isArray(operator) ||
    Object.keys(operator).some((k) => !["runtime", "activation"].includes(k))
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
    activation: operator.activation,
    policy: request.policy,
    operation: request.operation,
  };
}

export function spawnReference(
  invocation,
  { onOutput, signal, timeoutMs, maxOutputBytes },
  { spawnProcess = spawn, drainTimeoutMs = 2000 } = {},
) {
  return new Promise((resolve, reject) => {
    const child = spawnProcess(invocation.executable, invocation.args, {
      cwd: invocation.cwd,
      env: invocation.env,
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let bytes = 0,
      reason = null,
      done = false,
      watchdog = null,
      timer = null;
    const cleanup = () => {
      clearTimeout(timer);
      clearTimeout(watchdog);
      signal?.removeEventListener("abort", abort);
    };
    const finish = (result, error) => {
      if (done) return;
      done = true;
      cleanup();
      if (error) reject(error);
      else resolve({ ...result, terminated: false, cleanupVerified: false });
    };
    const startWatchdog = () => {
      if (watchdog || done) return;
      watchdog = setTimeout(() => {
        for (const stream of ["stdin", "stdout", "stderr"])
          child[stream]?.destroy();
        child.unref?.();
        finish({
          exitCode: null,
          bytesSeen: bytes,
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
        const remaining = Math.max(0, maxOutputBytes - bytes);
        bytes += data.length;
        try {
          if (remaining)
            onOutput({ stream, data: data.subarray(0, remaining) });
        } catch {
          stop("BROKER_LOST");
        }
        if (bytes > maxOutputBytes) stop("OUTPUT_LIMIT");
      });
    child.stdin.on("error", () => {});
    child.once("error", (error) => finish(null, error));
    // A descendant can retain inherited pipes after root exit; never wait indefinitely.
    child.once("exit", () => startWatchdog());
    child.once("close", (exitCode, exitSignal) =>
      finish({
        exitCode,
        exitSignal,
        bytesSeen: bytes,
        ...(reason ? { error: { code: reason } } : {}),
      }),
    );
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    child.stdin.end(invocation.stdin);
  });
}
