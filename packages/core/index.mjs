import { createHash, randomUUID } from "node:crypto";
import { win32 } from "node:path";

export const PROTOCOL = Object.freeze({ major: 1, minor: 0 });
export const OPERATION_KINDS = Object.freeze([
  "read",
  "write",
  "edit",
  "exec",
  "shell",
]);
export const ERROR_CODES = Object.freeze([
  "INVALID_REQUEST",
  "POLICY_DENIED",
  "POLICY_UNSUPPORTED",
  "POLICY_EXPIRED",
  "VERSION_MISMATCH",
  "BACKEND_UNAVAILABLE",
  "BUSY",
  "REQUEST_CONFLICT",
  "REQUEST_LIMIT",
  "SESSION_NOT_FOUND",
  "CANCELLED",
  "TIMEOUT",
  "OUTPUT_LIMIT",
  "BROKER_LOST",
  "CLEANUP_UNCONFIRMED",
  "FILE_CONFLICT",
]);
export class SandboxError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "SandboxError";
    this.code = code;
  }
}
const fail = (code, message) => {
  throw new SandboxError(code, message);
};
const plain = (v) =>
  v !== null &&
  typeof v === "object" &&
  Object.getPrototypeOf(v) === Object.prototype;
function shape(v, keys, required = []) {
  if (
    !plain(v) ||
    Object.keys(v).some((k) => !keys.includes(k)) ||
    required.some((k) => !(k in v))
  )
    fail("INVALID_REQUEST", "Unexpected object shape");
}
function str(v, max = 32768) {
  if (typeof v !== "string" || v.length > max || v.includes("\0"))
    fail("INVALID_REQUEST", "Invalid string");
  return v;
}
function integer(v, min, max) {
  if (!Number.isSafeInteger(v) || v < min || v > max)
    fail("INVALID_REQUEST", "Invalid integer");
  return v;
}
function choice(v, values) {
  if (!values.includes(v)) fail("INVALID_REQUEST", "Invalid enum");
  return v;
}
const uuid = (v) => {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      v,
    )
  )
    fail("INVALID_REQUEST", "Invalid UUID");
  return v;
};
const hash = (v) => {
  if (typeof v !== "string" || !/^[0-9a-f]{64}$/.test(v))
    fail("INVALID_REQUEST", "Invalid SHA-256");
  return v;
};
export function stableJson(v) {
  if (Array.isArray(v)) return "[" + v.map(stableJson).join(",") + "]";
  if (plain(v))
    return (
      "{" +
      Object.keys(v)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + stableJson(v[k]))
        .join(",") +
      "}"
    );
  return JSON.stringify(v);
}
export function deepFreeze(v) {
  if (v && typeof v === "object") {
    for (const x of Object.values(v)) deepFreeze(x);
    Object.freeze(v);
  }
  return v;
}
const digest = (v) => createHash("sha256").update(stableJson(v)).digest("hex");

/** Lexical validation ONLY. Native backend must resolve final identities, links and TOCTOU safely. */
export function canonicalWindowsPath(value) {
  str(value);
  if (
    !/^[a-z]:[\\/]/i.test(value) ||
    value.includes(":", 2) ||
    /[<>"|?*\x00-\x1f]/.test(value) ||
    value.includes("~")
  )
    fail("POLICY_DENIED", "Only unambiguous local drive paths are supported");
  const pieces = value.slice(3).split(/[\\/]/);
  if (
    pieces.some(
      (p) =>
        p === ".." ||
        p === "." ||
        /[ .]$/.test(p) ||
        /^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(p),
    )
  )
    fail("POLICY_DENIED", "Ambiguous Windows path");
  return win32
    .normalize(value)
    .replace(/\\$/, value.length === 3 ? "\\" : "")
    .toLowerCase();
}
export function isWithin(path, root) {
  return (
    path === root || path.startsWith(root.endsWith("\\") ? root : root + "\\")
  );
}
export function assertPathAllowed(path, policy, write = false) {
  const p = canonicalWindowsPath(path);
  if (
    policy.readDeny.some((r) => isWithin(p, r)) ||
    (write &&
      (policy.writeDeny.some((r) => isWithin(p, r)) ||
        !policy.writeRoots.some((r) => isWithin(p, r))))
  )
    fail("POLICY_DENIED", "Path outside approved policy");
  return p;
}
export function createPolicy(input) {
  shape(
    input,
    [
      "policyId",
      "revision",
      "ownerSid",
      "installId",
      "readMode",
      "writeRoots",
      "readDeny",
      "writeDeny",
      "networkMode",
      "runtimeSetId",
      "limits",
      "createdAt",
      "expiresAt",
    ],
    [
      "policyId",
      "revision",
      "ownerSid",
      "installId",
      "readMode",
      "writeRoots",
      "readDeny",
      "writeDeny",
      "networkMode",
      "runtimeSetId",
      "limits",
      "createdAt",
      "expiresAt",
    ],
  );
  uuid(input.policyId);
  integer(input.revision, 1, 2147483647);
  str(input.ownerSid, 184);
  if (!/^S-1-(?:\d+-)+\d+$/.test(input.ownerSid))
    fail("INVALID_REQUEST", "Invalid SID");
  str(input.installId, 128);
  str(input.runtimeSetId, 128);
  choice(input.readMode, ["broadReadWithDeny"]);
  choice(input.networkMode, ["offline", "online"]);
  shape(
    input.limits,
    ["timeoutMs", "maxOutputBytes", "maxRequests"],
    ["timeoutMs", "maxOutputBytes"],
  );
  integer(input.limits.timeoutMs, 1, 120000);
  integer(input.limits.maxOutputBytes, 1, 8388608);
  integer(input.limits.maxRequests ?? 1024, 1, 4096);
  for (const k of ["createdAt", "expiresAt"])
    if (typeof input[k] !== "string" || !Number.isFinite(Date.parse(input[k])))
      fail("INVALID_REQUEST", "Invalid timestamp");
  if (Date.parse(input.expiresAt) <= Date.parse(input.createdAt))
    fail("INVALID_REQUEST", "Invalid policy lifetime");
  const p = structuredClone(input);
  for (const k of ["writeRoots", "readDeny", "writeDeny"]) {
    if (
      !Array.isArray(p[k]) ||
      p[k].length > 128 ||
      (k === "writeRoots" && !p[k].length)
    )
      fail("INVALID_REQUEST", "Invalid roots");
    p[k] = [...new Set(p[k].map(canonicalWindowsPath))].sort();
  }
  p.limits.maxRequests ??= 1024;
  if (
    p.writeRoots.some(
      (r) =>
        r.length === 3 ||
        p.readDeny.some((d) => isWithin(r, d)) ||
        p.writeDeny.some((d) => isWithin(r, d)),
    )
  )
    fail("POLICY_DENIED", "Unsafe write root");
  return deepFreeze({ ...p, policyHash: digest(p) });
}
/** Only inert per-operation overrides; system/path/home/temp are native-owned, never inherited. */
export function validateEnvironment(env = {}) {
  shape(env, ["LANG", "LC_ALL", "PYTHONUTF8", "PYTHONIOENCODING"]);
  const out = {};
  for (const [k, v] of Object.entries(env)) {
    str(v, 128);
    if (!/^[a-zA-Z0-9_.:@+-]+$/.test(v))
      fail("POLICY_DENIED", "Invalid environment override");
    out[k] = v;
  }
  return out;
}
export function validateOperation(input, policy) {
  const common = ["kind", "timeoutMs", "maxOutputBytes"];
  const fields = {
    read: ["path", "offset", "length", "encoding"],
    write: ["path", "data", "encoding", "mode", "expectedHash"],
    edit: ["path", "expectedHash", "oldText", "newText"],
    exec: ["executable", "argv", "cwd", "env", "stdin"],
    shell: ["shellId", "script", "cwd", "env"],
  };
  if (!plain(input) || !OPERATION_KINDS.includes(input.kind))
    fail("INVALID_REQUEST", "Unknown operation");
  shape(input, [...common, ...fields[input.kind]], ["kind"]);
  const o = structuredClone(input);
  o.timeoutMs = integer(
    o.timeoutMs ?? policy.limits.timeoutMs,
    1,
    policy.limits.timeoutMs,
  );
  o.maxOutputBytes = integer(
    o.maxOutputBytes ?? policy.limits.maxOutputBytes,
    1,
    policy.limits.maxOutputBytes,
  );
  if (["read", "write", "edit"].includes(o.kind))
    o.path = assertPathAllowed(o.path, policy, o.kind !== "read");
  if (o.kind === "read") {
    o.offset = integer(o.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    o.length = integer(
      o.length ?? Math.min(65536, o.maxOutputBytes),
      1,
      o.maxOutputBytes,
    );
    o.encoding = choice(o.encoding ?? "utf8", ["utf8", "base64"]);
  }
  if (o.kind === "write") {
    str(o.data, 524288);
    choice(o.encoding, ["utf8", "base64"]);
    choice(o.mode, ["create", "replace"]);
    if (o.mode === "replace") hash(o.expectedHash);
    else if (o.expectedHash !== undefined)
      fail("INVALID_REQUEST", "Create must not carry expected hash");
    if (
      o.encoding === "base64" &&
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
        o.data,
      )
    )
      fail("INVALID_REQUEST", "Invalid base64");
  }
  if (o.kind === "edit") {
    hash(o.expectedHash);
    str(o.oldText, 262144);
    str(o.newText, 262144);
    if (!o.oldText.length) fail("INVALID_REQUEST", "Empty edit match");
  }
  if (["exec", "shell"].includes(o.kind)) {
    o.cwd = assertPathAllowed(o.cwd, policy, true);
    o.env = validateEnvironment(o.env);
  }
  if (o.kind === "exec") {
    o.executable = assertPathAllowed(o.executable, policy);
    if (!Array.isArray(o.argv) || o.argv.length > 256)
      fail("INVALID_REQUEST", "Invalid argv");
    o.argv.forEach((a) => str(a));
    shape(o.stdin, ["mode"], ["mode"]);
    choice(o.stdin.mode, ["closed"]);
  }
  if (o.kind === "shell") {
    choice(o.shellId, ["powershell"]);
    str(o.script, 262144);
  }
  if (Buffer.byteLength(stableJson(o)) > 1048576)
    fail("INVALID_REQUEST", "Operation too large");
  return deepFreeze(o);
}

/** No fallback exists: this object never executes operations. */
export class UnavailableBackend {
  capabilities() {
    return {
      nativeEnforcement: false,
      kinds: [],
      readModes: [],
      networkModes: [],
    };
  }
  async prepare() {
    fail(
      "BACKEND_UNAVAILABLE",
      "A verified Windows native backend is required",
    );
  }
  async execute() {
    fail("BACKEND_UNAVAILABLE", "Execution unavailable");
  }
  async cancel() {
    return { terminated: false };
  }
  async close() {
    return { cleaned: false };
  }
}
export class SandboxBroker {
  #backend;
  #now;
  #state = "READY";
  #session = null;
  #closePromise = null;
  #cleanupTimeoutMs;
  constructor({
    backend = new UnavailableBackend(),
    now = () => Date.now(),
    cleanupTimeoutMs = 2000,
  } = {}) {
    this.#backend = backend;
    this.#now = now;
    this.#cleanupTimeoutMs = integer(cleanupTimeoutMs, 1, 30000);
  }
  async #bounded(promise, timeoutMs) {
    let timer;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(
            () =>
              reject(
                new SandboxError(
                  "CLEANUP_UNCONFIRMED",
                  "Native operation or cleanup did not settle in time",
                ),
              ),
            timeoutMs,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  getStatus() {
    return deepFreeze({
      state: this.#state,
      sessionId: this.#session?.id ?? null,
      activeRequestId: this.#session?.active ?? null,
    });
  }
  #trackNative(session, action) {
    const pending = Promise.resolve().then(action);
    session.pending.add(pending);
    // Both handlers consume settlement; the caller still observes the original promise.
    pending.then(
      () => session.pending.delete(pending),
      () => session.pending.delete(pending),
    );
    return pending;
  }
  #assertPreparing(session) {
    if (
      this.#session !== session ||
      session.invalidated ||
      this.#state !== "PREPARING"
    ) {
      fail("CANCELLED", "Session preparation was invalidated");
    }
  }
  async createSession(policy) {
    if (this.#state !== "READY") fail("BUSY", "Broker is not ready");
    // Local validation cannot mutate native state and completes before admission.
    const { policyHash, ...input } = policy;
    const checked = createPolicy(input);
    if (checked.policyHash !== policyHash)
      fail("POLICY_DENIED", "Policy digest mismatch");
    this.#checkTime(checked);
    const session = {
      id: randomUUID(),
      policy: checked,
      requests: new Map(),
      active: null,
      pending: new Set(),
      invalidated: false,
    };
    this.#session = session;
    this.#state = "PREPARING";
    try {
      const capabilities = await this.#bounded(
        this.#trackNative(session, () => this.#backend.capabilities()),
        this.#cleanupTimeoutMs,
      );
      this.#assertPreparing(session);
      if (
        capabilities?.nativeEnforcement !== true ||
        !OPERATION_KINDS.every((kind) => capabilities.kinds?.includes(kind)) ||
        !capabilities.readModes?.includes(checked.readMode) ||
        !capabilities.networkModes?.includes(checked.networkMode)
      )
        fail(
          "BACKEND_UNAVAILABLE",
          "Required native enforcement capabilities unavailable",
        );
      const prepared = await this.#bounded(
        this.#trackNative(session, () =>
          this.#backend.prepare({ sessionId: session.id, policy: checked }),
        ),
        this.#cleanupTimeoutMs,
      );
      this.#assertPreparing(session);
      if (
        prepared?.enforced !== true ||
        prepared?.policyHash !== checked.policyHash
      )
        fail("BACKEND_UNAVAILABLE", "Native preparation not verified");
      this.#checkTime(checked);
      this.#state = "SESSION_ACTIVE";
      return deepFreeze({
        sessionId: session.id,
        policyRef: {
          id: checked.policyId,
          revision: checked.revision,
          hash: checked.policyHash,
        },
      });
    } catch (error) {
      session.invalidated = true;
      // A concurrent close owns its state; stale preparation may never reanimate it.
      if (this.#session === session && this.#state !== "CLEANUP")
        this.#state = "BLOCKED";
      throw error;
    }
  }
  #checkTime(p) {
    if (
      this.#now() < Date.parse(p.createdAt) ||
      this.#now() >= Date.parse(p.expiresAt)
    )
      fail("POLICY_EXPIRED", "Policy is not currently valid");
  }
  #getSession(id) {
    if (!this.#session || this.#session.id !== id)
      fail("SESSION_NOT_FOUND", "Unknown session");
    return this.#session;
  }
  execute(request) {
    shape(
      request,
      [
        "protocol",
        "requestId",
        "sessionId",
        "method",
        "policyRef",
        "operation",
      ],
      [
        "protocol",
        "requestId",
        "sessionId",
        "method",
        "policyRef",
        "operation",
      ],
    );
    shape(request.protocol, ["major", "minor"], ["major", "minor"]);
    if (request.protocol.major !== 1 || request.protocol.minor !== 0)
      fail("VERSION_MISMATCH", "Protocol mismatch");
    choice(request.method, ["execute"]);
    uuid(request.requestId);
    uuid(request.sessionId);
    const s = this.#getSession(request.sessionId);
    shape(
      request.policyRef,
      ["id", "revision", "hash"],
      ["id", "revision", "hash"],
    );
    if (
      request.policyRef.id !== s.policy.policyId ||
      request.policyRef.revision !== s.policy.revision ||
      request.policyRef.hash !== s.policy.policyHash
    )
      fail("POLICY_DENIED", "Policy reference mismatch");
    const operation = validateOperation(request.operation, s.policy),
      signature = digest(request.operation),
      old = s.requests.get(request.requestId);
    if (old) {
      if (old.signature !== signature)
        fail("REQUEST_CONFLICT", "Request ID has different payload");
      return old.promise;
    }
    if (this.#state !== "SESSION_ACTIVE" || s.active)
      fail("BUSY", "Session is busy or blocked");
    this.#checkTime(s.policy);
    if (s.requests.size >= s.policy.limits.maxRequests)
      fail(
        "REQUEST_LIMIT",
        "Start a new session; replay records are never evicted",
      );
    const record = {
      signature,
      controller: new AbortController(),
      reason: null,
      done: false,
      stopPromise: null,
    };
    s.active = request.requestId;
    s.requests.set(request.requestId, record);
    record.promise = this.#run(s, request.requestId, operation, record);
    return record.promise;
  }
  #stop(s, id, r, reason) {
    if (r.done) return Promise.resolve({ accepted: false, terminated: true });
    if (r.stopPromise) return r.stopPromise;
    r.reason = reason;
    r.controller.abort(reason);
    r.stopPromise = Promise.resolve()
      .then(() => this.#backend.cancel({ sessionId: s.id, requestId: id }))
      .catch(() => ({ terminated: false }));
    return r.stopPromise;
  }
  async #run(s, id, operation, r) {
    const outputs = [];
    let bytesSeen = 0,
      kept = 0,
      truncated = false,
      terminationConfirmed = false,
      result,
      error,
      outcome = "success";
    let cancelTimer;
    const cancelDeadline = new Promise((_, reject) => {
      r.controller.signal.addEventListener(
        "abort",
        () => {
          cancelTimer = setTimeout(
            () =>
              reject(
                new SandboxError(
                  "CLEANUP_UNCONFIRMED",
                  "Cancellation did not confirm cleanup in time",
                ),
              ),
            this.#cleanupTimeoutMs,
          );
        },
        { once: true },
      );
    });
    const timer = setTimeout(() => {
      void this.#stop(s, id, r, "TIMEOUT");
    }, operation.timeoutMs);
    try {
      result = await this.#bounded(
        Promise.race([
          cancelDeadline,
          this.#backend.execute({
            sessionId: s.id,
            requestId: id,
            policy: s.policy,
            operation,
            signal: r.controller.signal,
            onOutput: (chunk) => {
              if (r.done || r.reason) return;
              if (
                !chunk ||
                !["stdout", "stderr"].includes(chunk.stream) ||
                !(
                  typeof chunk.data === "string" ||
                  chunk.data instanceof Uint8Array
                )
              ) {
                void this.#stop(s, id, r, "BROKER_LOST");
                return;
              }
              const bytes = Buffer.from(chunk.data);
              bytesSeen = Math.min(
                Number.MAX_SAFE_INTEGER,
                bytesSeen + bytes.length,
              );
              const take = Math.min(
                bytes.length,
                operation.maxOutputBytes - kept,
              );
              if (outputs.length >= 4096) {
                truncated = true;
                void this.#stop(s, id, r, "OUTPUT_LIMIT");
                return;
              }
              if (take) {
                outputs.push({
                  stream: chunk.stream,
                  encoding: "base64",
                  data: bytes.subarray(0, take).toString("base64"),
                });
                kept += take;
              }
              if (bytesSeen > operation.maxOutputBytes) {
                truncated = true;
                void this.#stop(s, id, r, "OUTPUT_LIMIT");
              }
            },
          }),
        ]),
        operation.timeoutMs + this.#cleanupTimeoutMs,
      );
      if (result?.terminated !== true)
        fail(
          "CLEANUP_UNCONFIRMED",
          "Backend did not confirm process-tree termination",
        );
      terminationConfirmed = true;
      if (result.data !== undefined) {
        if (operation.kind === "read") {
          shape(
            result.data,
            ["encoding", "content", "eof", "hash"],
            ["encoding", "content", "eof"],
          );
          choice(result.data.encoding, ["utf8", "base64"]);
          str(result.data.content, operation.maxOutputBytes * 2);
          if (typeof result.data.eof !== "boolean")
            fail("BROKER_LOST", "Invalid read result");
          if (result.data.hash !== undefined) hash(result.data.hash);
        } else {
          shape(result.data, ["hash", "bytesWritten"], []);
          if (result.data.hash !== undefined) hash(result.data.hash);
          if (result.data.bytesWritten !== undefined)
            integer(result.data.bytesWritten, 0, Number.MAX_SAFE_INTEGER);
        }
      }
      if (
        result.data !== undefined &&
        Buffer.byteLength(JSON.stringify(result.data)) >
          operation.maxOutputBytes - kept
      ) {
        truncated = true;
        r.reason ??= "OUTPUT_LIMIT";
      }
      if (
        r.stopPromise &&
        (await this.#bounded(r.stopPromise, this.#cleanupTimeoutMs))
          ?.terminated !== true
      )
        fail("CLEANUP_UNCONFIRMED", "Cancellation cleanup not verified");
      if (r.reason) fail(r.reason, "Operation stopped");
      if (result.error)
        throw new SandboxError(
          ERROR_CODES.includes(result.error.code)
            ? result.error.code
            : "BROKER_LOST",
          "Native operation failed",
        );
      if (
        result.exitCode !== undefined &&
        !Number.isSafeInteger(result.exitCode)
      )
        fail("BROKER_LOST", "Invalid backend result");
    } catch (e) {
      const safeCodes = [
        "POLICY_DENIED",
        "FILE_CONFLICT",
        "TIMEOUT",
        "CANCELLED",
        "OUTPUT_LIMIT",
        "CLEANUP_UNCONFIRMED",
      ];
      const knownFailure =
        safeCodes.includes(e?.code) &&
        (terminationConfirmed || e?.code === "CLEANUP_UNCONFIRMED");
      error = {
        code: knownFailure ? e.code : "BROKER_LOST",
        message: knownFailure ? e.message : "Native backend failed",
      };
      outcome = ["BROKER_LOST", "CLEANUP_UNCONFIRMED"].includes(error.code)
        ? "unknown"
        : "error";
      if (outcome === "unknown") this.#state = "BLOCKED";
    } finally {
      clearTimeout(timer);
      clearTimeout(cancelTimer);
      r.done = true;
      s.active = null;
    }
    return deepFreeze({
      requestId: id,
      sessionId: s.id,
      policyHash: s.policy.policyHash,
      outcome,
      ...(error ? { error } : {}),
      ...(outcome === "success" && result?.exitCode !== undefined
        ? { exitCode: result.exitCode }
        : {}),
      ...(outcome === "success" && result?.data !== undefined
        ? { data: result.data }
        : {}),
      outputs,
      bytesSeen,
      truncated,
    });
  }
  async cancel(sessionId, requestId) {
    const s = this.#getSession(sessionId),
      r = s.requests.get(requestId);
    if (!r) fail("INVALID_REQUEST", "Unknown request");
    if (r.done) return { accepted: false, terminal: true };
    void this.#stop(s, requestId, r, "CANCELLED");
    return { accepted: true, terminal: false };
  }
  closeSession(sessionId) {
    this.#getSession(sessionId);
    if (this.#closePromise) return this.#closePromise;
    this.#closePromise = this.#close(sessionId).finally(() => {
      this.#closePromise = null;
    });
    return this.#closePromise;
  }
  async #close(sessionId) {
    const s = this.#getSession(sessionId);
    s.invalidated = true;
    this.#state = "CLEANUP";
    if (s.active) {
      const r = s.requests.get(s.active);
      void this.#stop(s, s.active, r, "CANCELLED");
      await r.promise;
    }
    try {
      // Do not remove protection while any preparation call can still mutate native state.
      await this.#bounded(
        Promise.allSettled([...s.pending]),
        this.#cleanupTimeoutMs,
      );
      const result = await this.#bounded(
        Promise.resolve().then(() => this.#backend.close({ sessionId })),
        this.#cleanupTimeoutMs,
      );
      if (result?.cleaned !== true)
        fail("CLEANUP_UNCONFIRMED", "Native cleanup not verified");
      this.#session = null;
      this.#state = "READY";
      return { closed: true };
    } catch (e) {
      this.#state = "BLOCKED";
      throw e;
    }
  }
}
