/** Runtime module is index.mjs. Declarations document the trusted local adapter contract. */
export type OperationKind = "read" | "write" | "edit" | "exec" | "shell";
export interface PolicyInput {
  policyId: string;
  revision: number;
  ownerSid: string;
  installId: string;
  readMode: "broadReadWithDeny";
  writeRoots: string[];
  readDeny: string[];
  writeDeny: string[];
  networkMode: "offline" | "online";
  runtimeSetId: string;
  limits: { timeoutMs: number; maxOutputBytes: number; maxRequests?: number };
  createdAt: string;
  expiresAt: string;
}
export type PolicySnapshot = Readonly<PolicyInput & { policyHash: string }>;
export interface PolicyRef {
  id: string;
  revision: number;
  hash: string;
}
export interface OperationLimits {
  timeoutMs?: number;
  maxOutputBytes?: number;
}
export type Environment = Partial<
  Record<"LANG" | "LC_ALL" | "PYTHONUTF8" | "PYTHONIOENCODING", string>
>;
export type Operation = OperationLimits &
  (
    | {
        kind: "read";
        path: string;
        offset?: number;
        length?: number;
        encoding?: "utf8" | "base64";
      }
    | {
        kind: "write";
        path: string;
        data: string;
        encoding: "utf8" | "base64";
        mode: "create" | "replace";
        expectedHash?: string;
      }
    | {
        kind: "edit";
        path: string;
        expectedHash: string;
        oldText: string;
        newText: string;
      }
    | {
        kind: "exec";
        executable: string;
        argv: string[];
        cwd: string;
        env?: Environment;
        stdin: { mode: "closed" };
      }
    | {
        kind: "shell";
        shellId: "powershell";
        script: string;
        cwd: string;
        env?: Environment;
      }
  );
export interface ExecuteRequest {
  protocol: { major: 1; minor: 0 };
  requestId: string;
  sessionId: string;
  method: "execute";
  policyRef: PolicyRef;
  operation: Operation;
}
export interface ReadData {
  /** Actual content encoding: UTF-8 requests may return base64 for byte-split or invalid UTF-8 ranges. */
  encoding: "utf8" | "base64";
  content: string;
  eof: boolean;
  hash?: string;
}
export interface WriteData {
  hash?: string;
  bytesWritten?: number;
}
export interface ExecutionResult {
  requestId: string;
  sessionId: string;
  policyHash: string;
  outcome: "success" | "error" | "unknown";
  error?: { code: string; message: string };
  exitCode?: number;
  data?: ReadData | WriteData;
  outputs: ReadonlyArray<{
    stream: "stdout" | "stderr";
    encoding: "base64";
    data: string;
  }>;
  bytesSeen: number;
  truncated: boolean;
}
export interface NativeBackend {
  capabilities():
    | {
        nativeEnforcement: boolean;
        kinds: OperationKind[];
        readModes: string[];
        networkModes: string[];
      }
    | Promise<{
        nativeEnforcement: boolean;
        kinds: OperationKind[];
        readModes: string[];
        networkModes: string[];
      }>;
  prepare(context: {
    sessionId: string;
    policy: PolicySnapshot;
  }): Promise<{ enforced: boolean; policyHash?: string }>;
  execute(context: {
    sessionId: string;
    requestId: string;
    policy: PolicySnapshot;
    operation: Operation;
    signal: AbortSignal;
    onOutput(chunk: {
      stream: "stdout" | "stderr";
      data: string | Uint8Array;
    }): void;
  }): Promise<{
    terminated: boolean;
    exitCode?: number;
    data?: ReadData | WriteData;
    error?: { code: string };
  }>;
  cancel(context: {
    sessionId: string;
    requestId: string;
  }): Promise<{ terminated: boolean }>;
  close(context: { sessionId: string }): Promise<{ cleaned: boolean }>;
}
export class SandboxError extends Error {
  code: string;
  constructor(code: string, message: string);
}
export const PROTOCOL: Readonly<{ major: 1; minor: 0 }>;
export const OPERATION_KINDS: readonly OperationKind[];
export const ERROR_CODES: readonly string[];
export function stableJson(value: unknown): string;
export function deepFreeze<T>(value: T): Readonly<T>;
export function canonicalWindowsPath(path: string): string;
export function isWithin(path: string, root: string): boolean;
export function assertPathAllowed(
  path: string,
  policy: PolicySnapshot,
  write?: boolean,
): string;
export function createPolicy(input: PolicyInput): PolicySnapshot;
export function validateOperation(
  operation: Operation,
  policy: PolicySnapshot,
): Readonly<Operation>;
export function validateEnvironment(env?: Environment): Environment;
export class UnavailableBackend implements NativeBackend {
  capabilities(): {
    nativeEnforcement: boolean;
    kinds: OperationKind[];
    readModes: string[];
    networkModes: string[];
  };
  prepare(): Promise<never>;
  execute(): Promise<never>;
  cancel(): Promise<{ terminated: boolean }>;
  close(): Promise<{ cleaned: boolean }>;
}
export class SandboxBroker {
  constructor(options?: {
    backend?: NativeBackend;
    now?: () => number;
    cleanupTimeoutMs?: number;
  });
  getStatus(): Readonly<{
    state: "READY" | "PREPARING" | "SESSION_ACTIVE" | "CLEANUP" | "BLOCKED";
    sessionId: string | null;
    activeRequestId: string | null;
  }>;
  createSession(
    policy: PolicySnapshot,
  ): Promise<Readonly<{ sessionId: string; policyRef: PolicyRef }>>;
  /** Validation can throw synchronously; native failures resolve to terminal results. */
  execute(request: ExecuteRequest): Promise<ExecutionResult>;
  cancel(
    sessionId: string,
    requestId: string,
  ): Promise<{ accepted: boolean; terminal: boolean }>;
  closeSession(sessionId: string): Promise<{ closed: boolean }>;
}
