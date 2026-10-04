import type { ToolDefinition, ResourceLoader, ModelRuntime } from '@earendil-works/pi-coding-agent';
import type * as PiSdk from '@earendil-works/pi-coding-agent';
export declare const PI_VERSION: '1.0.2';
export declare const PI_COMMIT: '200387122ca450d6387f033949423114a270b96c';
export interface SandboxBinding {
  sessionId: string;
  policyRef: { id: string; revision: number; hash: string };
  cwd: string;
}
export interface AdapterBroker {
  execute(request: import('../core/index.d.ts').ExecuteRequest): Promise<import('../core/index.d.ts').ExecutionResult>;
  cancel(sessionId: string, requestId: string): unknown;
}
export declare function createSandboxTools(broker: AdapterBroker, binding: SandboxBinding): ToolDefinition[];
export declare function createEmptyResourceLoader(sdk: Pick<typeof PiSdk, 'createExtensionRuntime'>): ResourceLoader;
export interface SandboxAgent {
  prompt(text: string): Promise<void>;
  abort(): Promise<void>;
  subscribe(listener: Parameters<PiSdk.AgentSession['subscribe']>[0]): () => void;
  dispose(): void;
}
export declare function createSandboxAgent(options: {
  sdk: typeof PiSdk; broker: AdapterBroker; binding: SandboxBinding;
  modelRuntime: ModelRuntime; model: NonNullable<Parameters<typeof PiSdk.createAgentSession>[0]>['model'];
}): Promise<SandboxAgent>;
