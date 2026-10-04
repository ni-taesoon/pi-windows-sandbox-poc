import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { createSandboxAgent } from '../../packages/pi-adapter/index.js';

// Explicit opt-in uses an independently installed pinned SDK; no provider request is made.
test('optional real Pi SDK: in-memory initialization, verified registry, disposal', { skip: !process.env.PI_SDK_ENTRY }, async () => {
  const sdk = await import(pathToFileURL(process.env.PI_SDK_ENTRY).href);
  const modelRuntime = await sdk.ModelRuntime.create({ credentials: { read: async () => undefined, list: async () => [], modify: async () => { throw new Error('Credentials disabled'); }, delete: async () => { throw new Error('Credentials disabled'); } }, modelsPath: null, refreshOnCreate: false, allowModelNetwork: false });
  const model = modelRuntime.getModels()[0];
  assert.ok(model);
  let called = false;
  const agent = await createSandboxAgent({
    sdk, modelRuntime, model,
    broker: { execute() { called = true; throw new Error('Unexpected execution'); }, cancel() { throw new Error('Unexpected cancel'); } },
    binding: { sessionId: '00000000-0000-4000-8000-000000000001', policyRef: { id: 'smoke', revision: 1, hash: 'a'.repeat(64) }, cwd: 'C:\\sandbox-poc' },
  });
  assert.deepEqual(Object.keys(agent).sort(), ['abort', 'dispose', 'prompt', 'subscribe']);
  await agent.dispose();
  assert.equal(called, false);
});
