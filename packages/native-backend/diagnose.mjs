import { NativeSandboxBackend, NATIVE_VERSION } from "./index.mjs";
// Read-only status. No Windows operation, setup, download, or spawn is performed.
if (process.argv.length !== 2) {
  console.error(
    "Usage: node diagnose.mjs (native execution is not yet validated)",
  );
  process.exitCode = 2;
} else {
  console.log(
    JSON.stringify(
      {
        version: NATIVE_VERSION,
        platform: process.platform,
        capabilities: new NativeSandboxBackend().capabilities(),
        nativeTestsRun: false,
      },
      null,
      2,
    ),
  );
}
