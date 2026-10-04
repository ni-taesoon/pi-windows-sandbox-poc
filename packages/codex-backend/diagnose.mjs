import { readFile } from "node:fs/promises";
import {
  CODEX_PIN,
  CodexReferenceBackend,
  runReferenceExperiment,
  parseExperimentInputs,
} from "./index.mjs";
// By default this command performs no Windows operations, downloads, setup, or spawning.
if (process.argv.length === 2) {
  console.log(
    JSON.stringify(
      {
        pin: CODEX_PIN,
        platform: process.platform,
        capabilities: new CodexReferenceBackend().capabilities(),
        nativeTestsRun: false,
      },
      null,
      2,
    ),
  );
} else if (
  process.argv.length === 5 &&
  process.argv[2] === "--explicit-windows-experiment"
) {
  // Separate operator-owned configuration, never supplied through Pi tool arguments.
  const input = JSON.parse(await readFile(process.argv[3], "utf8"));
  const request = JSON.parse(await readFile(process.argv[4], "utf8"));
  const result = await runReferenceExperiment({
    ...parseExperimentInputs(input, request),
    onOutput: (chunk) => process[chunk.stream].write(chunk.data),
  });
  process.stderr.write("\n" + JSON.stringify(result) + "\n");
  process.exitCode = result.exitCode ?? 1;
} else {
  console.error(
    "Usage: node diagnose.mjs [--explicit-windows-experiment OPERATOR_CONFIG.json POLICY_AND_OPERATION.json]",
  );
  process.exitCode = 2;
}
