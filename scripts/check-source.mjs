import { readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
async function walk(dir) {
  const files = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (['node_modules', '.git', '.local', 'artifacts', 'coverage'].includes(entry.name)) continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) files.push(...await walk(path));
    else if (entry.isFile() && /\.(mjs|js|cjs)$/.test(entry.name)) files.push(path);
  }
  return files;
}
const files = await walk(root);
let failures = 0;
for (const file of files) {
  const result = spawnSync(process.execPath, ['--check', file], { encoding: 'utf8' });
  if (result.status !== 0) {
    failures++;
    process.stderr.write(`${file}\n${result.stderr || result.error?.message || 'syntax check failed'}\n`);
  }
}
console.log(`Syntax checked ${files.length} JavaScript modules; failures=${failures}`);
process.exitCode = failures ? 1 : 0;
