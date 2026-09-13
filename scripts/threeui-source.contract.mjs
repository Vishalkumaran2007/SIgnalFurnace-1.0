import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [bundlePath, outputRoot] = process.argv.slice(2);
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
let checked = 0;

for (const file of bundle.files ?? []) {
  if (!file.path || !file.sha256 || typeof file.code !== "string") continue;
  const destination = join(outputRoot, file.path.replace(/^src\//, ""));
  if (!existsSync(destination)) throw new Error(`Missing extracted source: ${destination}`);
  const hash = createHash("sha256").update(readFileSync(destination)).digest("hex");
  if (hash !== file.sha256) throw new Error(`Hash mismatch for ${file.path}`);
  checked += 1;
}

console.log(`Verified ${checked} exact source files from ${bundle.id ?? "bundle"}.`);
