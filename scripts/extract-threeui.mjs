import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const [bundlePath, outputRoot] = process.argv.slice(2);

if (!bundlePath || !outputRoot) {
  throw new Error("Usage: node scripts/extract-threeui.mjs <bundle.json> <output-root>");
}

const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));

for (const file of bundle.files ?? []) {
  if (!file.path || typeof file.code !== "string") continue;
  const destination = join(outputRoot, file.path.replace(/^src\//, ""));
  mkdirSync(dirname(destination), { recursive: true });
  writeFileSync(destination, file.code, "utf8");
}

console.log(`Extracted ${(bundle.files ?? []).length} exact source files from ${bundle.id ?? "bundle"}.`);
