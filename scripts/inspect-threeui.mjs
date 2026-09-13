import { writeFile, readFile, mkdir } from "node:fs/promises";
import { basename, join } from "node:path";

const urls = {
  matrix: "https://threeui.com/source-code/matrix-field.json",
  rectangle: "https://threeui.com/source-code/rectangle-buttons.json",
  dock: "https://threeui.com/source-code/animated-top-dock.json",
};
const out = "/home/ubuntu/sih26106-cyber-forensics/.threeui-source";
await mkdir(out, { recursive: true });
for (const [name, url] of Object.entries(urls)) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${name}: ${response.status}`);
  const text = await response.text();
  await writeFile(join(out, `${name}.json`), text);
  const data = JSON.parse(text);
  console.log(`${name}: ${data.files?.length ?? 0} files`);
  for (const file of data.files ?? []) console.log(`  ${file.path} ${file.sha256}`);
}
