import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadRuleCatalog, renderRuleCatalog } from "../dist/src/rules/catalog.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const outputPath = join(root, "RULES.md");
const mode = process.argv[2];
assert.ok(mode === "--check" || mode === "--write", "usage: node scripts/rule-catalog.mjs --check|--write");
assert.equal(process.argv.length, 3, "rule catalog script accepts exactly one mode");

const rendered = renderRuleCatalog(loadRuleCatalog(join(root, "rules", "catalog.json")));
if (mode === "--write") {
  await writeFile(outputPath, rendered, "utf8");
  process.stdout.write(`Updated ${outputPath}\n`);
} else {
  const current = await readFile(outputPath, "utf8");
  assert.equal(current, rendered, "RULES.md is stale; run `npm run rules:render`");
  process.stdout.write("Rule catalog schema, references and generated Markdown are current.\n");
}
