import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { benchmarkSucceeded, runBenchmark } from "../src/benchmark.js";
import { loadRuleCatalog } from "../src/rules/catalog.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(here, "..", "..");

test("the public corpus gives every native Beta rule a positive and near-miss with the expected evidence level", async () => {
  const result = await runBenchmark();
  assert.deepEqual(result.catalog, { totalRules: 55, rulesWithPositive: 55, rulesWithNearMiss: 55 });
  assert.equal(result.totals.truePositive, 56);
  assert.equal(result.totals.falsePositive, 0);
  assert.equal(result.totals.falseNegative, 0);
  assert.equal(result.totals.evidenceMismatches, 0);
  assert.equal(result.totals.cweMismatches, 0);
  assert.equal(benchmarkSucceeded(result), true);
  assert.ok(Object.values(result.categories).every((category) => category.falsePositive === 0
    && category.falseNegative === 0 && category.evidenceMismatches === 0 && category.cweMismatches === 0));
  assert.equal(result.cases.filter((item) => item.variant === "positive").length, 16);
  assert.equal(result.cases.filter((item) => item.variant === "near_miss").length, 16);
});

test("the corpus catalog cannot drift from rule ids declared by native detectors", async () => {
  const detectorFiles = [
    "app-config.ts", "artifacts.ts", "baas.ts", "platform.ts", "python-api-auth.ts",
    "node-api-security.ts", "python-api-authorization.ts", "python-api-config.ts", "python-dataflow.ts", "secrets.ts", "typescript-dataflow.ts",
  ];
  const declared = new Set<string>();
  for (const filename of detectorFiles) {
    const source = await readFile(join(repositoryRoot, "src", "detectors", filename), "utf8");
    for (const match of source.matchAll(/(?:ruleId|id):\s*"([a-z0-9-]+\.[a-z0-9.-]+)"/g)) if (match[1]) declared.add(match[1]);
  }
  const catalog = new Set(loadRuleCatalog(join(repositoryRoot, "rules", "catalog.json")).rules
    .filter((item) => item.source === "native").map((item) => item.ruleId));
  assert.deepEqual([...catalog].sort(), [...declared].sort());
});
