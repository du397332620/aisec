import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject } from "./core/scan.js";

interface Manifest {
  schemaVersion: 1;
  description: string;
  cases: Array<{ id: string; path: string; expectedRuleIds: string[]; materializeSyntheticStripeKey?: boolean }>;
}

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..", "..");
const manifest = JSON.parse(await readFile(join(root, "benchmark", "manifest.json"), "utf8")) as Manifest;
let truePositive = 0;
let falsePositive = 0;
let falseNegative = 0;
const cases = [];
for (const item of manifest.cases) {
  let casePath = join(root, item.path);
  let temporary: string | undefined;
  try {
    if (item.materializeSyntheticStripeKey) {
      temporary = await mkdtemp(join(tmpdir(), "aisec-benchmark-fixture-"));
      casePath = join(temporary, "fixture");
      await cp(join(root, item.path), casePath, { recursive: true });
      const environmentPath = join(casePath, ".env.example");
      const environment = await readFile(environmentPath, "utf8");
      const syntheticKey = ["sk", "live", "aisecfixtureonly1234567890"].join("_");
      await writeFile(environmentPath, environment.replace("__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__", syntheticKey));
    }
    const { report } = await scanProject(casePath, { nativeOnly: true, persist: false });
    const actual = new Set(report.signals.map((signal) => signal.ruleId));
    const expected = new Set(item.expectedRuleIds);
    const tp = [...actual].filter((id) => expected.has(id));
    const fp = [...actual].filter((id) => !expected.has(id));
    const fn = [...expected].filter((id) => !actual.has(id));
    truePositive += tp.length;
    falsePositive += fp.length;
    falseNegative += fn.length;
    cases.push({ id: item.id, expected: [...expected], actual: [...actual].sort(), truePositive: tp, falsePositive: fp, falseNegative: fn });
  } finally {
    if (temporary) await rm(temporary, { recursive: true, force: true });
  }
}
const precision = truePositive + falsePositive === 0 ? 1 : truePositive / (truePositive + falsePositive);
const recall = truePositive + falseNegative === 0 ? 1 : truePositive / (truePositive + falseNegative);
const f1 = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
const result = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  disclaimer: manifest.description,
  totals: { truePositive, falsePositive, falseNegative, precision, recall, f1 },
  cases,
};
process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
if (falsePositive > 0 || falseNegative > 0) process.exitCode = 1;
