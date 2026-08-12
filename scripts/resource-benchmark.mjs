import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { performance } from "node:perf_hooks";

const repositoryRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

async function runWorker() {
  const project = process.argv[3];
  const options = JSON.parse(process.argv[4] ?? "{}");
  assert.equal(typeof project, "string");
  const { scanProject } = await import("../dist/src/core/scan.js");
  const started = performance.now();
  const { report } = await scanProject(project, { profile: "native", nativeOnly: true, persist: false, ...options });
  const elapsedMs = Math.round((performance.now() - started) * 10) / 10;
  const inventory = report.coverage.find((item) => item.domain === "project-inventory");
  const maxRssBytes = process.resourceUsage().maxRSS * 1024;
  process.stdout.write(`${JSON.stringify({
    elapsedMs,
    maxRssBytes,
    scannedFiles: report.profile.fileCount,
    skippedFiles: report.profile.skippedFiles,
    signals: report.signals.length,
    decision: report.decision,
    inventoryStatus: inventory?.status,
    inventoryReason: inventory?.reason,
  })}\n`);
}

function validateBudget(value) {
  assert.equal(value?.schemaVersion, 1, "resource budget must use schemaVersion 1");
  assert.equal(typeof value.description, "string");
  assert.ok(Array.isArray(value.cases) && value.cases.length > 0);
  for (const item of value.cases) {
    assert.match(item.id, /^[a-z0-9-]+$/);
    for (const key of ["fileCount", "fileBytes", "maxElapsedMs", "maxRssBytes"]) assert.ok(Number.isSafeInteger(item[key]) && item[key] > 0, `${item.id}.${key} must be a positive safe integer`);
    assert.ok(["no_blockers_found", "incomplete"].includes(item.expectedDecision));
    if (item.maxFiles !== undefined) assert.ok(Number.isSafeInteger(item.maxFiles) && item.maxFiles > 0);
  }
  return value;
}

function sourceFile(index, bytes) {
  const prefix = `export const fixture${String(index).padStart(6, "0")} = "`;
  const suffix = `";\n`;
  return `${prefix}${"x".repeat(Math.max(0, bytes - prefix.length - suffix.length))}${suffix}`;
}

async function materializeProject(root, item) {
  await writeFile(join(root, "package.json"), `${JSON.stringify({ name: `aisec-${item.id}`, private: true })}\n`);
  const batchSize = 100;
  for (let offset = 0; offset < item.fileCount; offset += batchSize) {
    const directory = join(root, "src", String(Math.floor(offset / batchSize)).padStart(3, "0"));
    await mkdir(directory, { recursive: true });
    const count = Math.min(batchSize, item.fileCount - offset);
    await Promise.all(Array.from({ length: count }, (_, localIndex) => {
      const index = offset + localIndex;
      return writeFile(join(directory, `${String(index).padStart(6, "0")}.ts`), sourceFile(index, item.fileBytes));
    }));
  }
}

function scanInChild(project, item) {
  const options = item.maxFiles ? { maxFiles: item.maxFiles } : {};
  const timeout = item.maxElapsedMs + 10_000;
  const result = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--worker", project, JSON.stringify(options)], {
    cwd: repositoryRoot,
    encoding: "utf8",
    timeout,
    maxBuffer: 1024 * 1024,
    env: { ...process.env, NO_UPDATE_NOTIFIER: "1" },
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`resource benchmark worker exited ${result.status}: ${(result.stderr || result.stdout).slice(-4000)}`);
  return JSON.parse(result.stdout);
}

async function runParent() {
  const budget = validateBudget(JSON.parse(await readFile(join(repositoryRoot, "benchmark", "resource-budget.json"), "utf8")));
  const temporary = await mkdtemp(join(tmpdir(), "aisec-resource-benchmark-"));
  const results = [];
  try {
    for (const item of budget.cases) {
      const project = join(temporary, item.id);
      await mkdir(project);
      await materializeProject(project, item);
      const measured = scanInChild(project, item);
      assert.equal(measured.decision, item.expectedDecision, `${item.id} decision drifted`);
      assert.ok(measured.elapsedMs <= item.maxElapsedMs, `${item.id} exceeded ${item.maxElapsedMs} ms: ${measured.elapsedMs} ms`);
      assert.ok(measured.maxRssBytes <= item.maxRssBytes, `${item.id} exceeded ${item.maxRssBytes} RSS bytes: ${measured.maxRssBytes}`);
      if (item.expectedInventoryReason) assert.match(measured.inventoryReason ?? "", new RegExp(item.expectedInventoryReason), `${item.id} did not expose truncation`);
      results.push({
        id: item.id,
        inputFiles: item.fileCount + 1,
        inputBytes: item.fileCount * item.fileBytes,
        limits: { maxFiles: item.maxFiles ?? 20_000, maxElapsedMs: item.maxElapsedMs, maxRssBytes: item.maxRssBytes },
        measured,
      });
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    platform: `${process.platform}/${process.arch}`,
    node: process.version,
    disclaimer: budget.description,
    results,
  }, null, 2)}\n`);
}

if (process.argv[2] === "--worker") await runWorker();
else await runParent();
