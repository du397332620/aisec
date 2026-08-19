import { cp, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { RuleCatalogEntry } from "./schema.js";
import { scanProject } from "./core/scan.js";
import { validateRuleCatalog } from "./core/schema-validation.js";

type CorpusVariant = "positive" | "near_miss";

interface ArtifactFixture {
  filename: string;
  entries: Record<string, string>;
}

interface CorpusCase {
  id: string;
  category: string;
  framework: string;
  variant: CorpusVariant;
  path?: string;
  artifact?: ArtifactFixture;
  materializeSyntheticValues?: boolean;
  expectedRuleIds: string[];
  nearMissRuleIds?: string[];
}

interface Manifest {
  schemaVersion: 3;
  description: string;
  cases: CorpusCase[];
}

interface Score {
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  evidenceMismatches: number;
  cweMismatches: number;
  precision: number;
  recall: number;
  f1: number;
}

interface MutableScore {
  truePositive: number;
  falsePositive: number;
  falseNegative: number;
  evidenceMismatches: number;
  cweMismatches: number;
}

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(here, "..", "..");

function syntheticValues(): Record<string, string> {
  return {
    __AISEC_STRIPE_LIVE_KEY__: ["sk", "live", "aisecfixturecorpus1234567890"].join("_"),
    __AISEC_OPENAI_KEY__: ["sk", "proj", "aisecfixtureopenai1234567890abcdef"].join("-"),
    __AISEC_AWS_ACCESS_KEY__: ["AKIA", "AISECFIXTURE1234"].join(""),
    __AISEC_GITHUB_TOKEN__: ["ghp", "aisecfixture12345678"].join("_"),
    __AISEC_PRIVATE_KEY_HEADER__: ["-----BEGIN", "PRIVATE KEY-----"].join(" "),
    __AISEC_INTERPOLATION_FALLBACK__: ["svc-A1b2C3d4E5f6", "G7h8I9j0K1l2"].join("."),
  };
}

function replaceSyntheticValues(value: string): string {
  let result = value;
  for (const [placeholder, replacement] of Object.entries(syntheticValues())) result = result.replaceAll(placeholder, replacement);
  return result;
}

async function materializeDirectory(source: string, temporary: string): Promise<string> {
  const target = join(temporary, "fixture");
  await cp(source, target, { recursive: true });
  const visit = async (directory: string): Promise<void> => {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else if (entry.isFile()) {
        const content = await readFile(path, "utf8");
        const materialized = replaceSyntheticValues(content);
        if (materialized !== content) await writeFile(path, materialized);
      }
    }
  };
  await visit(target);
  return target;
}

function crc32(value: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of value) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

async function writeStoredZip(path: string, entries: Record<string, string>): Promise<void> {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const [name, text] of Object.entries(entries)) {
    if (!name || name.startsWith("/") || name.split("/").includes("..") || name.includes("\\") || name.includes("\0")) throw new Error(`Unsafe benchmark archive entry: ${name}`);
    const filename = Buffer.from(name, "utf8");
    const data = Buffer.from(text, "utf8");
    const checksum = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0x0800, 6);
    local.writeUInt16LE(0, 8);
    local.writeUInt16LE(0, 10);
    local.writeUInt16LE(0x21, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(filename.length, 26);
    local.writeUInt16LE(0, 28);
    locals.push(local, filename, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(0, 10);
    central.writeUInt16LE(0, 12);
    central.writeUInt16LE(0x21, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(filename.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, filename);
    offset += local.length + filename.length + data.length;
  }
  const centralDirectory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(Object.keys(entries).length, 8);
  end.writeUInt16LE(Object.keys(entries).length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  await writeFile(path, Buffer.concat([...locals, centralDirectory, end]));
}

function validateManifest(value: unknown, nativeRules: RuleCatalogEntry[]): Manifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Benchmark manifest must be an object");
  const manifest = value as Partial<Manifest>;
  if (manifest.schemaVersion !== 3 || typeof manifest.description !== "string" || !manifest.description.trim()) throw new Error("Benchmark manifest must use schemaVersion 3 and include a description");
  if (!Array.isArray(manifest.cases) || manifest.cases.length === 0) throw new Error("Benchmark manifest requires cases");
  if (nativeRules.length === 0) throw new Error("Public rule catalog contains no native rules");
  const catalog = new Map(nativeRules.map((rule) => [rule.ruleId, rule]));
  const caseIds = new Set<string>();
  const positive = new Set<string>();
  const nearMiss = new Set<string>();
  for (const item of manifest.cases) {
    if (!item || typeof item.id !== "string" || !item.id || caseIds.has(item.id)) throw new Error(`Invalid or duplicate benchmark case: ${String(item?.id)}`);
    caseIds.add(item.id);
    if (!item.category || !item.framework || !["positive", "near_miss"].includes(item.variant) || !Array.isArray(item.expectedRuleIds)) throw new Error(`Invalid benchmark case metadata: ${item.id}`);
    if (Boolean(item.path) === Boolean(item.artifact)) throw new Error(`Benchmark case must define exactly one path or artifact: ${item.id}`);
    if (item.variant === "positive" && item.expectedRuleIds.length === 0) throw new Error(`Positive benchmark case has no expected rules: ${item.id}`);
    if (item.variant === "near_miss" && (item.expectedRuleIds.length > 0 || !Array.isArray(item.nearMissRuleIds) || item.nearMissRuleIds.length === 0)) throw new Error(`Near-miss benchmark case is incomplete: ${item.id}`);
    for (const ruleId of item.expectedRuleIds) {
      const rule = catalog.get(ruleId);
      if (!rule || rule.category !== item.category) throw new Error(`Unknown or miscategorized expected rule ${ruleId} in ${item.id}`);
      positive.add(ruleId);
    }
    for (const ruleId of item.nearMissRuleIds ?? []) {
      const rule = catalog.get(ruleId);
      if (!rule || rule.category !== item.category) throw new Error(`Unknown or miscategorized near-miss rule ${ruleId} in ${item.id}`);
      nearMiss.add(ruleId);
    }
  }
  const missingPositive = [...catalog.keys()].filter((ruleId) => !positive.has(ruleId));
  const missingNearMiss = [...catalog.keys()].filter((ruleId) => !nearMiss.has(ruleId));
  if (missingPositive.length > 0 || missingNearMiss.length > 0) throw new Error(`Benchmark catalog gaps: positive=[${missingPositive.join(", ")}], near-miss=[${missingNearMiss.join(", ")}]`);
  return manifest as Manifest;
}

async function prepareCase(root: string, item: CorpusCase): Promise<{ projectPath: string; artifacts: string[]; cleanup: () => Promise<void> }> {
  if (item.path && !item.materializeSyntheticValues) return { projectPath: join(root, item.path), artifacts: [], cleanup: async () => undefined };
  const temporary = await mkdtemp(join(tmpdir(), "aisec-corpus-"));
  try {
    if (item.path) {
      const projectPath = await materializeDirectory(join(root, item.path), temporary);
      return { projectPath, artifacts: [], cleanup: () => rm(temporary, { recursive: true, force: true }) };
    }
    const projectPath = join(temporary, "project");
    await mkdir(projectPath);
    const artifact = item.artifact!;
    if (!/^[A-Za-z0-9._-]+\.(?:apk|ipa)$/.test(artifact.filename) || Object.keys(artifact.entries).length === 0) throw new Error(`Invalid artifact benchmark case: ${item.id}`);
    const artifactPath = join(temporary, artifact.filename);
    const entries = Object.fromEntries(Object.entries(artifact.entries).map(([name, content]) => [name, item.materializeSyntheticValues ? replaceSyntheticValues(content) : content]));
    await writeStoredZip(artifactPath, entries);
    return { projectPath, artifacts: [artifactPath], cleanup: () => rm(temporary, { recursive: true, force: true }) };
  } catch (error) {
    await rm(temporary, { recursive: true, force: true });
    throw error;
  }
}

function finishScore(value: MutableScore): Score {
  const precision = value.truePositive + value.falsePositive === 0 ? 1 : value.truePositive / (value.truePositive + value.falsePositive);
  const recall = value.truePositive + value.falseNegative === 0 ? 1 : value.truePositive / (value.truePositive + value.falseNegative);
  const f1 = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
  return { ...value, precision, recall, f1 };
}

export async function runBenchmark(root = repositoryRoot) {
  const publicCatalog = validateRuleCatalog(JSON.parse(await readFile(join(root, "rules", "catalog.json"), "utf8")) as unknown);
  const nativeRules = publicCatalog.rules.filter((rule) => rule.source === "native");
  const manifest = validateManifest(JSON.parse(await readFile(join(root, "benchmark", "manifest.json"), "utf8")) as unknown, nativeRules);
  const catalog = new Map(nativeRules.map((item) => [item.ruleId, item]));
  const totals: MutableScore = { truePositive: 0, falsePositive: 0, falseNegative: 0, evidenceMismatches: 0, cweMismatches: 0 };
  const categoryScores = new Map<string, MutableScore>();
  for (const category of new Set(nativeRules.map((item) => item.category))) categoryScores.set(category, { truePositive: 0, falsePositive: 0, falseNegative: 0, evidenceMismatches: 0, cweMismatches: 0 });
  const cases = [];
  for (const item of manifest.cases) {
    const prepared = await prepareCase(root, item);
    try {
      const { report } = await scanProject(prepared.projectPath, { profile: "native", nativeOnly: true, artifacts: prepared.artifacts, persist: false });
      const actualSignals = report.signals.filter((signal) => signal.engine === "aisec-native"
        || signal.engine === "aisec-typescript" || signal.engine === "aisec-python"
        || signal.engine === "aisec-artifact");
      const actual = new Set(actualSignals.map((signal) => signal.ruleId));
      const expected = new Set(item.expectedRuleIds);
      const truePositive = [...actual].filter((ruleId) => expected.has(ruleId));
      const falsePositive = [...actual].filter((ruleId) => !expected.has(ruleId));
      const falseNegative = [...expected].filter((ruleId) => !actual.has(ruleId));
      const evidenceMismatches = [...expected].flatMap((ruleId) => {
        const expectedLevel = catalog.get(ruleId)!.defaultEvidenceLevel;
        const actualLevels = [...new Set(actualSignals.filter((signal) => signal.ruleId === ruleId).map((signal) => signal.evidenceLevel))];
        return actualLevels.some((level) => level !== expectedLevel) ? [{ ruleId, expected: expectedLevel, actual: actualLevels }] : [];
      });
      const cweMismatches = [...expected].flatMap((ruleId) => {
        const expectedCwe = [...catalog.get(ruleId)!.cwe].sort();
        const actualCwe = actualSignals.filter((signal) => signal.ruleId === ruleId).map((signal) => [...(signal.cwe ?? [])].sort());
        return actualCwe.some((value) => JSON.stringify(value) !== JSON.stringify(expectedCwe))
          ? [{ ruleId, expected: expectedCwe, actual: actualCwe }]
          : [];
      });
      totals.truePositive += truePositive.length;
      totals.falsePositive += falsePositive.length;
      totals.falseNegative += falseNegative.length;
      totals.evidenceMismatches += evidenceMismatches.length;
      totals.cweMismatches += cweMismatches.length;
      for (const ruleId of truePositive) categoryScores.get(catalog.get(ruleId)!.category)!.truePositive += 1;
      for (const ruleId of falsePositive) categoryScores.get(catalog.get(ruleId)?.category ?? item.category)!.falsePositive += 1;
      for (const ruleId of falseNegative) categoryScores.get(catalog.get(ruleId)!.category)!.falseNegative += 1;
      for (const mismatch of evidenceMismatches) categoryScores.get(catalog.get(mismatch.ruleId)!.category)!.evidenceMismatches += 1;
      for (const mismatch of cweMismatches) categoryScores.get(catalog.get(mismatch.ruleId)!.category)!.cweMismatches += 1;
      cases.push({
        id: item.id,
        category: item.category,
        framework: item.framework,
        variant: item.variant,
        expected: [...expected],
        actual: [...actual].sort(),
        truePositive,
        falsePositive,
        falseNegative,
        evidenceMismatches,
        cweMismatches,
      });
    } finally {
      await prepared.cleanup();
    }
  }
  return {
    schemaVersion: 3 as const,
    generatedAt: new Date().toISOString(),
    disclaimer: manifest.description,
    catalog: {
      totalRules: nativeRules.length,
      rulesWithPositive: nativeRules.length,
      rulesWithNearMiss: nativeRules.length,
    },
    totals: finishScore(totals),
    categories: Object.fromEntries([...categoryScores].map(([category, score]) => [category, finishScore(score)])),
    cases,
  };
}

export function benchmarkSucceeded(result: Awaited<ReturnType<typeof runBenchmark>>): boolean {
  return result.totals.falsePositive === 0 && result.totals.falseNegative === 0
    && result.totals.evidenceMismatches === 0 && result.totals.cweMismatches === 0;
}

async function isDirectExecution(): Promise<boolean> {
  if (!process.argv[1]) return false;
  try {
    return await realpath(process.argv[1]) === await realpath(fileURLToPath(import.meta.url));
  } catch {
    return resolve(process.argv[1]) === fileURLToPath(import.meta.url);
  }
}

if (await isDirectExecution()) {
  const result = await runBenchmark();
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (!benchmarkSucceeded(result)) process.exitCode = 1;
}
