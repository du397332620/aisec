import type { ScanOptions, ScanReport, Signal } from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { TOOL_VERSION } from "./constants.js";
import { collectProjectFiles } from "./files.js";
import { buildAssetGraph, inspectProject } from "./inspect.js";
import { resolveSafeRoot, newId, sortSignals } from "./utils.js";
import { runNativeDetectors } from "../detectors/index.js";
import { runArtifactDetector } from "../detectors/artifacts.js";
import { runExternalEngines } from "../engines/index.js";
import { correlateAttackPaths } from "./correlate.js";
import { parseConfig } from "./config.js";
import { buildFindings, decide, summarize } from "./findings.js";
import { compareReports } from "./compare.js";
import { loadReport, saveReport } from "./store.js";
import { validateScanReport } from "./schema-validation.js";

export const DEFAULT_SCAN_OPTIONS: ScanOptions = {
  profile: "predeploy",
  artifacts: [],
  nativeOnly: false,
  includeGitHistory: false,
  maxFiles: 20_000,
  maxFileBytes: 2 * 1024 * 1024,
  timeoutMs: 120_000,
  persist: true,
};

function normalizeOptions(overrides: Partial<ScanOptions>): ScanOptions {
  const options = { ...DEFAULT_SCAN_OPTIONS, ...overrides };
  if (!['predeploy', 'native'].includes(options.profile)) throw new Error(`Unsupported scan profile: ${options.profile}`);
  if (!Array.isArray(options.artifacts) || options.artifacts.some((item) => typeof item !== "string" || !item.trim())) throw new Error("artifacts must contain non-empty file paths");
  for (const [name, value] of Object.entries({ maxFiles: options.maxFiles, maxFileBytes: options.maxFileBytes, timeoutMs: options.timeoutMs })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`);
  }
  return options;
}

function deduplicateSignals(signals: Signal[]): Signal[] {
  const result = new Map<string, Signal>();
  for (const signal of signals) {
    const key = signal.id;
    if (!result.has(key)) result.set(key, signal);
  }
  return sortSignals([...result.values()]);
}

export async function scanProject(
  inputPath: string,
  overrides: Partial<ScanOptions> = {},
  baselineReference?: string,
): Promise<{ report: ScanReport; storedAt?: string }> {
  const startedAt = new Date().toISOString();
  const options = normalizeOptions(overrides);
  const root = await resolveSafeRoot(inputPath);
  const inventory = await collectProjectFiles(root, options);
  const profile = await inspectProject(root, inventory, options.artifacts);
  const assetGraph = buildAssetGraph(profile);
  const context = { root, inventory, profile, assetGraph, options };
  const [native, external, artifacts] = await Promise.all([
    runNativeDetectors(context),
    runExternalEngines(context),
    runArtifactDetector(context),
  ]);
  const coverage = [...native.coverage, ...external.coverage, artifacts.coverage];
  if (inventory.skippedFiles > 0) {
    coverage.push({
      domain: "project-inventory",
      engine: "aisec-native",
      status: ["file_limit", "entry_limit", "directory_depth", "oversized_file", "unreadable_file", "unreadable_directory", "symbolic_link", "path_escape"]
        .some((reason) => inventory.skippedReasons[reason]) ? "partial" : "complete",
      required: true,
      reason: Object.entries(inventory.skippedReasons).map(([reason, count]) => `${reason}: ${count}`).join(", "),
    });
  } else {
    coverage.push({ domain: "project-inventory", engine: "aisec-native", status: "complete", required: true });
  }

  const signals = deduplicateSignals([...native.signals, ...external.signals, ...artifacts.signals]);
  const attackPaths = correlateAttackPaths(signals, assetGraph);
  const config = parseConfig(inventory.files.find((file) => file.relativePath === ".aisec.yml")?.content);
  const findings = buildFindings(signals, attackPaths, config);
  const decisionResult = decide(findings, coverage);
  const report: ScanReport = {
    schemaVersion: SCHEMA_VERSION,
    toolVersion: TOOL_VERSION,
    scanId: newId("scan"),
    startedAt,
    completedAt: new Date().toISOString(),
    target: root,
    profileName: options.profile,
    profile,
    assetGraph,
    coverage,
    signals,
    attackPaths,
    findings,
    decision: decisionResult.decision,
    decisionReasons: decisionResult.reasons,
    summary: summarize(findings, attackPaths),
    disclaimer: "AIsec reports evidence found within executed coverage. no_blockers_found is not a guarantee, certification, or proof that the application is secure.",
  };
  if (baselineReference) report.comparison = compareReports(report, await loadReport(baselineReference));
  validateScanReport(report);
  const storedAt = options.persist ? await saveReport(report) : undefined;
  return { report, storedAt };
}

export async function inspectOnly(inputPath: string, options: Partial<ScanOptions> = {}) {
  const merged = normalizeOptions(options);
  const root = await resolveSafeRoot(inputPath);
  const inventory = await collectProjectFiles(root, merged);
  const profile = await inspectProject(root, inventory, merged.artifacts);
  return { profile, assetGraph: buildAssetGraph(profile), inventory: { skippedFiles: inventory.skippedFiles, skippedReasons: inventory.skippedReasons } };
}
