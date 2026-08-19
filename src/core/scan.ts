import type { ScanOptions, ScanReport, Signal } from "../schema.js";
import { SCAN_REPORT_SCHEMA_VERSION } from "../schema.js";
import { lstat } from "node:fs/promises";
import { join } from "node:path";
import { TOOL_VERSION } from "./constants.js";
import { collectProjectFiles } from "./files.js";
import { buildAssetGraph, inspectProject } from "./inspect.js";
import { resolveSafeRoot, newId, sortSignals } from "./utils.js";
import { runNativeDetectors } from "../detectors/index.js";
import { runArtifactDetector } from "../detectors/artifacts.js";
import { runExternalEngines } from "../engines/index.js";
import { correlateAttackPaths } from "./correlate.js";
import { createScanPolicyRecord, loadTrustedPolicy } from "./config.js";
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
  maxTotalBytes: 64 * 1024 * 1024,
  timeoutMs: 120_000,
  persist: true,
  confirmPolicySuppressions: false,
};

const HARD_SCAN_LIMITS = {
  artifacts: 10,
  maxFiles: 100_000,
  maxFileBytes: 16 * 1024 * 1024,
  maxTotalBytes: 512 * 1024 * 1024,
  timeoutMs: 30 * 60_000,
} as const;

function normalizeOptions(overrides: Partial<ScanOptions>): ScanOptions {
  const options = { ...DEFAULT_SCAN_OPTIONS, ...overrides };
  if (!['predeploy', 'native'].includes(options.profile)) throw new Error(`Unsupported scan profile: ${options.profile}`);
  if (options.profile === "native") options.nativeOnly = true;
  if (!Array.isArray(options.artifacts) || options.artifacts.some((item) => typeof item !== "string" || !item.trim())) throw new Error("artifacts must contain non-empty file paths");
  if (options.artifacts.length > HARD_SCAN_LIMITS.artifacts) throw new Error(`artifacts cannot exceed ${HARD_SCAN_LIMITS.artifacts}`);
  for (const [name, value] of Object.entries({ maxFiles: options.maxFiles, maxFileBytes: options.maxFileBytes, maxTotalBytes: options.maxTotalBytes, timeoutMs: options.timeoutMs })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`);
    const hardLimit = HARD_SCAN_LIMITS[name as keyof Omit<typeof HARD_SCAN_LIMITS, "artifacts">];
    if (value > hardLimit) throw new Error(`${name} cannot exceed ${hardLimit}`);
  }
  if (options.policyPath !== undefined && (typeof options.policyPath !== "string" || !options.policyPath.trim())) throw new Error("policyPath must be a non-empty file path");
  if (typeof options.confirmPolicySuppressions !== "boolean") throw new Error("confirmPolicySuppressions must be a boolean");
  return options;
}

async function targetConfiguration(root: string): Promise<"absent" | "ignored"> {
  try {
    await lstat(join(root, ".aisec.yml"));
    return "ignored";
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return "absent";
    return "ignored";
  }
}

function assertBaselinePolicy(current: ScanReport["policy"], baseline: ScanReport): void {
  if (baseline.policy?.source === "operator") {
    if (current?.source !== "operator") {
      throw new Error(`Baseline ${baseline.scanId} used operator policy ${baseline.policy.policyId}; rescan requires the same explicit --policy file`);
    }
    if (current.digestSha256 !== baseline.policy.digestSha256) {
      throw new Error(`Baseline ${baseline.scanId} used a different operator policy digest; create a new baseline for deliberate policy changes`);
    }
    return;
  }
  if (current?.source === "operator") {
    throw new Error(`Baseline ${baseline.scanId} did not use the same operator policy; create a new baseline before policy-governed verification`);
  }
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
  const loadedPolicy = options.policyPath ? await loadTrustedPolicy(options.policyPath, root) : undefined;
  if (loadedPolicy && (options.profile !== "predeploy" || options.nativeOnly)) {
    throw new Error("Operator security policies require profile predeploy with all external engines enabled; remove --profile native and --native-only");
  }
  if (loadedPolicy && loadedPolicy.policy.suppressions.length > 0 && !options.confirmPolicySuppressions) {
    throw new Error(`Operator security policy contains ${loadedPolicy.policy.suppressions.length} suppression(s); pass --confirm-policy-suppressions only after reviewing them`);
  }
  if (!loadedPolicy && options.confirmPolicySuppressions) throw new Error("--confirm-policy-suppressions requires --policy");
  const policy = createScanPolicyRecord(loadedPolicy, options, await targetConfiguration(root));
  const baseline = baselineReference ? await loadReport(baselineReference) : undefined;
  if (baseline) assertBaselinePolicy(policy, baseline);
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
      status: ["file_limit", "entry_limit", "total_bytes_limit", "directory_depth", "oversized_file", "binary_file", "non_regular_file", "unreadable_file", "unreadable_directory", "symbolic_link", "path_escape"]
        .some((reason) => inventory.skippedReasons[reason]) ? "partial" : "complete",
      required: true,
      reason: Object.entries(inventory.skippedReasons).map(([reason, count]) => `${reason}: ${count}`).join(", "),
    });
  } else {
    coverage.push({ domain: "project-inventory", engine: "aisec-native", status: "complete", required: true });
  }

  const signals = deduplicateSignals([...native.signals, ...external.signals, ...artifacts.signals]);
  const attackPaths = correlateAttackPaths(signals, assetGraph);
  const findings = buildFindings(signals, attackPaths, loadedPolicy?.policy.suppressions ?? []);
  const decisionResult = decide(findings, coverage, signals, policy);
  const report: ScanReport = {
    schemaVersion: SCAN_REPORT_SCHEMA_VERSION,
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
    policy,
    disclaimer: "AIsec reports evidence found within executed coverage. no_blockers_found is not a guarantee, certification, or proof that the application is secure.",
  };
  if (baseline) report.comparison = compareReports(report, baseline);
  validateScanReport(report);
  const storedAt = options.persist ? await saveReport(report) : undefined;
  return { report, storedAt };
}

export async function inspectOnly(inputPath: string, options: Partial<ScanOptions> = {}) {
  if (options.policyPath !== undefined || options.confirmPolicySuppressions) throw new Error("inspectOnly does not evaluate release policies; use scanProject");
  const merged = normalizeOptions(options);
  const root = await resolveSafeRoot(inputPath);
  const inventory = await collectProjectFiles(root, merged);
  const profile = await inspectProject(root, inventory, merged.artifacts);
  return { profile, assetGraph: buildAssetGraph(profile), inventory: { skippedFiles: inventory.skippedFiles, skippedReasons: inventory.skippedReasons } };
}
