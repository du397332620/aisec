import { constants, type Stats } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  readdir,
  realpath,
  rename,
  unlink,
} from "node:fs/promises";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
  sep,
} from "node:path";
import { randomUUID } from "node:crypto";
import type { ScanOptions, ScanReport } from "../schema.js";
import { loadTrustedPolicy } from "./config.js";
import { normalizeScanOptions, scanProject } from "./scan.js";
import { validateScanReport } from "./schema-validation.js";
import { resolveSafeRoot, sha256 } from "./utils.js";

const BASELINE_FILE = "baseline.json";
const LATEST_FILE = "latest.json";
const MAX_GATE_REPORT_BYTES = 64 * 1024 * 1024;

export interface LocalGateOptions {
  stateDirectory: string;
  policyPath: string;
  artifacts?: string[];
  includeGitHistory?: boolean;
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  timeoutMs?: number;
  confirmPolicySuppressions?: boolean;
  rulePackPaths?: string[];
}

export interface LocalGateResult {
  mode: "initialized" | "rescan";
  report: ScanReport;
  baselinePath: string;
  latestPath: string;
  exitCode: 0 | 1 | 2;
}

function pathIsInside(root: string, candidate: string): boolean {
  const result = relative(root, candidate);
  return result === "" || (result !== ".." && !result.startsWith(`..${sep}`) && !isAbsolute(result));
}

function decisionExitCode(decision: ScanReport["decision"]): 0 | 1 | 2 {
  if (decision === "block") return 1;
  if (decision === "incomplete") return 2;
  return 0;
}

function assertPrivateOwnership(entry: Stats, label: string): void {
  if (process.platform === "win32") return;
  const currentUserId = process.getuid?.();
  if (currentUserId !== undefined && entry.uid !== currentUserId) {
    throw new Error(`${label} must be owned by the current user`);
  }
  if ((entry.mode & 0o077) !== 0) {
    throw new Error(`${label} must grant access only to its owner`);
  }
}

async function nearestExistingPath(path: string): Promise<{ existing: string; suffix: string[] }> {
  const suffix: string[] = [];
  let cursor = path;
  while (true) {
    try {
      await lstat(cursor);
      return { existing: cursor, suffix };
    } catch (error) {
      if (!error || typeof error !== "object" || !("code" in error) || error.code !== "ENOENT") throw error;
      const parent = dirname(cursor);
      if (parent === cursor) throw new Error(`Local gate state directory has no existing parent: ${path}`);
      suffix.unshift(basename(cursor));
      cursor = parent;
    }
  }
}

async function resolvePrivateStateDirectory(input: string, targetRoot: string): Promise<string> {
  if (!input.trim()) throw new Error("Local gate state directory must be a non-empty path");
  const requested = resolve(input);
  if (pathIsInside(targetRoot, requested)) {
    throw new Error("Local gate state directory must be operator-owned and located outside the scanned target");
  }

  const nearest = await nearestExistingPath(requested);
  const existingRealPath = await realpath(nearest.existing);
  const projected = resolve(existingRealPath, ...nearest.suffix);
  if (pathIsInside(targetRoot, projected)) {
    throw new Error("Local gate state directory must be operator-owned and located outside the scanned target");
  }

  if (nearest.suffix.length === 0) {
    const existing = await lstat(requested);
    if (existing.isSymbolicLink()) throw new Error("Local gate state directory must not be a symbolic link");
    if (!existing.isDirectory()) throw new Error("Local gate state path must be a directory");
  } else {
    await mkdir(requested, { recursive: true, mode: 0o700 });
  }

  const [info, resolved] = await Promise.all([lstat(requested), realpath(requested)]);
  if (info.isSymbolicLink() || !info.isDirectory()) throw new Error("Local gate state directory must be a real directory");
  if (pathIsInside(targetRoot, resolved)) {
    throw new Error("Local gate state directory must be operator-owned and located outside the scanned target");
  }
  assertPrivateOwnership(info, "Local gate state directory");
  return resolved;
}

async function baselineExists(path: string): Promise<boolean> {
  try {
    await lstat(path);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
}

async function readBaseline(path: string): Promise<{ report: ScanReport; digestSha256: string }> {
  const entry = await lstat(path);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error("Local gate baseline must be a real regular file");
  const handle = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error("Local gate baseline must be a regular file");
    assertPrivateOwnership(info, "Local gate baseline");
    if (info.size > MAX_GATE_REPORT_BYTES) throw new Error("Local gate baseline exceeds 64 MiB");
    const raw = await handle.readFile();
    if (raw.byteLength > MAX_GATE_REPORT_BYTES) throw new Error("Local gate baseline exceeds 64 MiB");
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new Error("Local gate baseline is not valid JSON");
    }
    return { report: validateScanReport(parsed), digestSha256: sha256(raw) };
  } finally {
    await handle.close();
  }
}

async function writeExclusiveReport(path: string, report: ScanReport): Promise<void> {
  const raw = `${JSON.stringify(validateScanReport(report), null, 2)}\n`;
  if (Buffer.byteLength(raw, "utf8") > MAX_GATE_REPORT_BYTES) throw new Error("Local gate baseline exceeds 64 MiB");
  let created = false;
  try {
    const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    created = true;
    try {
      await handle.writeFile(raw, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
  } catch (error) {
    if (created) await unlink(path).catch(() => undefined);
    throw error;
  }
}

async function writeLatestReport(path: string, report: ScanReport): Promise<void> {
  const raw = `${JSON.stringify(validateScanReport(report), null, 2)}\n`;
  if (Buffer.byteLength(raw, "utf8") > MAX_GATE_REPORT_BYTES) throw new Error("Local gate latest report exceeds 64 MiB");
  const temporary = join(dirname(path), `.latest-${randomUUID()}.tmp`);
  try {
    const handle = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600);
    try {
      await handle.writeFile(raw, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

function scanOptions(options: LocalGateOptions): Partial<ScanOptions> {
  return {
    profile: "predeploy",
    nativeOnly: false,
    persist: false,
    policyPath: options.policyPath,
    artifacts: [...(options.artifacts ?? [])],
    includeGitHistory: options.includeGitHistory ?? false,
    ...(options.maxFiles === undefined ? {} : { maxFiles: options.maxFiles }),
    ...(options.maxFileBytes === undefined ? {} : { maxFileBytes: options.maxFileBytes }),
    ...(options.maxTotalBytes === undefined ? {} : { maxTotalBytes: options.maxTotalBytes }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    confirmPolicySuppressions: options.confirmPolicySuppressions ?? false,
    rulePackPaths: [...(options.rulePackPaths ?? [])],
  };
}

function assertLocalGateOptions(options: LocalGateOptions): void {
  if (!options || typeof options !== "object") throw new Error("Local gate options are required");
  if (typeof options.stateDirectory !== "string" || !options.stateDirectory.trim()) {
    throw new Error("Local gate state directory must be a non-empty path");
  }
  if (typeof options.policyPath !== "string" || !options.policyPath.trim()) {
    throw new Error("Local gate policy path must be a non-empty path");
  }
  if (options.artifacts !== undefined && (!Array.isArray(options.artifacts)
    || options.artifacts.some((item) => typeof item !== "string" || !item.trim()))) {
    throw new Error("Local gate artifacts must contain non-empty file paths");
  }
  if (options.rulePackPaths !== undefined && (!Array.isArray(options.rulePackPaths)
    || options.rulePackPaths.some((item) => typeof item !== "string" || !item.trim()))) {
    throw new Error("Local gate rulePackPaths must contain non-empty file paths");
  }
  if (options.includeGitHistory !== undefined && typeof options.includeGitHistory !== "boolean") {
    throw new Error("Local gate includeGitHistory must be a boolean");
  }
  if (options.confirmPolicySuppressions !== undefined && typeof options.confirmPolicySuppressions !== "boolean") {
    throw new Error("Local gate confirmPolicySuppressions must be a boolean");
  }
}

export async function runLocalGate(inputPath: string, options: LocalGateOptions): Promise<LocalGateResult> {
  assertLocalGateOptions(options);
  const effectiveScanOptions = normalizeScanOptions(scanOptions(options));
  const targetRoot = await resolveSafeRoot(inputPath);
  const loadedPolicy = await loadTrustedPolicy(options.policyPath, targetRoot);
  if (!loadedPolicy.policy.routeSecurityBaseline) {
    throw new Error("Local gate requires SecurityPolicy 1.1.0 with routeSecurityBaseline enabled");
  }
  const stateDirectory = await resolvePrivateStateDirectory(options.stateDirectory, targetRoot);
  const baselinePath = join(stateDirectory, BASELINE_FILE);
  const latestPath = join(stateDirectory, LATEST_FILE);
  const hasBaseline = await baselineExists(baselinePath);

  if (!hasBaseline) {
    const entries = await readdir(stateDirectory);
    if (entries.length > 0) {
      throw new Error("Local gate state directory is non-empty but has no recognized baseline; use a new empty private directory");
    }
    const { report } = await scanProject(targetRoot, effectiveScanOptions);
    if (report.policy?.source !== "operator" || report.policy.digestSha256 !== loadedPolicy.digestSha256) {
      throw new Error("Local gate policy changed while the baseline scan was running; retry with a stable policy file");
    }
    if (!report.policy.routeSecurityBaseline || decisionExitCode(report.decision) === 0) {
      throw new Error("Local gate bootstrap did not produce the required fail-closed route-security baseline evaluation");
    }
    if ((await readdir(stateDirectory)).length > 0) {
      throw new Error("Local gate state directory changed while the baseline scan was running; use a new empty private directory");
    }
    await writeExclusiveReport(baselinePath, report);
    await writeLatestReport(latestPath, report);
    return {
      mode: "initialized",
      report,
      baselinePath,
      latestPath,
      exitCode: decisionExitCode(report.decision),
    };
  }

  const baseline = await readBaseline(baselinePath);
  if (baseline.report.target !== targetRoot) {
    throw new Error(`Local gate state belongs to a different scan target: ${baseline.report.target}`);
  }
  if (baseline.report.policy?.source !== "operator" || !baseline.report.policy.routeSecurityBaseline) {
    throw new Error("Local gate baseline was not created with an operator route-security baseline policy");
  }
  const { report } = await scanProject(targetRoot, effectiveScanOptions, baselinePath);
  if (report.policy?.digestSha256 !== loadedPolicy.digestSha256) {
    throw new Error("Local gate policy changed while the rescan was running; retry with a stable policy file");
  }
  if (report.comparison?.baselineScanId !== baseline.report.scanId) {
    throw new Error("Local gate rescan did not compare against the pinned baseline");
  }
  const baselineAfterScan = await readBaseline(baselinePath);
  if (baselineAfterScan.digestSha256 !== baseline.digestSha256) {
    throw new Error("Local gate baseline changed while the rescan was running; no result was accepted");
  }
  await writeLatestReport(latestPath, report);
  return {
    mode: "rescan",
    report,
    baselinePath,
    latestPath,
    exitCode: decisionExitCode(report.decision),
  };
}
