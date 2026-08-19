import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdtemp, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultManifestPath = join(repositoryRoot, "scripts", "calibration", "baas-targets.json");
const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
const REPOSITORY_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\.git$/;
const RULE_ID_PATTERN = /^(?:firebase|supabase)\.[a-z0-9]+(?:[.-][a-z0-9]+)+$/;
const DECISIONS = new Set(["block", "incomplete", "review", "no_blockers_found"]);
const COVERAGE_STATUSES = new Set(["complete", "partial", "failed", "not_run"]);
const SENSITIVE_ENVIRONMENT_NAME = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

function fail(message) {
  throw new Error(message);
}

function usage() {
  return `Usage: node scripts/baas-calibration.mjs [options]

Static-only calibration against clean Git repositories at exact commits.

Options:
  --confirm-download       Explicitly allow HTTPS fetches for targets without --local
  --target <id>            Run one target (repeatable; defaults to every target)
  --local <id>=<path>      Use a clean local Git repository at the expected commit
  --manifest <path>        Use another strictly validated calibration manifest
  --help                   Show this help

The script never installs dependencies, runs project code, deploys rules, or contacts target applications.`;
}

function parseArguments(argv) {
  const options = { confirmDownload: false, help: false, manifestPath: defaultManifestPath, manifestWasProvided: false, targets: [], local: new Map() };
  const valueAfter = (index, option) => {
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) fail(`${option} requires a value`);
    return value;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help") options.help = true;
    else if (argument === "--confirm-download") options.confirmDownload = true;
    else if (argument === "--target") {
      options.targets.push(valueAfter(index, argument));
      index += 1;
    } else if (argument === "--manifest") {
      if (options.manifestWasProvided) fail("--manifest may only be provided once");
      options.manifestPath = resolve(valueAfter(index, argument));
      options.manifestWasProvided = true;
      index += 1;
    } else if (argument === "--local") {
      const assignment = valueAfter(index, argument);
      const separator = assignment.indexOf("=");
      if (separator <= 0 || separator === assignment.length - 1) fail("--local must use <id>=<path>");
      const id = assignment.slice(0, separator);
      if (options.local.has(id)) fail(`--local was provided more than once for ${id}`);
      options.local.set(id, resolve(assignment.slice(separator + 1)));
      index += 1;
    } else fail(`unknown option: ${argument}`);
  }
  if (new Set(options.targets).size !== options.targets.length) fail("--target values must be unique");
  return options;
}

function plainObject(value, label, allowedKeys, requiredKeys = allowedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) if (!allowedKeys.includes(key)) fail(`${label} contains unknown field ${key}`);
  for (const key of requiredKeys) if (!(key in value)) fail(`${label} is missing ${key}`);
  return value;
}

function nonEmptyString(value, label, pattern) {
  if (typeof value !== "string" || value.length === 0 || value.length > 500 || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be a non-empty string without control characters`);
  }
  if (pattern && !pattern.test(value)) fail(`${label} has an invalid value: ${value}`);
  return value;
}

function positiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) fail(`${label} must be a positive safe integer`);
  return value;
}

function safeRelativePath(value, label, allowDot = false) {
  const path = nonEmptyString(value, label);
  if ((path === "." && allowDot)) return path;
  if (path === "." || path.startsWith("/") || path.startsWith("-") || path.endsWith("/") || path.includes("\\") || path.includes("//")) fail(`${label} must be a normalized relative POSIX path`);
  if (path.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) fail(`${label} must not contain dot or empty segments`);
  return path;
}

function uniqueStrings(value, label, parser) {
  if (!Array.isArray(value) || value.length === 0) fail(`${label} must be a non-empty array`);
  const result = value.map((item, index) => parser(item, `${label}[${index}]`));
  if (new Set(result).size !== result.length) fail(`${label} must not contain duplicates`);
  return result;
}

function validateSignals(value, label) {
  if (!Array.isArray(value) || value.length === 0) fail(`${label} must be a non-empty array`);
  const signals = value.map((item, index) => {
    const entryLabel = `${label}[${index}]`;
    const entry = plainObject(item, entryLabel, ["ruleId", "count", "paths"]);
    if (!Array.isArray(entry.paths)) fail(`${entryLabel}.paths must be an array`);
    const paths = entry.paths.map((pathEntry, pathIndex) => {
      const pathLabel = `${entryLabel}.paths[${pathIndex}]`;
      const parsed = plainObject(pathEntry, pathLabel, ["path", "count"]);
      return { path: safeRelativePath(parsed.path, `${pathLabel}.path`), count: positiveInteger(parsed.count, `${pathLabel}.count`) };
    }).sort((left, right) => left.path.localeCompare(right.path));
    if (paths.length === 0) fail(`${entryLabel}.paths must be non-empty`);
    if (new Set(paths.map((path) => path.path)).size !== paths.length) fail(`${entryLabel}.paths must not contain duplicates`);
    const count = positiveInteger(entry.count, `${entryLabel}.count`);
    if (paths.reduce((sum, path) => sum + path.count, 0) !== count) fail(`${entryLabel}.count must equal the sum of path counts`);
    return { ruleId: nonEmptyString(entry.ruleId, `${entryLabel}.ruleId`, RULE_ID_PATTERN), count, paths };
  }).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  if (new Set(signals.map((signal) => signal.ruleId)).size !== signals.length) fail(`${label} contains duplicate rule IDs`);
  return signals;
}

function validateManifest(value) {
  const manifest = plainObject(value, "manifest", ["schemaVersion", "description", "targets"]);
  if (manifest.schemaVersion !== 1) fail("manifest.schemaVersion must equal 1");
  const description = nonEmptyString(manifest.description, "manifest.description");
  if (!Array.isArray(manifest.targets) || manifest.targets.length === 0 || manifest.targets.length > 10) fail("manifest.targets must contain between 1 and 10 targets");
  const targets = manifest.targets.map((item, index) => {
    const label = `manifest.targets[${index}]`;
    const target = plainObject(item, label, ["id", "repository", "commit", "scanPath", "sparsePaths", "expected"]);
    const expectedValue = plainObject(target.expected, `${label}.expected`, ["baas", "coverageStatus", "decision", "signals"]);
    const coverageStatus = nonEmptyString(expectedValue.coverageStatus, `${label}.expected.coverageStatus`);
    if (!COVERAGE_STATUSES.has(coverageStatus)) fail(`${label}.expected.coverageStatus is unsupported: ${coverageStatus}`);
    const decision = nonEmptyString(expectedValue.decision, `${label}.expected.decision`);
    if (!DECISIONS.has(decision)) fail(`${label}.expected.decision is unsupported: ${decision}`);
    return {
      id: nonEmptyString(target.id, `${label}.id`, /^[a-z0-9]+(?:-[a-z0-9]+)*$/),
      repository: nonEmptyString(target.repository, `${label}.repository`, REPOSITORY_PATTERN),
      commit: nonEmptyString(target.commit, `${label}.commit`, /^[0-9a-f]{40}$/),
      scanPath: safeRelativePath(target.scanPath, `${label}.scanPath`, true),
      sparsePaths: uniqueStrings(target.sparsePaths, `${label}.sparsePaths`, (path, pathLabel) => safeRelativePath(path, pathLabel, true)),
      expected: {
        baas: uniqueStrings(expectedValue.baas, `${label}.expected.baas`, (name, nameLabel) => nonEmptyString(name, nameLabel, /^(?:Firebase|Supabase)$/)).sort(),
        coverageStatus,
        decision,
        signals: validateSignals(expectedValue.signals, `${label}.expected.signals`),
      },
    };
  });
  if (new Set(targets.map((target) => target.id)).size !== targets.length) fail("manifest.targets contains duplicate IDs");
  return { schemaVersion: 1, description, targets };
}

async function loadManifest(path) {
  const details = await stat(path).catch(() => undefined);
  if (!details?.isFile()) fail("manifest path must be a regular file");
  if (details.size > 1024 * 1024) fail("manifest cannot exceed 1 MiB");
  try {
    return validateManifest(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if (error instanceof SyntaxError) fail(`manifest is not valid JSON: ${error.message}`);
    throw error;
  }
}

function gitEnvironment() {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_") && name !== "SSH_ASKPASS" && !SENSITIVE_ENVIRONMENT_NAME.test(name)));
  return { ...environment, GIT_CONFIG_GLOBAL: nullDevice, GIT_CONFIG_NOSYSTEM: "1", GIT_LFS_SKIP_SMUDGE: "1", GIT_TERMINAL_PROMPT: "0" };
}

function runGit(args, label, timeout = 30_000) {
  const safetyConfiguration = [
    "-c", `core.hooksPath=${nullDevice}`,
    "-c", `core.attributesFile=${nullDevice}`,
    "-c", "core.fsmonitor=false",
    "-c", "credential.helper=",
    "-c", "protocol.file.allow=never",
    "-c", "submodule.recurse=false",
    "-c", "filter.lfs.smudge=",
    "-c", "filter.lfs.process=",
    "-c", "filter.lfs.required=false",
  ];
  const result = spawnSync("git", [...safetyConfiguration, ...args], { cwd: repositoryRoot, encoding: "utf8", env: gitEnvironment(), maxBuffer: 1024 * 1024, timeout, windowsHide: true });
  if (result.error) fail(`${label} failed: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = `${result.stderr ?? ""}\n${result.stdout ?? ""}`.trim().slice(-2_000);
    fail(`${label} exited ${result.status}${detail ? `: ${detail}` : ""}`);
  }
  return (result.stdout ?? "").trim();
}

async function pathExists(path) {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return false;
    throw error;
  }
}

async function verifySource(target, root) {
  const details = await stat(root).catch(() => undefined);
  if (!details?.isDirectory()) fail(`${target.id}: local source must be a directory`);
  const canonicalRoot = await realpath(root);
  const topLevel = await realpath(runGit(["-C", canonicalRoot, "rev-parse", "--show-toplevel"], `${target.id}: resolve Git root`));
  if (topLevel !== canonicalRoot) fail(`${target.id}: --local must point to the Git worktree root`);
  const commit = runGit(["-C", canonicalRoot, "rev-parse", "HEAD"], `${target.id}: resolve Git commit`);
  if (commit !== target.commit) fail(`${target.id}: expected commit ${target.commit}, got ${commit}`);
  const status = runGit(["-C", canonicalRoot, "status", "--porcelain=v1", "--untracked-files=all"], `${target.id}: inspect Git worktree`);
  if (status) fail(`${target.id}: Git worktree is not clean; calibration requires the exact committed tree`);
  return canonicalRoot;
}

async function resolveScanRoot(target, repository) {
  const candidate = target.scanPath === "." ? repository : join(repository, ...target.scanPath.split("/"));
  const details = await stat(candidate).catch(() => undefined);
  if (!details?.isDirectory()) fail(`${target.id}: scanPath is not a directory: ${target.scanPath}`);
  const canonical = await realpath(candidate);
  const fromRepository = relative(repository, canonical);
  if (fromRepository.startsWith("..") || isAbsolute(fromRepository)) fail(`${target.id}: scanPath resolves outside the repository`);
  for (const root of new Set([repository, canonical])) {
    for (const configuration of [".aisec.yml", ".aisec.yaml"]) {
      if (await pathExists(join(root, configuration))) fail(`${target.id}: target-controlled ${configuration} is not allowed in calibration`);
    }
  }
  return canonical;
}

function downloadSource(target, destination) {
  process.stderr.write(`[baas-calibration] ${target.id}: fetching fixed commit ${target.commit.slice(0, 12)} over HTTPS\n`);
  runGit(["init", "--quiet", destination], `${target.id}: initialize temporary repository`);
  runGit(["-C", destination, "remote", "add", "origin", target.repository], `${target.id}: configure fixed repository`);
  runGit(["-C", destination, "sparse-checkout", "init", "--cone"], `${target.id}: initialize sparse checkout`);
  runGit(["-C", destination, "sparse-checkout", "set", ...target.sparsePaths], `${target.id}: configure sparse checkout`);
  runGit(["-C", destination, "fetch", "--quiet", "--depth=1", "--filter=blob:none", "--no-tags", "origin", target.commit], `${target.id}: fetch fixed commit`, 180_000);
  runGit(["-C", destination, "switch", "--quiet", "--detach", "FETCH_HEAD"], `${target.id}: check out fixed commit`, 60_000);
}

function summarizeSignals(signals) {
  const grouped = new Map();
  for (const signal of signals.filter((item) => RULE_ID_PATTERN.test(item.ruleId))) {
    const location = signal.locations[0]?.path;
    if (typeof location !== "string") fail(`${signal.ruleId}: calibration signal has no source path`);
    const current = grouped.get(signal.ruleId) ?? new Map();
    current.set(location, (current.get(location) ?? 0) + 1);
    grouped.set(signal.ruleId, current);
  }
  return [...grouped].map(([ruleId, pathCounts]) => ({
    ruleId,
    count: [...pathCounts.values()].reduce((sum, count) => sum + count, 0),
    paths: [...pathCounts].map(([path, count]) => ({ path, count })).sort((left, right) => left.path.localeCompare(right.path)),
  })).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

function assertExpected(target, report, source) {
  const baas = [...report.profile.baas].sort();
  if (JSON.stringify(baas) !== JSON.stringify(target.expected.baas)) fail(`${target.id}: BaaS profile drifted; expected ${JSON.stringify(target.expected.baas)}, got ${JSON.stringify(baas)}`);
  const signals = summarizeSignals(report.signals);
  if (JSON.stringify(signals) !== JSON.stringify(target.expected.signals)) fail(`${target.id}: BaaS findings drifted; expected ${JSON.stringify(target.expected.signals)}, got ${JSON.stringify(signals)}`);
  const coverage = report.coverage.filter((record) => record.domain === "baas-authorization");
  if (coverage.length !== 1) fail(`${target.id}: expected one BaaS coverage record, got ${coverage.length}`);
  if (coverage[0].status !== target.expected.coverageStatus) fail(`${target.id}: BaaS coverage drifted; expected ${target.expected.coverageStatus}, got ${coverage[0].status}`);
  if (report.decision !== target.expected.decision) fail(`${target.id}: decision drifted; expected ${target.expected.decision}, got ${report.decision}`);
  return { id: target.id, repository: target.repository, commit: target.commit, scanPath: target.scanPath, source, baas, coverageStatus: coverage[0].status, signals, decision: report.decision };
}

async function run() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  const manifest = await loadManifest(options.manifestPath);
  const available = new Map(manifest.targets.map((target) => [target.id, target]));
  for (const id of [...options.targets, ...options.local.keys()]) if (!available.has(id)) fail(`unknown calibration target: ${id}`);
  const selected = options.targets.length > 0 ? options.targets.map((id) => available.get(id)) : manifest.targets;
  for (const id of options.local.keys()) if (!selected.some((target) => target.id === id)) fail(`--local ${id} is unused because that target was not selected`);
  const downloads = selected.filter((target) => !options.local.has(target.id));
  if (downloads.length > 0 && !options.confirmDownload) fail(`network download is disabled; pass --confirm-download to fetch fixed commits for: ${downloads.map((target) => target.id).join(", ")}`);

  runGit(["--version"], "locate Git");
  const scanModulePath = join(repositoryRoot, "dist", "src", "core", "scan.js");
  if (!(await pathExists(scanModulePath))) fail("built scanner is missing; run npm run build first");
  const { scanProject } = await import(pathToFileURL(scanModulePath).href);
  const temporary = downloads.length > 0 ? await mkdtemp(join(tmpdir(), "aisec-baas-calibration-")) : undefined;
  const results = [];
  try {
    for (const target of selected) {
      const local = options.local.get(target.id);
      const source = local ? "verified-local-repository" : "fixed-commit-download";
      const targetRoot = local ?? join(temporary, target.id);
      if (!local) downloadSource(target, targetRoot);
      const verifiedRoot = await verifySource(target, targetRoot);
      const scanRoot = await resolveScanRoot(target, verifiedRoot);
      process.stderr.write(`[baas-calibration] ${target.id}: scanning committed policy source without installing or running it\n`);
      const { report } = await scanProject(scanRoot, { profile: "native", nativeOnly: true, persist: false });
      results.push(assertExpected(target, report, source));
      await verifySource(target, verifiedRoot);
      process.stderr.write(`[baas-calibration] ${target.id}: expected behavior confirmed\n`);
    }
  } finally {
    if (temporary) await rm(temporary, { recursive: true, force: true });
  }
  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    disclaimer: manifest.description,
    safety: { targetDependenciesInstalled: false, targetCodeExecuted: false, targetBackendRequestsSent: false, rulesDeployed: false, rawReportsPersisted: false },
    results,
  }, null, 2)}\n`);
}

run().catch((error) => {
  process.stderr.write(`baas-calibration: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
