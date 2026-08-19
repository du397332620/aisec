import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { access, mkdtemp, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultManifestPath = join(repositoryRoot, "scripts", "calibration", "node-api-targets.json");
const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
const DECISIONS = new Set(["block", "incomplete", "review", "no_blockers_found"]);
const COVERAGE_STATUSES = new Set(["complete", "partial", "failed", "not_run"]);
const ROUTE_PATTERN = /^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|ALL) \/\S*$/;
const RULE_ID_PATTERN = /^[a-z][a-z0-9]*(?:[.-][a-z0-9]+)+$/;
const NODE_RULE_PATTERN = /^(?:express|nestjs)\.(?:auth|authorization)\./;
const MOBILE_RULE_PATTERN = /^(?:mobile|android|ios|react-native|flutter)\./;
const REPOSITORY_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\.git$/;
const SENSITIVE_ENVIRONMENT_NAME = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

function fail(message) {
  throw new Error(message);
}

function usage() {
  return `Usage: node scripts/node-api-calibration.mjs [options]

Static-only calibration against clean Git repositories at exact commits.

Options:
  --confirm-download       Explicitly allow HTTPS fetches for targets without --local
  --target <id>            Run one target (repeatable; defaults to every target)
  --local <id>=<path>      Use a clean local Git repository at the expected commit
  --manifest <path>        Use another strictly validated calibration manifest
  --help                   Show this help

The script never installs dependencies, builds, runs, or contacts target applications.
Downloaded repositories are temporary and are deleted after the scan.`;
}

function parseArguments(argv) {
  const options = {
    confirmDownload: false,
    help: false,
    manifestPath: defaultManifestPath,
    manifestWasProvided: false,
    targets: [],
    local: new Map(),
  };
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
      const id = valueAfter(index, argument);
      options.targets.push(id);
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
      const path = assignment.slice(separator + 1);
      if (options.local.has(id)) fail(`--local was provided more than once for ${id}`);
      options.local.set(id, resolve(path));
      index += 1;
    } else fail(`unknown option: ${argument}`);
  }
  if (new Set(options.targets).size !== options.targets.length) fail("--target values must be unique");
  return options;
}

function plainObject(value, label, allowedKeys, requiredKeys = allowedKeys) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object`);
  for (const key of Object.keys(value)) {
    if (!allowedKeys.includes(key)) fail(`${label} contains unknown field ${key}`);
  }
  for (const key of requiredKeys) {
    if (!(key in value)) fail(`${label} is missing ${key}`);
  }
  return value;
}

function nonEmptyString(value, label, pattern) {
  if (typeof value !== "string" || value.length === 0 || value.length > 500 || /[\u0000-\u001f\u007f]/.test(value)) {
    fail(`${label} must be a non-empty string without control characters`);
  }
  if (pattern && !pattern.test(value)) fail(`${label} has an invalid value: ${value}`);
  return value;
}

function positiveInteger(value, label, allowZero = false) {
  if (!Number.isSafeInteger(value) || value < (allowZero ? 0 : 1)) fail(`${label} must be ${allowZero ? "a non-negative" : "a positive"} safe integer`);
  return value;
}

function uniqueStrings(value, label, pattern) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const result = value.map((item, index) => nonEmptyString(item, `${label}[${index}]`, pattern));
  if (new Set(result).size !== result.length) fail(`${label} must not contain duplicates`);
  return result;
}

function validateCoverage(value, label) {
  if (!Array.isArray(value) || value.length === 0) fail(`${label} must be a non-empty array`);
  const records = value.map((item, index) => {
    const entryLabel = `${label}[${index}]`;
    const entry = plainObject(item, entryLabel, ["domain", "status"]);
    const domain = nonEmptyString(entry.domain, `${entryLabel}.domain`, RULE_ID_PATTERN);
    const status = nonEmptyString(entry.status, `${entryLabel}.status`);
    if (!COVERAGE_STATUSES.has(status)) fail(`${entryLabel}.status is unsupported: ${status}`);
    return { domain, status };
  });
  if (new Set(records.map((item) => item.domain)).size !== records.length) fail(`${label} contains duplicate domains`);
  return records;
}

function validateNodeFindings(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const findings = value.map((item, index) => {
    const entryLabel = `${label}[${index}]`;
    const entry = plainObject(item, entryLabel, ["ruleId", "count", "routes"]);
    const ruleId = nonEmptyString(entry.ruleId, `${entryLabel}.ruleId`, RULE_ID_PATTERN);
    if (!NODE_RULE_PATTERN.test(ruleId)) fail(`${entryLabel}.ruleId must be an Express or NestJS interface-security rule`);
    const count = positiveInteger(entry.count, `${entryLabel}.count`);
    const routes = uniqueStrings(entry.routes, `${entryLabel}.routes`, ROUTE_PATTERN);
    if (routes.length !== count) fail(`${entryLabel}.count must equal its unique route count`);
    return { ruleId, count, routes: routes.sort() };
  }).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  if (new Set(findings.map((item) => item.ruleId)).size !== findings.length) fail(`${label} contains duplicate rule IDs`);
  return findings;
}

function validateSignalCounts(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const counts = value.map((item, index) => {
    const entryLabel = `${label}[${index}]`;
    const entry = plainObject(item, entryLabel, ["ruleId", "count"]);
    return {
      ruleId: nonEmptyString(entry.ruleId, `${entryLabel}.ruleId`, RULE_ID_PATTERN),
      count: positiveInteger(entry.count, `${entryLabel}.count`),
    };
  }).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  if (new Set(counts.map((item) => item.ruleId)).size !== counts.length) fail(`${label} contains duplicate rule IDs`);
  if (counts.some((item) => NODE_RULE_PATTERN.test(item.ruleId))) fail(`${label} must use nodeFindings for interface-security rules`);
  return counts;
}

function validateManifest(value) {
  const manifest = plainObject(value, "manifest", ["schemaVersion", "description", "targets"]);
  if (manifest.schemaVersion !== 1) fail("manifest.schemaVersion must equal 1");
  const description = nonEmptyString(manifest.description, "manifest.description");
  if (!Array.isArray(manifest.targets) || manifest.targets.length === 0 || manifest.targets.length > 10) {
    fail("manifest.targets must contain between 1 and 10 targets");
  }
  const targets = manifest.targets.map((item, index) => {
    const label = `manifest.targets[${index}]`;
    const target = plainObject(item, label, ["id", "repository", "commit", "expected"]);
    const id = nonEmptyString(target.id, `${label}.id`, /^[a-z0-9]+(?:-[a-z0-9]+)*$/);
    const repository = nonEmptyString(target.repository, `${label}.repository`, REPOSITORY_PATTERN);
    const commit = nonEmptyString(target.commit, `${label}.commit`, /^[0-9a-f]{40}$/);
    const expectedValue = plainObject(target.expected, `${label}.expected`, [
      "routeCount",
      "requiredRoutes",
      "decision",
      "coverage",
      "nodeFindings",
      "requiredSignalCounts",
    ]);
    const decision = nonEmptyString(expectedValue.decision, `${label}.expected.decision`);
    if (!DECISIONS.has(decision)) fail(`${label}.expected.decision is unsupported: ${decision}`);
    return {
      id,
      repository,
      commit,
      expected: {
        routeCount: positiveInteger(expectedValue.routeCount, `${label}.expected.routeCount`, true),
        requiredRoutes: uniqueStrings(expectedValue.requiredRoutes, `${label}.expected.requiredRoutes`, ROUTE_PATTERN).sort(),
        decision,
        coverage: validateCoverage(expectedValue.coverage, `${label}.expected.coverage`).sort((left, right) => left.domain.localeCompare(right.domain)),
        nodeFindings: validateNodeFindings(expectedValue.nodeFindings, `${label}.expected.nodeFindings`),
        requiredSignalCounts: validateSignalCounts(expectedValue.requiredSignalCounts, `${label}.expected.requiredSignalCounts`),
      },
    };
  });
  if (new Set(targets.map((item) => item.id)).size !== targets.length) fail("manifest.targets contains duplicate IDs");
  if (new Set(targets.map((item) => item.repository)).size !== targets.length) fail("manifest.targets contains duplicate repositories");
  return { schemaVersion: 1, description, targets };
}

async function loadManifest(path) {
  let source;
  try {
    const details = await stat(path);
    if (!details.isFile()) fail("manifest path must be a regular file");
    if (details.size > 1024 * 1024) fail("manifest cannot exceed 1 MiB");
    source = await readFile(path, "utf8");
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("manifest ")) throw error;
    fail(`cannot read manifest: ${error instanceof Error ? error.message : String(error)}`);
  }
  try {
    return validateManifest(JSON.parse(source));
  } catch (error) {
    if (error instanceof SyntaxError) fail(`manifest is not valid JSON: ${error.message}`);
    throw error;
  }
}

function gitEnvironment() {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_") && name !== "SSH_ASKPASS" && !SENSITIVE_ENVIRONMENT_NAME.test(name)));
  return {
    ...environment,
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
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
  const result = spawnSync("git", [...safetyConfiguration, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: gitEnvironment(),
    maxBuffer: 1024 * 1024,
    timeout,
    windowsHide: true,
  });
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
  const topLevelOutput = runGit(["-C", canonicalRoot, "rev-parse", "--show-toplevel"], `${target.id}: resolve Git root`);
  const topLevel = await realpath(topLevelOutput);
  if (topLevel !== canonicalRoot) fail(`${target.id}: --local must point to the Git worktree root`);
  const commit = runGit(["-C", canonicalRoot, "rev-parse", "HEAD"], `${target.id}: resolve Git commit`);
  if (commit !== target.commit) fail(`${target.id}: expected commit ${target.commit}, got ${commit}`);
  const status = runGit(["-C", canonicalRoot, "status", "--porcelain=v1", "--untracked-files=all"], `${target.id}: inspect Git worktree`);
  if (status) fail(`${target.id}: Git worktree is not clean; calibration requires the exact committed tree`);
  for (const configuration of [".aisec.yml", ".aisec.yaml"]) {
    if (await pathExists(join(canonicalRoot, configuration))) fail(`${target.id}: target-controlled ${configuration} is not allowed in calibration`);
  }
  return canonicalRoot;
}

function downloadSource(target, destination) {
  process.stderr.write(`[calibration] ${target.id}: fetching fixed commit ${target.commit.slice(0, 12)} over HTTPS\n`);
  runGit(["init", "--quiet", destination], `${target.id}: initialize temporary repository`);
  runGit(["-C", destination, "remote", "add", "origin", target.repository], `${target.id}: configure fixed repository`);
  runGit([
    "-C", destination, "fetch", "--quiet", "--depth=1", "--no-tags", "origin", target.commit,
  ], `${target.id}: fetch fixed commit`, 180_000);
  runGit(["-C", destination, "checkout", "--quiet", "--detach", "FETCH_HEAD"], `${target.id}: check out fixed commit`, 60_000);
}

function summarizeNodeFindings(signals) {
  const grouped = new Map();
  for (const signal of signals.filter((item) => NODE_RULE_PATTERN.test(item.ruleId))) {
    const current = grouped.get(signal.ruleId) ?? { ruleId: signal.ruleId, count: 0, routes: new Set() };
    current.count += 1;
    if (typeof signal.metadata?.route === "string") current.routes.add(signal.metadata.route);
    grouped.set(signal.ruleId, current);
  }
  return [...grouped.values()].map((item) => ({
    ruleId: item.ruleId,
    count: item.count,
    routes: [...item.routes].sort(),
  })).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

function assertExpected(target, report, source) {
  const expected = target.expected;
  const routes = [...report.profile.routes].sort();
  if (routes.length !== expected.routeCount) fail(`${target.id}: route count drifted; expected ${expected.routeCount}, got ${routes.length}`);
  for (const route of expected.requiredRoutes) {
    if (!routes.includes(route)) fail(`${target.id}: required route is missing: ${route}`);
  }

  const nodeFindings = summarizeNodeFindings(report.signals);
  if (JSON.stringify(nodeFindings) !== JSON.stringify(expected.nodeFindings)) {
    fail(`${target.id}: Node interface findings drifted; expected ${JSON.stringify(expected.nodeFindings)}, got ${JSON.stringify(nodeFindings)}`);
  }

  const requiredSignalCounts = expected.requiredSignalCounts.map((item) => {
    const count = report.signals.filter((signal) => signal.ruleId === item.ruleId).length;
    if (count !== item.count) fail(`${target.id}: ${item.ruleId} count drifted; expected ${item.count}, got ${count}`);
    return { ruleId: item.ruleId, count };
  });

  const coverage = expected.coverage.map((item) => {
    const matches = report.coverage.filter((record) => record.domain === item.domain);
    if (matches.length !== 1) fail(`${target.id}: expected exactly one ${item.domain} coverage record, got ${matches.length}`);
    const status = matches[0].status;
    if (status !== item.status) fail(`${target.id}: ${item.domain} coverage drifted; expected ${item.status}, got ${status}`);
    return { domain: item.domain, status };
  });

  if (expected.coverage.some((item) => item.domain === "mobile-source-config" && item.status === "not_run")) {
    const unexpectedMobile = report.signals.filter((signal) => MOBILE_RULE_PATTERN.test(signal.ruleId)).map((signal) => signal.ruleId);
    if (unexpectedMobile.length > 0) fail(`${target.id}: server-only calibration emitted mobile findings: ${[...new Set(unexpectedMobile)].sort().join(", ")}`);
  }
  if (report.decision !== expected.decision) fail(`${target.id}: decision drifted; expected ${expected.decision}, got ${report.decision}`);

  return {
    id: target.id,
    repository: target.repository,
    commit: target.commit,
    source,
    routeCount: routes.length,
    requiredRoutes: expected.requiredRoutes,
    nodeFindings,
    requiredSignalCounts,
    coverage,
    decision: report.decision,
    summary: report.summary,
  };
}

async function run() {
  const options = parseArguments(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const manifest = await loadManifest(options.manifestPath);
  const available = new Map(manifest.targets.map((target) => [target.id, target]));
  for (const id of [...options.targets, ...options.local.keys()]) {
    if (!available.has(id)) fail(`unknown calibration target: ${id}`);
  }
  const selected = options.targets.length > 0 ? options.targets.map((id) => available.get(id)) : manifest.targets;
  for (const id of options.local.keys()) {
    if (!selected.some((target) => target.id === id)) fail(`--local ${id} is unused because that target was not selected`);
  }
  const downloads = selected.filter((target) => !options.local.has(target.id));
  if (downloads.length > 0 && !options.confirmDownload) {
    fail(`network download is disabled; pass --confirm-download to fetch fixed commits for: ${downloads.map((target) => target.id).join(", ")}`);
  }

  runGit(["--version"], "locate Git");
  const scanModulePath = join(repositoryRoot, "dist", "src", "core", "scan.js");
  if (!(await pathExists(scanModulePath))) fail("built scanner is missing; run npm run build first");
  const { scanProject } = await import(pathToFileURL(scanModulePath).href);
  const temporary = downloads.length > 0 ? await mkdtemp(join(tmpdir(), "aisec-node-api-calibration-")) : undefined;
  const results = [];
  try {
    for (const target of selected) {
      const local = options.local.get(target.id);
      const source = local ? "verified-local-repository" : "fixed-commit-download";
      const targetRoot = local ?? join(temporary, target.id);
      if (!local) downloadSource(target, targetRoot);
      const verifiedRoot = await verifySource(target, targetRoot);
      process.stderr.write(`[calibration] ${target.id}: scanning committed source without installing or running it\n`);
      const { report } = await scanProject(verifiedRoot, { profile: "native", nativeOnly: true, persist: false });
      results.push(assertExpected(target, report, source));
      await verifySource(target, verifiedRoot);
      process.stderr.write(`[calibration] ${target.id}: expected behavior confirmed\n`);
    }
  } finally {
    if (temporary) await rm(temporary, { recursive: true, force: true });
  }

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    disclaimer: manifest.description,
    safety: {
      targetDependenciesInstalled: false,
      targetCodeExecuted: false,
      targetHttpRequestsSent: false,
      rawReportsPersisted: false,
    },
    results,
  }, null, 2)}\n`);
}

run().catch((error) => {
  process.stderr.write(`node-api-calibration: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
