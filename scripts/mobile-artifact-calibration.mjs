import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { createReadStream } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readFile, realpath, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const defaultManifestPath = join(repositoryRoot, "scripts", "calibration", "mobile-artifact-targets.json");
const ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const RULE_ID_PATTERN = /^artifact\.[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const FILENAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.(?:apk|ipa)$/;
const PROJECT_PATTERN = /^https:\/\/github\.com\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})\/[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$/;
const SENSITIVE_ENVIRONMENT_NAME = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;
const MAX_ARTIFACT_BYTES = 128 * 1024 * 1024;
const MAX_DOWNLOAD_REDIRECTS = 5;
const FINAL_DOWNLOAD_HOSTS = new Set(["github.com", "raw.githubusercontent.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]);

function fail(message) {
  throw new Error(message);
}

function childEnvironment(overrides = {}) {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
    !SENSITIVE_ENVIRONMENT_NAME.test(name) || name === "GH_TOKEN" || name === "GITHUB_TOKEN"));
  delete environment.NODE_OPTIONS;
  delete environment.NODE_TLS_REJECT_UNAUTHORIZED;
  return { ...environment, ...overrides };
}

function reexecWithEnvironmentProxy() {
  const proxyConfigured = ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"].some((name) => process.env[name]);
  if (!proxyConfigured || !process.argv.slice(2).includes("--confirm-download") || process.execArgv.includes("--use-env-proxy")) return false;
  if (!process.allowedNodeEnvironmentFlags.has("--use-env-proxy")) return false;
  const result = spawnSync(process.execPath, ["--use-env-proxy", fileURLToPath(import.meta.url), ...process.argv.slice(2)], {
    cwd: repositoryRoot,
    stdio: "inherit",
    env: childEnvironment(),
    timeout: 10 * 60_000,
    windowsHide: true,
  });
  if (result.error) fail(`proxy-enabled calibration process failed: ${result.error.message}`);
  if (result.signal) fail(`proxy-enabled calibration process ended with ${result.signal}`);
  process.exitCode = result.status ?? 1;
  return true;
}

function usage() {
  return `Usage: node scripts/mobile-artifact-calibration.mjs [options]

Static-only calibration against fixed open-source APK/IPA assets.

Options:
  --confirm-download       Explicitly allow HTTPS downloads for targets without --local
  --target <id>            Run one target (repeatable; defaults to every target)
  --local <id>=<path>      Use a local artifact that matches the pinned size and SHA-256
  --manifest <path>        Use another strictly validated calibration manifest
  --help                   Show this help

The script never installs, launches, signs, builds, decompiles, or contacts target apps.
Downloaded artifacts are temporary and are deleted after bounded static scanning.`;
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
  if (!Number.isSafeInteger(value) || value < 1) fail(`${label} must be a positive safe integer`);
  return value;
}

function validateHttpsUrl(value, label) {
  const source = nonEmptyString(value, label);
  let url;
  try {
    url = new URL(source);
  } catch {
    fail(`${label} must be a valid HTTPS URL`);
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.search) fail(`${label} must be a credential-free HTTPS URL without query or fragment`);
  return url;
}

function validateSourceUrl(value, label, filename) {
  const url = validateHttpsUrl(value, label);
  const release = url.hostname === "github.com" && /^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/releases\/download\/[^/]+\/[^/]+$/.test(url.pathname);
  const raw = url.hostname === "raw.githubusercontent.com" && /^\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/[0-9a-f]{40}\/.+/.test(url.pathname);
  if (!release && !raw) fail(`${label} must be a fixed GitHub release asset or raw 40-character commit URL`);
  if (!url.pathname.endsWith(`/${filename}`)) fail(`${label} must end with the declared filename`);
  return url.toString();
}

function validateExpectedFindings(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  const findings = value.map((item, index) => {
    const entryLabel = `${label}[${index}]`;
    const entry = plainObject(item, entryLabel, ["ruleId", "count"]);
    return {
      ruleId: nonEmptyString(entry.ruleId, `${entryLabel}.ruleId`, RULE_ID_PATTERN),
      count: positiveInteger(entry.count, `${entryLabel}.count`),
    };
  }).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  if (new Set(findings.map((item) => item.ruleId)).size !== findings.length) fail(`${label} contains duplicate rule IDs`);
  return findings;
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
    const target = plainObject(item, label, [
      "id", "platform", "classification", "project", "license", "licenseUrl", "revision",
      "filename", "sourceUrl", "byteSize", "sha256", "expected",
    ]);
    const id = nonEmptyString(target.id, `${label}.id`, ID_PATTERN);
    const platform = nonEmptyString(target.platform, `${label}.platform`);
    if (!["android", "ios"].includes(platform)) fail(`${label}.platform must be android or ios`);
    const classification = nonEmptyString(target.classification, `${label}.classification`);
    if (!["positive", "near-miss"].includes(classification)) fail(`${label}.classification must be positive or near-miss`);
    const project = nonEmptyString(target.project, `${label}.project`, PROJECT_PATTERN);
    const license = nonEmptyString(target.license, `${label}.license`, /^[A-Za-z0-9][A-Za-z0-9.+-]{0,49}$/);
    const revision = nonEmptyString(target.revision, `${label}.revision`, /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/);
    const licenseUrl = validateHttpsUrl(target.licenseUrl, `${label}.licenseUrl`).toString();
    if (!licenseUrl.startsWith(`${project}/blob/${revision}/`)) fail(`${label}.licenseUrl must pin the declared revision in the GitHub project`);
    const filename = nonEmptyString(target.filename, `${label}.filename`, FILENAME_PATTERN);
    const extension = filename.slice(filename.lastIndexOf(".") + 1).toLowerCase();
    if ((platform === "android" && extension !== "apk") || (platform === "ios" && extension !== "ipa")) fail(`${label}.filename does not match its platform`);
    const sourceUrl = validateSourceUrl(target.sourceUrl, `${label}.sourceUrl`, filename);
    const projectParts = new URL(project).pathname.split("/").filter(Boolean);
    const source = new URL(sourceUrl);
    const sourceParts = source.pathname.split("/").filter(Boolean);
    if (sourceParts[0] !== projectParts[0] || sourceParts[1] !== projectParts[1]) fail(`${label}.sourceUrl must use the declared GitHub project`);
    const sourceRevision = source.hostname === "github.com" ? decodeURIComponent(sourceParts[4] ?? "") : sourceParts[2];
    if (sourceRevision !== revision) fail(`${label}.sourceUrl must use the declared revision`);
    const byteSize = positiveInteger(target.byteSize, `${label}.byteSize`);
    if (byteSize > MAX_ARTIFACT_BYTES) fail(`${label}.byteSize cannot exceed ${MAX_ARTIFACT_BYTES}`);
    const sha256 = nonEmptyString(target.sha256, `${label}.sha256`, SHA256_PATTERN);
    const expected = plainObject(target.expected, `${label}.expected`, ["coverageStatus", "artifactFindings"]);
    if (expected.coverageStatus !== "complete") fail(`${label}.expected.coverageStatus must equal complete`);
    const artifactFindings = validateExpectedFindings(expected.artifactFindings, `${label}.expected.artifactFindings`);
    if (classification === "positive" && artifactFindings.length === 0) fail(`${label} positive target must expect at least one artifact finding`);
    if (classification === "near-miss" && artifactFindings.length !== 0) fail(`${label} near-miss target must expect no artifact findings`);
    return { id, platform, classification, project, license, licenseUrl, revision, filename, sourceUrl, byteSize, sha256, expected: { coverageStatus: "complete", artifactFindings } };
  });
  if (new Set(targets.map((item) => item.id)).size !== targets.length) fail("manifest.targets contains duplicate IDs");
  if (new Set(targets.map((item) => item.sourceUrl)).size !== targets.length) fail("manifest.targets contains duplicate source URLs");
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

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function verifyArtifact(target, path) {
  const details = await lstat(path).catch(() => undefined);
  if (!details?.isFile()) fail(`${target.id}: local artifact must be a regular file, not a link or directory`);
  if (details.size !== target.byteSize) fail(`${target.id}: byte size drifted; expected ${target.byteSize}, got ${details.size}`);
  const digest = await sha256(path);
  if (digest !== target.sha256) fail(`${target.id}: SHA-256 drifted; expected ${target.sha256}, got ${digest}`);
  return realpath(path);
}

async function writeAll(handle, value) {
  let offset = 0;
  while (offset < value.length) {
    const { bytesWritten } = await handle.write(value, offset, value.length - offset);
    if (bytesWritten <= 0) fail("download write made no progress");
    offset += bytesWritten;
  }
}

async function downloadReleaseWithGithubCli(target, destination) {
  const url = new URL(target.sourceUrl);
  const match = url.pathname.match(/^\/([^/]+)\/([^/]+)\/releases\/download\/([^/]+)\/([^/]+)$/);
  if (url.hostname !== "github.com" || !match) return false;
  const [, owner, repository, encodedTag, encodedFilename] = match;
  const tag = decodeURIComponent(encodedTag);
  const filename = decodeURIComponent(encodedFilename);
  if (filename !== target.filename) fail(`${target.id}: release URL filename drifted`);
  const result = spawnSync("gh", [
    "release", "download", tag,
    "--repo", `${owner}/${repository}`,
    "--pattern", filename,
    "--output", "-",
  ], {
    cwd: repositoryRoot,
    env: childEnvironment({ GH_HOST: "github.com", GH_PROMPT_DISABLED: "1" }),
    maxBuffer: target.byteSize + 64 * 1024,
    timeout: 180_000,
    windowsHide: true,
  });
  if (result.status === 0 && Buffer.isBuffer(result.stdout)) {
    if (result.stdout.length !== target.byteSize) {
      fail(`${target.id}: GitHub CLI byte size drifted; expected ${target.byteSize}, got ${result.stdout.length}`);
    }
    await mkdir(dirname(destination), { recursive: true });
    const handle = await open(destination, "wx", 0o600);
    try {
      await writeAll(handle, result.stdout);
    } finally {
      await handle.close();
    }
    return true;
  }
  if (result.error?.code === "ENOBUFS") fail(`${target.id}: GitHub CLI download exceeded its pinned byte size`);
  process.stderr.write(`[calibration] ${target.id}: GitHub CLI download unavailable; using bounded HTTPS fallback\n`);
  return false;
}

async function fetchFromApprovedGithubHosts(target) {
  let current = new URL(target.sourceUrl);
  for (let redirects = 0; redirects <= MAX_DOWNLOAD_REDIRECTS; redirects += 1) {
    if (current.protocol !== "https:" || !FINAL_DOWNLOAD_HOSTS.has(current.hostname)) {
      fail(`${target.id}: download redirected to an unapproved host`);
    }
    const response = await fetch(current, {
      redirect: "manual",
      signal: AbortSignal.timeout(180_000),
      headers: { "user-agent": "aisec-mobile-artifact-calibration/1" },
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    if (redirects === MAX_DOWNLOAD_REDIRECTS) fail(`${target.id}: download exceeded ${MAX_DOWNLOAD_REDIRECTS} redirects`);
    const location = response.headers.get("location");
    if (!location) fail(`${target.id}: download redirect omitted its location`);
    await response.body?.cancel();
    current = new URL(location, current);
  }
  fail(`${target.id}: download redirect handling failed`);
}

async function downloadArtifact(target, destination) {
  process.stderr.write(`[calibration] ${target.id}: downloading fixed ${target.revision} asset over HTTPS\n`);
  await mkdir(dirname(destination), { recursive: true });
  if (await downloadReleaseWithGithubCli(target, destination)) return;
  const response = await fetchFromApprovedGithubHosts(target);
  if (!response.ok || !response.body) fail(`${target.id}: download failed with HTTP ${response.status}`);
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) !== target.byteSize) fail(`${target.id}: server content length drifted`);

  const handle = await open(destination, "wx", 0o600);
  const hash = createHash("sha256");
  let bytes = 0;
  try {
    const reader = response.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > target.byteSize || bytes > MAX_ARTIFACT_BYTES) {
        await reader.cancel();
        fail(`${target.id}: download exceeded its pinned byte size`);
      }
      const buffer = Buffer.from(value);
      hash.update(buffer);
      await writeAll(handle, buffer);
    }
  } finally {
    await handle.close();
  }
  if (bytes !== target.byteSize) fail(`${target.id}: downloaded byte size drifted; expected ${target.byteSize}, got ${bytes}`);
  const digest = hash.digest("hex");
  if (digest !== target.sha256) fail(`${target.id}: downloaded SHA-256 drifted; expected ${target.sha256}, got ${digest}`);
}

function summarizeArtifactFindings(signals) {
  const counts = new Map();
  for (const signal of signals.filter((item) => item.engine === "aisec-artifact")) {
    counts.set(signal.ruleId, (counts.get(signal.ruleId) ?? 0) + 1);
  }
  return [...counts].map(([ruleId, count]) => ({ ruleId, count })).sort((left, right) => left.ruleId.localeCompare(right.ruleId));
}

function assertExpected(target, report, source) {
  const coverage = report.coverage.filter((item) => item.domain === "mobile-artifact-static");
  if (coverage.length !== 1) fail(`${target.id}: expected exactly one mobile-artifact-static coverage record, got ${coverage.length}`);
  if (coverage[0].status !== target.expected.coverageStatus) {
    fail(`${target.id}: artifact coverage drifted; expected ${target.expected.coverageStatus}, got ${coverage[0].status}${coverage[0].reason ? ` (${coverage[0].reason})` : ""}`);
  }
  const artifactFindings = summarizeArtifactFindings(report.signals);
  if (JSON.stringify(artifactFindings) !== JSON.stringify(target.expected.artifactFindings)) {
    fail(`${target.id}: artifact findings drifted; expected ${JSON.stringify(target.expected.artifactFindings)}, got ${JSON.stringify(artifactFindings)}`);
  }
  return {
    id: target.id,
    platform: target.platform,
    classification: target.classification,
    project: target.project,
    revision: target.revision,
    license: target.license,
    byteSize: target.byteSize,
    sha256: target.sha256,
    source,
    coverageStatus: coverage[0].status,
    artifactFindings,
    decision: report.decision,
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
  for (const id of [...options.targets, ...options.local.keys()]) if (!available.has(id)) fail(`unknown calibration target: ${id}`);
  const selected = options.targets.length > 0 ? options.targets.map((id) => available.get(id)) : manifest.targets;
  for (const id of options.local.keys()) if (!selected.some((target) => target.id === id)) fail(`--local ${id} is unused because that target was not selected`);
  const downloads = selected.filter((target) => !options.local.has(target.id));
  if (downloads.length > 0 && !options.confirmDownload) {
    fail(`network download is disabled; pass --confirm-download to fetch fixed assets for: ${downloads.map((target) => target.id).join(", ")}`);
  }

  const scanModulePath = join(repositoryRoot, "dist", "src", "core", "scan.js");
  const built = await stat(scanModulePath).catch(() => undefined);
  if (!built?.isFile()) fail("built scanner is missing; run npm run build first");
  const { scanProject } = await import(pathToFileURL(scanModulePath).href);
  const temporary = await mkdtemp(join(tmpdir(), "aisec-mobile-artifact-calibration-"));
  const scanRoot = join(temporary, "empty-scan-root");
  await mkdir(scanRoot);
  const results = [];
  try {
    for (const target of selected) {
      const local = options.local.get(target.id);
      const artifactPath = local ?? join(temporary, target.id, target.filename);
      if (!local) await downloadArtifact(target, artifactPath);
      const verifiedPath = await verifyArtifact(target, artifactPath);
      process.stderr.write(`[calibration] ${target.id}: bounded static scan; artifact is not installed or executed\n`);
      const { report } = await scanProject(scanRoot, {
        profile: "predeploy",
        nativeOnly: true,
        artifacts: [verifiedPath],
        persist: false,
        timeoutMs: 120_000,
      });
      results.push(assertExpected(target, report, local ? "verified-local-artifact" : "fixed-asset-download"));
      await verifyArtifact(target, verifiedPath);
      process.stderr.write(`[calibration] ${target.id}: expected rule-specific behavior confirmed\n`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }

  process.stdout.write(`${JSON.stringify({
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    passed: true,
    disclaimer: manifest.description,
    safety: {
      artifactsInstalled: false,
      targetCodeExecuted: false,
      targetBuildsRun: false,
      targetHttpRequestsSent: false,
      archiveMembersExtractedToDisk: false,
      rawReportsPersisted: false,
      downloadedArtifactsRetained: false,
    },
    results,
  }, null, 2)}\n`);
}

async function main() {
  if (reexecWithEnvironmentProxy()) return;
  await run();
}

main().catch((error) => {
  process.stderr.write(`mobile-artifact-calibration: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
