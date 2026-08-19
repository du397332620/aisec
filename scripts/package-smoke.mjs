import assert from "node:assert/strict";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const packageMetadata = JSON.parse(await readFile(join(repositoryRoot, "package.json"), "utf8"));
const sensitiveEnvironmentName = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

function childEnvironment(overrides = {}) {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name)));
  return { ...environment, ...overrides };
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repositoryRoot,
    encoding: "utf8",
    env: childEnvironment(options.env),
    maxBuffer: 10 * 1024 * 1024,
    timeout: options.timeout ?? 60_000,
  });
  if (result.error) throw new Error(`${command} ${args.join(" ")} failed: ${result.error.message}`, { cause: result.error });
  const expectedStatus = options.expectedStatus ?? 0;
  if (result.status !== expectedStatus) {
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim().slice(-4_000);
    const reason = result.signal ? `terminated by ${result.signal}` : `exited ${result.status}`;
    throw new Error(`${command} ${args.join(" ")} ${reason}; expected ${expectedStatus}\n${output}`);
  }
  return result.stdout;
}

function parseReport(output, label) {
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${label} did not return a JSON report: ${output.slice(0, 1_000)}`);
  }
}

const temporary = await mkdtemp(join(tmpdir(), "aisec-package-smoke-"));
try {
  const tarballs = join(temporary, "tarballs");
  const consumer = join(temporary, "consumer");
  await mkdir(tarballs);
  await mkdir(consumer);
  await writeFile(join(consumer, "package.json"), '{"name":"aisec-package-smoke","private":true}\n');

  process.stdout.write("Packing AIsec and installing it into an empty project...\n");
  const packed = JSON.parse(run(npmCommand, ["pack", "--ignore-scripts", "--json", "--pack-destination", tarballs]));
  assert.equal(packed.length, 1, "npm pack must create exactly one tarball");
  assert.equal(packed[0].name, packageMetadata.name);
  assert.equal(packed[0].version, packageMetadata.version);
  assert.match(packed[0].filename, /^[A-Za-z0-9._-]+\.tgz$/);
  const packedPaths = new Set(packed[0].files.map((file) => file.path));
  assert.ok(packedPaths.has("RULES.md"), "generated public rule documentation must be packaged");
  assert.ok(packedPaths.has("rules/catalog.json"), "machine-readable rule catalog must be packaged");
  assert.ok(packedPaths.has("schemas/rule-catalog.schema.json"), "rule catalog schema must be packaged");
  assert.ok(packedPaths.has("schemas/rule-pack.schema.json"), "declarative rule-pack schema must be packaged");
  assert.ok(packedPaths.has("schemas/security-policy.schema.json"), "security policy schema must be packaged");
  assert.ok(packedPaths.has("schemas/ci-report.schema.json"), "CI report schema must be packaged");
  assert.ok(packedPaths.has("examples/security-policy.example.yml"), "trusted policy example must be packaged");
  assert.ok(packedPaths.has("examples/rule-pack.example.yml"), "declarative rule-pack example must be packaged");
  assert.ok(![...packedPaths].some((path) => path.startsWith("docs/") || path.startsWith(".scratch/")), "local progress documents must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/baas-calibration.mjs"), "BaaS calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/baas-targets.json"), "real BaaS calibration manifest must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/node-api-calibration.mjs"), "networked calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/node-api-targets.json"), "real-project calibration manifest must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/mobile-artifact-calibration.mjs"), "mobile artifact calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/mobile-artifact-targets.json"), "real mobile artifact manifest must stay out of the npm package");
  assert.ok(![...packedPaths].some((path) => /\.(?:apk|ipa)$/i.test(path)), "third-party mobile binaries must stay out of the npm package");
  const tarball = join(tarballs, packed[0].filename);
  await access(tarball, constants.R_OK);

  run(npmCommand, [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--registry=https://registry.npmjs.org",
    tarball,
  ], { cwd: consumer, timeout: 180_000 });

  const packageRoot = join(consumer, "node_modules", ...packageMetadata.name.split("/"));
  const executable = join(consumer, "node_modules", ".bin", process.platform === "win32" ? "aisec.cmd" : "aisec");
  await access(executable, process.platform === "win32" ? constants.R_OK : constants.X_OK);
  await access(join(packageRoot, "schemas", "bola-authorization-manifest.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-draft.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "rule-catalog.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "rule-pack.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "security-policy.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "ci-report.schema.json"), constants.R_OK);
  await access(join(packageRoot, "RULES.md"), constants.R_OK);
  const ruleCatalog = JSON.parse(await readFile(join(packageRoot, "rules", "catalog.json"), "utf8"));
  assert.equal(ruleCatalog.rules.length, 56);
  await access(join(packageRoot, "examples", "authorization.bola.local.yml"), constants.R_OK);
  await access(join(packageRoot, "examples", "security-policy.example.yml"), constants.R_OK);
  await access(join(packageRoot, "examples", "rule-pack.example.yml"), constants.R_OK);
  const scanEnvironment = { AISEC_DATA_DIR: join(temporary, "data") };

  const catalogApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { loadRuleCatalog } from ${JSON.stringify(packageMetadata.name)}; process.stdout.write(JSON.stringify(loadRuleCatalog()));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed rule catalog API");
  assert.equal(catalogApi.rules.length, 56);

  const policyApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { validateSecurityPolicy } from ${JSON.stringify(packageMetadata.name)}; const value = validateSecurityPolicy(${JSON.stringify({
      schemaVersion: "1.0.0",
      policyId: "package-smoke",
      expiresAt: "2099-12-31T23:59:59Z",
      profile: "predeploy",
      requiredEngines: ["gitleaks", "opengrep", "trivy"],
      gate: { minimumSeverity: "high", includeInferred: false, requireNoSuppressions: false },
      rules: { required: ["secret.openai"], block: [] },
      suppressions: [],
    })}); process.stdout.write(JSON.stringify(value));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed security policy API");
  assert.equal(policyApi.policyId, "package-smoke");

  const rulePackApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { parseRulePack, validateRulePack } from ${JSON.stringify(packageMetadata.name)}; const value = validateRulePack(parseRulePack(readFileSync(${JSON.stringify(join(packageRoot, "examples", "rule-pack.example.yml"))}, "utf8"))); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, packId: value.packId, rules: value.rules.length, absent: value.rules.some((rule) => rule.match.emitWhen === "absent") }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed rule-pack API");
  assert.deepEqual(rulePackApi, { schemaVersion: "1.1.0", packId: "example.local", rules: 2, absent: true });

  assert.equal(run(executable, ["--version"], { cwd: consumer, env: scanEnvironment }).trim(), packageMetadata.version);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /--policy <file>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /--rule-pack <file>/);

  process.stdout.write("Running the installed CLI against safe and vulnerable fixtures...\n");
  const safe = parseReport(run(executable, [
    "scan",
    join(packageRoot, "test", "fixtures", "safe"),
    "--native-only",
    "--no-persist",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment }), "safe fixture");
  assert.equal(safe.decision, "no_blockers_found");

  const customTarget = join(temporary, "custom-target");
  await mkdir(join(customTarget, "src"), { recursive: true });
  await writeFile(join(customTarget, "src", "transport.ts"), "const options = { rejectUnauthorized: false };\n");
  await writeFile(join(customTarget, "src", "security.ts"), "app.use(helmet());\n");
  const custom = parseReport(run(executable, [
    "scan",
    customTarget,
    "--profile",
    "native",
    "--rule-pack",
    join(packageRoot, "examples", "rule-pack.example.yml"),
    "--no-persist",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 1 }), "installed declarative rule-pack scan");
  assert.equal(custom.rulePacks[0].packId, "example.local");
  assert.ok(custom.signals.some((item) => item.ruleId === "custom.example.local.tls-verification-disabled"));
  assert.ok(!custom.signals.some((item) => item.ruleId === "custom.example.local.security-middleware-required"));
  assert.equal(custom.coverage.find((item) => item.domain === "rule-pack:example.local")?.status, "complete");

  const vulnerable = parseReport(run(executable, [
    "scan",
    join(packageRoot, "test", "fixtures", "vulnerable"),
    "--native-only",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 1 }), "vulnerable fixture");
  assert.equal(vulnerable.decision, "block");
  const storedReport = join(temporary, "data", "scans", `${vulnerable.scanId}.json`);
  const ci = parseReport(run(executable, ["report", storedReport, "--format", "ci"], { cwd: consumer, env: scanEnvironment }), "installed CI report");
  assert.equal(ci.schemaVersion, "1.1.0");
  assert.equal(ci.recommendedExitCode, 1);
  assert.ok(ci.annotations.length <= 71);
  const github = run(executable, ["report", storedReport, "--format", "github"], { cwd: consumer, env: scanEnvironment });
  assert.match(github, /^::error title=AIsec decision%3A block::/u);
  const markdown = run(executable, ["report", storedReport, "--format", "markdown"], { cwd: consumer, env: scanEnvironment });
  assert.match(markdown, /^# AIsec security acceptance/u);

  const ciApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { buildCiReport, validateCiReport } from ${JSON.stringify(packageMetadata.name)}; const scan = JSON.parse(readFileSync(${JSON.stringify(storedReport)}, "utf8")); const value = validateCiReport(buildCiReport(scan)); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, annotations: value.annotations.length }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed CI report API");
  assert.equal(ciApi.schemaVersion, "1.1.0");
  assert.equal(ciApi.annotations, ci.annotations.length);

  const bolaDraft = parseReport(run(executable, [
    "draft-bola",
    "--scan",
    storedReport,
  ], { cwd: consumer, env: scanEnvironment }), "installed BOLA draft");
  assert.equal(bolaDraft.status, "review_required");
  assert.equal(bolaDraft.scanId, vulnerable.scanId);

  process.stdout.write("Running the public corpus from inside the installed package...\n");
  const benchmarkOutput = run(process.execPath, [join(packageRoot, "dist", "src", "benchmark.js")], {
    cwd: consumer,
    env: scanEnvironment,
  });
  assert.ok(benchmarkOutput.trim(), "the installed benchmark entry point must produce a result");
  const benchmark = JSON.parse(benchmarkOutput);
  assert.deepEqual(benchmark.catalog, { totalRules: 53, rulesWithPositive: 53, rulesWithNearMiss: 53 });
  assert.equal(benchmark.totals.truePositive, 54);
  assert.equal(benchmark.totals.falsePositive, 0);
  assert.equal(benchmark.totals.falseNegative, 0);
  assert.equal(benchmark.totals.evidenceMismatches, 0);
  assert.equal(benchmark.totals.cweMismatches, 0);

  process.stdout.write(`Package smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
