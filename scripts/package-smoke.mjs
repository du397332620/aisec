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

function completedBolaManifest(template) {
  const dataPrefix = "aisec-binding-smoke";
  const cases = template.manifest.cases.map((item, index) => {
    const binding = template.bindings[index];
    const objectValues = new Map(binding.objectIdFields.map((field, fieldIndex) => [
      field,
      String(920_000 + index * 100 + fieldIndex),
    ]));
    let path = item.path;
    for (const [field, value] of objectValues) {
      path = path
        .replaceAll(`{${field}}`, encodeURIComponent(value))
        .replaceAll(`[${field}]`, encodeURIComponent(value))
        .replaceAll(`*${field}`, encodeURIComponent(value))
        .replace(new RegExp(`:${field}(?=/|\\?|$)`, "gu"), encodeURIComponent(value));
    }
    const testDataLabel = `${dataPrefix}-case-${index + 1}`;
    return {
      id: item.id,
      method: item.method,
      path,
      readOnly: true,
      testDataLabel,
      ownerAccount: "owner",
      otherAccount: "other",
      ...(item.method === "POST"
        ? { body: Object.fromEntries([...objectValues].map(([field, value]) => [field, Number(value)])) }
        : {}),
      expected: binding.evidenceMode === "ownerIdentity"
        ? { match: "ownerIdentity", statusCodes: [200], jsonPath: "data.fixture_owner" }
        : { match: "testDataLabel", statusCodes: [200], jsonPath: "data.object_label", value: testDataLabel },
    };
  });
  return {
    schemaVersion: "1.0.0",
    targetBaseUrl: "http://127.0.0.1:65535/",
    environment: "local",
    ownedBy: "AIsec offline binding smoke",
    allowedHosts: ["127.0.0.1"],
    dataPrefix,
    maxRequests: template.manifest.maxRequests,
    accounts: [
      { label: "owner", usernameEnv: "AISEC_BOLA_SMOKE_OWNER_USERNAME", passwordEnv: "AISEC_BOLA_SMOKE_OWNER_PASSWORD" },
      { label: "other", usernameEnv: "AISEC_BOLA_SMOKE_OTHER_USERNAME", passwordEnv: "AISEC_BOLA_SMOKE_OTHER_PASSWORD" },
    ],
    login: {
      path: "/auth/login",
      usernameField: "username",
      passwordField: "password",
      successStatusCodes: [200],
      tokenJsonPath: "data.access_token",
      identityJsonPath: "data.user_id",
      tokenPrefix: "Bearer",
    },
    cases,
    acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data",
  };
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
  assert.ok(packedPaths.has("schemas/rule-pack-preview.schema.json"), "rule-pack preview schema must be packaged");
  assert.ok(packedPaths.has("schemas/security-policy.schema.json"), "security policy schema must be packaged");
  assert.ok(packedPaths.has("schemas/ci-report.schema.json"), "CI report schema must be packaged");
  assert.ok(packedPaths.has("schemas/interface-security-audit.schema.json"), "interface-security audit schema must be packaged");
  assert.ok(packedPaths.has("schemas/interface-security-disposition.schema.json"), "interface-security disposition schema must be packaged");
  assert.ok(packedPaths.has("schemas/interface-security-review.schema.json"), "interface-security review schema must be packaged");
  assert.ok(packedPaths.has("schemas/interface-security-review-check.schema.json"), "interface-security review-check schema must be packaged");
  assert.ok(packedPaths.has("schemas/interface-verification-queue.schema.json"), "interface-verification queue schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-authorization-template.schema.json"), "BOLA authorization template schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-authorization-check.schema.json"), "BOLA authorization check schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-verification-report.schema.json"), "BOLA verification report schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-verification-audit.schema.json"), "BOLA verification audit schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-verification-lineage-audit.schema.json"), "BOLA verification lineage audit schema must be packaged");
  assert.ok(packedPaths.has("schemas/bola-verification-lineage-check.schema.json"), "BOLA verification lineage check schema must be packaged");
  assert.ok(packedPaths.has("examples/security-policy.example.yml"), "trusted policy example must be packaged");
  assert.ok(packedPaths.has("examples/rule-pack.example.yml"), "declarative rule-pack example must be packaged");
  assert.ok(![...packedPaths].some((path) => path.startsWith("docs/") || path.startsWith(".scratch/")), "local progress documents must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/baas-calibration.mjs"), "BaaS calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/baas-targets.json"), "real BaaS calibration manifest must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/node-api-calibration.mjs"), "networked calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/node-api-targets.json"), "real-project calibration manifest must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/fastapi-rbac-calibration.mjs"), "FastAPI RBAC calibration runner must stay out of the npm package");
  assert.ok(!packedPaths.has("scripts/calibration/fastapi-rbac-targets.json"), "FastAPI RBAC calibration manifest must stay out of the npm package");
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
  await access(join(packageRoot, "schemas", "bola-authorization-template.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-authorization-check.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-verification-report.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-verification-audit.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-verification-lineage-audit.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "bola-verification-lineage-check.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "rule-catalog.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "rule-pack.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "rule-pack-preview.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "security-policy.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "ci-report.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "interface-security-audit.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "interface-security-disposition.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "interface-security-review.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "interface-security-review-check.schema.json"), constants.R_OK);
  await access(join(packageRoot, "schemas", "interface-verification-queue.schema.json"), constants.R_OK);
  await access(join(packageRoot, "RULES.md"), constants.R_OK);
  const ruleCatalog = JSON.parse(await readFile(join(packageRoot, "rules", "catalog.json"), "utf8"));
  assert.equal(ruleCatalog.rules.length, 59);
  await access(join(packageRoot, "examples", "authorization.bola.local.yml"), constants.R_OK);
  await access(join(packageRoot, "examples", "security-policy.example.yml"), constants.R_OK);
  await access(join(packageRoot, "examples", "rule-pack.example.yml"), constants.R_OK);
  const scanEnvironment = { AISEC_DATA_DIR: join(temporary, "data") };

  const catalogApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { loadRuleCatalog } from ${JSON.stringify(packageMetadata.name)}; process.stdout.write(JSON.stringify(loadRuleCatalog()));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed rule catalog API");
  assert.equal(catalogApi.rules.length, 59);

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

  const localGateApi = run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { runLocalGate } from ${JSON.stringify(packageMetadata.name)}; process.stdout.write(typeof runLocalGate);`,
  ], { cwd: consumer, env: scanEnvironment });
  assert.equal(localGateApi, "function");

  const rulePackApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { parseRulePack, validateRulePack } from ${JSON.stringify(packageMetadata.name)}; const value = validateRulePack(parseRulePack(readFileSync(${JSON.stringify(join(packageRoot, "examples", "rule-pack.example.yml"))}, "utf8"))); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, packId: value.packId, rules: value.rules.length, absent: value.rules.some((rule) => rule.match.emitWhen === "absent") }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed rule-pack API");
  assert.deepEqual(rulePackApi, { schemaVersion: "1.1.0", packId: "example.local", rules: 2, absent: true });

  assert.equal(run(executable, ["--version"], { cwd: consumer, env: scanEnvironment }).trim(), packageMetadata.version);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /--policy <file>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /--rule-pack <file>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /rule-pack check \[path\]/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /local-gate \[path\].*--state-dir <private-directory>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /draft-bola --scan <scan-id\|report\.json>.*--candidate interface-candidate-id/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /prepare-bola --draft <selected-bola-draft\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /check-bola --authorization <completed-manifest\.yml>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /--template same-template\.json/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /verify-bola --authorization <manifest\.yml> --template <same-template\.json> --check <authorization-check\.json> --confirm/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /audit-bola --authorization <same-manifest\.yml> --template <same-template\.json> --check <authorization-check\.json> --report <verification-report\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /audit-bola-lineage --scan-report <scan-report\.json> --draft <selected-draft\.json> --authorization <same-manifest\.yml>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /check-bola-lineage --scan-report <scan-report\.json> --draft <selected-draft\.json> --authorization <same-manifest\.yml>.*--lineage-audit <lineage-audit\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /interface-audit --scan <scan-id\|report\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /prepare-interface-review --audit <interface-audit\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /check-interface-review --audit <same-interface-audit\.json> --disposition <completed-disposition\.json>/);
  assert.match(run(executable, ["--help"], { cwd: consumer, env: scanEnvironment }), /check-interface-review-receipt --audit <same-interface-audit\.json> --disposition <same-disposition\.json> --review <saved-interface-review\.json>/);

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

  const localGateTarget = join(temporary, "local-gate-target");
  const localGateState = join(temporary, "local-gate-state");
  const localGatePolicy = join(temporary, "local-gate-policy.yml");
  const localGateEnvironment = {
    ...scanEnvironment,
    AISEC_GITLEAKS_PATH: join(temporary, "missing-gitleaks"),
    AISEC_OPENGREP_PATH: join(temporary, "missing-opengrep"),
    AISEC_TRIVY_PATH: join(temporary, "missing-trivy"),
  };
  const routeSource = (routes) => `from fastapi import FastAPI\n\napp = FastAPI()\n\n${routes.map((route, index) => `@app.get("${route}")\nasync def handler_${index}():\n    try:\n        return load_value()\n    except Exception as error:\n        return {"message": str(error)}\n`).join("\n")}`;
  await mkdir(localGateTarget);
  await writeFile(join(localGateTarget, "main.py"), routeSource(["/legacy"]));
  await writeFile(localGatePolicy, `schemaVersion: 1.1.0
policyId: package-local-gate
expiresAt: 2099-12-31T23:59:59Z
profile: predeploy
requiredEngines: [gitleaks, opengrep, trivy]
gate:
  minimumSeverity: high
  includeInferred: false
  requireNoSuppressions: false
routeSecurityBaseline:
  minimumSeverity: medium
  includeInferred: false
  requireComplete: true
rules:
  required: [privacy.sensitive-logging]
  block: []
suppressions: []
`);
  const localGateArgs = ["local-gate", localGateTarget, "--policy", localGatePolicy, "--state-dir", localGateState, "--format", "json"];
  const localGateFirst = parseReport(run(executable, localGateArgs, { cwd: consumer, env: localGateEnvironment, expectedStatus: 2 }), "installed local gate bootstrap");
  const pinnedLocalBaseline = await readFile(join(localGateState, "baseline.json"), "utf8");
  assert.equal(localGateFirst.decision, "incomplete");
  await writeFile(join(localGateTarget, "main.py"), routeSource(["/legacy", "/new"]));
  const localGateSecond = parseReport(run(executable, localGateArgs, { cwd: consumer, env: localGateEnvironment, expectedStatus: 1 }), "installed local gate rescan");
  assert.equal(localGateSecond.decision, "block");
  assert.ok(localGateSecond.comparison.routeSecurity.new.some((entry) => entry.route === "GET /new"));
  assert.equal(await readFile(join(localGateState, "baseline.json"), "utf8"), pinnedLocalBaseline);

  const customTarget = join(temporary, "custom-target");
  await mkdir(join(customTarget, "src"), { recursive: true });
  await writeFile(join(customTarget, "src", "transport.ts"), "const options = { rejectUnauthorized: false };\n");
  await writeFile(join(customTarget, "src", "security.ts"), "app.use(helmet());\n");
  const previewApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { previewRulePacks, validateRulePackPreview } from ${JSON.stringify(packageMetadata.name)}; const value = validateRulePackPreview(await previewRulePacks(${JSON.stringify(customTarget)}, { rulePackPaths: [${JSON.stringify(join(packageRoot, "examples", "rule-pack.example.yml"))}] })); process.stdout.write(JSON.stringify(value));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed rule-pack preview API");
  assert.equal(previewApi.schemaVersion, "1.0.0");
  assert.equal(previewApi.status, "complete");
  assert.equal(previewApi.rulePacks[0].packId, "example.local");
  assert.doesNotMatch(JSON.stringify(previewApi), /rejectUnauthorized: false|helmet\(|rule-pack\.example\.yml/);

  const previewCli = parseReport(run(executable, [
    "rule-pack",
    "check",
    customTarget,
    "--rule-pack",
    join(packageRoot, "examples", "rule-pack.example.yml"),
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment }), "installed rule-pack preview CLI");
  assert.equal(previewCli.status, "complete");
  assert.equal(previewCli.rulePacks[0].rules.length, 2);
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

  await writeFile(join(customTarget, "src", "oversized.ts"), "x".repeat(2 * 1024 * 1024 + 1));
  const partialCustom = parseReport(run(executable, [
    "scan",
    customTarget,
    "--profile",
    "native",
    "--rule-pack",
    join(packageRoot, "examples", "rule-pack.example.yml"),
    "--no-persist",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 1 }), "installed partial-inventory rule-pack scan");
  const partialPackCoverage = partialCustom.coverage.find((item) => item.domain === "rule-pack:example.local");
  assert.equal(partialPackCoverage?.status, "partial");
  assert.match(partialPackCoverage?.reason ?? "", /project inventory is partial: oversized_file: 1/);
  assert.ok(partialCustom.signals.some((item) => item.ruleId === "custom.example.local.tls-verification-disabled"));

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
  assert.equal(ci.schemaVersion, "1.4.0");
  assert.ok(ci.routeAttribution);
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
  assert.equal(ciApi.schemaVersion, "1.4.0");
  assert.equal(ciApi.annotations, ci.annotations.length);

  const interfaceQueue = parseReport(run(executable, [
    "interface-queue",
    "--scan",
    storedReport,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface queue");
  assert.equal(interfaceQueue.status, "review_required");
  assert.equal(interfaceQueue.scanId, vulnerable.scanId);
  assert.equal(interfaceQueue.networkRequests, 0);

  const interfaceAudit = parseReport(run(executable, [
    "interface-audit",
    "--scan",
    storedReport,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface security audit");
  assert.equal(interfaceAudit.schemaVersion, "1.0.0");
  assert.equal(interfaceAudit.scan.scanId, vulnerable.scanId);
  assert.equal(interfaceAudit.coverageScope, "observed_attributed_routes_only");
  assert.equal(interfaceAudit.networkRequests, 0);
  assert.ok(!("target" in interfaceAudit.scan));

  const interfaceAuditApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { createInterfaceSecurityAudit, validateInterfaceSecurityAudit } from ${JSON.stringify(packageMetadata.name)}; const scan = JSON.parse(readFileSync(${JSON.stringify(storedReport)}, "utf8")); const value = validateInterfaceSecurityAudit(createInterfaceSecurityAudit(scan)); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, scanId: value.scan.scanId, networkRequests: value.networkRequests }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface security audit API");
  assert.deepEqual(interfaceAuditApi, { schemaVersion: "1.0.0", scanId: vulnerable.scanId, networkRequests: 0 });

  const installedInterfaceAuditPath = join(temporary, "installed-interface-audit.json");
  const installedDispositionPath = join(temporary, "installed-interface-disposition.json");
  const installedInterfaceReviewPath = join(temporary, "installed-interface-review.json");
  await writeFile(installedInterfaceAuditPath, `${JSON.stringify(interfaceAudit)}\n`);
  const installedDispositionOutput = run(executable, [
    "prepare-interface-review",
    "--audit",
    installedInterfaceAuditPath,
    "--output",
    installedDispositionPath,
  ], { cwd: consumer, env: scanEnvironment });
  assert.equal(installedDispositionOutput, "");
  const installedDisposition = JSON.parse(await readFile(installedDispositionPath, "utf8"));
  assert.equal(installedDisposition.audit.auditId, interfaceAudit.auditId);
  assert.equal(installedDisposition.reviewedBy, "<SET_REVIEW_OWNER>");
  const installedInterfaceReview = parseReport(run(executable, [
    "check-interface-review",
    "--audit",
    installedInterfaceAuditPath,
    "--disposition",
    installedDispositionPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface review");
  assert.equal(installedInterfaceReview.status, "incomplete");
  assert.equal(installedInterfaceReview.assertions.originalDecisionUnchanged, true);
  assert.equal(installedInterfaceReview.networkRequests, 0);
  await writeFile(installedInterfaceReviewPath, `${JSON.stringify(installedInterfaceReview)}\n`);

  const installedInterfaceReviewCheck = parseReport(run(executable, [
    "check-interface-review-receipt",
    "--audit",
    installedInterfaceAuditPath,
    "--disposition",
    installedDispositionPath,
    "--review",
    installedInterfaceReviewPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed saved interface review check");
  assert.equal(installedInterfaceReviewCheck.status, "saved_review_verified");
  assert.equal(installedInterfaceReviewCheck.currentEvaluation.status, "incomplete");
  assert.equal(installedInterfaceReviewCheck.currentEvaluation.changedSinceSaved, false);
  assert.equal(installedInterfaceReviewCheck.binding.exactReceiptDigest, true);
  assert.equal(installedInterfaceReviewCheck.networkRequests, 0);
  assert.ok(!("entries" in installedInterfaceReviewCheck));

  const interfaceReviewApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { checkInterfaceSecurityReview, createInterfaceSecurityDisposition, validateInterfaceSecurityDisposition, validateInterfaceSecurityReview } from ${JSON.stringify(packageMetadata.name)}; const audit = JSON.parse(readFileSync(${JSON.stringify(installedInterfaceAuditPath)}, "utf8")); const disposition = validateInterfaceSecurityDisposition(createInterfaceSecurityDisposition(audit)); const review = validateInterfaceSecurityReview(checkInterfaceSecurityReview(audit, disposition)); process.stdout.write(JSON.stringify({ disposition: disposition.schemaVersion, review: review.schemaVersion, status: review.status, networkRequests: review.networkRequests }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface review API");
  assert.deepEqual(interfaceReviewApi, {
    disposition: "1.0.0",
    review: "1.0.0",
    status: "incomplete",
    networkRequests: 0,
  });

  const interfaceReviewCheckApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { checkSavedInterfaceSecurityReview, validateInterfaceSecurityReviewCheck } from ${JSON.stringify(packageMetadata.name)}; const audit = JSON.parse(readFileSync(${JSON.stringify(installedInterfaceAuditPath)}, "utf8")); const disposition = JSON.parse(readFileSync(${JSON.stringify(installedDispositionPath)}, "utf8")); const review = JSON.parse(readFileSync(${JSON.stringify(installedInterfaceReviewPath)}, "utf8")); const value = validateInterfaceSecurityReviewCheck(checkSavedInterfaceSecurityReview(audit, disposition, review)); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, status: value.status, current: value.currentEvaluation.status, networkRequests: value.networkRequests }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed saved interface review-check API");
  assert.deepEqual(interfaceReviewCheckApi, {
    schemaVersion: "1.0.0",
    status: "saved_review_verified",
    current: "incomplete",
    networkRequests: 0,
  });

  const interfaceQueueApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { createInterfaceVerificationQueue, validateInterfaceVerificationQueue } from ${JSON.stringify(packageMetadata.name)}; const scan = JSON.parse(readFileSync(${JSON.stringify(storedReport)}, "utf8")); const value = validateInterfaceVerificationQueue(createInterfaceVerificationQueue(scan)); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, networkRequests: value.networkRequests }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed interface queue API");
  assert.deepEqual(interfaceQueueApi, { schemaVersion: "1.0.0", networkRequests: 0 });

  const bolaDraft = parseReport(run(executable, [
    "draft-bola",
    "--scan",
    storedReport,
  ], { cwd: consumer, env: scanEnvironment }), "installed BOLA draft");
  assert.equal(bolaDraft.status, "review_required");
  assert.equal(bolaDraft.scanId, vulnerable.scanId);
  assert.equal(bolaDraft.schemaVersion, "1.0.0");

  const selectedSource = parseReport(run(executable, [
    "scan",
    join(packageRoot, "test", "fixtures", "corpus", "fastapi-authorization", "positive-read"),
    "--profile",
    "native",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 2 }), "installed selected BOLA source scan");
  const selectedSourcePath = join(temporary, "data", "scans", `${selectedSource.scanId}.json`);
  const selectedQueue = parseReport(run(executable, [
    "interface-queue",
    "--scan",
    selectedSourcePath,
  ], { cwd: consumer, env: scanEnvironment }), "installed selected BOLA queue");
  assert.equal(selectedQueue.candidates.length, 1);
  const selectedDraft = parseReport(run(executable, [
    "draft-bola",
    "--scan",
    selectedSourcePath,
    "--candidate",
    selectedQueue.candidates[0].id,
  ], { cwd: consumer, env: scanEnvironment }), "installed selected BOLA draft");
  assert.equal(selectedDraft.schemaVersion, "1.1.0");
  assert.equal(selectedDraft.selection.queueId, selectedQueue.queueId);
  assert.deepEqual(selectedDraft.selection.candidateIds, [selectedQueue.candidates[0].id]);
  const selectedDraftPath = join(temporary, "installed-selected-bola-draft.json");
  await writeFile(selectedDraftPath, `${JSON.stringify(selectedDraft)}\n`);
  const authorizationTemplate = parseReport(run(executable, [
    "prepare-bola",
    "--draft",
    selectedDraftPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed BOLA authorization template");
  assert.equal(authorizationTemplate.status, "placeholders_required");
  assert.equal(authorizationTemplate.schemaVersion, "1.1.0");
  assert.equal(authorizationTemplate.networkRequests, 0);
  assert.equal(authorizationTemplate.selection.queueId, selectedQueue.queueId);
  assert.equal(authorizationTemplate.bindings[0].route, selectedQueue.candidates[0].route);

  const authorizationTemplatePath = join(temporary, "installed-bola-authorization-template.json");
  const completedAuthorizationPath = join(temporary, "installed-completed-bola-authorization.json");
  await writeFile(authorizationTemplatePath, `${JSON.stringify(authorizationTemplate)}\n`);
  await writeFile(completedAuthorizationPath, `${JSON.stringify(completedBolaManifest(authorizationTemplate))}\n`);
  const authorizationCheck = parseReport(run(executable, [
    "check-bola",
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
  ], { cwd: consumer, env: scanEnvironment }), "installed offline BOLA authorization check");
  assert.equal(authorizationCheck.schemaVersion, "1.2.0");
  assert.equal(authorizationCheck.status, "valid_review_required");
  assert.equal(authorizationCheck.templateBinding.status, "verified");
  assert.equal(authorizationCheck.templateBinding.templateId, authorizationTemplate.templateId);
  assert.equal(authorizationCheck.networkRequests, 0);
  assert.equal(authorizationCheck.environmentValuesRead, 0);
  assert.equal(authorizationCheck.dnsLookups, 0);
  assert.doesNotMatch(JSON.stringify(authorizationCheck), /127\.0\.0\.1|\/project\/detail|project_id/u);
  const authorizationCheckPath = join(temporary, "installed-bola-authorization-check.json");
  const verificationReportPath = join(temporary, "installed-bola-verification-report.json");
  const lineageAuditPath = join(temporary, "installed-bola-lineage-audit.json");
  await writeFile(authorizationCheckPath, `${JSON.stringify(authorizationCheck)}\n`);
  assert.equal(run(executable, [
    "verify-bola",
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
    "--check",
    authorizationCheckPath,
    "--confirm",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 64 }), "");

  const selectedDraftApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync } from "node:fs"; import { createInterfaceVerificationQueue, createSelectedBolaDraftPlan, validateBolaDraftPlan } from ${JSON.stringify(packageMetadata.name)}; const scan = JSON.parse(readFileSync(${JSON.stringify(selectedSourcePath)}, "utf8")); const queue = createInterfaceVerificationQueue(scan); const value = validateBolaDraftPlan(createSelectedBolaDraftPlan(scan, [queue.candidates[0].id])); process.stdout.write(JSON.stringify({ schemaVersion: value.schemaVersion, queueId: value.selection.queueId, candidates: value.candidates.length }));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed selected BOLA API");
  assert.deepEqual(selectedDraftApi, {
    schemaVersion: "1.1.0",
    queueId: selectedQueue.queueId,
    candidates: 1,
  });

  const bolaPreflightApi = parseReport(run(process.execPath, [
    "--input-type=module",
    "--eval",
    `import { readFileSync, writeFileSync } from "node:fs";
import * as rootApi from ${JSON.stringify(packageMetadata.name)};
import { assertBolaVerificationPreflight, auditBola, auditBolaLineage, auditBolaVerification, auditBolaVerificationLineage, checkBola, checkBolaLineage, checkBolaVerificationLineageReceipt, createBolaAuthorizationTemplate, loadBolaAuthorizationCheck, loadBolaAuthorizationTemplate, loadBolaVerificationLineageAudit, loadBolaVerificationReport, validateBolaAuthorizationCheck, validateBolaAuthorizationTemplate, validateBolaVerificationAudit, validateBolaVerificationLineageAudit, validateBolaVerificationLineageCheck, validateBolaVerificationReport, verifyBola } from ${JSON.stringify(packageMetadata.name)};
const scan = JSON.parse(readFileSync(${JSON.stringify(selectedSourcePath)}, "utf8"));
const draft = JSON.parse(readFileSync(${JSON.stringify(selectedDraftPath)}, "utf8"));
const manifest = JSON.parse(readFileSync(${JSON.stringify(completedAuthorizationPath)}, "utf8"));
const template = validateBolaAuthorizationTemplate(createBolaAuthorizationTemplate(draft));
const loaded = await loadBolaAuthorizationTemplate(${JSON.stringify(authorizationTemplatePath)});
const check = validateBolaAuthorizationCheck(await checkBola(${JSON.stringify(completedAuthorizationPath)}, ${JSON.stringify(authorizationTemplatePath)}));
const receipt = await loadBolaAuthorizationCheck(${JSON.stringify(authorizationCheckPath)});
const matched = assertBolaVerificationPreflight(manifest, loaded, receipt);
const environment = {};
environment[manifest.accounts[0].usernameEnv] = "fixture_owner";
environment[manifest.accounts[0].passwordEnv] = "owner_password";
environment[manifest.accounts[1].usernameEnv] = "fixture_other";
environment[manifest.accounts[1].passwordEnv] = "other_password";
const setPath = (root, path, value) => {
  const segments = path.split(".");
  let current = root;
  for (const segment of segments.slice(0, -1)) current = current[segment] ??= {};
  current[segments.at(-1)] = value;
};
let activeRequests = 0;
const requester = async (input) => {
  activeRequests += 1;
  const response = (status, body) => ({ url: input.url, status, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  if (input.url.endsWith(manifest.login.path)) {
    const fields = JSON.parse(input.body ?? "{}");
    const owner = fields[manifest.login.usernameField] === "fixture_owner";
    const body = {};
    setPath(body, manifest.login.tokenJsonPath, owner ? "owner-token" : "other-token");
    setPath(body, manifest.login.identityJsonPath, owner ? "owner-id" : "other-id");
    return response(200, body);
  }
  if (input.headers?.authorization === "Bearer owner-token") {
    const item = manifest.cases.find((candidate) => new URL(candidate.path, manifest.targetBaseUrl).toString() === input.url);
    if (!item) throw new Error("unexpected installed-package case");
    const body = {};
    setPath(body, item.expected.jsonPath, item.expected.match === "ownerIdentity" ? "owner-id" : item.expected.value);
    return response(200, body);
  }
  return response(403, { detail: "installed-private-response" });
};
const active = validateBolaVerificationReport(await verifyBola(${JSON.stringify(completedAuthorizationPath)}, {
  confirmed: true,
  templatePath: ${JSON.stringify(authorizationTemplatePath)},
  checkPath: ${JSON.stringify(authorizationCheckPath)},
  environment,
  requester,
}));
writeFileSync(${JSON.stringify(verificationReportPath)}, JSON.stringify(active), { mode: 0o600 });
const loadedReport = await loadBolaVerificationReport(${JSON.stringify(verificationReportPath)});
const directAudit = validateBolaVerificationAudit(auditBolaVerification(manifest, loaded, receipt, active));
const savedAudit = validateBolaVerificationAudit(await auditBola(${JSON.stringify(completedAuthorizationPath)}, {
  templatePath: ${JSON.stringify(authorizationTemplatePath)},
  checkPath: ${JSON.stringify(authorizationCheckPath)},
  reportPath: ${JSON.stringify(verificationReportPath)},
}));
const directLineage = validateBolaVerificationLineageAudit(auditBolaVerificationLineage(scan, draft, manifest, loaded, receipt, active));
const savedLineage = validateBolaVerificationLineageAudit(await auditBolaLineage({
  scanReportPath: ${JSON.stringify(selectedSourcePath)},
  draftPath: ${JSON.stringify(selectedDraftPath)},
  authorizationPath: ${JSON.stringify(completedAuthorizationPath)},
  templatePath: ${JSON.stringify(authorizationTemplatePath)},
  checkPath: ${JSON.stringify(authorizationCheckPath)},
  reportPath: ${JSON.stringify(verificationReportPath)},
}));
writeFileSync(${JSON.stringify(lineageAuditPath)}, JSON.stringify(savedLineage), { mode: 0o600 });
const loadedLineage = await loadBolaVerificationLineageAudit(${JSON.stringify(lineageAuditPath)});
const directLineageCheck = validateBolaVerificationLineageCheck(checkBolaVerificationLineageReceipt(
  scan,
  draft,
  manifest,
  loaded,
  receipt,
  active,
  loadedLineage,
));
const savedLineageCheck = validateBolaVerificationLineageCheck(await checkBolaLineage({
  scanReportPath: ${JSON.stringify(selectedSourcePath)},
  draftPath: ${JSON.stringify(selectedDraftPath)},
  authorizationPath: ${JSON.stringify(completedAuthorizationPath)},
  templatePath: ${JSON.stringify(authorizationTemplatePath)},
  checkPath: ${JSON.stringify(authorizationCheckPath)},
  reportPath: ${JSON.stringify(verificationReportPath)},
  lineageAuditPath: ${JSON.stringify(lineageAuditPath)},
}));
const serialized = JSON.stringify(active);
const provenance = JSON.stringify(active.provenance);
const auditSerialized = JSON.stringify(savedAudit);
const lineageSerialized = JSON.stringify(savedLineage);
const lineageCheckSerialized = JSON.stringify(savedLineageCheck);
const sanitized = ![...Object.values(environment), "owner-token", "other-token", "owner-id", "other-id", "installed-private-response"].some((value) => serialized.includes(value));
const provenanceSanitized = !/127\\.0\\.0\\.1|\\/auth\\/login|\\/project\\/detail|920000|AISEC_BOLA/u.test(provenance);
const auditSanitized = !/127\\.0\\.0\\.1|\\/auth\\/login|\\/project\\/detail|920000|AISEC_BOLA|fixture_owner|owner-token|owner-id|installed-private-response/u.test(auditSerialized);
const lineageSanitized = !["127.0.0.1", "/auth/login", "/project/detail", "main.py", "fastapi.authorization", "920000", "AISEC_BOLA", "fixture_owner", "owner-token", "owner-id", "installed-private-response"].some((value) => lineageSerialized.includes(value));
const lineageCheckSanitized = !["127.0.0.1", "/auth/login", "/project/detail", "main.py", "fastapi.authorization", "920000", "AISEC_BOLA", "fixture_owner", "owner-token", "owner-id", "installed-private-response"].some((value) => lineageCheckSerialized.includes(value));
process.stdout.write(JSON.stringify({
  template: template.status,
  loaded: loaded.templateId === template.templateId,
  check: check.status,
  binding: check.templateBinding.status,
  matched: matched.checkId === receipt.checkId,
  version: check.schemaVersion,
  requests: template.networkRequests + check.networkRequests,
  reportVersion: active.schemaVersion,
  reportProvenance: active.provenance.status,
  reportReceipt: active.provenance.receipt.checkId === receipt.checkId,
  reportCases: active.provenance.authorization.caseIds.length,
  activeRequests,
  sanitized,
  provenanceSanitized,
  loadedReport: loadedReport.verificationId === active.verificationId,
  auditVersion: savedAudit.schemaVersion,
  auditStatus: savedAudit.status,
  auditMatch: savedAudit.auditId === directAudit.auditId,
  auditRequests: savedAudit.io.networkRequests + savedAudit.io.requesterCalls,
  auditSanitized,
  lineageVersion: savedLineage.schemaVersion,
  lineageStatus: savedLineage.status,
  lineageMatch: savedLineage.lineageAuditId === directLineage.lineageAuditId,
  lineageRequests: savedLineage.io.networkRequests + savedLineage.io.requesterCalls,
  lineageSanitized,
  lineageCheckVersion: savedLineageCheck.schemaVersion,
  lineageCheckStatus: savedLineageCheck.status,
  lineageCheckMatch: savedLineageCheck.lineageCheckId === directLineageCheck.lineageCheckId,
  lineageCheckReceipt: savedLineageCheck.receipt.lineageAuditId === savedLineage.lineageAuditId,
  lineageCheckRequests: savedLineageCheck.io.networkRequests + savedLineageCheck.io.requesterCalls,
  lineageCheckSanitized,
  lowLevelExported: Object.hasOwn(rootApi, "executeBolaVerification"),
}));`,
  ], { cwd: consumer, env: scanEnvironment }), "installed BOLA preflight API");
  assert.deepEqual(bolaPreflightApi, {
    template: "placeholders_required",
    loaded: true,
    check: "valid_review_required",
    binding: "verified",
    matched: true,
    version: "1.2.0",
    requests: 0,
    reportVersion: "1.1.0",
    reportProvenance: "preflight_verified",
    reportReceipt: true,
    reportCases: 1,
    activeRequests: 4,
    sanitized: true,
    provenanceSanitized: true,
    loadedReport: true,
    auditVersion: "1.0.0",
    auditStatus: "artifacts_verified",
    auditMatch: true,
    auditRequests: 0,
    auditSanitized: true,
    lineageVersion: "1.0.0",
    lineageStatus: "lineage_verified",
    lineageMatch: true,
    lineageRequests: 0,
    lineageSanitized: true,
    lineageCheckVersion: "1.0.0",
    lineageCheckStatus: "saved_lineage_verified",
    lineageCheckMatch: true,
    lineageCheckReceipt: true,
    lineageCheckRequests: 0,
    lineageCheckSanitized: true,
    lowLevelExported: false,
  });

  const installedAudit = parseReport(run(executable, [
    "audit-bola",
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
    "--check",
    authorizationCheckPath,
    "--report",
    verificationReportPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed offline BOLA audit");
  assert.equal(installedAudit.schemaVersion, "1.0.0");
  assert.equal(installedAudit.status, "artifacts_verified");
  assert.equal(installedAudit.io.networkRequests, 0);
  assert.equal(installedAudit.io.requesterCalls, 0);
  assert.doesNotMatch(JSON.stringify(installedAudit), /127\.0\.0\.1|\/project\/detail|920000|AISEC_BOLA/u);

  const installedLineageAudit = parseReport(run(executable, [
    "audit-bola-lineage",
    "--scan-report",
    selectedSourcePath,
    "--draft",
    selectedDraftPath,
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
    "--check",
    authorizationCheckPath,
    "--report",
    verificationReportPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed offline BOLA lineage audit");
  assert.equal(installedLineageAudit.schemaVersion, "1.0.0");
  assert.equal(installedLineageAudit.status, "lineage_verified");
  assert.equal(installedLineageAudit.io.networkRequests, 0);
  assert.equal(installedLineageAudit.io.requesterCalls, 0);
  assert.doesNotMatch(
    JSON.stringify(installedLineageAudit),
    /127\.0\.0\.1|\/project\/detail|main\.py|fastapi\.authorization|920000|AISEC_BOLA/u,
  );

  const installedLineageCheck = parseReport(run(executable, [
    "check-bola-lineage",
    "--scan-report",
    selectedSourcePath,
    "--draft",
    selectedDraftPath,
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
    "--check",
    authorizationCheckPath,
    "--report",
    verificationReportPath,
    "--lineage-audit",
    lineageAuditPath,
  ], { cwd: consumer, env: scanEnvironment }), "installed offline saved BOLA lineage check");
  assert.equal(installedLineageCheck.schemaVersion, "1.0.0");
  assert.equal(installedLineageCheck.status, "saved_lineage_verified");
  assert.equal(installedLineageCheck.receipt.lineageAuditId, installedLineageAudit.lineageAuditId);
  assert.equal(installedLineageCheck.io.networkRequests, 0);
  assert.equal(installedLineageCheck.io.requesterCalls, 0);
  assert.doesNotMatch(
    JSON.stringify(installedLineageCheck),
    /127\.0\.0\.1|\/project\/detail|main\.py|fastapi\.authorization|920000|AISEC_BOLA/u,
  );

  process.stdout.write("Running the public corpus from inside the installed package...\n");
  const benchmarkOutput = run(process.execPath, [join(packageRoot, "dist", "src", "benchmark.js")], {
    cwd: consumer,
    env: scanEnvironment,
  });
  assert.ok(benchmarkOutput.trim(), "the installed benchmark entry point must produce a result");
  const benchmark = JSON.parse(benchmarkOutput);
  assert.deepEqual(benchmark.catalog, { totalRules: 56, rulesWithPositive: 56, rulesWithNearMiss: 56 });
  assert.equal(benchmark.totals.truePositive, 57);
  assert.equal(benchmark.totals.falsePositive, 0);
  assert.equal(benchmark.totals.falseNegative, 0);
  assert.equal(benchmark.totals.evidenceMismatches, 0);
  assert.equal(benchmark.totals.cweMismatches, 0);

  process.stdout.write(`Package smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
