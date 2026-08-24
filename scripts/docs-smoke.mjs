import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(repositoryRoot, "dist", "src", "cli.js");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const temporary = await mkdtemp(join(tmpdir(), "aisec-docs-smoke-"));
const sensitiveEnvironmentName = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;
const environment = {
  ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name))),
  AISEC_DATA_DIR: join(temporary, "data"),
  // Make the documented full-scan failure deterministic even on a contributor
  // machine that happens to have every optional engine installed.
  AISEC_GITLEAKS_PATH: join(temporary, "missing-gitleaks"),
  AISEC_OPENGREP_PATH: join(temporary, "missing-opengrep"),
  AISEC_TRIVY_PATH: join(temporary, "missing-trivy"),
};

function run(args, expectedStatus = 0) {
  const result = spawnSync(process.execPath, [cli, ...args], {
    cwd: repositoryRoot,
    env: environment,
    encoding: "utf8",
    timeout: 30_000,
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.error) throw result.error;
  if (result.status !== expectedStatus) {
    throw new Error(`aisec ${args.join(" ")} exited ${result.status}; expected ${expectedStatus}\n${result.stdout}\n${result.stderr}`);
  }
  return result;
}

function report(result, label) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    throw new Error(`${label} did not produce a JSON report: ${result.stdout.slice(0, 1_000)}`);
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

try {
  await access(join(repositoryRoot, "schemas", "bola-verification-report.schema.json"));
  await access(join(repositoryRoot, "schemas", "bola-verification-audit.schema.json"));
  const readme = await readFile(join(repositoryRoot, "README.md"), "utf8");
  for (const required of [
    "git clone https://github.com/du397332620/aisec.git",
    "npm ci --ignore-scripts --registry=https://registry.npmjs.org",
    "npm exec --no -- aisec doctor",
    "ref: <40-character-reviewed-aisec-commit>",
    "npm exec --no -- aisec scan ../target --profile native",
    "terminal|json|html|sarif|ci|github|markdown",
    "## Beta capability matrix",
    "--policy ../trusted/security-policy.yml",
    "--rule-pack ../trusted/rule-pack.yml",
    "aisec rule-pack check ../target",
    "aisec interface-queue",
    "InterfaceVerificationQueue 1.0.0",
    "BolaDraftPlan 1.1.0",
    "aisec prepare-bola",
    "aisec check-bola",
    "aisec audit-bola",
    "BolaAuthorizationTemplate 1.1.0",
    "BolaAuthorizationCheck 1.2.0",
    "BolaVerificationReport 1.1.0",
    "BolaVerificationAudit 1.0.0",
    "--template bola-authorization-template.json",
    "RulePack 1.1.0",
    "RulePackPreview 1.0.0",
    "SecurityPolicy 1.1.0",
    "CiReport 1.4.0",
    "routeSecurityBaseline",
    "node dist/src/cli.js local-gate ../target",
    "never advanced automatically",
    "does not accept `--output`",
    "deterministic inventory exclusions",
    "presentation-only dependency and",
    "does not download or evaluate the\nvulnerability set of a referenced base image",
    "stable machine-readable reasons",
    "also makes every active pack's required scan coverage `partial`",
    "emitWhen: absent",
    "--confirm-policy-suppressions",
    "target-owned `.aisec.yml` is ignored",
    "npm run calibrate:baas -- --confirm-download",
    "npm run calibrate:mobile-artifacts -- --confirm-download",
    "0.1.0` is not published to npm",
    "npm registry\npublication is intentionally not planned",
  ]) assert.ok(readme.includes(required), `README is missing documented first-run contract: ${required}`);

  const localExecutable = spawnSync(npmCommand, ["exec", "--no", "--", "aisec", "--version"], {
    cwd: repositoryRoot,
    env: environment,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(localExecutable.status, 0, localExecutable.stderr);
  assert.equal(localExecutable.stdout.trim(), "0.1.0");
  assert.equal(run(["--version"]).stdout.trim(), "0.1.0");
  const help = run(["--help"]).stdout;
  assert.match(help, /--profile predeploy\|native/);
  assert.match(help, /--policy <file>/);
  assert.match(help, /--rule-pack <file>/);
  assert.match(help, /rule-pack check \[path\]/);
  assert.match(help, /local-gate \[path\].*--state-dir <private-directory>/);
  assert.match(help, /--confirm-policy-suppressions/);
  assert.match(help, /terminal\|json\|html\|sarif\|ci\|github\|markdown/);
  assert.match(help, /verify-bola --authorization <manifest\.yml> --template <same-template\.json> --check <authorization-check\.json> --confirm/);
  assert.match(help, /audit-bola --authorization <same-manifest\.yml> --template <same-template\.json> --check <authorization-check\.json> --report <verification-report\.json>/);
  assert.match(help, /audit-bola rechecks retained artifacts offline and emits a sanitized audit receipt/u);
  assert.match(help, /strict 1\.1 result binds sanitized receipt\/template provenance/u);
  assert.match(help, /interface-queue --scan <scan-id\|report\.json>/);
  assert.match(help, /draft-bola --scan <scan-id\|report\.json>.*--candidate interface-candidate-id/);
  assert.match(help, /prepare-bola --draft <selected-bola-draft\.json>/);
  assert.match(help, /check-bola --authorization <completed-manifest\.yml>/);
  assert.match(help, /--template same-template\.json/);
  const doctor = report(run(["doctor", "--json"]), "doctor");
  assert.equal(doctor.node, process.version);
  assert.deepEqual(doctor.engines.map((item) => item.source), ["invalid", "invalid", "invalid"]);

  const safe = report(run(["scan", "test/fixtures/safe", "--profile", "native", "--no-persist", "--format", "json"]), "safe fixture");
  assert.equal(safe.decision, "no_blockers_found");
  assert.equal(safe.schemaVersion, "1.4.0");
  assert.equal(safe.profileName, "native");
  assert.equal(safe.coverage.find((item) => item.domain === "project-inventory")?.status, "complete");

  const vulnerable = report(run(["scan", "test/fixtures/vulnerable", "--profile", "native", "--format", "json"], 1), "vulnerable fixture");
  assert.equal(vulnerable.decision, "block");
  const stored = join(temporary, "data", "scans", `${vulnerable.scanId}.json`);
  await access(stored);
  const ci = report(run(["report", stored, "--format", "ci"]), "CI report");
  assert.equal(ci.schemaVersion, "1.4.0");
  assert.deepEqual(ci.routeAttribution, {
    eligibleSignals: 0,
    attributedSignals: 0,
    unattributedSignals: 0,
    unattributedFindings: 0,
    reasons: [],
  });
  assert.equal(ci.scanId, vulnerable.scanId);
  assert.equal(ci.recommendedExitCode, 1);
  assert.ok(ci.annotations.length <= 71);
  assert.equal(ci.annotations.filter((item) => item.kind === "decision").length, 1);
  const github = run(["report", stored, "--format", "github"]).stdout;
  assert.match(github, /^::error title=AIsec decision%3A block::/u);
  assert.equal(github.trimEnd().split("\n").length, ci.annotations.length);
  const markdownOutput = join(temporary, "github-step-summary.md");
  assert.equal(run(["report", stored, "--format", "markdown", "--output", markdownOutput]).stdout, "");
  const markdown = await readFile(markdownOutput, "utf8");
  assert.match(markdown, /^# AIsec security acceptance/u);
  assert.match(markdown, /## Required coverage/u);
  assert.match(markdown, /## Route attribution/u);
  assert.match(markdown, /## Policy/u);
  const finding = vulnerable.findings.find((item) => item.status === "open");
  assert.ok(finding, "vulnerable fixture must expose a finding for the documented fix-contract path");
  const contract = JSON.parse(run(["fix-contract", "--scan", vulnerable.scanId, "--finding", finding.id, "--format", "json"]).stdout);
  assert.equal(contract.scanId, vulnerable.scanId);

  const interfaceQueue = report(run(["interface-queue", "--scan", vulnerable.scanId]), "interface queue");
  assert.equal(interfaceQueue.scanId, vulnerable.scanId);
  assert.equal(interfaceQueue.status, "review_required");
  assert.equal(interfaceQueue.networkRequests, 0);
  assert.equal(interfaceQueue.summary.reviewedRoutes, interfaceQueue.summary.eligibleRoutes + interfaceQueue.summary.excludedRoutes);

  const bolaDraft = report(run(["draft-bola", "--scan", vulnerable.scanId]), "BOLA draft");
  assert.equal(bolaDraft.scanId, vulnerable.scanId);
  assert.equal(bolaDraft.schemaVersion, "1.0.0");
  assert.equal(bolaDraft.status, "review_required");
  assert.match(bolaDraft.disclaimer, /performs no network requests/);

  const bolaSource = report(run([
    "scan",
    "test/fixtures/corpus/fastapi-authorization/positive-read",
    "--profile",
    "native",
    "--format",
    "json",
  ], 2), "selected BOLA source scan");
  const selectedQueue = report(run(["interface-queue", "--scan", bolaSource.scanId]), "selected BOLA queue");
  assert.equal(selectedQueue.candidates.length, 1);
  const selectedDraft = report(run([
    "draft-bola",
    "--scan",
    bolaSource.scanId,
    "--candidate",
    selectedQueue.candidates[0].id,
  ]), "selected BOLA draft");
  assert.equal(selectedDraft.schemaVersion, "1.1.0");
  assert.deepEqual(selectedDraft.selection.candidateIds, [selectedQueue.candidates[0].id]);
  assert.equal(selectedDraft.selection.queueId, selectedQueue.queueId);
  assert.equal(selectedDraft.selection.bindings[0].route, selectedQueue.candidates[0].route);
  assert.equal(selectedDraft.summary.total, 1);
  const selectedDraftPath = join(temporary, "selected-bola-draft.json");
  await writeFile(selectedDraftPath, `${JSON.stringify(selectedDraft)}\n`);
  const authorizationTemplate = report(run([
    "prepare-bola",
    "--draft",
    selectedDraftPath,
  ]), "BOLA authorization template");
  assert.equal(authorizationTemplate.status, "placeholders_required");
  assert.equal(authorizationTemplate.schemaVersion, "1.1.0");
  assert.equal(authorizationTemplate.networkRequests, 0);
  assert.equal(authorizationTemplate.selection.queueId, selectedQueue.queueId);
  assert.equal(authorizationTemplate.bindings[0].route, selectedQueue.candidates[0].route);
  assert.equal(authorizationTemplate.manifest.targetBaseUrl, "<SET_AUTHORIZED_BASE_URL>");

  const authorizationTemplatePath = join(temporary, "bola-authorization-template.json");
  const completedAuthorizationPath = join(temporary, "completed-bola-authorization.json");
  await writeFile(authorizationTemplatePath, `${JSON.stringify(authorizationTemplate)}\n`);
  await writeFile(completedAuthorizationPath, `${JSON.stringify(completedBolaManifest(authorizationTemplate))}\n`);
  const authorizationCheck = report(run([
    "check-bola",
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
  ]), "offline BOLA authorization check");
  assert.equal(authorizationCheck.schemaVersion, "1.2.0");
  assert.equal(authorizationCheck.status, "valid_review_required");
  assert.equal(authorizationCheck.templateBinding.status, "verified");
  assert.equal(authorizationCheck.templateBinding.templateId, authorizationTemplate.templateId);
  assert.equal(authorizationCheck.networkRequests, 0);
  assert.equal(authorizationCheck.environmentValuesRead, 0);
  assert.equal(authorizationCheck.dnsLookups, 0);
  assert.doesNotMatch(JSON.stringify(authorizationCheck), /127\.0\.0\.1|\/project\/detail|project_id/u);
  const authorizationCheckPath = join(temporary, "bola-authorization-check.json");
  await writeFile(authorizationCheckPath, `${JSON.stringify(authorizationCheck)}\n`);
  const activeWithoutCredentials = run([
    "verify-bola",
    "--authorization",
    completedAuthorizationPath,
    "--template",
    authorizationTemplatePath,
    "--check",
    authorizationCheckPath,
    "--confirm",
  ], 64);
  assert.equal(activeWithoutCredentials.stdout, "");
  assert.match(activeWithoutCredentials.stderr, /Both BOLA test-account usernames must be provided/u);
  const legacyAuthorizationCheck = report(run([
    "check-bola",
    "--authorization",
    "examples/authorization.bola.local.yml",
  ]), "legacy unbound BOLA authorization check");
  assert.equal(legacyAuthorizationCheck.schemaVersion, "1.0.0");
  assert.ok(!("templateBinding" in legacyAuthorizationCheck));
  const duplicateSelection = run([
    "draft-bola",
    "--scan",
    bolaSource.scanId,
    "--candidate",
    selectedQueue.candidates[0].id,
    "--candidate",
    selectedQueue.candidates[0].id,
  ], 64);
  assert.equal(duplicateSelection.stdout, "");
  assert.match(duplicateSelection.stderr, /duplicate interface candidate ID/u);

  const incomplete = report(run(["scan", "test/fixtures/safe", "--no-persist", "--format", "json"], 2), "full scan without engines");
  assert.equal(incomplete.decision, "incomplete");
  assert.ok(incomplete.coverage.some((item) => item.required && ["failed", "not_run", "partial"].includes(item.status)));

  const explicitNativeOnly = report(run(["scan", "test/fixtures/safe", "--native-only", "--no-persist", "--format", "json"]), "predeploy profile with external engines disabled");
  assert.equal(explicitNativeOnly.profileName, "predeploy");
  assert.ok(explicitNativeOnly.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine)).every((item) => item.status === "not_run" && !item.required));
  assert.deepEqual(explicitNativeOnly.policy.relaxations, ["external_engines_disabled"]);

  const policyTarget = join(temporary, "policy-target");
  const trustedPolicy = join(temporary, "trusted-policy.yml");
  await mkdir(policyTarget);
  await writeFile(join(policyTarget, "index.ts"), "console.log(refreshToken);\n");
  await writeFile(trustedPolicy, `schemaVersion: 1.1.0
policyId: docs-smoke
expiresAt: 2099-12-31T23:59:59Z
profile: predeploy
requiredEngines: [gitleaks, opengrep, trivy]
gate:
  minimumSeverity: high
  includeInferred: false
  requireNoSuppressions: false
routeSecurityBaseline:
  minimumSeverity: high
  includeInferred: false
  requireComplete: true
rules:
  required: [privacy.sensitive-logging]
  block: [privacy.sensitive-logging]
suppressions: []
`);
  const policyReport = report(run(["scan", policyTarget, "--policy", trustedPolicy, "--no-persist", "--format", "json"], 1), "trusted policy scan");
  assert.equal(policyReport.policy.source, "operator");
  assert.equal(policyReport.policy.policyId, "docs-smoke");

  const localGateState = join(temporary, "local-gate-state");
  const localGateArgs = ["local-gate", policyTarget, "--policy", trustedPolicy, "--state-dir", localGateState, "--format", "json"];
  const localGateFirstResult = run(localGateArgs, 1);
  const localGateFirst = report(localGateFirstResult, "local gate bootstrap");
  assert.equal(localGateFirst.decision, "block");
  assert.match(localGateFirstResult.stderr, /Local gate baseline initialized:/);
  assert.equal((await stat(localGateState)).mode & 0o077, 0);
  const localGateBaselinePath = join(localGateState, "baseline.json");
  const localGateBaseline = await readFile(localGateBaselinePath, "utf8");
  const localGateSecondResult = run(localGateArgs, 1);
  const localGateSecond = report(localGateSecondResult, "local gate rescan");
  assert.equal(localGateSecond.comparison.baselineScanId, localGateFirst.scanId);
  assert.match(localGateSecondResult.stderr, /Local gate baseline \(unchanged\):/);
  assert.equal(await readFile(localGateBaselinePath, "utf8"), localGateBaseline);

  const trustedRulePack = join(temporary, "trusted-rule-pack.yml");
  await writeFile(trustedRulePack, `schemaVersion: 1.0.0
packId: docs.smoke
description: Documentation smoke rule pack
rules:
  - ruleId: custom.docs.smoke.refresh-token-log
    title: Project token logging invariant failed
    description: A reviewed local literal identifies token logging.
    severity: high
    evidenceLevel: static_confirmed
    confidence: high
    cwe: [CWE-532]
    tags: [logging, custom-policy]
    remediation: Remove the token from the logging call.
    files:
      extensions: [.ts]
    match:
      containsAny: [console.log(refreshToken)]
`);
  const rulePackPreview = report(run(["rule-pack", "check", policyTarget, "--rule-pack", trustedRulePack, "--format", "json"]), "rule-pack selector preview");
  assert.equal(rulePackPreview.schemaVersion, "1.0.0");
  assert.equal(rulePackPreview.status, "complete");
  assert.equal(rulePackPreview.rulePacks[0].packId, "docs.smoke");
  assert.deepEqual(rulePackPreview.rulePacks[0].rules[0].selectedFiles, ["index.ts"]);
  assert.doesNotMatch(JSON.stringify(rulePackPreview), /console\.log\(refreshToken\)|trusted-rule-pack\.yml/);
  const rulePackReport = report(run(["scan", policyTarget, "--profile", "native", "--rule-pack", trustedRulePack, "--no-persist", "--format", "json"], 1), "declarative rule-pack scan");
  assert.equal(rulePackReport.rulePacks[0].packId, "docs.smoke");
  assert.ok(rulePackReport.signals.some((item) => item.ruleId === "custom.docs.smoke.refresh-token-log"));

  const mobileWithoutArtifact = report(run(["scan", "test/fixtures/corpus/react-native/near-miss", "--native-only", "--no-persist", "--format", "json"], 2), "predeploy mobile scan without an artifact");
  assert.equal(mobileWithoutArtifact.profileName, "predeploy");
  const artifactCoverage = mobileWithoutArtifact.coverage.find((item) => item.domain === "mobile-artifact-static");
  assert.equal(artifactCoverage?.status, "not_run");
  assert.equal(artifactCoverage?.required, true);

  const request = JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "tools/list",
    params: { _meta: { "io.modelcontextprotocol/protocolVersion": "2026-07-28" } },
  });
  const mcp = spawnSync(process.execPath, [cli, "mcp"], {
    cwd: repositoryRoot,
    env: environment,
    input: `${request}\n`,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(mcp.status, 0, mcp.stderr);
  const mcpResponse = JSON.parse(mcp.stdout);
  assert.deepEqual(mcpResponse.result.tools.map((tool) => tool.name), [
    "inspect_project",
    "run_predeploy_scan",
    "preview_rule_packs",
    "get_report",
    "create_fix_contract",
    "verify_fix",
  ]);
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "run_predeploy_scan").inputSchema.properties.policy.type, "string");
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "run_predeploy_scan").inputSchema.properties.confirmPolicySuppressions.type, "boolean");
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "run_predeploy_scan").inputSchema.properties.rulePacks.maxItems, 8);
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "preview_rule_packs").inputSchema.properties.rulePacks.minItems, 1);

  process.stdout.write(`Documentation smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
