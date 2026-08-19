import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(repositoryRoot, "dist", "src", "cli.js");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const temporary = await mkdtemp(join(tmpdir(), "aisec-docs-smoke-"));
const environment = {
  ...process.env,
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

try {
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
    "--confirm-policy-suppressions",
    "target-owned `.aisec.yml` is ignored",
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
  assert.match(help, /--confirm-policy-suppressions/);
  assert.match(help, /terminal\|json\|html\|sarif\|ci\|github\|markdown/);
  assert.match(help, /verify-bola --authorization <manifest\.yml> --confirm/);
  assert.match(help, /draft-bola --scan <scan-id\|report\.json>/);
  const doctor = report(run(["doctor", "--json"]), "doctor");
  assert.equal(doctor.node, process.version);
  assert.deepEqual(doctor.engines.map((item) => item.source), ["invalid", "invalid", "invalid"]);

  const safe = report(run(["scan", "test/fixtures/safe", "--profile", "native", "--no-persist", "--format", "json"]), "safe fixture");
  assert.equal(safe.decision, "no_blockers_found");
  assert.equal(safe.profileName, "native");
  assert.equal(safe.coverage.find((item) => item.domain === "project-inventory")?.status, "complete");

  const vulnerable = report(run(["scan", "test/fixtures/vulnerable", "--profile", "native", "--format", "json"], 1), "vulnerable fixture");
  assert.equal(vulnerable.decision, "block");
  const stored = join(temporary, "data", "scans", `${vulnerable.scanId}.json`);
  await access(stored);
  const ci = report(run(["report", stored, "--format", "ci"]), "CI report");
  assert.equal(ci.schemaVersion, "1.0.0");
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
  assert.match(markdown, /## Policy/u);
  const finding = vulnerable.findings.find((item) => item.status === "open");
  assert.ok(finding, "vulnerable fixture must expose a finding for the documented fix-contract path");
  const contract = JSON.parse(run(["fix-contract", "--scan", vulnerable.scanId, "--finding", finding.id, "--format", "json"]).stdout);
  assert.equal(contract.scanId, vulnerable.scanId);

  const bolaDraft = report(run(["draft-bola", "--scan", vulnerable.scanId]), "BOLA draft");
  assert.equal(bolaDraft.scanId, vulnerable.scanId);
  assert.equal(bolaDraft.status, "review_required");
  assert.match(bolaDraft.disclaimer, /performs no network requests/);

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
  await writeFile(trustedPolicy, `schemaVersion: 1.0.0
policyId: docs-smoke
expiresAt: 2099-12-31T23:59:59Z
profile: predeploy
requiredEngines: [gitleaks, opengrep, trivy]
gate:
  minimumSeverity: high
  includeInferred: false
  requireNoSuppressions: false
rules:
  required: [privacy.sensitive-logging]
  block: [privacy.sensitive-logging]
suppressions: []
`);
  const policyReport = report(run(["scan", policyTarget, "--policy", trustedPolicy, "--no-persist", "--format", "json"], 1), "trusted policy scan");
  assert.equal(policyReport.policy.source, "operator");
  assert.equal(policyReport.policy.policyId, "docs-smoke");

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
    "get_report",
    "create_fix_contract",
    "verify_fix",
  ]);
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "run_predeploy_scan").inputSchema.properties.policy.type, "string");
  assert.equal(mcpResponse.result.tools.find((tool) => tool.name === "run_predeploy_scan").inputSchema.properties.confirmPolicySuppressions.type, "boolean");

  process.stdout.write(`Documentation smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
