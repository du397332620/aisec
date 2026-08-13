import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
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
    "## Beta capability matrix",
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
  assert.match(run(["--help"]).stdout, /--profile predeploy\|native/);
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
  const finding = vulnerable.findings.find((item) => item.status === "open");
  assert.ok(finding, "vulnerable fixture must expose a finding for the documented fix-contract path");
  const contract = JSON.parse(run(["fix-contract", "--scan", vulnerable.scanId, "--finding", finding.id, "--format", "json"]).stdout);
  assert.equal(contract.scanId, vulnerable.scanId);

  const incomplete = report(run(["scan", "test/fixtures/safe", "--no-persist", "--format", "json"], 2), "full scan without engines");
  assert.equal(incomplete.decision, "incomplete");
  assert.ok(incomplete.coverage.some((item) => item.required && ["failed", "not_run", "partial"].includes(item.status)));

  const explicitNativeOnly = report(run(["scan", "test/fixtures/safe", "--native-only", "--no-persist", "--format", "json"]), "predeploy profile with external engines disabled");
  assert.equal(explicitNativeOnly.profileName, "predeploy");
  assert.ok(explicitNativeOnly.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine)).every((item) => item.status === "not_run" && !item.required));

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

  process.stdout.write(`Documentation smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
