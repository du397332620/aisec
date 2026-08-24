import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import YAML from "yaml";
import { runLocalGate } from "../src/core/local-gate.js";
import { validateScanReport } from "../src/core/schema-validation.js";
import type { SecurityPolicy } from "../src/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const sensitiveEnvironmentName = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

function routePolicy(overrides: Partial<SecurityPolicy> = {}): SecurityPolicy {
  return {
    schemaVersion: "1.1.0",
    policyId: "local-route-gate",
    expiresAt: "2099-12-31T23:59:59Z",
    profile: "predeploy",
    requiredEngines: ["gitleaks", "opengrep", "trivy"],
    gate: { minimumSeverity: "high", includeInferred: false, requireNoSuppressions: false },
    routeSecurityBaseline: { minimumSeverity: "medium", includeInferred: false, requireComplete: true },
    rules: { required: ["privacy.sensitive-logging"], block: [] },
    suppressions: [],
    ...overrides,
  };
}

function routeSource(routes: readonly string[]): string {
  return `from fastapi import FastAPI

app = FastAPI()

${routes.map((route, index) => `@app.get("${route}")
async def handler_${index}():
    try:
        return load_value()
    except Exception as error:
        return {"message": str(error)}
`).join("\n")}`;
}

function unavailableEngineEnvironment(parent: string): Record<string, string> {
  return {
    AISEC_GITLEAKS_PATH: join(parent, "missing-gitleaks"),
    AISEC_OPENGREP_PATH: join(parent, "missing-opengrep"),
    AISEC_TRIVY_PATH: join(parent, "missing-trivy"),
  };
}

async function withUnavailableEngines<T>(parent: string, operation: () => Promise<T>): Promise<T> {
  const overrides = unavailableEngineEnvironment(parent);
  const previous = new Map(Object.keys(overrides).map((name) => [name, process.env[name]]));
  Object.assign(process.env, overrides);
  try {
    return await operation();
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

function childEnvironment(parent: string): NodeJS.ProcessEnv {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name)));
  return { ...environment, ...unavailableEngineEnvironment(parent) };
}

test("local gate pins the first baseline and never advances blocked route evidence", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-local-gate-life-"));
  try {
    const target = join(parent, "target");
    const stateDirectory = join(parent, "private-state");
    const policyPath = join(parent, "policy.yml");
    await mkdir(target);
    await writeFile(join(target, "main.py"), routeSource(["/legacy"]));
    await writeFile(policyPath, YAML.stringify(routePolicy()));

    const first = await withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory, policyPath }));
    assert.equal(first.mode, "initialized");
    assert.equal(first.exitCode, 2);
    assert.equal(first.report.decision, "incomplete");
    assert.match(first.report.decisionReasons.join("\n"), /requires a baseline comparison/u);
    assert.equal((await stat(stateDirectory)).mode & 0o077, 0);
    assert.equal((await stat(first.baselinePath)).mode & 0o077, 0);
    assert.equal((await stat(first.latestPath)).mode & 0o077, 0);
    const pinnedBaseline = await readFile(first.baselinePath, "utf8");

    await writeFile(join(target, "main.py"), routeSource(["/legacy", "/new"]));
    const second = await withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory, policyPath }));
    assert.equal(second.mode, "rescan");
    assert.equal(second.exitCode, 1);
    assert.equal(second.report.decision, "block");
    assert.ok(second.report.comparison?.routeSecurity?.new.some((entry) => entry.route === "GET /new"));
    assert.equal(await readFile(second.baselinePath, "utf8"), pinnedBaseline);
    assert.equal(validateScanReport(JSON.parse(await readFile(second.latestPath, "utf8"))).scanId, second.report.scanId);

    const third = await withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory, policyPath }));
    assert.equal(third.exitCode, 1);
    assert.ok(third.report.comparison?.routeSecurity?.new.some((entry) => entry.route === "GET /new"));
    assert.equal(await readFile(third.baselinePath, "utf8"), pinnedBaseline, "a repeated blocked check must not roll the finding into baseline debt");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("local gate rejects target-controlled, shared, ambiguous or mismatched state", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-local-gate-trust-"));
  try {
    const target = join(parent, "target");
    const otherTarget = join(parent, "other-target");
    const policyPath = join(parent, "policy.yml");
    await mkdir(target);
    await mkdir(otherTarget);
    await writeFile(join(target, "main.py"), routeSource(["/legacy"]));
    await writeFile(join(otherTarget, "main.py"), routeSource(["/other"]));
    await writeFile(policyPath, YAML.stringify(routePolicy()));

    const targetState = join(target, "state");
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: targetState, policyPath }),
      /outside the scanned target/u,
    );
    await assert.rejects(() => stat(targetState), /ENOENT/u);

    const targetStateReal = join(target, "state-real");
    const linkedState = join(parent, "linked-state");
    await mkdir(targetStateReal, { mode: 0o700 });
    await symlink(targetStateReal, linkedState);
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: linkedState, policyPath }),
      /outside the scanned target/u,
    );

    const sharedState = join(parent, "shared-state");
    await mkdir(sharedState, { mode: 0o700 });
    await chmod(sharedState, 0o755);
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: sharedState, policyPath }),
      /access only to its owner/u,
    );

    const unrelatedState = join(parent, "unrelated-state");
    await mkdir(unrelatedState, { mode: 0o700 });
    await writeFile(join(unrelatedState, "notes.txt"), "operator notes\n");
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: unrelatedState, policyPath }),
      /non-empty but has no recognized baseline/u,
    );
    assert.equal(await readFile(join(unrelatedState, "notes.txt"), "utf8"), "operator notes\n");

    const noGatePolicy = join(parent, "no-gate-policy.yml");
    const withoutRouteGate = routePolicy();
    delete withoutRouteGate.routeSecurityBaseline;
    await writeFile(noGatePolicy, YAML.stringify(withoutRouteGate));
    const unusedState = join(parent, "unused-state");
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: unusedState, policyPath: noGatePolicy }),
      /routeSecurityBaseline enabled/u,
    );
    await assert.rejects(() => stat(unusedState), /ENOENT/u);

    const invalidOptionsState = join(parent, "invalid-options-state");
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: invalidOptionsState, policyPath, maxFiles: 0 }),
      /maxFiles must be a positive safe integer/u,
    );
    await assert.rejects(() => stat(invalidOptionsState), /ENOENT/u);

    const pinnedState = join(parent, "pinned-state");
    await withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory: pinnedState, policyPath }));
    const pinnedBaselinePath = join(pinnedState, "baseline.json");
    const pinnedBaseline = await readFile(pinnedBaselinePath, "utf8");
    await assert.rejects(
      () => runLocalGate(otherTarget, { stateDirectory: pinnedState, policyPath }),
      /belongs to a different scan target/u,
    );
    assert.equal(await readFile(pinnedBaselinePath, "utf8"), pinnedBaseline);

    const pinnedLatestPath = join(pinnedState, "latest.json");
    await rm(pinnedLatestPath);
    await mkdir(pinnedLatestPath);
    await assert.rejects(
      () => withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory: pinnedState, policyPath })),
    );
    assert.deepEqual((await readdir(pinnedState)).filter((name) => name.startsWith(".latest-")), []);
    assert.equal(await readFile(pinnedBaselinePath, "utf8"), pinnedBaseline);
    await rm(pinnedLatestPath, { recursive: true });

    await writeFile(policyPath, YAML.stringify(routePolicy({ policyId: "changed-policy" })));
    await assert.rejects(
      () => withUnavailableEngines(parent, () => runLocalGate(target, { stateDirectory: pinnedState, policyPath })),
      /different operator policy digest/u,
    );
    assert.equal(await readFile(pinnedBaselinePath, "utf8"), pinnedBaseline);

    await writeFile(policyPath, YAML.stringify(routePolicy()));
    const savedBaseline = join(pinnedState, "saved-baseline.json");
    await rename(pinnedBaselinePath, savedBaseline);
    await symlink(savedBaseline, pinnedBaselinePath);
    await assert.rejects(
      () => runLocalGate(target, { stateDirectory: pinnedState, policyPath }),
      /real regular file/u,
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("local-gate CLI keeps JSON on stdout and exposes stable lifecycle exits", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-local-gate-cli-"));
  try {
    const target = join(parent, "target");
    const stateDirectory = join(parent, "state");
    const policyPath = join(parent, "policy.yml");
    await mkdir(target);
    await writeFile(join(target, "main.py"), routeSource(["/legacy"]));
    await writeFile(policyPath, YAML.stringify(routePolicy()));
    const cli = join(here, "..", "src", "cli.js");
    const environment = childEnvironment(parent);
    const args = ["local-gate", target, "--policy", policyPath, "--state-dir", stateDirectory, "--format", "json"];

    const first = spawnSync(process.execPath, [cli, ...args], { env: environment, encoding: "utf8", timeout: 30_000 });
    assert.equal(first.status, 2, first.stderr);
    assert.equal(validateScanReport(JSON.parse(first.stdout)).decision, "incomplete");
    assert.match(first.stderr, /Local gate baseline initialized:/u);
    assert.doesNotMatch(first.stdout, /Local gate baseline initialized:/u);

    const pinnedBaseline = await readFile(join(stateDirectory, "baseline.json"), "utf8");
    await writeFile(join(target, "main.py"), routeSource(["/legacy", "/new"]));
    const second = spawnSync(process.execPath, [cli, ...args], { env: environment, encoding: "utf8", timeout: 30_000 });
    assert.equal(second.status, 1, second.stderr);
    const report = validateScanReport(JSON.parse(second.stdout));
    assert.equal(report.decision, "block");
    assert.match(second.stderr, /Local gate baseline \(unchanged\):/u);
    assert.equal(await readFile(join(stateDirectory, "baseline.json"), "utf8"), pinnedBaseline);

    const unsupported = spawnSync(process.execPath, [cli, ...args, "--native-only"], { env: environment, encoding: "utf8", timeout: 30_000 });
    assert.equal(unsupported.status, 64);
    assert.equal(unsupported.stdout, "");
    assert.match(unsupported.stderr, /manages --native-only internally/u);

    const overwriteAttempt = spawnSync(process.execPath, [cli, ...args, "--output", join(stateDirectory, "baseline.json")], { env: environment, encoding: "utf8", timeout: 30_000 });
    assert.equal(overwriteAttempt.status, 64);
    assert.equal(overwriteAttempt.stdout, "");
    assert.match(overwriteAttempt.stderr, /manages --output internally/u);
    assert.equal(await readFile(join(stateDirectory, "baseline.json"), "utf8"), pinnedBaseline);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
