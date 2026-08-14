import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const calibrationScript = join(repositoryRoot, "scripts", "node-api-calibration.mjs");

function runCalibration(args: string[]) {
  return spawnSync(process.execPath, [calibrationScript, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, NO_UPDATE_NOTIFIER: "1" },
    maxBuffer: 2 * 1024 * 1024,
    timeout: 30_000,
    windowsHide: true,
  });
}

function runGit(root: string, args: string[]): string {
  const result = spawnSync("git", [
    "-c", "commit.gpgsign=false",
    "-c", "core.hooksPath=/dev/null",
    "-c", "user.name=AIsec calibration fixture",
    "-c", "user.email=fixture.invalid@example.invalid",
    ...args,
  ], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

test("real-project calibration refuses implicit network access", () => {
  const result = runCalibration([]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /network download is disabled; pass --confirm-download/);
  assert.doesNotMatch(result.stderr, /fetching fixed commit/);
});

test("real-project calibration validates a clean local fixed commit without executing it", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-calibration-test-"));
  try {
    const project = join(temporary, "fixture");
    await mkdir(project);
    runGit(project, ["init", "--quiet"]);
    await writeFile(join(project, "package.json"), `${JSON.stringify({
      name: "aisec-calibration-fixture",
      private: true,
      dependencies: { express: "5.1.0" },
    }, null, 2)}\n`);
    await writeFile(join(project, "app.js"), `
import express from "express";
const app = express();
app.get("/health", (_request, response) => response.json({ ok: true }));
export default app;
`);
    runGit(project, ["add", "package.json", "app.js"]);
    runGit(project, ["commit", "--quiet", "-m", "calibration fixture"]);
    const commit = runGit(project, ["rev-parse", "HEAD"]);

    const manifest = join(temporary, "manifest.json");
    const manifestValue = {
      schemaVersion: 1,
      description: "Test-only static calibration; no exploitability or security claim.",
      targets: [{
        id: "fixture",
        repository: "https://github.com/example/aisec-calibration-fixture.git",
        commit,
        expected: {
          routeCount: 1,
          requiredRoutes: ["GET /health"],
          decision: "incomplete",
          coverage: [
            { domain: "mobile-source-config", status: "not_run" },
            { domain: "node-api-security", status: "partial" },
          ],
          nodeFindings: [],
          requiredSignalCounts: [],
        },
      }],
    };
    await writeFile(manifest, `${JSON.stringify(manifestValue, null, 2)}\n`);

    const args = ["--manifest", manifest, "--local", `fixture=${project}`];
    const result = runCalibration(args);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout) as {
      passed: boolean;
      safety: Record<string, boolean>;
      results: Array<{ id: string; source: string; routeCount: number; decision: string; nodeFindings: unknown[] }>;
    };
    assert.equal(output.passed, true);
    assert.deepEqual(output.safety, {
      targetDependenciesInstalled: false,
      targetCodeExecuted: false,
      targetHttpRequestsSent: false,
      rawReportsPersisted: false,
    });
    assert.deepEqual(output.results, [{
      id: "fixture",
      repository: "https://github.com/example/aisec-calibration-fixture.git",
      commit,
      source: "verified-local-repository",
      routeCount: 1,
      requiredRoutes: ["GET /health"],
      nodeFindings: [],
      requiredSignalCounts: [],
      coverage: [
        { domain: "mobile-source-config", status: "not_run" },
        { domain: "node-api-security", status: "partial" },
      ],
      decision: "incomplete",
      summary: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        attackPaths: 0,
        suppressed: 0,
      },
    }]);
    assert.match(result.stderr, /scanning committed source without installing or running it/);

    await writeFile(join(project, "untracked.js"), "export const drift = true;\n");
    const dirty = runCalibration(args);
    assert.equal(dirty.status, 1);
    assert.match(dirty.stderr, /Git worktree is not clean/);

    const invalidManifest = join(temporary, "invalid-manifest.json");
    const invalidValue = structuredClone(manifestValue);
    invalidValue.targets[0]!.repository = "file:///private/tmp/untrusted.git";
    await writeFile(invalidManifest, `${JSON.stringify(invalidValue)}\n`);
    const invalid = runCalibration(["--manifest", invalidManifest, "--local", `fixture=${project}`]);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /repository has an invalid value/);

    const unknownManifest = join(temporary, "unknown-manifest.json");
    await writeFile(unknownManifest, `${JSON.stringify({ ...manifestValue, unexpected: true })}\n`);
    const unknown = runCalibration(["--manifest", unknownManifest, "--local", `fixture=${project}`]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /manifest contains unknown field unexpected/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
