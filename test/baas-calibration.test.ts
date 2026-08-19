import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const calibrationScript = join(repositoryRoot, "scripts", "baas-calibration.mjs");
const sensitiveEnvironmentName = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;
const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";

function cleanEnvironment() {
  return { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name))), NO_UPDATE_NOTIFIER: "1" };
}

function runCalibration(args: string[]) {
  return spawnSync(process.execPath, [calibrationScript, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: cleanEnvironment(),
    maxBuffer: 2 * 1024 * 1024,
    timeout: 30_000,
    windowsHide: true,
  });
}

function runGit(root: string, args: string[]): string {
  const result = spawnSync("git", [
    "-c", "commit.gpgsign=false",
    "-c", `core.hooksPath=${nullDevice}`,
    "-c", "user.name=AIsec calibration fixture",
    "-c", "user.email=fixture.invalid@example.invalid",
    ...args,
  ], {
    cwd: root,
    encoding: "utf8",
    env: cleanEnvironment(),
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

test("BaaS calibration refuses implicit network access", () => {
  const result = runCalibration([]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /network download is disabled; pass --confirm-download/);
  assert.doesNotMatch(result.stderr, /fetching fixed commit/);
});

test("BaaS calibration validates a clean local fixed commit without executing it", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-baas-calibration-test-"));
  try {
    const project = join(temporary, "fixture");
    await mkdir(project);
    runGit(project, ["init", "--quiet"]);
    await writeFile(join(project, "storage.rules"), `
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /users/{userId}/{fileName} {
      allow create: if request.auth != null;
    }
  }
}
`);
    runGit(project, ["add", "storage.rules"]);
    runGit(project, ["commit", "--quiet", "-m", "calibration fixture"]);
    const commit = runGit(project, ["rev-parse", "HEAD"]);

    const manifestValue = {
      schemaVersion: 1,
      description: "Test-only static BaaS calibration; no exploitability or security claim.",
      targets: [{
        id: "fixture",
        repository: "https://github.com/example/aisec-baas-calibration-fixture.git",
        commit,
        scanPath: ".",
        sparsePaths: ["."],
        expected: {
          baas: ["Firebase"],
          coverageStatus: "complete",
          decision: "block",
          signals: [
            {
              ruleId: "firebase.authenticated-access-without-resource-check",
              count: 1,
              paths: [{ path: "storage.rules", count: 1 }],
            },
            {
              ruleId: "firebase.storage-upload-without-size-limit",
              count: 1,
              paths: [{ path: "storage.rules", count: 1 }],
            },
          ],
        },
      }],
    };
    const manifest = join(temporary, "manifest.json");
    await writeFile(manifest, `${JSON.stringify(manifestValue, null, 2)}\n`);
    const args = ["--manifest", manifest, "--local", `fixture=${project}`];
    const result = runCalibration(args);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout) as {
      passed: boolean;
      safety: Record<string, boolean>;
      results: Array<{ id: string; source: string; signals: unknown[]; coverageStatus: string; decision: string }>;
    };
    assert.equal(output.passed, true);
    assert.deepEqual(output.safety, {
      targetDependenciesInstalled: false,
      targetCodeExecuted: false,
      targetBackendRequestsSent: false,
      rulesDeployed: false,
      rawReportsPersisted: false,
    });
    assert.deepEqual(output.results, [{
      id: "fixture",
      repository: "https://github.com/example/aisec-baas-calibration-fixture.git",
      commit,
      scanPath: ".",
      source: "verified-local-repository",
      baas: ["Firebase"],
      coverageStatus: "complete",
      signals: manifestValue.targets[0]!.expected.signals,
      decision: "block",
    }]);
    assert.match(result.stderr, /scanning committed policy source without installing or running it/);

    const invalidManifest = join(temporary, "invalid-manifest.json");
    const invalidValue = structuredClone(manifestValue);
    invalidValue.targets[0]!.scanPath = "../outside";
    await writeFile(invalidManifest, `${JSON.stringify(invalidValue)}\n`);
    const invalid = runCalibration(["--manifest", invalidManifest, "--local", `fixture=${project}`]);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /scanPath must not contain dot or empty segments/);

    const unknownManifest = join(temporary, "unknown-manifest.json");
    await writeFile(unknownManifest, `${JSON.stringify({ ...manifestValue, unexpected: true })}\n`);
    const unknown = runCalibration(["--manifest", unknownManifest, "--local", `fixture=${project}`]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /manifest contains unknown field unexpected/);

    await writeFile(join(project, "untracked.rules"), "service firebase.storage {}\n");
    const dirty = runCalibration(args);
    assert.equal(dirty.status, 1);
    assert.match(dirty.stderr, /Git worktree is not clean/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
