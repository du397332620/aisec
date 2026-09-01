import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const calibrationScript = join(repositoryRoot, "scripts", "fastapi-rbac-calibration.mjs");
const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";
const sensitiveEnvironmentName = /(?:^|_)(?:API_?KEY|TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?|AUTH)(?:_|$)/i;

function runCalibration(args: string[]) {
  return spawnSync(process.execPath, [calibrationScript, ...args], {
    cwd: repositoryRoot,
    encoding: "utf8",
    env: { ...Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name))), NO_UPDATE_NOTIFIER: "1" },
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
    env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !sensitiveEnvironmentName.test(name))),
    maxBuffer: 1024 * 1024,
    timeout: 10_000,
    windowsHide: true,
  });
  assert.equal(result.status, 0, `${result.stderr}\n${result.stdout}`);
  return result.stdout.trim();
}

test("FastAPI RBAC calibration refuses implicit network access", () => {
  const result = runCalibration([]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /network download is disabled; pass --confirm-download/);
  assert.doesNotMatch(result.stderr, /fetching fixed commit/);
});

test("FastAPI RBAC calibration validates a licensed clean fixed commit without executing it", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-fastapi-rbac-calibration-test-"));
  try {
    const project = join(temporary, "fixture");
    await mkdir(project);
    await mkdir(join(project, "app"));
    runGit(project, ["init", "--quiet"]);
    await writeFile(join(project, "LICENSE"), "MIT License\n");
    await writeFile(join(project, "app", "main.py"), `
from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {"ok": True}
`);
    runGit(project, ["add", "LICENSE", "app/main.py"]);
    runGit(project, ["commit", "--quiet", "-m", "calibration fixture"]);
    const commit = runGit(project, ["rev-parse", "HEAD"]);

    const manifest = join(temporary, "manifest.json");
    const manifestValue = {
      schemaVersion: 1,
      description: "Test-only static FastAPI calibration; no exploitability or security claim.",
      targets: [{
        id: "fixture",
        repository: "https://github.com/example/aisec-fastapi-calibration-fixture.git",
        commit,
        license: "MIT",
        licenseFile: "LICENSE",
        scanPath: "app",
        expected: {
          routeCount: 1,
          requiredRoutes: ["GET /health"],
          decision: "incomplete",
          coverage: [
            { domain: "fastapi-authentication", status: "complete" },
            { domain: "fastapi-object-authorization", status: "partial" },
            { domain: "fastapi-privileged-authorization", status: "partial" },
          ],
          fastapiFindings: [],
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
      results: Array<Record<string, unknown>>;
    };
    assert.equal(output.passed, true);
    assert.deepEqual(output.safety, {
      targetDependenciesInstalled: false,
      targetCodeImported: false,
      targetCodeExecuted: false,
      targetHttpRequestsSent: false,
      rawReportsPersisted: false,
    });
    assert.deepEqual(output.results, [{
      id: "fixture",
      repository: "https://github.com/example/aisec-fastapi-calibration-fixture.git",
      commit,
      license: "MIT",
      licenseFile: "LICENSE",
      scanPath: "app",
      source: "verified-local-repository",
      routeCount: 1,
      requiredRoutes: ["GET /health"],
      fastapiFindings: [],
      authenticationGapReasons: [],
      objectCapabilityMutations: [],
      requiredSignalCounts: [],
      coverage: [
        { domain: "fastapi-authentication", status: "complete" },
        { domain: "fastapi-object-authorization", status: "partial" },
        { domain: "fastapi-privileged-authorization", status: "partial" },
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
    assert.match(result.stderr, /scanning committed source without installing, importing, or running it/);

    const invalidManifest = join(temporary, "invalid-manifest.json");
    const invalidValue = structuredClone(manifestValue);
    invalidValue.targets[0]!.scanPath = "../outside";
    await writeFile(invalidManifest, `${JSON.stringify(invalidValue)}\n`);
    const invalid = runCalibration(["--manifest", invalidManifest, "--local", `fixture=${project}`]);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /scanPath must be a safe relative path/);

    const unknownManifest = join(temporary, "unknown-manifest.json");
    await writeFile(unknownManifest, `${JSON.stringify({ ...manifestValue, unexpected: true })}\n`);
    const unknown = runCalibration(["--manifest", unknownManifest, "--local", `fixture=${project}`]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /manifest contains unknown field unexpected/);

    const unsupportedReasonManifest = join(temporary, "unsupported-reason-manifest.json");
    const unsupportedReasonValue = {
      ...structuredClone(manifestValue),
      targets: [{
        ...structuredClone(manifestValue.targets[0]!),
        expected: {
          ...structuredClone(manifestValue.targets[0]!.expected),
          authenticationGapReasons: [{
            reason: "parser_guess",
            count: 1,
            routes: ["POST /admin"],
          }],
        },
      }],
    };
    await writeFile(unsupportedReasonManifest, `${JSON.stringify(unsupportedReasonValue)}\n`);
    const unsupportedReason = runCalibration([
      "--manifest", unsupportedReasonManifest,
      "--local", `fixture=${project}`,
    ]);
    assert.equal(unsupportedReason.status, 1);
    assert.match(unsupportedReason.stderr, /authenticationGapReasons\[0\]\.reason is unsupported/);

    const unsupportedCapabilityManifest = join(temporary, "unsupported-capability-manifest.json");
    const unsupportedCapabilityValue = {
      ...structuredClone(manifestValue),
      targets: [{
        ...structuredClone(manifestValue.targets[0]!),
        expected: {
          ...structuredClone(manifestValue.targets[0]!.expected),
          objectCapabilityMutations: [{
            route: "POST /objects/{object_id}/submit",
            identifierFields: ["object_id"],
            identifierSource: "path_parameter",
            entropyEvidence: "invented_entropy",
            lifecycleEvidence: "not_proven",
            oneTimeEvidence: "not_proven",
            mutationImpact: "generic_sensitive_state",
            analysisDepth: "handler_only",
          }],
        },
      }],
    };
    await writeFile(unsupportedCapabilityManifest, `${JSON.stringify(unsupportedCapabilityValue)}\n`);
    const unsupportedCapability = runCalibration([
      "--manifest", unsupportedCapabilityManifest,
      "--local", `fixture=${project}`,
    ]);
    assert.equal(unsupportedCapability.status, 1);
    assert.match(
      unsupportedCapability.stderr,
      /objectCapabilityMutations\[0\]\.entropyEvidence is unsupported/,
    );

    await writeFile(join(project, "untracked.py"), "drift = True\n");
    const dirty = runCalibration(args);
    assert.equal(dirty.status, 1);
    assert.match(dirty.stderr, /Git worktree is not clean/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
