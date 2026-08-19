import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { executableExists } from "../src/core/utils.js";
import { writeStoredZip } from "./helpers/write-stored-zip.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const calibrationScript = join(repositoryRoot, "scripts", "mobile-artifact-calibration.mjs");
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

test("mobile artifact calibration refuses implicit network access", () => {
  const result = runCalibration([]);
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /network download is disabled; pass --confirm-download/);
  assert.doesNotMatch(result.stderr, /downloading fixed/);
});

test("mobile artifact calibration verifies a local pinned binary without installing or executing it", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-mobile-calibration-test-"));
  try {
    const artifact = join(temporary, "fixture.apk");
    await writeStoredZip(artifact, {
      "classes.dex": Buffer.concat([
        Buffer.from([0x64, 0x65, 0x78, 0x0a, 0x00, 0xff]),
        Buffer.from("http://api.mobile-fixture.test/v1", "ascii"),
      ]),
    });
    const details = await stat(artifact);
    const digest = createHash("sha256").update(await readFile(artifact)).digest("hex");
    const commit = "1".repeat(40);
    const manifestValue = {
      schemaVersion: 1,
      description: "Test-only rule-specific calibration; no security or exploitability claim.",
      targets: [{
        id: "fixture-android",
        platform: "android",
        classification: "positive",
        project: "https://github.com/example/mobile-fixture",
        license: "MIT",
        licenseUrl: `https://github.com/example/mobile-fixture/blob/${commit}/LICENSE`,
        revision: commit,
        filename: "fixture.apk",
        sourceUrl: `https://raw.githubusercontent.com/example/mobile-fixture/${commit}/fixture.apk`,
        byteSize: details.size,
        sha256: digest,
        expected: {
          coverageStatus: "complete",
          artifactFindings: [{ ruleId: "artifact.cleartext-endpoint", count: 1 }],
        },
      }],
    };
    const manifest = join(temporary, "manifest.json");
    await writeFile(manifest, `${JSON.stringify(manifestValue, null, 2)}\n`);

    const args = ["--manifest", manifest, "--local", `fixture-android=${artifact}`];
    const result = runCalibration(args);
    assert.equal(result.status, 0, result.stderr);
    const output = JSON.parse(result.stdout) as {
      passed: boolean;
      safety: Record<string, boolean>;
      results: Array<Record<string, unknown>>;
    };
    assert.equal(output.passed, true);
    assert.deepEqual(output.safety, {
      artifactsInstalled: false,
      targetCodeExecuted: false,
      targetBuildsRun: false,
      targetHttpRequestsSent: false,
      archiveMembersExtractedToDisk: false,
      rawReportsPersisted: false,
      downloadedArtifactsRetained: false,
    });
    assert.deepEqual(output.results, [{
      id: "fixture-android",
      platform: "android",
      classification: "positive",
      project: "https://github.com/example/mobile-fixture",
      revision: commit,
      license: "MIT",
      byteSize: details.size,
      sha256: digest,
      source: "verified-local-artifact",
      coverageStatus: "complete",
      artifactFindings: [{ ruleId: "artifact.cleartext-endpoint", count: 1 }],
      decision: "block",
    }]);
    assert.match(result.stderr, /artifact is not installed or executed/);

    const wrongDigestManifest = join(temporary, "wrong-digest.json");
    const wrongDigest = structuredClone(manifestValue);
    wrongDigest.targets[0]!.sha256 = "0".repeat(64);
    await writeFile(wrongDigestManifest, `${JSON.stringify(wrongDigest)}\n`);
    const rejected = runCalibration(["--manifest", wrongDigestManifest, "--local", `fixture-android=${artifact}`]);
    assert.equal(rejected.status, 1);
    assert.match(rejected.stderr, /SHA-256 drifted/);

    const invalidUrlManifest = join(temporary, "invalid-url.json");
    const invalidUrl = structuredClone(manifestValue);
    invalidUrl.targets[0]!.sourceUrl = "http://example.invalid/fixture.apk";
    await writeFile(invalidUrlManifest, `${JSON.stringify(invalidUrl)}\n`);
    const invalid = runCalibration(["--manifest", invalidUrlManifest, "--local", `fixture-android=${artifact}`]);
    assert.equal(invalid.status, 1);
    assert.match(invalid.stderr, /sourceUrl must be a credential-free HTTPS URL/);

    const revisionDriftManifest = join(temporary, "revision-drift.json");
    const revisionDrift = structuredClone(manifestValue);
    const otherCommit = "2".repeat(40);
    revisionDrift.targets[0]!.revision = otherCommit;
    revisionDrift.targets[0]!.licenseUrl = `https://github.com/example/mobile-fixture/blob/${otherCommit}/LICENSE`;
    await writeFile(revisionDriftManifest, `${JSON.stringify(revisionDrift)}\n`);
    const revisionRejected = runCalibration(["--manifest", revisionDriftManifest, "--local", `fixture-android=${artifact}`]);
    assert.equal(revisionRejected.status, 1);
    assert.match(revisionRejected.stderr, /sourceUrl must use the declared revision/);

    const unknownManifest = join(temporary, "unknown.json");
    await writeFile(unknownManifest, `${JSON.stringify({ ...manifestValue, unexpected: true })}\n`);
    const unknown = runCalibration(["--manifest", unknownManifest, "--local", `fixture-android=${artifact}`]);
    assert.equal(unknown.status, 1);
    assert.match(unknown.stderr, /manifest contains unknown field unexpected/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
