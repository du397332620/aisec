import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createFixContract } from "../src/core/contracts.js";
import { scanProject } from "../src/core/scan.js";
import { loadReport, reportPath, saveReport } from "../src/core/store.js";
import {
  validateAuthorizationManifestSchema,
  validateFixContract,
  validateScanReport,
} from "../src/core/schema-validation.js";
import { validateAuthorization } from "../src/web/authorization.js";
import { serializeReport } from "../src/reporters/index.js";
import { materializeFixture, SYNTHETIC_STRIPE_LIVE_KEY } from "./helpers/materialize-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

test("generated reports and fix contracts satisfy the complete public schemas", async () => {
  const fixture = await materializeFixture(join(fixtures, "vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_STRIPE_LIVE_KEY,
  }]);
  try {
    const { report } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    assert.equal(validateScanReport(report), report);
    const contract = createFixContract(report, report.findings[0]!.id);
    assert.equal(validateFixContract(contract), contract);

    const compatible = structuredClone(report);
    compatible.toolVersion = "0.1.0-beta.1+build.7";
    delete compatible.comparison;
    for (const signal of compatible.signals) {
      delete signal.metadata;
      delete signal.remediation;
    }
    assert.equal(validateScanReport(compatible), compatible, "optional 1.0.0 fields remain backward compatible");
  } finally {
    await fixture.cleanup();
  }
});

test("public schemas reject unsupported versions, unknown fields and invalid nested values", async () => {
  const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
  const unsupported = { ...report, schemaVersion: "2.0.0" };
  assert.throws(() => validateScanReport(unsupported), /ScanReport.*schemaVersion/);

  const unknown = { ...report, untrustedClaim: "secure" };
  assert.throws(() => validateScanReport(unknown), /ScanReport.*additional properties/);

  const invalidCoverage = structuredClone(report) as unknown as { coverage: Array<{ status: string }> };
  invalidCoverage.coverage[0]!.status = "clean";
  assert.throws(() => validateScanReport(invalidCoverage), /ScanReport.*coverage.*status/);

  const fixture = await materializeFixture(join(fixtures, "vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_STRIPE_LIVE_KEY,
  }]);
  try {
    const vulnerable = (await scanProject(fixture.path, { nativeOnly: true, persist: false })).report;
    const contract = createFixContract(vulnerable, vulnerable.findings[0]!.id);
    const invalidContract = structuredClone(contract);
    invalidContract.evidence[0]!.locations[0]!.line = 0;
    assert.throws(() => validateFixContract(invalidContract), /FixContract.*evidence.*locations.*line/);
  } finally {
    await fixture.cleanup();
  }
});

test("report persistence validates before write and after read", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-schema-store-"));
  const previous = process.env.AISEC_DATA_DIR;
  process.env.AISEC_DATA_DIR = temporary;
  try {
    const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
    await saveReport(report);
    assert.deepEqual(await loadReport(report.scanId), JSON.parse(await readFile(reportPath(report.scanId), "utf8")));

    const corrupted = { ...report, decision: "safe" };
    await writeFile(reportPath(report.scanId), `${JSON.stringify(corrupted)}\n`);
    await assert.rejects(() => loadReport(report.scanId), /ScanReport.*decision/);

    const invalidId = `scan_00000000-0000-4000-8000-000000000000`;
    const invalidPath = reportPath(invalidId);
    const invalidReport = { ...report, scanId: invalidId, unexpected: true };
    await assert.rejects(() => saveReport(invalidReport), /ScanReport.*additional properties/);
    await assert.rejects(() => readFile(invalidPath, "utf8"), /ENOENT/);
  } finally {
    if (previous === undefined) delete process.env.AISEC_DATA_DIR;
    else process.env.AISEC_DATA_DIR = previous;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("serialization and the CLI report command reject malformed reports", async (context) => {
  const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
  const invalid = { ...report, decision: "safe" };
  assert.throws(() => serializeReport(invalid as unknown as typeof report, "json"), /ScanReport.*decision/);

  const temporary = await mkdtemp(join(tmpdir(), "aisec-schema-cli-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const path = join(temporary, "invalid-report.json");
  await writeFile(path, `${JSON.stringify(invalid)}\n`);
  const cli = join(here, "..", "src", "cli.js");
  const child = spawn(process.execPath, [cli, "report", path, "--format", "json"], { stdio: ["ignore", "pipe", "pipe"] });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { stdout += chunk; });
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const [exitCode] = await once(child, "close");
  assert.equal(exitCode, 64);
  assert.equal(stdout, "");
  assert.match(stderr, /aisec: ScanReport does not match schema 1\.0\.0.*decision/);
});

test("authorization manifests use the public schema before semantic authorization checks", () => {
  const manifest = {
    schemaVersion: "1.0.0",
    targetBaseUrl: "http://127.0.0.1:3000/",
    environment: "local",
    ownedBy: "AIsec tests",
    allowedHosts: ["127.0.0.1"],
    dataPrefix: "aisec-schema-test",
    maxRequests: 6,
    acknowledgment: "I am authorized to test this target",
  } as const;
  assert.equal(validateAuthorizationManifestSchema(manifest), manifest);
  assert.equal(validateAuthorization(manifest).targetBaseUrl, manifest.targetBaseUrl);
  assert.throws(() => validateAuthorization({ ...manifest, productionOverride: true }), /AuthorizationManifest.*additional properties/);
  assert.throws(() => validateAuthorization({ ...manifest, accounts: [{ label: "test", usernameEnv: "lowercase", passwordEnv: "PASSWORD" }] }), /AuthorizationManifest.*usernameEnv/);
});

test("date-only suppressions remain valid in the 1.0.0 report contract", async () => {
  const fixture = await materializeFixture(join(fixtures, "vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_STRIPE_LIVE_KEY,
  }]);
  try {
    const initial = (await scanProject(fixture.path, { nativeOnly: true, persist: false })).report;
    const fingerprint = initial.findings[0]!.fingerprint;
    await writeFile(join(fixture.path, ".aisec.yml"), `version: 1\nsuppressions:\n  - fingerprint: ${fingerprint}\n    reason: temporary verified exception\n    expires: 2099-12-31\n`);
    const rescanned = (await scanProject(fixture.path, { nativeOnly: true, persist: false })).report;
    const suppressed = rescanned.findings.find((finding) => finding.fingerprint === fingerprint);
    assert.equal(suppressed?.status, "suppressed");
    assert.equal(suppressed.suppression?.expires, "2099-12-31");
    assert.equal(validateScanReport(rescanned), rescanned);
  } finally {
    await fixture.cleanup();
  }
});
