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
  validateBolaAuthorizationManifestSchema,
  validateBolaDraftPlan,
  validateFixContract,
  validateScanReport,
} from "../src/core/schema-validation.js";
import { validateAuthorization } from "../src/web/authorization.js";
import { validateBolaAuthorization } from "../src/web/authorization.js";
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

    const policyEra = structuredClone(report);
    policyEra.schemaVersion = "1.1.0";
    delete policyEra.rulePacks;
    assert.equal(validateScanReport(policyEra), policyEra, "legacy ScanReport 1.1.0 remains readable without rule-pack records");

    const routeComparisonEra = structuredClone(report);
    routeComparisonEra.schemaVersion = "1.3.0";
    assert.equal(validateScanReport(routeComparisonEra), routeComparisonEra, "legacy ScanReport 1.3.0 remains readable without route-security policy gates");

    const compatible = structuredClone(report);
    compatible.schemaVersion = "1.0.0";
    compatible.toolVersion = "0.1.0-beta.1+build.7";
    delete compatible.comparison;
    delete compatible.policy;
    delete compatible.rulePacks;
    for (const signal of compatible.signals) {
      delete signal.metadata;
      delete signal.remediation;
    }
    assert.equal(validateScanReport(compatible), compatible, "legacy ScanReport 1.0.0 remains readable without a policy record");
  } finally {
    await fixture.cleanup();
  }
});

test("public schemas reject unsupported versions, unknown fields and invalid nested values", async () => {
  const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
  const missingPolicy = structuredClone(report);
  delete missingPolicy.policy;
  assert.throws(() => validateScanReport(missingPolicy), /ScanReport.*policy/);

  const missingRulePacks = structuredClone(report);
  delete missingRulePacks.rulePacks;
  assert.throws(() => validateScanReport(missingRulePacks), /ScanReport.*rulePacks/);

  const legacyClaimingPolicy = structuredClone(report);
  legacyClaimingPolicy.schemaVersion = "1.0.0";
  assert.throws(() => validateScanReport(legacyClaimingPolicy), /ScanReport.*policy/);

  const concealedRelaxation = structuredClone(report);
  concealedRelaxation.policy!.relaxations = [];
  assert.throws(() => validateScanReport(concealedRelaxation), /inconsistent default policy relaxations/);

  const forgedDefaultGate = structuredClone(report);
  forgedDefaultGate.policy!.gate.minimumSeverity = "medium";
  assert.throws(() => validateScanReport(forgedDefaultGate), /must retain the built-in gate/);

  const forgedDefaultRouteGate = structuredClone(report);
  forgedDefaultRouteGate.policy!.routeSecurityBaseline = { minimumSeverity: "high", includeInferred: false, requireComplete: true };
  assert.throws(() => validateScanReport(forgedDefaultRouteGate), /cannot claim an operator route-security baseline gate/);
  const legacyRouteGate = structuredClone(forgedDefaultRouteGate);
  legacyRouteGate.schemaVersion = "1.3.0";
  assert.throws(() => validateScanReport(legacyRouteGate), /ScanReport.*routeSecurityBaseline/);

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

test("Python route-attribution metadata fails closed on unsupported or contradictory claims", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "python-dataflow", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const signal = report.signals.find((candidate) => candidate.ruleId === "python.dataflow.ssrf");
  assert.ok(signal?.metadata);

  const unsupported = structuredClone(report);
  const unsupportedSignal = unsupported.signals.find((candidate) => candidate.id === signal.id)!;
  unsupportedSignal.metadata!.routeAttributionStatus = "unattributed";
  unsupportedSignal.metadata!.routeAttributionReason = "target_claimed_safe";
  delete unsupportedSignal.metadata!.route;
  delete unsupportedSignal.metadata!.routes;
  delete unsupportedSignal.metadata!.handler;
  delete unsupportedSignal.metadata!.routeAttribution;
  delete unsupportedSignal.metadata!.routeCallDepth;
  assert.throws(() => validateScanReport(unsupported), /requires one supported reason/u);

  const contradictory = structuredClone(report);
  const contradictorySignal = contradictory.signals.find((candidate) => candidate.id === signal.id)!;
  contradictorySignal.metadata!.routeAttributionReason = "request_origin_not_proven";
  assert.throws(() => validateScanReport(contradictory), /requires route evidence without a gap reason/u);
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
  assert.match(stderr, /aisec: ScanReport does not match schema 1\.4\.0.*decision/);
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

test("BOLA authorization manifests use a separate strict public schema", () => {
  const manifest = {
    schemaVersion: "1.0.0",
    targetBaseUrl: "http://127.0.0.1:8000/",
    environment: "local",
    ownedBy: "AIsec tests",
    allowedHosts: ["127.0.0.1"],
    dataPrefix: "aisec-schema",
    maxRequests: 4,
    accounts: [
      { label: "owner", usernameEnv: "AISEC_BOLA_OWNER_USER", passwordEnv: "AISEC_BOLA_OWNER_PASSWORD" },
      { label: "other", usernameEnv: "AISEC_BOLA_OTHER_USER", passwordEnv: "AISEC_BOLA_OTHER_PASSWORD" },
    ],
    login: { path: "/user/login", usernameField: "username", passwordField: "password", successStatusCodes: [200], tokenJsonPath: "data.access_token", identityJsonPath: "data.user_id", tokenPrefix: "Bearer" },
    cases: [{
      id: "project-detail", method: "POST", path: "/project/detail", readOnly: true,
      testDataLabel: "aisec-schema-project", ownerAccount: "owner", otherAccount: "other",
      body: { project_id: 42 }, expected: { statusCodes: [200], jsonPath: "data.project_name", value: "aisec-schema-project" },
    }],
    acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data",
  } as const;
  assert.equal(validateBolaAuthorizationManifestSchema(manifest), manifest);
  assert.equal(validateBolaAuthorization(manifest).cases[0]?.id, "project-detail");
  const ownerIdentityManifest = {
    ...manifest,
    cases: [{
      ...manifest.cases[0],
      path: "/session/get",
      body: { session_id: 42 },
      expected: { match: "ownerIdentity", statusCodes: [200], jsonPath: "data.user_id" },
    }],
  } as const;
  assert.equal(validateBolaAuthorizationManifestSchema(ownerIdentityManifest), ownerIdentityManifest);
  assert.equal(validateBolaAuthorization(ownerIdentityManifest).cases[0]?.expected.match, "ownerIdentity");
  assert.throws(() => validateBolaAuthorization({ ...manifest, destructiveOverride: true }), /BolaAuthorizationManifest.*additional properties/);
});

test("target-owned suppressions are ignored and recorded in the 1.4.0 report contract", async () => {
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
    const finding = rescanned.findings.find((item) => item.fingerprint === fingerprint);
    assert.equal(finding?.status, "open");
    assert.equal(finding?.suppression, undefined);
    assert.equal(rescanned.policy?.source, "defaults");
    assert.equal(rescanned.policy?.targetConfiguration, "ignored");
    assert.equal(validateScanReport(rescanned), rescanned);
  } finally {
    await fixture.cleanup();
  }
});
