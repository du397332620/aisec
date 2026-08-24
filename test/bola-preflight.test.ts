import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import type { BolaAuthorizationManifest, ScanReport } from "../src/schema.js";
import {
  validateBolaAuthorizationCheck,
  validateBolaAuthorizationTemplate,
} from "../src/core/schema-validation.js";
import { scanProject } from "../src/core/scan.js";
import { createSelectedBolaDraftPlan, createBolaDraftPlan } from "../src/web/bola-draft.js";
import { createInterfaceVerificationQueue } from "../src/web/interface-verification-queue.js";
import { validateBolaAuthorization } from "../src/web/authorization.js";
import { verifyBola } from "../src/web/bola.js";
import {
  MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
  checkBola,
  checkBolaAuthorization,
  createBolaAuthorizationTemplate,
  prepareBola,
} from "../src/web/bola-preflight.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

const authorizationManifest: BolaAuthorizationManifest = {
  schemaVersion: "1.0.0",
  targetBaseUrl: "https://staging.preflight.invalid/",
  environment: "staging",
  ownedBy: "AIsec preflight tests",
  allowedHosts: ["staging.preflight.invalid"],
  dataPrefix: "aisec-preflight",
  maxRequests: 4,
  accounts: [
    { label: "owner", usernameEnv: "AISEC_BOLA_PREFLIGHT_OWNER_USERNAME", passwordEnv: "AISEC_BOLA_PREFLIGHT_OWNER_PASSWORD" },
    { label: "other", usernameEnv: "AISEC_BOLA_PREFLIGHT_OTHER_USERNAME", passwordEnv: "AISEC_BOLA_PREFLIGHT_OTHER_PASSWORD" },
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
  cases: [{
    id: "preflight-case",
    method: "POST",
    path: "/private/object/detail",
    readOnly: true,
    testDataLabel: "aisec-preflight-owner-object",
    ownerAccount: "owner",
    otherAccount: "other",
    body: { object_id: 912_345 },
    expected: {
      match: "testDataLabel",
      statusCodes: [200],
      jsonPath: "data.object_label",
      value: "aisec-preflight-owner-object",
    },
  }],
  acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data",
};

async function fastApiReport(): Promise<ScanReport> {
  return (await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
}

async function selectedDraft(): Promise<ReturnType<typeof createSelectedBolaDraftPlan>> {
  const report = await fastApiReport();
  const candidate = createInterfaceVerificationQueue(report).candidates[0];
  assert.ok(candidate);
  return createSelectedBolaDraftPlan(report, [candidate.id]);
}

test("prepare-bola converts a selected draft into a bound non-executable template without requests", async () => {
  const draft = await selectedDraft();
  const before = structuredClone(draft);
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("prepare-bola must never call fetch");
  }) as typeof fetch;
  try {
    const template = createBolaAuthorizationTemplate(draft);
    assert.equal(fetchCalls, 0);
    assert.equal(template.schemaVersion, "1.0.0");
    assert.match(template.templateId, /^bola_template_[0-9a-f]{16}$/u);
    assert.equal(template.draftId, draft.draftId);
    assert.equal(template.status, "placeholders_required");
    assert.equal(template.networkRequests, 0);
    assert.deepEqual(template.selection, {
      mode: "interface_queue",
      queueId: draft.selection!.queueId,
      queueCoverage: draft.selection!.queueCoverage,
      queueCoverageScope: "observed_route_cards_only",
      candidateIds: draft.selection!.candidateIds,
    });
    assert.equal(template.manifest.targetBaseUrl, "<SET_AUTHORIZED_BASE_URL>");
    assert.equal(template.manifest.environment, "<SET_LOCAL_TEST_OR_STAGING>");
    assert.equal(template.manifest.maxRequests, 4);
    assert.equal(template.manifest.cases.length, 1);
    assert.deepEqual(template.manifest.cases[0]?.body, {
      report_id: "<SET_PRECREATED_OWNER_REPORT_ID>",
    });
    assert.equal(template.manifest.cases[0]?.expected.match, "ownerIdentity");
    assert.equal(template.bindings[0]?.route, "POST /document/detail");
    assert.deepEqual(template.bindings[0]?.objectIdFields, ["report_id"]);
    assert.equal(template.bindings[0]?.evidenceMode, "ownerIdentity");
    assert.doesNotThrow(() => validateBolaAuthorizationTemplate(template));
    assert.throws(() => validateBolaAuthorization(template.manifest), /BolaAuthorizationManifest|unresolved instruction placeholder/u);
    assert.deepEqual(draft, before, "template preparation must not mutate the selected draft");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("prepare-bola preserves GET route provenance and fails closed for legacy or forged inputs", async () => {
  const report = await fastApiReport();
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal?.metadata);
  signal.metadata.routes = [String(signal.metadata.route), "GET /document/{report_id}"];
  const queue = createInterfaceVerificationQueue(report);
  const alias = queue.candidates.find((candidate) => candidate.route === "GET /document/{report_id}");
  assert.ok(alias);
  const draft = createSelectedBolaDraftPlan(report, [alias.id]);
  const template = createBolaAuthorizationTemplate(draft);
  assert.equal(template.manifest.cases[0]?.method, "GET");
  assert.equal(template.manifest.cases[0]?.path, "/document/{report_id}");
  assert.ok(!("body" in template.manifest.cases[0]!));
  assert.equal(template.bindings[0]?.route, "GET /document/{report_id}");
  const twoRoutes = createBolaAuthorizationTemplate(
    createSelectedBolaDraftPlan(report, queue.candidates.map((candidate) => candidate.id)),
  );
  assert.equal(twoRoutes.bindings.length, 2);
  assert.equal(new Set(twoRoutes.bindings.map((binding) => binding.signalId)).size, 1);
  assert.doesNotThrow(() => validateBolaAuthorizationTemplate(twoRoutes));

  assert.throws(() => createBolaAuthorizationTemplate(createBolaDraftPlan(report)), /selected BolaDraftPlan 1\.1\.0/u);
  const forgedRoute = structuredClone(template);
  forgedRoute.bindings[0]!.route = "GET /forged";
  assert.throws(() => validateBolaAuthorizationTemplate(forgedRoute), /binding route is inconsistent/u);
  const resolvedCriticalPlaceholder = structuredClone(template);
  resolvedCriticalPlaceholder.manifest.targetBaseUrl = "https://example.test/" as typeof resolvedCriticalPlaceholder.manifest.targetBaseUrl;
  assert.throws(() => validateBolaAuthorizationTemplate(resolvedCriticalPlaceholder), /BolaAuthorizationTemplate.*targetBaseUrl/u);
  const forgedId = structuredClone(template);
  forgedId.templateId = "bola_template_0000000000000000";
  assert.throws(() => validateBolaAuthorizationTemplate(forgedId), /stable template ID is inconsistent/u);
  const forgedProject = structuredClone(template);
  forgedProject.projectId = "project_0000000000000000";
  assert.throws(() => validateBolaAuthorizationTemplate(forgedProject), /stable template ID is inconsistent/u);
});

test("preflight document loading is JSON-only for drafts and bounded before parsing", async (context) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-preflight-input-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const draft = await selectedDraft();
  const draftPath = join(temporary, "draft.json");
  await writeFile(draftPath, `${JSON.stringify(draft)}\n`);
  const loaded = await prepareBola(draftPath);
  const direct = createBolaAuthorizationTemplate(draft);
  assert.equal(loaded.templateId, direct.templateId);
  assert.deepEqual(
    { ...loaded, generatedAt: "<TIME>" },
    { ...direct, generatedAt: "<TIME>" },
  );

  const yamlPath = join(temporary, "draft.yml");
  await writeFile(yamlPath, "schemaVersion: 1.1.0\n");
  await assert.rejects(() => prepareBola(yamlPath), /valid JSON/u);

  const oversized = join(temporary, "oversized.json");
  await writeFile(oversized, "x".repeat(MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES + 1));
  await assert.rejects(() => prepareBola(oversized), /exceeds 1048576 bytes/u);
  await assert.rejects(() => prepareBola(temporary), /regular file/u);
});

test("check-bola validates a completed manifest without reading credentials, DNS or HTTP", async () => {
  const originalEnvironment = process.env;
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  process.env = new Proxy(originalEnvironment, {
    get(target, property, receiver) {
      if (typeof property === "string" && property.startsWith("AISEC_BOLA_PREFLIGHT_")) {
        throw new Error(`credential environment value was read: ${property}`);
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("check-bola must never call fetch");
  }) as typeof fetch;
  try {
    const first = checkBolaAuthorization(authorizationManifest);
    const second = checkBolaAuthorization(structuredClone(authorizationManifest));
    const firstOrder = structuredClone(authorizationManifest);
    firstOrder.cases[0]!.body = { z_object_id: 1, a_object_id: 2 };
    const secondOrder = structuredClone(authorizationManifest);
    secondOrder.cases[0]!.body = { a_object_id: 2, z_object_id: 1 };
    assert.equal(
      checkBolaAuthorization(firstOrder).manifestDigestSha256,
      checkBolaAuthorization(secondOrder).manifestDigestSha256,
      "canonical digest must not depend on JSON object insertion order",
    );
    assert.equal(fetchCalls, 0);
    assert.equal(first.schemaVersion, "1.0.0");
    assert.equal(first.status, "valid_review_required");
    assert.equal(first.networkRequests, 0);
    assert.equal(first.environmentValuesRead, 0);
    assert.equal(first.dnsLookups, 0);
    assert.deepEqual(first.summary, {
      cases: 1,
      requiredRequests: 4,
      maxRequests: 4,
      getCases: 0,
      postCases: 1,
      testDataLabelCases: 1,
      ownerIdentityCases: 0,
    });
    assert.equal(first.checkId, second.checkId);
    assert.equal(first.manifestDigestSha256, second.manifestDigestSha256);
    assert.match(first.manifestDigestSha256, /^[0-9a-f]{64}$/u);
    assert.doesNotThrow(() => validateBolaAuthorizationCheck(first));
    const forgedSummary = structuredClone(first);
    forgedSummary.summary.cases = 2;
    assert.throws(() => validateBolaAuthorizationCheck(forgedSummary), /summary totals are inconsistent/u);
    const forgedCheckId = structuredClone(first);
    forgedCheckId.checkId = "bola_check_0000000000000000";
    assert.throws(() => validateBolaAuthorizationCheck(forgedCheckId), /stable check ID is inconsistent/u);
    assert.throws(
      () => validateBolaAuthorizationCheck({ ...first, targetBaseUrl: authorizationManifest.targetBaseUrl }),
      /BolaAuthorizationCheck.*additional properties/u,
    );
    const serialized = JSON.stringify(first);
    for (const forbidden of [
      "staging.preflight.invalid",
      "/private/object/detail",
      "912345",
      "aisec-preflight-owner-object",
      "AISEC_BOLA_PREFLIGHT_OWNER_USERNAME",
      "data.object_label",
    ]) assert.ok(!serialized.includes(forbidden), `check output leaked ${forbidden}`);
  } finally {
    process.env = originalEnvironment;
    globalThis.fetch = originalFetch;
  }
});

test("check-bola rejects residual placeholders, route templates and malformed manifests", async (context) => {
  const unresolvedBody = structuredClone(authorizationManifest);
  unresolvedBody.cases[0]!.body = { object_id: "<SET_PRECREATED_OWNER_OBJECT_ID>" };
  assert.throws(() => checkBolaAuthorization(unresolvedBody), /unresolved instruction placeholder/u);
  assert.throws(() => validateBolaAuthorization(unresolvedBody), /unresolved instruction placeholder/u);
  const angleBracketData = structuredClone(authorizationManifest);
  angleBracketData.cases[0]!.body = { object_id: 912_345, response_format: "<section>" };
  assert.doesNotThrow(() => checkBolaAuthorization(angleBracketData));

  const unresolvedRoute = structuredClone(authorizationManifest);
  unresolvedRoute.cases[0]!.method = "GET";
  unresolvedRoute.cases[0]!.path = "/private/object/{object_id}";
  delete unresolvedRoute.cases[0]!.body;
  assert.throws(() => checkBolaAuthorization(unresolvedRoute), /unresolved route parameter/u);
  const unresolvedLogin = structuredClone(authorizationManifest);
  unresolvedLogin.login.path = "/tenant/{tenant_id}/login";
  assert.throws(() => checkBolaAuthorization(unresolvedLogin), /login\.path contains an unresolved route parameter/u);

  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-check-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const yamlPath = join(temporary, "authorization.yml");
  await writeFile(yamlPath, `schemaVersion: 1.0.0
targetBaseUrl: https://staging.preflight.invalid/
environment: staging
ownedBy: AIsec preflight tests
allowedHosts: [staging.preflight.invalid]
dataPrefix: aisec-preflight
maxRequests: 4
accounts:
  - { label: owner, usernameEnv: AISEC_BOLA_PREFLIGHT_OWNER_USERNAME, passwordEnv: AISEC_BOLA_PREFLIGHT_OWNER_PASSWORD }
  - { label: other, usernameEnv: AISEC_BOLA_PREFLIGHT_OTHER_USERNAME, passwordEnv: AISEC_BOLA_PREFLIGHT_OTHER_PASSWORD }
login:
  path: /auth/login
  usernameField: username
  passwordField: password
  successStatusCodes: [200]
  tokenJsonPath: data.access_token
  identityJsonPath: data.user_id
  tokenPrefix: Bearer
cases:
  - id: preflight-case
    method: POST
    path: /private/object/detail
    readOnly: true
    testDataLabel: aisec-preflight-owner-object
    ownerAccount: owner
    otherAccount: other
    body: { object_id: 912345 }
    expected: { match: testDataLabel, statusCodes: [200], jsonPath: data.object_label, value: aisec-preflight-owner-object }
acknowledgment: I am authorized to test this non-production target with two low-privilege accounts and pre-created test data
`);
  const check = await checkBola(yamlPath);
  assert.equal(check.status, "valid_review_required");

  const unresolvedPath = join(temporary, "unresolved.json");
  await writeFile(unresolvedPath, `${JSON.stringify(unresolvedBody)}\n`);
  let credentialReads = 0;
  const throwingEnvironment = new Proxy({} as NodeJS.ProcessEnv, {
    get() {
      credentialReads += 1;
      throw new Error("active verification must validate placeholders before reading credentials");
    },
  });
  await assert.rejects(
    () => verifyBola(unresolvedPath, true, throwingEnvironment),
    /unresolved instruction placeholder/u,
  );
  assert.equal(credentialReads, 0);

  const oversized = join(temporary, "oversized.yml");
  await writeFile(oversized, "x".repeat(MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES + 1));
  await assert.rejects(() => checkBola(oversized), /exceeds 1048576 bytes/u);
});

test("prepare-bola and check-bola CLI return strict JSON without confirmation or credentials", async (context) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-preflight-cli-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const draftPath = join(temporary, "draft.json");
  const manifestPath = join(temporary, "authorization.json");
  await writeFile(draftPath, `${JSON.stringify(await selectedDraft())}\n`);
  await writeFile(manifestPath, `${JSON.stringify(authorizationManifest)}\n`);
  const cli = join(here, "..", "src", "cli.js");

  async function run(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(process.execPath, [cli, ...args], {
      env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("AISEC_BOLA_PREFLIGHT_"))),
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => { stdout += chunk; });
    child.stderr.on("data", (chunk: string) => { stderr += chunk; });
    const [code] = await once(child, "close");
    return { code: code as number | null, stdout, stderr };
  }

  const prepared = await run(["prepare-bola", "--draft", draftPath]);
  assert.equal(prepared.code, 0, prepared.stderr);
  assert.equal(JSON.parse(prepared.stdout).status, "placeholders_required");
  const checked = await run(["check-bola", "--authorization", manifestPath]);
  assert.equal(checked.code, 0, checked.stderr);
  assert.equal(JSON.parse(checked.stdout).status, "valid_review_required");
  const unsupportedConfirmation = await run(["check-bola", "--authorization", manifestPath, "--confirm"]);
  assert.equal(unsupportedConfirmation.code, 64);
  assert.equal(unsupportedConfirmation.stdout, "");
  assert.match(unsupportedConfirmation.stderr, /check-bola does not support --confirm/u);

  const invalidPath = join(temporary, "invalid.json");
  const invalid = structuredClone(authorizationManifest);
  invalid.cases[0]!.body = { object_id: "<SET_PRECREATED_OWNER_OBJECT_ID>" };
  await writeFile(invalidPath, `${JSON.stringify(invalid)}\n`);
  const rejected = await run(["check-bola", "--authorization", invalidPath]);
  assert.equal(rejected.code, 64);
  assert.equal(rejected.stdout, "");
  assert.match(rejected.stderr, /unresolved instruction placeholder/u);
});
