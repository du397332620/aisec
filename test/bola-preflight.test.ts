import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import type { BolaAuthorizationCheck, BolaAuthorizationManifest, BolaAuthorizationTemplate, BolaVerificationAudit, ScanReport } from "../src/schema.js";
import {
  validateBolaAuthorizationCheck,
  validateBolaAuthorizationTemplate,
  validateBolaVerificationAudit,
  validateBolaVerificationReport,
} from "../src/core/schema-validation.js";
import { scanProject } from "../src/core/scan.js";
import { createSelectedBolaDraftPlan, createBolaDraftPlan } from "../src/web/bola-draft.js";
import { createInterfaceVerificationQueue } from "../src/web/interface-verification-queue.js";
import { validateBolaAuthorization } from "../src/web/authorization.js";
import { verifyBola } from "../src/web/bola.js";
import {
  MAX_BOLA_AUDIT_DOCUMENT_BYTES,
  auditBola,
  auditBolaVerification,
  loadBolaVerificationReport,
} from "../src/web/bola-audit.js";
import {
  MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
  assertBolaVerificationPreflight,
  checkBola,
  checkBolaAuthorization,
  createBolaAuthorizationTemplate,
  loadBolaAuthorizationCheck,
  loadBolaAuthorizationTemplate,
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

const LEGACY_TEMPLATE_REVIEW_CHECKLIST = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Create two distinct low-privilege accounts and pre-created synthetic owner fixtures; never enumerate identifiers.",
  "Replace every target, login, fixture, route/body and response-evidence placeholder after reviewing each binding.",
  "Confirm every case is read-only and ownerIdentity evidence is server-derived rather than request-echoed.",
  "Copy only the completed manifest object to a separate file and run check-bola before any active verification.",
];

const LEGACY_CHECK_REVIEW_REQUIREMENTS = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Provide two distinct low-privilege accounts through the declared environment variable names.",
  "Confirm every object identifier references only a pre-created synthetic owner fixture; never enumerate identifiers.",
  "Confirm every case is read-only and its response evidence is server-derived rather than request-echoed.",
  "Run verify-bola with --confirm only after this manual review.",
];

function legacyTemplate(value: BolaAuthorizationTemplate): BolaAuthorizationTemplate {
  const legacy = structuredClone(value);
  legacy.schemaVersion = "1.0.0";
  legacy.reviewChecklist = [...LEGACY_TEMPLATE_REVIEW_CHECKLIST];
  legacy.nextCommand = "aisec check-bola --authorization <completed-manifest.yml>";
  return legacy;
}

function legacyBoundCheck(value: BolaAuthorizationCheck): BolaAuthorizationCheck {
  const legacy = structuredClone(value);
  legacy.schemaVersion = "1.1.0";
  legacy.reviewRequired = [...LEGACY_CHECK_REVIEW_REQUIREMENTS];
  legacy.nextCommand = "aisec verify-bola --authorization <same-reviewed-manifest.yml> --confirm";
  return legacy;
}

function completedPath(
  path: string,
  objectValues: ReadonlyMap<string, string>,
): string {
  let completed = path;
  for (const [field, value] of objectValues) {
    completed = completed
      .replaceAll(`{${field}}`, encodeURIComponent(value))
      .replaceAll(`[${field}]`, encodeURIComponent(value))
      .replaceAll(`*${field}`, encodeURIComponent(value));
    completed = completed.replace(
      new RegExp(`:${field}(?=/|\\?|$)`, "gu"),
      encodeURIComponent(value),
    );
  }
  return completed;
}

function completedManifest(template: BolaAuthorizationTemplate): BolaAuthorizationManifest {
  const dataPrefix = "aisec-binding";
  return {
    schemaVersion: "1.0.0",
    targetBaseUrl: "https://staging.binding.invalid/",
    environment: "staging",
    ownedBy: "AIsec template binding tests",
    allowedHosts: ["staging.binding.invalid"],
    dataPrefix,
    maxRequests: template.manifest.maxRequests,
    accounts: [
      { label: "owner", usernameEnv: "AISEC_BOLA_BINDING_OWNER_USERNAME", passwordEnv: "AISEC_BOLA_BINDING_OWNER_PASSWORD" },
      { label: "other", usernameEnv: "AISEC_BOLA_BINDING_OTHER_USERNAME", passwordEnv: "AISEC_BOLA_BINDING_OTHER_PASSWORD" },
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
    cases: template.manifest.cases.map((item, index) => {
      const binding = template.bindings[index]!;
      const objectValues = new Map(binding.objectIdFields.map((field, fieldIndex) => [
        field,
        String(910_000 + index * 100 + fieldIndex),
      ]));
      const testDataLabel = `${dataPrefix}-case-${index + 1}`;
      return {
        id: item.id,
        method: item.method,
        path: completedPath(item.path, objectValues),
        readOnly: true as const,
        testDataLabel,
        ownerAccount: "owner",
        otherAccount: "other",
        ...(item.method === "POST"
          ? { body: Object.fromEntries([...objectValues].map(([field, value]) => [field, Number(value)])) }
          : {}),
        expected: binding.evidenceMode === "ownerIdentity"
          ? {
              match: "ownerIdentity" as const,
              statusCodes: [200],
              jsonPath: "data.fixture_owner",
            }
          : {
              match: "testDataLabel" as const,
              statusCodes: [200],
              jsonPath: "data.object_label",
              value: testDataLabel,
            },
      };
    }),
    acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data",
  };
}

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

async function templateForRoute(route: string): Promise<BolaAuthorizationTemplate> {
  const report = await fastApiReport();
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal?.metadata);
  signal.metadata.routes = [String(signal.metadata.route), route];
  const candidate = createInterfaceVerificationQueue(report).candidates.find((item) => item.route === route);
  assert.ok(candidate, `expected an interface candidate for ${route}`);
  return createBolaAuthorizationTemplate(createSelectedBolaDraftPlan(report, [candidate.id]));
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
    assert.equal(template.schemaVersion, "1.1.0");
    assert.match(template.templateId, /^bola_template_[0-9a-f]{16}$/u);
    assert.equal(template.draftId, draft.draftId);
    assert.equal(template.status, "placeholders_required");
    assert.equal(template.networkRequests, 0);
    assert.equal(
      template.nextCommand,
      "aisec check-bola --authorization <completed-manifest.yml> --template <same-template.json>",
    );
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

  const compatibleLegacy = legacyTemplate(template);
  assert.doesNotThrow(() => validateBolaAuthorizationTemplate(compatibleLegacy));
  const falselyLegacy = structuredClone(template);
  falselyLegacy.schemaVersion = "1.0.0";
  assert.throws(() => validateBolaAuthorizationTemplate(falselyLegacy), /BolaAuthorizationTemplate/u);
  const falselyCurrent = legacyTemplate(template);
  falselyCurrent.schemaVersion = "1.1.0";
  assert.throws(() => validateBolaAuthorizationTemplate(falselyCurrent), /BolaAuthorizationTemplate/u);

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

  const template = createBolaAuthorizationTemplate(draft);
  const templatePath = join(temporary, "template.json");
  await writeFile(templatePath, `${JSON.stringify(template)}\n`);
  assert.deepEqual(await loadBolaAuthorizationTemplate(templatePath), template);
  const templateYaml = join(temporary, "template.yml");
  await writeFile(templateYaml, "schemaVersion: 1.1.0\n");
  await assert.rejects(() => loadBolaAuthorizationTemplate(templateYaml), /valid JSON/u);
  const oversizedTemplate = join(temporary, "oversized-template.json");
  await writeFile(oversizedTemplate, "x".repeat(MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES + 1));
  await assert.rejects(() => loadBolaAuthorizationTemplate(oversizedTemplate), /exceeds 1048576 bytes/u);
  await assert.rejects(() => loadBolaAuthorizationTemplate(temporary), /regular file/u);

  const receipt = checkBolaAuthorization(completedManifest(template), template);
  const receiptPath = join(temporary, "check.json");
  await writeFile(receiptPath, `${JSON.stringify(receipt)}\n`);
  assert.deepEqual(await loadBolaAuthorizationCheck(receiptPath), receipt);
  const receiptYaml = join(temporary, "check.yml");
  await writeFile(receiptYaml, "schemaVersion: 1.2.0\n");
  await assert.rejects(() => loadBolaAuthorizationCheck(receiptYaml), /valid JSON/u);
  const oversizedReceipt = join(temporary, "oversized-check.json");
  await writeFile(oversizedReceipt, "x".repeat(MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES + 1));
  await assert.rejects(() => loadBolaAuthorizationCheck(oversizedReceipt), /exceeds 1048576 bytes/u);
  await assert.rejects(() => loadBolaAuthorizationCheck(temporary), /regular file/u);
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

test("check-bola binds a completed manifest to template provenance without credentials, DNS or HTTP", async () => {
  const template = createBolaAuthorizationTemplate(await selectedDraft());
  const manifest = completedManifest(template);
  const originalEnvironment = process.env;
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  process.env = new Proxy(originalEnvironment, {
    get(target, property, receiver) {
      if (typeof property === "string" && property.startsWith("AISEC_BOLA_BINDING_")) {
        throw new Error(`credential environment value was read: ${property}`);
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("bound check-bola must never call fetch");
  }) as typeof fetch;
  try {
    const first = checkBolaAuthorization(manifest, template);
    const second = checkBolaAuthorization(structuredClone(manifest), structuredClone(template));
    assert.equal(fetchCalls, 0);
    assert.equal(first.schemaVersion, "1.2.0");
    assert.equal(first.status, "valid_review_required");
    assert.equal(first.networkRequests, 0);
    assert.equal(first.environmentValuesRead, 0);
    assert.equal(first.dnsLookups, 0);
    assert.equal(first.checkId, second.checkId);
    assert.equal(first.templateBinding?.status, "verified");
    assert.equal(first.templateBinding?.templateId, template.templateId);
    assert.equal(first.templateBinding?.matchedCases, template.bindings.length);
    assert.equal(first.templateBinding?.queueId, template.selection.queueId);
    assert.equal(first.templateBinding?.exactCaseOrder, true);
    assert.equal(first.templateBinding?.exactRequestBudget, true);
    assert.equal(first.templateBinding?.routeTemplatesMatched, true);
    assert.equal(first.templateBinding?.concreteObjectIds, true);
    assert.match(first.templateBinding?.templateDigestSha256 ?? "", /^[0-9a-f]{64}$/u);
    assert.equal(
      first.nextCommand,
      "aisec verify-bola --authorization <same-reviewed-manifest.yml> --template <same-template.json> --check <this-check.json> --confirm",
    );
    assert.doesNotThrow(() => validateBolaAuthorizationCheck(first));
    assert.doesNotThrow(() => validateBolaAuthorizationCheck(legacyBoundCheck(first)));

    const forgedTotal = structuredClone(first);
    forgedTotal.templateBinding!.matchedCases += 1;
    assert.throws(() => validateBolaAuthorizationCheck(forgedTotal), /template binding totals are inconsistent/u);
    const forgedId = structuredClone(first);
    forgedId.checkId = "bola_check_0000000000000000";
    assert.throws(() => validateBolaAuthorizationCheck(forgedId), /stable check ID is inconsistent/u);
    const forgedSource = structuredClone(first);
    forgedSource.templateBinding!.projectId = "project_0000000000000000";
    assert.throws(() => validateBolaAuthorizationCheck(forgedSource), /stable check ID is inconsistent/u);
    const falselyLegacy = structuredClone(first);
    falselyLegacy.schemaVersion = "1.0.0";
    assert.throws(() => validateBolaAuthorizationCheck(falselyLegacy), /BolaAuthorizationCheck/u);
    const falselyPrevious = structuredClone(first);
    falselyPrevious.schemaVersion = "1.1.0";
    assert.throws(() => validateBolaAuthorizationCheck(falselyPrevious), /BolaAuthorizationCheck/u);
    const missingBinding = structuredClone(first);
    delete missingBinding.templateBinding;
    assert.throws(() => validateBolaAuthorizationCheck(missingBinding), /BolaAuthorizationCheck/u);

    const serialized = JSON.stringify(first);
    for (const forbidden of [
      "staging.binding.invalid",
      "/document/detail",
      "910000",
      "aisec-binding-case-1",
      "AISEC_BOLA_BINDING_OWNER_USERNAME",
      "data.fixture_owner",
      "report_id",
    ]) assert.ok(!serialized.includes(forbidden), `bound check output leaked ${forbidden}`);

    const legacyBound = checkBolaAuthorization(manifest, legacyTemplate(template));
    assert.equal(legacyBound.schemaVersion, "1.2.0");
    assert.equal(legacyBound.templateBinding?.templateId, template.templateId);
    assert.notEqual(legacyBound.checkId, first.checkId, "template digest must bind exact template version/content");
  } finally {
    process.env = originalEnvironment;
    globalThis.fetch = originalFetch;
  }
});

test("active BOLA preflight accepts current and legacy bound receipts but rejects drift", async () => {
  const template = createBolaAuthorizationTemplate(await selectedDraft());
  const manifest = completedManifest(template);
  const receipt = checkBolaAuthorization(manifest, template);
  assert.equal(assertBolaVerificationPreflight(manifest, template, receipt), receipt);
  const legacyReceipt = legacyBoundCheck(receipt);
  assert.equal(assertBolaVerificationPreflight(manifest, template, legacyReceipt), legacyReceipt);

  const changedTime = structuredClone(receipt);
  changedTime.checkedAt = "2020-01-01T00:00:00.000Z";
  assert.doesNotThrow(() => assertBolaVerificationPreflight(manifest, template, changedTime));

  const unbound = checkBolaAuthorization(manifest);
  assert.throws(
    () => assertBolaVerificationPreflight(manifest, template, unbound),
    /requires a template-bound authorization check/u,
  );

  const changedManifest = structuredClone(manifest);
  changedManifest.ownedBy = "Different authorization owner";
  assert.throws(
    () => assertBolaVerificationPreflight(changedManifest, template, receipt),
    /does not match the supplied manifest and template/u,
  );
  assert.throws(
    () => assertBolaVerificationPreflight(manifest, legacyTemplate(template), receipt),
    /does not match the supplied manifest and template/u,
  );

  const changedEnvironment = structuredClone(receipt);
  changedEnvironment.environment = "test";
  assert.throws(
    () => assertBolaVerificationPreflight(manifest, template, changedEnvironment),
    /does not match the supplied manifest and template/u,
  );
  const changedSummary = structuredClone(receipt);
  changedSummary.summary.getCases = 1;
  changedSummary.summary.postCases = 0;
  assert.throws(
    () => assertBolaVerificationPreflight(manifest, template, changedSummary),
    /does not match the supplied manifest and template/u,
  );
  const changedCaseIds = structuredClone(receipt);
  changedCaseIds.caseIds = ["different-case"];
  assert.throws(
    () => assertBolaVerificationPreflight(manifest, template, changedCaseIds),
    /does not match the supplied manifest and template/u,
  );
});

test("verify-bola checks bound files before credentials or requests and executes only a match", async (context) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-active-preflight-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const template = createBolaAuthorizationTemplate(await selectedDraft());
  const manifest = completedManifest(template);
  const receipt = checkBolaAuthorization(manifest, template);
  const manifestPath = join(temporary, "authorization.json");
  const templatePath = join(temporary, "template.json");
  const receiptPath = join(temporary, "check.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
  await writeFile(templatePath, `${JSON.stringify(template)}\n`);
  await writeFile(receiptPath, `${JSON.stringify(receipt)}\n`);

  let credentialReads = 0;
  let requests = 0;
  const throwingEnvironment = new Proxy({} as NodeJS.ProcessEnv, {
    get() {
      credentialReads += 1;
      throw new Error("credentials must not be read before the receipt matches");
    },
  });
  const throwingRequester = async (): Promise<never> => {
    requests += 1;
    throw new Error("requests must not run before the receipt matches");
  };

  await assert.rejects(
    () => verifyBola("missing-manifest", {
      confirmed: false,
      templatePath: "missing-template",
      checkPath: "missing-check",
      environment: throwingEnvironment,
      requester: throwingRequester,
    }),
    /requires --confirm/u,
  );

  const changedManifest = structuredClone(manifest);
  changedManifest.ownedBy = "Changed after preflight";
  await writeFile(manifestPath, `${JSON.stringify(changedManifest)}\n`);
  await assert.rejects(
    () => verifyBola(manifestPath, {
      confirmed: true,
      templatePath,
      checkPath: receiptPath,
      environment: throwingEnvironment,
      requester: throwingRequester,
    }),
    /does not match the supplied manifest and template/u,
  );
  assert.equal(credentialReads, 0);
  assert.equal(requests, 0);

  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
  await writeFile(templatePath, `${JSON.stringify(legacyTemplate(template))}\n`);
  await assert.rejects(
    () => verifyBola(manifestPath, {
      confirmed: true,
      templatePath,
      checkPath: receiptPath,
      environment: throwingEnvironment,
      requester: throwingRequester,
    }),
    /does not match the supplied manifest and template/u,
  );
  assert.equal(credentialReads, 0);
  assert.equal(requests, 0);

  await writeFile(templatePath, `${JSON.stringify(template)}\n`);
  const changedReceipt = structuredClone(receipt);
  changedReceipt.environment = "test";
  await writeFile(receiptPath, `${JSON.stringify(changedReceipt)}\n`);
  await assert.rejects(
    () => verifyBola(manifestPath, {
      confirmed: true,
      templatePath,
      checkPath: receiptPath,
      environment: throwingEnvironment,
      requester: throwingRequester,
    }),
    /does not match the supplied manifest and template/u,
  );
  assert.equal(credentialReads, 0);
  assert.equal(requests, 0);

  await writeFile(receiptPath, `${JSON.stringify(checkBolaAuthorization(manifest))}\n`);
  await assert.rejects(
    () => verifyBola(manifestPath, {
      confirmed: true,
      templatePath,
      checkPath: receiptPath,
      environment: throwingEnvironment,
      requester: throwingRequester,
    }),
    /requires a template-bound authorization check/u,
  );
  assert.equal(credentialReads, 0);
  assert.equal(requests, 0);

  await writeFile(receiptPath, `${JSON.stringify(receipt)}\n`);
  const credentials = {
    AISEC_BOLA_BINDING_OWNER_USERNAME: "fixture_owner",
    AISEC_BOLA_BINDING_OWNER_PASSWORD: "owner_password",
    AISEC_BOLA_BINDING_OTHER_USERNAME: "fixture_other",
    AISEC_BOLA_BINDING_OTHER_PASSWORD: "other_password",
  };
  const requester = async (input: { url: string; headers?: Record<string, string>; body?: string }) => {
    requests += 1;
    if (input.url.endsWith("/auth/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      const owner = login.username === "fixture_owner";
      return {
        url: input.url,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: {
          access_token: owner ? "owner-token" : "other-token",
          user_id: owner ? "owner-id" : "other-id",
        } }),
      };
    }
    if (input.headers?.authorization === "Bearer owner-token") {
      return {
        url: input.url,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: { fixture_owner: "owner-id" } }),
      };
    }
    return {
      url: input.url,
      status: 403,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ detail: "forbidden" }),
    };
  };
  const report = await verifyBola(manifestPath, {
    confirmed: true,
    templatePath,
    checkPath: receiptPath,
    environment: credentials,
    requester,
  });
  assert.equal(report.schemaVersion, "1.1.0");
  assert.equal(validateBolaVerificationReport(report), report);
  assert.equal(report.provenance?.status, "preflight_verified");
  assert.equal(report.provenance?.receipt.schemaVersion, receipt.schemaVersion);
  assert.equal(report.provenance?.receipt.checkId, receipt.checkId);
  assert.equal(report.provenance?.receipt.checkedAt, receipt.checkedAt);
  assert.equal(report.provenance?.manifest.digestSha256, receipt.manifestDigestSha256);
  assert.equal(report.provenance?.template.schemaVersion, template.schemaVersion);
  assert.equal(report.provenance?.template.templateId, template.templateId);
  assert.deepEqual(report.provenance?.authorization.caseIds, receipt.caseIds);
  assert.equal(report.requestCount, 4);
  assert.equal(report.cases[0]?.status, "protected");
  assert.equal(requests, 4);
  const serializedProvenance = JSON.stringify(report.provenance);
  assert.doesNotMatch(
    serializedProvenance,
    /staging\.binding\.invalid|\/auth\/login|\/private\/object|object_id|912345|AISEC_BOLA|fixture_owner|owner-token|owner-id|forbidden/u,
  );
  const serializedReport = JSON.stringify(report);
  for (const secret of [...Object.values(credentials), "owner-token", "other-token", "owner-id", "other-id", "forbidden"]) {
    assert.ok(!serializedReport.includes(secret), `active report must not contain ${secret}`);
  }

  const missingProvenance = structuredClone(report) as typeof report & { provenance?: unknown };
  delete missingProvenance.provenance;
  assert.throws(() => validateBolaVerificationReport(missingProvenance), /BolaVerificationReport.*provenance/u);
  const forgedReceipt = structuredClone(report);
  forgedReceipt.provenance!.receipt.checkId = "bola_check_0000000000000000";
  assert.throws(() => validateBolaVerificationReport(forgedReceipt), /receipt identity is inconsistent/u);
  const forgedCases = structuredClone(report);
  forgedCases.provenance!.authorization.caseIds = ["different-case"];
  assert.throws(() => validateBolaVerificationReport(forgedCases), /authorization provenance is inconsistent/u);
  const forgedBudget = structuredClone(report);
  forgedBudget.provenance!.authorization.summary.maxRequests = 3;
  assert.throws(() => validateBolaVerificationReport(forgedBudget), /BolaVerificationReport.*maxRequests|authorization provenance/u);
  const leakedTokenField = structuredClone(report) as typeof report & {
    provenance: NonNullable<typeof report.provenance> & { token?: string };
  };
  leakedTokenField.provenance.token = "must-not-be-recorded";
  assert.throws(() => validateBolaVerificationReport(leakedTokenField), /BolaVerificationReport.*additional properties.*token/u);

  await writeFile(receiptPath, `${JSON.stringify(legacyBoundCheck(receipt))}\n`);
  const legacyReport = await verifyBola(manifestPath, {
    confirmed: true,
    templatePath,
    checkPath: receiptPath,
    environment: credentials,
    requester,
  });
  assert.equal(legacyReport.schemaVersion, "1.1.0");
  assert.equal(legacyReport.provenance?.receipt.schemaVersion, "1.1.0");
  assert.equal(legacyReport.provenance?.receipt.checkId, receipt.checkId);
  assert.equal(validateBolaVerificationReport(legacyReport), legacyReport);
  assert.equal(requests, 8);
});

test("audit-bola proves exact retained artifact binding offline and emits only a sanitized receipt", async (context) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-offline-audit-"));
  context.after(() => rm(temporary, { recursive: true, force: true }));
  const template = createBolaAuthorizationTemplate(await selectedDraft());
  const manifest = completedManifest(template);
  const currentReceipt = checkBolaAuthorization(manifest, template);
  const legacyReceipt = legacyBoundCheck(currentReceipt);
  const manifestPath = join(temporary, "authorization.json");
  const templatePath = join(temporary, "template.json");
  const checkPath = join(temporary, "check.json");
  const reportPath = join(temporary, "report.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`);
  await writeFile(templatePath, `${JSON.stringify(template)}\n`);

  const credentials = {
    AISEC_BOLA_BINDING_OWNER_USERNAME: "audit_fixture_owner",
    AISEC_BOLA_BINDING_OWNER_PASSWORD: "audit_owner_password",
    AISEC_BOLA_BINDING_OTHER_USERNAME: "audit_fixture_other",
    AISEC_BOLA_BINDING_OTHER_PASSWORD: "audit_other_password",
  };
  let activeRequesterCalls = 0;
  const requester = async (input: { url: string; headers?: Record<string, string>; body?: string }) => {
    activeRequesterCalls += 1;
    if (input.url.endsWith("/auth/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      const owner = login.username === credentials.AISEC_BOLA_BINDING_OWNER_USERNAME;
      return {
        url: input.url,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: {
          access_token: owner ? "audit-owner-token" : "audit-other-token",
          user_id: owner ? "audit-owner-id" : "audit-other-id",
        } }),
      };
    }
    if (input.headers?.authorization === "Bearer audit-owner-token") {
      return {
        url: input.url,
        status: 200,
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: { fixture_owner: "audit-owner-id" } }),
      };
    }
    return {
      url: input.url,
      status: 403,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ detail: "audit-forbidden-response" }),
    };
  };

  await writeFile(checkPath, `${JSON.stringify(currentReceipt)}\n`);
  const currentReport = await verifyBola(manifestPath, {
    confirmed: true,
    templatePath,
    checkPath,
    environment: credentials,
    requester,
  });
  await writeFile(checkPath, `${JSON.stringify(legacyReceipt)}\n`);
  const legacyBoundReport = await verifyBola(manifestPath, {
    confirmed: true,
    templatePath,
    checkPath,
    environment: credentials,
    requester,
  });
  assert.equal(activeRequesterCalls, 8);
  await writeFile(checkPath, `${JSON.stringify(currentReceipt)}\n`);
  await writeFile(reportPath, `${JSON.stringify(currentReport)}\n`);
  assert.deepEqual(await loadBolaVerificationReport(reportPath), currentReport);

  const originalEnvironment = process.env;
  const originalFetch = globalThis.fetch;
  let credentialReads = 0;
  let fetchCalls = 0;
  process.env = new Proxy(originalEnvironment, {
    get(target, property, receiver) {
      if (typeof property === "string" && property.startsWith("AISEC_BOLA_")) {
        credentialReads += 1;
        throw new Error(`offline audit read credential environment value ${property}`);
      }
      return Reflect.get(target, property, receiver) as unknown;
    },
  });
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("audit-bola must never call fetch");
  }) as typeof fetch;
  try {
    const direct = auditBolaVerification(manifest, template, currentReceipt, currentReport);
    const loaded = await auditBola(manifestPath, {
      templatePath,
      checkPath,
      reportPath,
    });
    assert.equal(validateBolaVerificationAudit(direct), direct);
    assert.equal(validateBolaVerificationAudit(loaded), loaded);
    assert.equal(loaded.schemaVersion, "1.0.0");
    assert.equal(loaded.status, "artifacts_verified");
    assert.equal(loaded.auditId, direct.auditId);
    assert.equal(loaded.report.digestSha256, direct.report.digestSha256);
    assert.equal(loaded.report.summary.cases, 1);
    assert.equal(loaded.report.summary.protected, 1);
    assert.equal(loaded.report.summary.verifiedSignals, 0);
    assert.equal(loaded.report.requestCount, 4);
    assert.equal(loaded.report.requiredRequests, 4);
    assert.equal(loaded.report.authorizedMaxRequests, 4);
    assert.equal(loaded.receipt.schemaVersion, "1.2.0");
    assert.deepEqual(loaded.io, {
      environmentValuesRead: 0,
      dnsLookups: 0,
      requesterCalls: 0,
      networkRequests: 0,
    });

    const reorderedReport = Object.fromEntries(Object.entries(currentReport).reverse());
    const reorderedAudit = auditBolaVerification(manifest, template, currentReceipt, reorderedReport);
    assert.equal(reorderedAudit.report.digestSha256, direct.report.digestSha256);
    assert.equal(reorderedAudit.auditId, direct.auditId);

    const legacyAudit = auditBolaVerification(manifest, template, legacyReceipt, legacyBoundReport);
    assert.equal(legacyAudit.receipt.schemaVersion, "1.1.0");
    assert.notEqual(legacyAudit.report.digestSha256, direct.report.digestSha256);

    const serialized = JSON.stringify(loaded);
    for (const forbidden of [
      "staging.binding.invalid",
      "/document/detail",
      "910000",
      "aisec-binding-case-1",
      "AISEC_BOLA_BINDING_OWNER_USERNAME",
      "data.fixture_owner",
      "audit_fixture_owner",
      "audit_owner_password",
      "audit-owner-token",
      "audit-owner-id",
      "audit-forbidden-response",
      "cross-account request was denied",
    ]) assert.ok(!serialized.includes(forbidden), `offline audit leaked ${forbidden}`);
    assert.equal(credentialReads, 0);
    assert.equal(fetchCalls, 0);

    const changedProvenance = structuredClone(currentReport);
    changedProvenance.provenance!.receipt.checkedAt = "2020-01-01T00:00:00.000Z";
    assert.doesNotThrow(() => validateBolaVerificationReport(changedProvenance));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, changedProvenance),
      /provenance does not match/u,
    );

    const changedTarget = structuredClone(currentReport);
    changedTarget.target = "https://different-audit.invalid/";
    assert.doesNotThrow(() => validateBolaVerificationReport(changedTarget));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, changedTarget),
      /source fields do not match/u,
    );
    const changedAccounts = structuredClone(currentReport);
    changedAccounts.accounts.reverse();
    assert.doesNotThrow(() => validateBolaVerificationReport(changedAccounts));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, changedAccounts),
      /source fields do not match/u,
    );
    const changedPath = structuredClone(currentReport);
    changedPath.cases[0]!.path = "/different/object/910000";
    assert.doesNotThrow(() => validateBolaVerificationReport(changedPath));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, changedPath),
      /source fields differ at case index 0/u,
    );
    const changedLabel = structuredClone(currentReport);
    changedLabel.cases[0]!.testDataLabel = "aisec-forged-label";
    assert.doesNotThrow(() => validateBolaVerificationReport(changedLabel));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, changedLabel),
      /source fields differ at case index 0/u,
    );

    const legacyReport = structuredClone(currentReport) as typeof currentReport & { provenance?: unknown };
    legacyReport.schemaVersion = "1.0.0";
    delete legacyReport.provenance;
    assert.doesNotThrow(() => validateBolaVerificationReport(legacyReport));
    assert.throws(
      () => auditBolaVerification(manifest, template, currentReceipt, legacyReport),
      /requires a provenance-bound BolaVerificationReport 1\.1\.0/u,
    );

    const forgedAuditId = structuredClone(loaded);
    forgedAuditId.auditId = "bola_audit_0000000000000000";
    assert.throws(() => validateBolaVerificationAudit(forgedAuditId), /stable audit ID is inconsistent/u);
    const forgedReceiptTime = structuredClone(loaded);
    forgedReceiptTime.receipt.checkedAt = "2020-01-01T00:00:00.000Z";
    assert.throws(() => validateBolaVerificationAudit(forgedReceiptTime), /stable audit ID is inconsistent/u);
    const forgedSummary = structuredClone(loaded);
    forgedSummary.report.summary.protected = 0;
    assert.throws(() => validateBolaVerificationAudit(forgedSummary), /summary totals are inconsistent/u);
    const forgedRequestCount = structuredClone(loaded);
    forgedRequestCount.report.requestCount = 0;
    assert.throws(() => validateBolaVerificationAudit(forgedRequestCount), /request budget is inconsistent/u);
    const leakedAudit = structuredClone(loaded) as BolaVerificationAudit & { target?: string };
    leakedAudit.target = manifest.targetBaseUrl;
    assert.throws(() => validateBolaVerificationAudit(leakedAudit), /additional properties.*target/u);
  } finally {
    process.env = originalEnvironment;
    globalThis.fetch = originalFetch;
  }

  const invalidReportPath = join(temporary, "invalid-report.json");
  await writeFile(invalidReportPath, "schemaVersion: 1.1.0\n");
  await assert.rejects(() => loadBolaVerificationReport(invalidReportPath), /valid JSON/u);
  const oversizedReportPath = join(temporary, "oversized-report.json");
  await writeFile(oversizedReportPath, "x".repeat(MAX_BOLA_AUDIT_DOCUMENT_BYTES + 1));
  await assert.rejects(() => loadBolaVerificationReport(oversizedReportPath), /exceeds 1048576 bytes/u);
  await assert.rejects(() => loadBolaVerificationReport(temporary), /regular file/u);

  const cli = join(here, "..", "src", "cli.js");
  async function runAudit(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
    const child = spawn(process.execPath, [cli, ...args], {
      env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("AISEC_BOLA_"))),
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
  const audited = await runAudit([
    "audit-bola",
    "--authorization", manifestPath,
    "--template", templatePath,
    "--check", checkPath,
    "--report", reportPath,
  ]);
  assert.equal(audited.code, 0, audited.stderr);
  const auditedJson: unknown = JSON.parse(audited.stdout);
  assert.equal(validateBolaVerificationAudit(auditedJson), auditedJson);
  const missingReport = await runAudit([
    "audit-bola",
    "--authorization", manifestPath,
    "--template", templatePath,
    "--check", checkPath,
  ]);
  assert.equal(missingReport.code, 64);
  assert.match(missingReport.stderr, /--report is required/u);
  const duplicateReport = await runAudit([
    "audit-bola",
    "--authorization", manifestPath,
    "--template", templatePath,
    "--check", checkPath,
    "--report", reportPath,
    "--report", reportPath,
  ]);
  assert.equal(duplicateReport.code, 64);
  assert.match(duplicateReport.stderr, /accepts --report at most once/u);
  const unsupportedConfirm = await runAudit([
    "audit-bola",
    "--authorization", manifestPath,
    "--template", templatePath,
    "--check", checkPath,
    "--report", reportPath,
    "--confirm",
  ]);
  assert.equal(unsupportedConfirm.code, 64);
  assert.match(unsupportedConfirm.stderr, /does not support --confirm/u);
});

test("template binding accepts concrete GET route forms and rejects ambiguous route changes", async () => {
  for (const route of [
    "GET /document/{report_id}",
    "GET /document/:report_id",
    "GET /document/[report_id]",
    "GET /document/*report_id",
    "GET /document/detail?scope=owner&report_id={report_id}",
  ]) {
    const template = await templateForRoute(route);
    const manifest = completedManifest(template);
    const check = checkBolaAuthorization(manifest, template);
    assert.equal(check.templateBinding?.routeTemplatesMatched, true, route);
  }

  const repeatedTemplate = await templateForRoute("GET /document/{report_id}/detail/{report_id}");
  const repeatedManifest = completedManifest(repeatedTemplate);
  assert.doesNotThrow(() => checkBolaAuthorization(repeatedManifest, repeatedTemplate));
  repeatedManifest.cases[0]!.path = repeatedManifest.cases[0]!.path.replace(/\/detail\/[^/]+$/u, "/detail/999999");
  assert.throws(
    () => checkBolaAuthorization(repeatedManifest, repeatedTemplate),
    /repeats an object identifier with different values/u,
  );

  const getTemplate = await templateForRoute("GET /document/{report_id}");
  const extraSegment = completedManifest(getTemplate);
  extraSegment.cases[0]!.path += "/extra";
  assert.throws(() => checkBolaAuthorization(extraSegment, getTemplate), /route structure differs/u);
  const extraQuery = completedManifest(getTemplate);
  extraQuery.cases[0]!.path += "?scope=other";
  assert.throws(() => checkBolaAuthorization(extraQuery, getTemplate), /route structure differs/u);

  const unboundGetTemplate = await templateForRoute("GET /document/detail");
  assert.throws(
    () => checkBolaAuthorization(completedManifest(unboundGetTemplate), unboundGetTemplate),
    /GET object-ID fields differ/u,
    "a GET route without an object-ID placeholder cannot claim exact binding",
  );
});

test("template binding fails closed for case, method, route, object, evidence and budget drift", async () => {
  const template = createBolaAuthorizationTemplate(await selectedDraft());
  const base = completedManifest(template);

  const changedId = structuredClone(base);
  changedId.cases[0]!.id = "case_aaaaaaaaaaaaaaaa";
  assert.throws(() => checkBolaAuthorization(changedId, template), /case order or ID differs/u);

  const changedMethod = structuredClone(base);
  changedMethod.cases[0]!.method = "GET";
  delete changedMethod.cases[0]!.body;
  assert.throws(() => checkBolaAuthorization(changedMethod, template), /method or read-only declaration differs/u);

  const changedRoute = structuredClone(base);
  changedRoute.cases[0]!.path = "/document/query";
  assert.doesNotThrow(() => checkBolaAuthorization(changedRoute));
  assert.throws(() => checkBolaAuthorization(changedRoute, template), /static route differs/u);

  const changedBodyField = structuredClone(base);
  changedBodyField.cases[0]!.body = { other_id: 910_000 };
  assert.throws(() => checkBolaAuthorization(changedBodyField, template), /POST object-ID fields differ/u);
  const structuredObjectId = structuredClone(base);
  structuredObjectId.cases[0]!.body = { report_id: { value: 910_000 } };
  assert.throws(() => checkBolaAuthorization(structuredObjectId, template), /object identifier is not concrete/u);

  const changedEvidence = structuredClone(base);
  changedEvidence.cases[0]!.expected = {
    match: "testDataLabel",
    statusCodes: [200],
    jsonPath: "data.object_label",
    value: changedEvidence.cases[0]!.testDataLabel,
  };
  assert.throws(() => checkBolaAuthorization(changedEvidence, template), /evidence mode differs/u);

  const changedStatus = structuredClone(base);
  changedStatus.cases[0]!.expected.statusCodes = [201];
  assert.throws(() => checkBolaAuthorization(changedStatus, template), /status codes differ/u);
  const changedBudget = structuredClone(base);
  changedBudget.maxRequests += 1;
  assert.throws(() => checkBolaAuthorization(changedBudget, template), /request budget differs/u);
  const changedRoles = structuredClone(base);
  changedRoles.cases[0]!.ownerAccount = "other";
  changedRoles.cases[0]!.otherAccount = "owner";
  assert.throws(() => checkBolaAuthorization(changedRoles, template), /account roles differ/u);

  const report = await fastApiReport();
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal?.metadata);
  signal.metadata.routes = [String(signal.metadata.route), "GET /document/{report_id}"];
  const queue = createInterfaceVerificationQueue(report);
  const multiTemplate = createBolaAuthorizationTemplate(
    createSelectedBolaDraftPlan(report, queue.candidates.map((candidate) => candidate.id)),
  );
  const reordered = completedManifest(multiTemplate);
  reordered.cases.reverse();
  assert.throws(() => checkBolaAuthorization(reordered, multiTemplate), /case order or ID differs/u);

  const forgedTemplate = structuredClone(template);
  forgedTemplate.bindings[0]!.route = "POST /document/query";
  assert.throws(() => checkBolaAuthorization(base, forgedTemplate), /binding route is inconsistent/u);
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
  const gateTemplate = createBolaAuthorizationTemplate(await selectedDraft());
  const gateManifest = completedManifest(gateTemplate);
  const gateTemplatePath = join(temporary, "template.json");
  const gateCheckPath = join(temporary, "check.json");
  await writeFile(gateTemplatePath, `${JSON.stringify(gateTemplate)}\n`);
  await writeFile(gateCheckPath, `${JSON.stringify(checkBolaAuthorization(gateManifest, gateTemplate))}\n`);
  await assert.rejects(
    () => verifyBola(unresolvedPath, {
      confirmed: true,
      templatePath: gateTemplatePath,
      checkPath: gateCheckPath,
      environment: throwingEnvironment,
    }),
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
  const draft = await selectedDraft();
  await writeFile(draftPath, `${JSON.stringify(draft)}\n`);
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
  const template = JSON.parse(prepared.stdout) as BolaAuthorizationTemplate;
  assert.equal(template.status, "placeholders_required");
  assert.equal(template.schemaVersion, "1.1.0");
  const checked = await run(["check-bola", "--authorization", manifestPath]);
  assert.equal(checked.code, 0, checked.stderr);
  assert.equal(JSON.parse(checked.stdout).schemaVersion, "1.0.0");
  assert.equal(JSON.parse(checked.stdout).status, "valid_review_required");

  const templatePath = join(temporary, "template.json");
  const boundManifestPath = join(temporary, "bound-authorization.json");
  await writeFile(templatePath, `${JSON.stringify(template)}\n`);
  await writeFile(boundManifestPath, `${JSON.stringify(completedManifest(template))}\n`);
  const bound = await run([
    "check-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
  ]);
  assert.equal(bound.code, 0, bound.stderr);
  const boundCheck = JSON.parse(bound.stdout) as BolaAuthorizationCheck;
  assert.equal(boundCheck.schemaVersion, "1.2.0");
  assert.equal(boundCheck.templateBinding?.status, "verified");
  const boundCheckPath = join(temporary, "bound-check.json");
  await writeFile(boundCheckPath, `${JSON.stringify(boundCheck)}\n`);

  const unconfirmedVerify = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--check",
    boundCheckPath,
  ]);
  assert.equal(unconfirmedVerify.code, 64);
  assert.equal(unconfirmedVerify.stdout, "");
  assert.match(unconfirmedVerify.stderr, /requires --confirm/u);
  const missingVerifyCheck = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--confirm",
  ]);
  assert.equal(missingVerifyCheck.code, 64);
  assert.match(missingVerifyCheck.stderr, /--check is required/u);
  const missingVerifyTemplate = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--check",
    boundCheckPath,
    "--confirm",
  ]);
  assert.equal(missingVerifyTemplate.code, 64);
  assert.match(missingVerifyTemplate.stderr, /--template is required/u);
  const duplicateVerifyCheck = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--check",
    boundCheckPath,
    "--check",
    boundCheckPath,
    "--confirm",
  ]);
  assert.equal(duplicateVerifyCheck.code, 64);
  assert.match(duplicateVerifyCheck.stderr, /accepts --check at most once/u);
  const unsupportedVerifyFlag = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--check",
    boundCheckPath,
    "--confirm",
    "--unsafe",
  ]);
  assert.equal(unsupportedVerifyFlag.code, 64);
  assert.match(unsupportedVerifyFlag.stderr, /does not support --unsafe/u);

  const unboundCheckPath = join(temporary, "unbound-check.json");
  await writeFile(unboundCheckPath, `${JSON.stringify(checkBolaAuthorization(completedManifest(template)))}\n`);
  const unboundVerify = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--check",
    unboundCheckPath,
    "--confirm",
  ]);
  assert.equal(unboundVerify.code, 64);
  assert.equal(unboundVerify.stdout, "");
  assert.match(unboundVerify.stderr, /requires a template-bound authorization check/u);

  const matchedVerify = await run([
    "verify-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--check",
    boundCheckPath,
    "--confirm",
  ]);
  assert.equal(matchedVerify.code, 64);
  assert.equal(matchedVerify.stdout, "");
  assert.match(matchedVerify.stderr, /Both BOLA test-account usernames must be provided/u);

  const mismatch = await run([
    "check-bola",
    "--authorization",
    manifestPath,
    "--template",
    templatePath,
  ]);
  assert.equal(mismatch.code, 64);
  assert.equal(mismatch.stdout, "");
  assert.match(mismatch.stderr, /template binding/u);
  const duplicateTemplate = await run([
    "check-bola",
    "--authorization",
    boundManifestPath,
    "--template",
    templatePath,
    "--template",
    templatePath,
  ]);
  assert.equal(duplicateTemplate.code, 64);
  assert.match(duplicateTemplate.stderr, /accepts --template at most once/u);
  const missingTemplatePath = await run(["check-bola", "--authorization", boundManifestPath, "--template"]);
  assert.equal(missingTemplatePath.code, 64);
  assert.match(missingTemplatePath.stderr, /--template requires a file path/u);
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
