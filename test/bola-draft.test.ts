import assert from "node:assert/strict";
import test from "node:test";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import { createBolaDraftPlan, createSelectedBolaDraftPlan } from "../src/web/bola-draft.js";
import { validateBolaDraftPlan } from "../src/core/schema-validation.js";
import { createInterfaceVerificationQueue } from "../src/web/interface-verification-queue.js";
import type { Finding, ScanReport, Signal } from "../src/schema.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

async function fastApiReadReport(): Promise<ScanReport> {
  return (await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
}

test("BOLA draft turns an open static read finding into a non-executable review template", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const draft = createBolaDraftPlan(report);
  assert.deepEqual(draft.summary, { total: 1, readCandidates: 1, mutationExcluded: 0, manualReview: 0 });
  const candidate = draft.candidates[0];
  assert.equal(candidate?.classification, "read_candidate");
  assert.equal(candidate?.method, "POST");
  assert.equal(candidate?.path, "/document/detail");
  assert.deepEqual(candidate?.objectIdFields, ["report_id"]);
  assert.equal(candidate?.suggestedEvidenceMode, "ownerIdentity");
  assert.deepEqual(candidate?.ownerIdentityFieldCandidates, ["user_id"]);
  assert.match(candidate?.evidenceSuggestionReason ?? "", /server-derived ownership field/);
  assert.deepEqual(candidate?.requestTemplate?.body, { report_id: "<SET_PRECREATED_OWNER_REPORT_ID>" });
  assert.equal(candidate?.expectedTemplate?.match, "ownerIdentity");
  assert.equal(candidate?.expectedTemplate?.jsonPath, "<REVIEW_JSON_PATH_TO_SERVER_DERIVED_OWNER_FIELD>");
  assert.ok(!("value" in (candidate?.expectedTemplate ?? {})));
  assert.equal(draft.status, "review_required");
  assert.match(draft.disclaimer, /performs no network requests/);
  assert.doesNotThrow(() => validateBolaDraftPlan(draft));
});

test("selected BOLA draft binds one same-report interface candidate without performing requests", async () => {
  const report = await fastApiReadReport();
  const before = structuredClone(report);
  const queue = createInterfaceVerificationQueue(report);
  const interfaceCandidate = queue.candidates[0];
  assert.ok(interfaceCandidate);
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("selected BOLA draft must never call fetch");
  }) as typeof fetch;
  try {
    const draft = createSelectedBolaDraftPlan(report, [interfaceCandidate.id]);
    assert.equal(fetchCalls, 0);
    assert.equal(draft.schemaVersion, "1.1.0");
    assert.deepEqual(draft.summary, { total: 1, readCandidates: 1, mutationExcluded: 0, manualReview: 0 });
    assert.deepEqual(draft.selection, {
      mode: "interface_queue",
      queueId: queue.queueId,
      queueCoverage: "complete",
      queueCoverageScope: "observed_route_cards_only",
      candidateIds: [interfaceCandidate.id],
      bindings: [{
        interfaceCandidateId: interfaceCandidate.id,
        bolaCandidateId: draft.candidates[0]!.id,
        signalId: interfaceCandidate.sources[0]!.signalId,
        route: interfaceCandidate.route,
      }],
    });
    assert.equal(draft.candidates[0]?.classification, "read_candidate");
    assert.deepEqual(draft.candidates[0]?.requestTemplate?.body, {
      report_id: "<SET_PRECREATED_OWNER_REPORT_ID>",
    });
    assert.match(draft.disclaimer, /performs no network requests/u);
    assert.doesNotThrow(() => validateBolaDraftPlan(draft));
    assert.deepEqual(report, before, "selected draft derivation must not mutate canonical evidence");

    const legacy = createBolaDraftPlan(report);
    assert.equal(legacy.schemaVersion, "1.0.0");
    assert.equal(legacy.selection, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("selected BOLA draft preserves the exact queue alias instead of the signal primary route", async () => {
  const report = await fastApiReadReport();
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal?.metadata);
  signal.metadata.routes = [String(signal.metadata.route), "GET /document/{report_id}"];
  const queue = createInterfaceVerificationQueue(report);
  const alias = queue.candidates.find((candidate) => candidate.route === "GET /document/{report_id}");
  assert.ok(alias);

  const draft = createSelectedBolaDraftPlan(report, [alias.id]);
  const candidate = draft.candidates[0];
  assert.equal(candidate?.method, "GET");
  assert.equal(candidate?.path, "/document/{report_id}");
  assert.equal(candidate?.requestTemplate?.method, "GET");
  assert.equal(candidate?.requestTemplate?.path, "/document/{report_id}");
  assert.equal(candidate?.requestTemplate?.body, undefined);
  assert.equal(draft.selection?.bindings[0]?.route, "GET /document/{report_id}");
  assert.notEqual(candidate?.id, createBolaDraftPlan(report).candidates[0]?.id);

  const both = createSelectedBolaDraftPlan(report, queue.candidates.map((candidate) => candidate.id));
  assert.equal(both.candidates.length, 2);
  assert.equal(new Set(both.selection?.bindings.map((binding) => binding.signalId)).size, 1);
  assert.doesNotThrow(() => validateBolaDraftPlan(both));
});

test("selected BOLA draft fails closed for invalid, excluded or incomplete selections", async () => {
  const report = await fastApiReadReport();
  const queue = createInterfaceVerificationQueue(report);
  const id = queue.candidates[0]!.id;
  assert.throws(() => createSelectedBolaDraftPlan(report, []), /one to nine candidate IDs/u);
  assert.throws(() => createSelectedBolaDraftPlan(report, [id, id]), /duplicate interface candidate ID/u);
  assert.throws(() => createSelectedBolaDraftPlan(report, ["interface_candidate_0000000000000000"]), /not an emitted eligible candidate/u);

  const tooMany = await fastApiReadReport();
  const tooManySignal = tooMany.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(tooManySignal?.metadata);
  tooManySignal.metadata.routes = Array.from({ length: 10 }, (_, index) => `GET /document/${index}/{report_id}`);
  const tooManyIds = createInterfaceVerificationQueue(tooMany).candidates.slice(0, 10).map((candidate) => candidate.id);
  assert.equal(tooManyIds.length, 10);
  assert.throws(() => createSelectedBolaDraftPlan(tooMany, tooManyIds), /one to nine candidate IDs/u);

  const mutation = (await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
  const excludedId = createInterfaceVerificationQueue(mutation).exclusions[0]!.id;
  assert.throws(() => createSelectedBolaDraftPlan(mutation, [excludedId]), /candidate ID is invalid/u);

  const multipleSources = await fastApiReadReport();
  const sourceSignal = multipleSources.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  const sourceFinding = multipleSources.findings.find((finding) => sourceSignal && finding.signalIds.includes(sourceSignal.id));
  assert.ok(sourceSignal);
  assert.ok(sourceFinding);
  const secondSignal: Signal = {
    ...structuredClone(sourceSignal),
    id: "sig_ffffffffffffffff",
    fingerprint: "f".repeat(64),
  };
  const secondFinding: Finding = {
    ...structuredClone(sourceFinding),
    id: "finding_ffffffffffffffff",
    fingerprint: "e".repeat(64),
    signalIds: [secondSignal.id],
  };
  multipleSources.signals.push(secondSignal);
  multipleSources.findings.push(secondFinding);
  const multipleSourceId = createInterfaceVerificationQueue(multipleSources).candidates[0]!.id;
  assert.throws(() => createSelectedBolaDraftPlan(multipleSources, [multipleSourceId]), /exactly one complete source/u);

  const truncatedFindings = await fastApiReadReport();
  const truncatedSignal = truncatedFindings.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  const truncatedFinding = truncatedFindings.findings.find((finding) => truncatedSignal && finding.signalIds.includes(truncatedSignal.id));
  assert.ok(truncatedSignal);
  assert.ok(truncatedFinding);
  truncatedFindings.findings = Array.from({ length: 21 }, (_, index): Finding => ({
    ...structuredClone(truncatedFinding),
    id: `finding_${index.toString(16).padStart(16, "0")}`,
    fingerprint: index.toString(16).padStart(64, "0"),
    signalIds: [truncatedSignal.id],
  }));
  const truncatedId = createInterfaceVerificationQueue(truncatedFindings).candidates[0]!.id;
  assert.throws(() => createSelectedBolaDraftPlan(truncatedFindings, [truncatedId]), /omits open finding IDs/u);
});

test("selected BOLA draft validator rejects forged selection bindings and version combinations", async () => {
  const report = await fastApiReadReport();
  const id = createInterfaceVerificationQueue(report).candidates[0]!.id;
  const draft = createSelectedBolaDraftPlan(report, [id]);

  const wrongCount = structuredClone(draft);
  wrongCount.summary.total = 2;
  assert.throws(() => validateBolaDraftPlan(wrongCount), /selected summary totals are inconsistent/u);

  const wrongRoute = structuredClone(draft);
  wrongRoute.selection!.bindings[0]!.route = "GET /forged";
  assert.throws(() => validateBolaDraftPlan(wrongRoute), /binding route is inconsistent/u);

  const wrongSignal = structuredClone(draft);
  wrongSignal.selection!.bindings[0]!.signalId = "sig_0000000000000000";
  assert.throws(() => validateBolaDraftPlan(wrongSignal), /binding signal is inconsistent/u);

  const wrongQueue = structuredClone(draft);
  wrongQueue.selection!.queueId = "interface_queue_0000000000000000";
  assert.throws(() => validateBolaDraftPlan(wrongQueue), /stable draft ID is inconsistent/u);

  const unsafeSource = structuredClone(draft);
  unsafeSource.candidates[0]!.source.location.path = "../outside.py";
  assert.throws(() => validateBolaDraftPlan(unsafeSource), /unsafe or non-normalized source path/u);

  const falselyLegacy = { ...draft, schemaVersion: "1.0.0" };
  assert.throws(() => validateBolaDraftPlan(falselyLegacy), /BolaDraftPlan.*selection/u);

  const missingSelection = structuredClone(draft) as Partial<typeof draft>;
  delete missingSelection.selection;
  assert.throws(() => validateBolaDraftPlan(missingSelection), /BolaDraftPlan.*selection/u);
});

test("BOLA draft excludes mutation routes and never emits request templates for them", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const draft = createBolaDraftPlan(report);
  assert.deepEqual(draft.summary, { total: 1, readCandidates: 0, mutationExcluded: 1, manualReview: 0 });
  const candidate = draft.candidates[0];
  assert.equal(candidate?.classification, "mutation_excluded");
  assert.equal(candidate?.path, "/document/delete");
  assert.equal(candidate?.suggestedEvidenceMode, "testDataLabel");
  assert.deepEqual(candidate?.ownerIdentityFieldCandidates, []);
  assert.equal(candidate?.requestTemplate, undefined);
  assert.equal(candidate?.expectedTemplate, undefined);
  assert.match(candidate?.reason ?? "", /state-changing marker delete/);
});

test("BOLA draft consumes Express and NestJS object-authorization evidence", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "node-api", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const draft = createBolaDraftPlan(report);
  assert.deepEqual(draft.summary, { total: 2, readCandidates: 2, mutationExcluded: 0, manualReview: 0 });
  const express = draft.candidates.find((candidate) => candidate.path === "/api/document/detail");
  assert.equal(express?.source.ruleId, "express.authorization.object-without-ownership-check");
  assert.deepEqual(express?.ownerIdentityFieldCandidates, ["user_id"]);
  assert.deepEqual(express?.requestTemplate?.body, { document_id: "<SET_PRECREATED_OWNER_DOCUMENT_ID>" });
  const nest = draft.candidates.find((candidate) => candidate.path === "/reports/detail");
  assert.equal(nest?.source.ruleId, "nestjs.authorization.object-without-ownership-check");
  assert.deepEqual(nest?.ownerIdentityFieldCandidates, ["tenantId"]);
  assert.deepEqual(nest?.requestTemplate?.body, { report_id: "<SET_PRECREATED_OWNER_REPORT_ID>" });
});

test("BOLA draft considers only open BOLA findings", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  report.findings = report.findings.map((finding) => ({
    ...finding,
    status: "suppressed" as const,
    suppression: { reason: "accepted for test", expires: "2099-01-01" },
  }));
  const draft = createBolaDraftPlan(report);
  assert.equal(draft.summary.total, 0);
  assert.deepEqual(draft.candidates, []);
});

test("BOLA draft falls back to a synthetic marker when no response owner field is visible", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal);
  signal.metadata = { ...signal.metadata, ownerIdentityFields: [] };
  const candidate = createBolaDraftPlan(report).candidates[0];
  assert.equal(candidate?.suggestedEvidenceMode, "testDataLabel");
  assert.deepEqual(candidate?.ownerIdentityFieldCandidates, []);
  assert.equal(candidate?.expectedTemplate?.jsonPath, "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>");
  assert.ok(candidate?.expectedTemplate && "value" in candidate.expectedTemplate);
  if (candidate?.expectedTemplate && "value" in candidate.expectedTemplate) assert.match(candidate.expectedTemplate.value, /^aisec-draft-/);
});

test("BOLA draft does not recommend an ownership field also supplied as the object id", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal);
  signal.metadata = { ...signal.metadata, objectIdFields: ["user_id"], ownerIdentityFields: ["user_id"] };
  const candidate = createBolaDraftPlan(report).candidates[0];
  assert.equal(candidate?.suggestedEvidenceMode, "testDataLabel");
  assert.deepEqual(candidate?.ownerIdentityFieldCandidates, []);
});

test("BOLA draft schema rejects executable-looking read candidates without placeholders", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const draft = createBolaDraftPlan(report);
  const invalid = structuredClone(draft) as unknown as { candidates: Array<{ requestTemplate?: { body?: Record<string, string> } }> };
  invalid.candidates[0]!.requestTemplate!.body!.report_id = "42";
  assert.throws(() => validateBolaDraftPlan(invalid), /BolaDraftPlan.*body.*pattern/);

  const invalidOwnerSuggestion = structuredClone(draft) as unknown as {
    candidates: Array<{ ownerIdentityFieldCandidates?: string[] }>;
  };
  invalidOwnerSuggestion.candidates[0]!.ownerIdentityFieldCandidates = [];
  assert.throws(() => validateBolaDraftPlan(invalidOwnerSuggestion), /BolaDraftPlan.*ownerIdentityFieldCandidates/);
});

test("BOLA draft schema remains compatible with previously stored synthetic-marker drafts", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const legacy = structuredClone(createBolaDraftPlan(report)) as unknown as {
    candidates: Array<{
      suggestedEvidenceMode?: string;
      ownerIdentityFieldCandidates?: string[];
      evidenceSuggestionReason?: string;
      expectedTemplate?: unknown;
    }>;
  };
  delete legacy.candidates[0]!.suggestedEvidenceMode;
  delete legacy.candidates[0]!.ownerIdentityFieldCandidates;
  delete legacy.candidates[0]!.evidenceSuggestionReason;
  legacy.candidates[0]!.expectedTemplate = {
    statusCodes: [200],
    jsonPath: "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>",
    value: "aisec-draft-document-detail",
  };
  assert.doesNotThrow(() => validateBolaDraftPlan(legacy));
});
