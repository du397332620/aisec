import assert from "node:assert/strict";
import test from "node:test";
import { join } from "node:path";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import { createBolaDraftPlan } from "../src/web/bola-draft.js";
import { validateBolaDraftPlan } from "../src/core/schema-validation.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

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
  const express = draft.candidates.find((candidate) => candidate.path === "/document/detail");
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
