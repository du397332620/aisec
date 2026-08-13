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
  assert.deepEqual(candidate?.requestTemplate?.body, { report_id: "<SET_PRECREATED_OWNER_REPORT_ID>" });
  assert.equal(candidate?.expectedTemplate?.jsonPath, "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>");
  assert.match(candidate?.expectedTemplate?.value ?? "", /^aisec-draft-/);
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
  assert.equal(candidate?.requestTemplate, undefined);
  assert.equal(candidate?.expectedTemplate, undefined);
  assert.match(candidate?.reason ?? "", /state-changing marker delete/);
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
});
