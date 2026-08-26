import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import {
  validateInterfaceSecurityReview,
  validateInterfaceSecurityReviewCheck,
} from "../src/core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../src/core/utils.js";
import type {
  InterfaceSecurityAudit,
  InterfaceSecurityDisposition,
  InterfaceSecurityReview,
  ScanReport,
} from "../src/schema.js";
import { createInterfaceSecurityAudit } from "../src/web/interface-security-audit.js";
import {
  checkInterfaceSecurityReview,
  createInterfaceSecurityDisposition,
} from "../src/web/interface-security-review.js";
import {
  checkInterfaceReviewReceipt,
  checkSavedInterfaceSecurityReview,
  loadInterfaceSecurityReview,
  MAX_INTERFACE_SECURITY_REVIEW_BYTES,
} from "../src/web/interface-security-review-check.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(here, "..", "..");
const fixtures = join(repositoryRoot, "test", "fixtures");
const cli = join(repositoryRoot, "dist", "src", "cli.js");

async function fixtureReport(...parts: string[]): Promise<ScanReport> {
  return (await scanProject(join(fixtures, "corpus", ...parts), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
}

async function fixtureAudit(...parts: string[]): Promise<InterfaceSecurityAudit> {
  return createInterfaceSecurityAudit(await fixtureReport(...parts));
}

function acceptedDisposition(
  audit: InterfaceSecurityAudit,
  options: {
    preparedAt?: string;
    reviewedAt?: string;
    expiresAt?: string;
  } = {},
): InterfaceSecurityDisposition {
  const disposition = createInterfaceSecurityDisposition(audit);
  disposition.preparedAt = options.preparedAt ?? disposition.preparedAt;
  disposition.reviewedBy = "AIsec local receipt-check test operator";
  disposition.reviewedAt = options.reviewedAt ?? disposition.preparedAt;
  disposition.entries = disposition.entries.map((entry, index) => ({
    ...entry,
    decision: "accepted_risk",
    rationale: `Reviewed retained static evidence for local test entry ${index}.`,
    expiresAt: options.expiresAt ?? "2099-01-01T00:00:00.000Z",
  }));
  return disposition;
}

function retimeReview(
  source: InterfaceSecurityReview,
  checkedAt: string,
  status: InterfaceSecurityReview["status"],
  expiredDecisions: number,
): InterfaceSecurityReview {
  const review = structuredClone(source);
  review.checkedAt = checkedAt;
  review.status = status;
  review.summary.expiredDecisions = expiredDecisions;
  review.reviewId = stableId(
    "interface_security_review",
    review.schemaVersion,
    review.audit.schemaVersion,
    review.audit.auditId,
    review.audit.digestSha256,
    review.disposition.schemaVersion,
    review.disposition.digestSha256,
    review.checkedAt,
  );
  return validateInterfaceSecurityReview(review);
}

test("saved interface review check binds exact retained files, stays offline and minimizes output", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = acceptedDisposition(audit);
  const review = checkInterfaceSecurityReview(audit, disposition);
  const before = {
    audit: structuredClone(audit),
    disposition: structuredClone(disposition),
    review: structuredClone(review),
  };
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("saved interface review check must never call fetch");
  }) as typeof fetch;
  try {
    const result = checkSavedInterfaceSecurityReview(audit, disposition, review);
    assert.equal(result.status, "saved_review_verified");
    assert.equal(result.savedReview.reviewId, review.reviewId);
    assert.equal(result.savedReview.digestSha256, sha256(canonicalJson(review)));
    assert.equal(result.savedReview.status, "recorded");
    assert.equal(result.currentEvaluation.status, "recorded");
    assert.equal(result.currentEvaluation.expiredDecisions, 0);
    assert.equal(result.currentEvaluation.changedSinceSaved, false);
    assert.deepEqual(result.binding, {
      savedReceipt: true,
      exactAudit: true,
      exactDisposition: true,
      exactEntryOrder: true,
      exactSavedFields: true,
      exactReceiptDigest: true,
      currentExpiryReevaluated: true,
    });
    assert.equal(result.networkRequests, 0);
    assert.equal(result.dnsLookups, 0);
    assert.equal(result.credentialEnvironmentReads, 0);
    assert.equal(result.targetCodeExecutions, 0);
    assert.doesNotThrow(() => validateInterfaceSecurityReviewCheck(result));
    assert.deepEqual({ audit, disposition, review }, before);
    const serialized = JSON.stringify(result);
    assert.doesNotMatch(
      serialized,
      /"(?:reviewedBy|rationale|route|target|source|requestBody|responseBody|credentialValue)"\s*:/u,
    );
    assert.match(result.disclaimer, /not a security pass|not.*safe/iu);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(fetchCalls, 0);
});

test("saved review remains valid while current local expiry evaluation becomes incomplete", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = acceptedDisposition(audit, {
    preparedAt: "2020-01-01T00:00:00.000Z",
    reviewedAt: "2020-01-02T00:00:00.000Z",
    expiresAt: "2021-01-01T00:00:00.000Z",
  });
  const currentlyExpired = checkInterfaceSecurityReview(audit, disposition);
  assert.equal(currentlyExpired.status, "incomplete");
  const saved = retimeReview(
    currentlyExpired,
    "2020-01-03T00:00:00.000Z",
    "recorded",
    0,
  );

  const result = checkSavedInterfaceSecurityReview(audit, disposition, saved);
  assert.equal(result.savedReview.status, "recorded");
  assert.equal(result.savedReview.expiredDecisions, 0);
  assert.equal(result.currentEvaluation.status, "incomplete");
  assert.equal(result.currentEvaluation.expiredDecisions, 1);
  assert.equal(result.currentEvaluation.changedSinceSaved, true);
  assert.doesNotThrow(() => validateInterfaceSecurityReviewCheck(result));
});

test("saved incomplete review revalidates without inventing a complete outcome", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = createInterfaceSecurityDisposition(audit);
  const saved = checkInterfaceSecurityReview(audit, disposition);
  const result = checkSavedInterfaceSecurityReview(audit, disposition, saved);
  assert.equal(result.savedReview.status, "incomplete");
  assert.equal(result.currentEvaluation.status, "incomplete");
  assert.equal(result.currentEvaluation.changedSinceSaved, false);
});

test("saved review check rejects audit, disposition and saved-receipt drift", async () => {
  const audit = await fixtureAudit("node-api", "positive");
  const disposition = acceptedDisposition(audit);
  const saved = checkInterfaceSecurityReview(audit, disposition);

  const auditDrift = structuredClone(audit);
  auditDrift.generatedAt = "2099-01-01T00:00:00.000Z";
  assert.throws(
    () => checkSavedInterfaceSecurityReview(auditDrift, disposition, saved),
    /saved.*audit fields.*retained audit/iu,
  );

  const dispositionDrift = structuredClone(disposition);
  dispositionDrift.reviewedBy = "Different local operator";
  assert.throws(
    () => checkSavedInterfaceSecurityReview(audit, dispositionDrift, saved),
    /saved.*disposition fields.*retained disposition/iu,
  );

  const forgedId = structuredClone(saved);
  forgedId.reviewId = "interface_security_review_0000000000000000";
  assert.throws(
    () => checkSavedInterfaceSecurityReview(audit, disposition, forgedId),
    /stable review ID/iu,
  );

  const forgedDigest = structuredClone(saved);
  forgedDigest.disposition.digestSha256 = "0".repeat(64);
  assert.throws(
    () => checkSavedInterfaceSecurityReview(audit, disposition, forgedDigest),
    /disposition digest/iu,
  );

  const forgedStatus = structuredClone(saved);
  forgedStatus.status = "action_required";
  assert.throws(
    () => checkSavedInterfaceSecurityReview(audit, disposition, forgedStatus),
    /status is inconsistent/iu,
  );
});

test("saved review check rejects a valid but future-dated retained receipt", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const currentDisposition = acceptedDisposition(audit);
  const base = checkInterfaceSecurityReview(audit, currentDisposition);
  const futureDisposition = acceptedDisposition(audit, {
    preparedAt: "2098-01-01T00:00:00.000Z",
    reviewedAt: "2099-01-01T00:00:00.000Z",
    expiresAt: "2100-01-01T00:00:00.000Z",
  });
  const future = structuredClone(base);
  future.checkedAt = "2099-01-02T00:00:00.000Z";
  future.disposition = {
    schemaVersion: futureDisposition.schemaVersion,
    digestSha256: sha256(canonicalJson(futureDisposition)),
    preparedAt: futureDisposition.preparedAt,
    reviewedBy: futureDisposition.reviewedBy,
    reviewedAt: futureDisposition.reviewedAt,
  };
  future.entries = structuredClone(futureDisposition.entries);
  future.summary.expiredDecisions = 0;
  future.status = "recorded";
  future.reviewId = stableId(
    "interface_security_review",
    future.schemaVersion,
    future.audit.schemaVersion,
    future.audit.auditId,
    future.audit.digestSha256,
    future.disposition.schemaVersion,
    future.disposition.digestSha256,
    future.checkedAt,
  );
  assert.doesNotThrow(() => validateInterfaceSecurityReview(future));
  assert.throws(
    () => checkSavedInterfaceSecurityReview(audit, futureDisposition, future),
    /saved.*checkedAt.*future.*current local check/iu,
  );
});

test("saved review check validator fails closed on forged IDs and time-transition claims", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = acceptedDisposition(audit);
  const saved = checkInterfaceSecurityReview(audit, disposition);
  const result = checkSavedInterfaceSecurityReview(audit, disposition, saved);

  const forgedId = structuredClone(result);
  forgedId.receiptCheckId = "interface_security_review_check_0000000000000000";
  assert.throws(() => validateInterfaceSecurityReviewCheck(forgedId), /stable check ID/iu);

  const forgedChange = structuredClone(result);
  forgedChange.currentEvaluation.changedSinceSaved = true;
  assert.throws(() => validateInterfaceSecurityReviewCheck(forgedChange), /change flag/iu);

  const reversedExpiry = structuredClone(result);
  reversedExpiry.savedReview.expiredDecisions = 1;
  assert.throws(() => validateInterfaceSecurityReviewCheck(reversedExpiry), /expired-decision count.*decrease/iu);

  const contradictoryExpiry = structuredClone(result);
  contradictoryExpiry.currentEvaluation.expiredDecisions = 1;
  contradictoryExpiry.currentEvaluation.changedSinceSaved = true;
  assert.throws(() => validateInterfaceSecurityReviewCheck(contradictoryExpiry), /expired decisions require an incomplete status/iu);

  assert.throws(
    () => validateInterfaceSecurityReviewCheck({ ...result, targetUrl: "https://example.test" }),
    /InterfaceSecurityReviewCheck.*additional properties/u,
  );
});

test("saved review loader rejects malformed, oversized and non-regular files", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-review-receipt-input-test-"));
  try {
    const malformed = join(temporary, "malformed-review.json");
    const oversized = join(temporary, "oversized-review.json");
    const directory = join(temporary, "review-directory.json");
    await writeFile(malformed, "{bad-json}");
    await writeFile(oversized, "");
    await truncate(oversized, MAX_INTERFACE_SECURITY_REVIEW_BYTES + 1);
    await mkdir(directory);

    await assert.rejects(loadInterfaceSecurityReview(malformed), /must be valid JSON/u);
    await assert.rejects(loadInterfaceSecurityReview(oversized), /exceeds 2097152 bytes/u);
    await assert.rejects(loadInterfaceSecurityReview(directory), /must be a regular file/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("saved review receipt file API and CLI emit local artifacts and reject active flags", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-review-receipt-cli-test-"));
  try {
    const audit = await fixtureAudit("fastapi-authorization", "positive-read");
    const disposition = acceptedDisposition(audit);
    const review = checkInterfaceSecurityReview(audit, disposition);
    const auditPath = join(temporary, "audit.json");
    const dispositionPath = join(temporary, "disposition.json");
    const reviewPath = join(temporary, "review.json");
    const outputPath = join(temporary, "review-check.json");
    await writeFile(auditPath, `${JSON.stringify(audit)}\n`);
    await writeFile(dispositionPath, `${JSON.stringify(disposition)}\n`);
    await writeFile(reviewPath, `${JSON.stringify(review)}\n`);

    const api = await checkInterfaceReviewReceipt({
      auditPath,
      dispositionPath,
      reviewPath,
    });
    assert.equal(api.status, "saved_review_verified");

    const checked = spawnSync(process.execPath, [
      cli,
      "check-interface-review-receipt",
      "--audit",
      auditPath,
      "--disposition",
      dispositionPath,
      "--review",
      reviewPath,
      "--output",
      outputPath,
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(checked.stdout, "");
    assert.equal(JSON.parse(await readFile(outputPath, "utf8")).status, "saved_review_verified");

    const stdout = spawnSync(process.execPath, [
      cli,
      "check-interface-review-receipt",
      "--audit",
      auditPath,
      "--disposition",
      dispositionPath,
      "--review",
      reviewPath,
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(stdout.status, 0, stdout.stderr);
    assert.equal(JSON.parse(stdout.stdout).schemaVersion, "1.0.0");

    for (const args of [
      ["check-interface-review-receipt"],
      ["check-interface-review-receipt", "--audit", auditPath, "--disposition", dispositionPath],
      ["check-interface-review-receipt", "--audit", auditPath, "--disposition", dispositionPath, "--review", reviewPath, "--confirm"],
      ["check-interface-review-receipt", reviewPath, "--audit", auditPath, "--disposition", dispositionPath, "--review", reviewPath],
      ["check-interface-review-receipt", "--audit", auditPath, "--audit", auditPath, "--disposition", dispositionPath, "--review", reviewPath],
      ["check-interface-review-receipt", "--audit", auditPath, "--disposition", dispositionPath, "--review", reviewPath, "--target", "https://example.test"],
    ]) {
      const rejected = spawnSync(process.execPath, [cli, ...args], {
        encoding: "utf8",
        timeout: 30_000,
      });
      assert.equal(rejected.status, 64, `${args.join(" ")} must fail closed`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
