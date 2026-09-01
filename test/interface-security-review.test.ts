import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import {
  validateInterfaceSecurityAudit,
  validateInterfaceSecurityDisposition,
  validateInterfaceSecurityReview,
} from "../src/core/schema-validation.js";
import { canonicalJson, sha256 } from "../src/core/utils.js";
import type {
  InterfaceSecurityAudit,
  InterfaceSecurityDisposition,
  InterfaceSecurityDispositionDecision,
  ScanReport,
} from "../src/schema.js";
import { createInterfaceSecurityAudit } from "../src/web/interface-security-audit.js";
import {
  checkInterfaceReview,
  checkInterfaceSecurityReview,
  createInterfaceSecurityDisposition,
  loadInterfaceSecurityAudit,
  loadInterfaceSecurityDisposition,
  MAX_INTERFACE_SECURITY_AUDIT_BYTES,
  MAX_INTERFACE_SECURITY_DISPOSITION_BYTES,
  prepareInterfaceReview,
} from "../src/web/interface-security-review.js";

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

function completeDisposition(
  template: InterfaceSecurityDisposition,
  decision: Exclude<InterfaceSecurityDispositionDecision, "unreviewed">,
  options: { reviewedAt?: string; expiresAt?: string } = {},
): InterfaceSecurityDisposition {
  const disposition = structuredClone(template);
  disposition.reviewedBy = "AIsec local test operator";
  disposition.reviewedAt = options.reviewedAt ?? disposition.preparedAt;
  disposition.entries = disposition.entries.map((entry, index) => ({
    ...entry,
    decision,
    rationale: `Reviewed static evidence for test entry ${index}; this records disposition only.`,
    ...((decision === "false_positive" || decision === "accepted_risk")
      ? { expiresAt: options.expiresAt ?? "2099-01-01T00:00:00.000Z" }
      : {}),
  }));
  return disposition;
}

test("interface review template binds the exact audit and remains offline and non-mutating", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const before = structuredClone(audit);
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("interface review must never call fetch");
  }) as typeof fetch;
  try {
    const disposition = createInterfaceSecurityDisposition(audit);
    assert.equal(disposition.audit.schemaVersion, audit.schemaVersion);
    assert.equal(disposition.audit.auditId, audit.auditId);
    assert.equal(disposition.audit.digestSha256, sha256(canonicalJson(audit)));
    assert.equal(disposition.reviewedBy, "<SET_REVIEW_OWNER>");
    assert.equal(disposition.reviewedAt, undefined);
    assert.deepEqual(disposition.entries.map((entry) => entry.entryId), audit.entries.map((entry) => entry.id));
    assert.ok(disposition.entries.every((entry) => entry.decision === "unreviewed"));
    assert.doesNotThrow(() => validateInterfaceSecurityDisposition(disposition));

    const review = checkInterfaceSecurityReview(audit, disposition);
    assert.equal(review.status, "incomplete");
    assert.equal(review.summary.unreviewed, audit.entries.length);
    assert.equal(review.audit.digestSha256, disposition.audit.digestSha256);
    assert.equal(review.disposition.digestSha256, sha256(canonicalJson(disposition)));
    assert.deepEqual(review.assertions, {
      auditBindingVerified: true,
      exactEntrySetVerified: true,
      originalFindingsUnchanged: true,
      originalDecisionUnchanged: true,
    });
    assert.equal(review.networkRequests, 0);
    assert.equal(review.dnsLookups, 0);
    assert.equal(review.credentialEnvironmentReads, 0);
    assert.equal(review.targetCodeExecutions, 0);
    assert.match(review.disclaimer, /not.*safe|does not.*safe/iu);
    assert.doesNotThrow(() => validateInterfaceSecurityReview(review));
    assert.deepEqual(audit, before);
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(fetchCalls, 0);
});

test("interface disposition and review retain bounded authentication-gap reasons without deciding them", async () => {
  const report = await fixtureReport("fastapi-auth", "positive");
  const originalSignal = report.signals.find((signal) => (
    signal.ruleId === "fastapi.auth.sensitive-route-without-guard"
  ));
  const originalFinding = report.findings.find((finding) => (
    originalSignal && finding.signalIds.includes(originalSignal.id)
  ));
  assert.ok(originalSignal?.metadata);
  assert.ok(originalFinding);
  const duplicateSignal = structuredClone(originalSignal);
  duplicateSignal.id = "sig_ffffffffffffffff";
  duplicateSignal.fingerprint = "f".repeat(64);
  duplicateSignal.metadata!.authenticationGapReason = "optional_or_disabled_guard";
  const duplicateFinding = structuredClone(originalFinding);
  duplicateFinding.id = "finding_ffffffffffffffff";
  duplicateFinding.fingerprint = "f".repeat(64);
  duplicateFinding.signalIds = [duplicateSignal.id];
  report.signals.push(duplicateSignal);
  report.findings.push(duplicateFinding);

  const audit = createInterfaceSecurityAudit(report);
  const disposition = createInterfaceSecurityDisposition(audit);
  assert.equal(disposition.schemaVersion, "1.1.0");
  for (let index = 0; index < audit.entries.length; index += 1) {
    const expected = [...new Set(audit.entries[index]!.sources.flatMap((source) => (
      source.authenticationGapReason ? [source.authenticationGapReason] : []
    )))].sort((left, right) => (
      ["optional_or_disabled_guard", "no_visible_guard"].indexOf(left)
      - ["optional_or_disabled_guard", "no_visible_guard"].indexOf(right)
    ));
    assert.deepEqual(disposition.entries[index]!.authenticationGapReasons ?? [], expected);
    assert.equal(disposition.entries[index]!.decision, "unreviewed");
  }
  assert.ok(disposition.entries.some((entry) => (
    JSON.stringify(entry.authenticationGapReasons)
      === JSON.stringify(["optional_or_disabled_guard", "no_visible_guard"])
  )));
  const review = checkInterfaceSecurityReview(audit, disposition);
  assert.equal(review.schemaVersion, "1.1.0");
  assert.deepEqual(review.entries, disposition.entries);

  const drift = structuredClone(disposition);
  const gapEntry = drift.entries.find((entry) => entry.authenticationGapReasons?.length);
  assert.ok(gapEntry?.authenticationGapReasons);
  gapEntry.authenticationGapReasons = [gapEntry.authenticationGapReasons[0] === "no_visible_guard"
    ? "optional_or_disabled_guard"
    : "no_visible_guard"];
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(drift));
  assert.throws(() => checkInterfaceSecurityReview(audit, drift), /entry context/iu);

  const misplaced = createInterfaceSecurityDisposition(
    await fixtureAudit("fastapi-authorization", "positive-read"),
  );
  misplaced.entries[0]!.authenticationGapReasons = ["no_visible_guard"];
  assert.throws(
    () => validateInterfaceSecurityDisposition(misplaced),
    /misplaced authentication-gap reasons|must be equal to constant/iu,
  );
});

test("legacy 1.0 interface audit and review artifacts remain processable without new fields", async () => {
  const legacy = structuredClone(await fixtureAudit("fastapi-auth", "positive"));
  legacy.schemaVersion = "1.0.0";
  delete legacy.summary.missingAuthenticationGapReasons;
  for (const source of legacy.entries.flatMap((entry) => entry.sources)) {
    delete source.authenticationGapReason;
  }
  assert.doesNotThrow(() => validateInterfaceSecurityAudit(legacy));
  const disposition = createInterfaceSecurityDisposition(legacy);
  assert.equal(disposition.schemaVersion, "1.0.0");
  assert.ok(disposition.entries.every((entry) => entry.authenticationGapReasons === undefined));
  const review = checkInterfaceSecurityReview(legacy, disposition);
  assert.equal(review.schemaVersion, "1.0.0");
  assert.doesNotThrow(() => validateInterfaceSecurityReview(review));
});

test("interface review distinguishes recorded, action-required and incomplete outcomes", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const template = createInterfaceSecurityDisposition(audit);

  const recorded = checkInterfaceSecurityReview(
    audit,
    completeDisposition(template, "accepted_risk"),
  );
  assert.equal(recorded.status, "recorded");
  assert.deepEqual(recorded.summary, {
    total: 1,
    unreviewed: 0,
    fixRequired: 0,
    falsePositive: 0,
    acceptedRisk: 1,
    authorizedVerificationRequired: 0,
    expiredDecisions: 0,
  });
  assert.match(recorded.disclaimer, /recorded.*not.*security|not.*safe/iu);

  const fixRequired = checkInterfaceSecurityReview(
    audit,
    completeDisposition(template, "fix_required"),
  );
  assert.equal(fixRequired.status, "action_required");
  assert.equal(fixRequired.summary.fixRequired, 1);

  const verificationRequired = checkInterfaceSecurityReview(
    audit,
    completeDisposition(template, "authorized_verification_required"),
  );
  assert.equal(verificationRequired.status, "action_required");
  assert.equal(verificationRequired.summary.authorizedVerificationRequired, 1);

  const mixedAudit = await fixtureAudit("node-api", "positive");
  const mixed = createInterfaceSecurityDisposition(mixedAudit);
  mixed.reviewedBy = "AIsec local test operator";
  mixed.reviewedAt = mixed.preparedAt;
  const decisions: InterfaceSecurityDispositionDecision[] = [
    "unreviewed",
    "fix_required",
    "false_positive",
    "accepted_risk",
    "authorized_verification_required",
    "fix_required",
  ];
  mixed.entries = mixed.entries.map((entry, index) => ({
    ...entry,
    decision: decisions[index]!,
    rationale: decisions[index] === "unreviewed"
      ? entry.rationale
      : `Operator rationale for mixed review entry ${index}.`,
    ...(["false_positive", "accepted_risk"].includes(decisions[index]!)
      ? { expiresAt: "2099-01-01T00:00:00.000Z" }
      : {}),
  }));
  const incomplete = checkInterfaceSecurityReview(mixedAudit, mixed);
  assert.equal(incomplete.status, "incomplete");
  assert.deepEqual(incomplete.summary, {
    total: 6,
    unreviewed: 1,
    fixRequired: 2,
    falsePositive: 1,
    acceptedRisk: 1,
    authorizedVerificationRequired: 1,
    expiredDecisions: 0,
  });
});

test("partial source coverage and expired decisions always keep interface review incomplete", async () => {
  const report = await fixtureReport("python-dataflow", "positive");
  const signal = report.signals.find((candidate) => candidate.ruleId === "python.dataflow.ssrf");
  assert.ok(signal?.metadata);
  delete signal.metadata.route;
  delete signal.metadata.routes;
  delete signal.metadata.handler;
  delete signal.metadata.routeAttribution;
  delete signal.metadata.routeCallDepth;
  signal.metadata.routeAttributionStatus = "unattributed";
  signal.metadata.routeAttributionReason = "request_origin_not_proven";
  const partialAudit = createInterfaceSecurityAudit(report);
  assert.equal(partialAudit.coverage, "partial");
  const handled = completeDisposition(
    createInterfaceSecurityDisposition(partialAudit),
    "false_positive",
  );
  const partialReview = checkInterfaceSecurityReview(partialAudit, handled);
  assert.equal(partialReview.status, "incomplete");
  assert.equal(partialReview.summary.unreviewed, 0);
  assert.equal(partialReview.audit.unattributedSignals, 1);

  const completeAudit = await fixtureAudit("fastapi-authorization", "positive-read");
  const expiredTemplate = createInterfaceSecurityDisposition(completeAudit);
  expiredTemplate.preparedAt = "2020-01-01T00:00:00.000Z";
  const expired = completeDisposition(expiredTemplate, "accepted_risk", {
    reviewedAt: "2020-01-02T00:00:00.000Z",
    expiresAt: "2021-01-01T00:00:00.000Z",
  });
  const expiredReview = checkInterfaceSecurityReview(completeAudit, expired);
  assert.equal(expiredReview.status, "incomplete");
  assert.equal(expiredReview.summary.expiredDecisions, 1);
});

test("interface disposition validation fails closed on owner, rationale and expiry contradictions", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const template = createInterfaceSecurityDisposition(audit);

  assert.throws(
    () => validateInterfaceSecurityDisposition({ ...template, targetUrl: "https://example.test" }),
    /InterfaceSecurityDisposition.*additional properties/u,
  );

  const mixedVersion = structuredClone(template);
  mixedVersion.schemaVersion = "1.0.0";
  assert.throws(
    () => validateInterfaceSecurityDisposition(mixedVersion),
    /schema version.*audit binding|audit\/schemaVersion must be equal to constant/iu,
  );

  const placeholderDecision = structuredClone(template);
  placeholderDecision.entries[0]!.decision = "fix_required";
  placeholderDecision.entries[0]!.rationale = "A concrete operator rationale.";
  assert.throws(() => validateInterfaceSecurityDisposition(placeholderDecision), /review owner.*reviewedAt/iu);

  const defaultRationale = completeDisposition(template, "fix_required");
  defaultRationale.entries[0]!.rationale = template.entries[0]!.rationale;
  assert.throws(() => validateInterfaceSecurityDisposition(defaultRationale), /template rationale/iu);

  const missingExpiry = completeDisposition(template, "accepted_risk");
  delete missingExpiry.entries[0]!.expiresAt;
  assert.throws(() => validateInterfaceSecurityDisposition(missingExpiry), /requires expiresAt/u);

  const forbiddenExpiry = completeDisposition(template, "fix_required");
  forbiddenExpiry.entries[0]!.expiresAt = "2099-01-01T00:00:00.000Z";
  assert.throws(() => validateInterfaceSecurityDisposition(forbiddenExpiry), /forbids expiresAt/u);

  const staleOnArrival = completeDisposition(template, "false_positive", {
    expiresAt: template.preparedAt,
  });
  assert.throws(() => validateInterfaceSecurityDisposition(staleOnArrival), /after reviewedAt/u);

  const futureReview = completeDisposition(template, "fix_required", {
    reviewedAt: "2099-01-01T00:00:00.000Z",
  });
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(futureReview));
  assert.throws(() => checkInterfaceSecurityReview(audit, futureReview), /reviewedAt.*future/iu);
});

test("interface review rejects audit drift, spliced dispositions and entry-set drift", async () => {
  const audit = await fixtureAudit("node-api", "positive");
  const template = createInterfaceSecurityDisposition(audit);
  const otherAudit = structuredClone(audit);
  otherAudit.generatedAt = "2099-01-01T00:00:00.000Z";
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(template));
  assert.throws(() => checkInterfaceSecurityReview(otherAudit, template), /exact audit digest/u);

  const differentReport = await fixtureReport("node-api", "positive");
  differentReport.target = `${differentReport.target}-different`;
  const differentAudit = createInterfaceSecurityAudit(differentReport);
  const spliced = createInterfaceSecurityDisposition(differentAudit);
  assert.throws(() => checkInterfaceSecurityReview(audit, spliced), /audit binding/u);

  const missing = structuredClone(template);
  missing.entries.pop();
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(missing));
  assert.throws(() => checkInterfaceSecurityReview(audit, missing), /exact ordered entry set/u);

  const reordered = structuredClone(template);
  reordered.entries.reverse();
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(reordered));
  assert.throws(() => checkInterfaceSecurityReview(audit, reordered), /exact ordered entry set/u);

  const contextDrift = structuredClone(template);
  contextDrift.entries[0]!.severity = contextDrift.entries[0]!.severity === "high" ? "medium" : "high";
  assert.doesNotThrow(() => validateInterfaceSecurityDisposition(contextDrift));
  assert.throws(() => checkInterfaceSecurityReview(audit, contextDrift), /entry context/u);

  const duplicate = structuredClone(template);
  duplicate.entries.push(structuredClone(duplicate.entries[0]!));
  assert.throws(() => validateInterfaceSecurityDisposition(duplicate), /duplicate entry ID/u);

  const forgedDigest = structuredClone(template);
  forgedDigest.audit.digestSha256 = "0".repeat(64);
  assert.throws(() => checkInterfaceSecurityReview(audit, forgedDigest), /exact audit digest/u);
});

test("interface review receipt validator rejects forged IDs, digests, summaries and outcomes", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = completeDisposition(
    createInterfaceSecurityDisposition(audit),
    "accepted_risk",
  );
  const review = checkInterfaceSecurityReview(audit, disposition);

  const forgedId = structuredClone(review);
  forgedId.reviewId = "interface_security_review_0000000000000000";
  assert.throws(() => validateInterfaceSecurityReview(forgedId), /stable review ID/u);

  const forgedDigest = structuredClone(review);
  forgedDigest.disposition.digestSha256 = "0".repeat(64);
  assert.throws(() => validateInterfaceSecurityReview(forgedDigest), /disposition digest/u);

  const forgedSummary = structuredClone(review);
  forgedSummary.summary.acceptedRisk += 1;
  assert.throws(() => validateInterfaceSecurityReview(forgedSummary), /summary totals/u);

  const forgedStatus = structuredClone(review);
  forgedStatus.status = "action_required";
  assert.throws(() => validateInterfaceSecurityReview(forgedStatus), /status is inconsistent/u);

  const mixedVersion = structuredClone(review);
  mixedVersion.schemaVersion = "1.0.0";
  assert.throws(
    () => validateInterfaceSecurityReview(mixedVersion),
    /schema versions are inconsistent|audit\/schemaVersion must be equal to constant/iu,
  );

  assert.throws(
    () => validateInterfaceSecurityReview({ ...review, targetUrl: "https://example.test" }),
    /InterfaceSecurityReview.*additional properties/u,
  );
});

test("interface review loaders reject malformed, oversized and non-regular JSON files", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-review-input-test-"));
  try {
    const malformedAudit = join(temporary, "malformed-audit.json");
    const oversizedAudit = join(temporary, "oversized-audit.json");
    const malformedDisposition = join(temporary, "malformed-disposition.json");
    const oversizedDisposition = join(temporary, "oversized-disposition.json");
    const auditDirectory = join(temporary, "audit-directory.json");
    const dispositionDirectory = join(temporary, "disposition-directory.json");
    await writeFile(malformedAudit, "{bad-json}");
    await writeFile(oversizedAudit, "");
    await truncate(oversizedAudit, MAX_INTERFACE_SECURITY_AUDIT_BYTES + 1);
    await writeFile(malformedDisposition, "{bad-json}");
    await writeFile(oversizedDisposition, "");
    await truncate(oversizedDisposition, MAX_INTERFACE_SECURITY_DISPOSITION_BYTES + 1);
    await mkdir(auditDirectory);
    await mkdir(dispositionDirectory);

    await assert.rejects(loadInterfaceSecurityAudit(malformedAudit), /must be valid JSON/u);
    await assert.rejects(loadInterfaceSecurityAudit(oversizedAudit), /exceeds 16777216 bytes/u);
    await assert.rejects(loadInterfaceSecurityAudit(auditDirectory), /must be a regular file/u);
    await assert.rejects(loadInterfaceSecurityDisposition(malformedDisposition), /must be valid JSON/u);
    await assert.rejects(loadInterfaceSecurityDisposition(oversizedDisposition), /exceeds 1048576 bytes/u);
    await assert.rejects(loadInterfaceSecurityDisposition(dispositionDirectory), /must be a regular file/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("interface review file APIs and CLIs emit bounded local artifacts and reject active flags", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-review-cli-test-"));
  try {
    const audit = await fixtureAudit("fastapi-authorization", "positive-read");
    const auditPath = join(temporary, "interface-audit.json");
    const dispositionPath = join(temporary, "disposition.json");
    const reviewPath = join(temporary, "review.json");
    await writeFile(auditPath, `${JSON.stringify(audit)}\n`);

    const apiTemplate = await prepareInterfaceReview(auditPath);
    await writeFile(dispositionPath, `${JSON.stringify(apiTemplate)}\n`);
    const apiReview = await checkInterfaceReview({
      auditPath,
      dispositionPath,
    });
    assert.equal(apiReview.status, "incomplete");

    const prepared = spawnSync(process.execPath, [
      cli,
      "prepare-interface-review",
      "--audit",
      auditPath,
      "--output",
      dispositionPath,
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(prepared.status, 0, prepared.stderr);
    assert.equal(prepared.stdout, "");
    assert.equal(JSON.parse(await readFile(dispositionPath, "utf8")).schemaVersion, "1.1.0");

    const checked = spawnSync(process.execPath, [
      cli,
      "check-interface-review",
      "--audit",
      auditPath,
      "--disposition",
      dispositionPath,
      "--output",
      reviewPath,
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(checked.status, 0, checked.stderr);
    assert.equal(checked.stdout, "");
    assert.equal(JSON.parse(await readFile(reviewPath, "utf8")).status, "incomplete");

    const stdout = spawnSync(process.execPath, [
      cli,
      "check-interface-review",
      "--audit",
      auditPath,
      "--disposition",
      dispositionPath,
    ], { encoding: "utf8", timeout: 30_000 });
    assert.equal(stdout.status, 0, stdout.stderr);
    assert.equal(JSON.parse(stdout.stdout).schemaVersion, "1.1.0");

    for (const args of [
      ["prepare-interface-review"],
      ["prepare-interface-review", "--audit", auditPath, "--confirm"],
      ["prepare-interface-review", auditPath, "--audit", auditPath],
      ["check-interface-review", "--audit", auditPath],
      ["check-interface-review", "--audit", auditPath, "--audit", auditPath, "--disposition", dispositionPath],
      ["check-interface-review", "--audit", auditPath, "--disposition", dispositionPath, "--confirm"],
      ["check-interface-review", dispositionPath, "--audit", auditPath, "--disposition", dispositionPath],
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

test("interface disposition and review do not add source, target or request secrets", async () => {
  const audit = await fixtureAudit("fastapi-authorization", "positive-read");
  const disposition = completeDisposition(
    createInterfaceSecurityDisposition(audit),
    "false_positive",
  );
  const review = checkInterfaceSecurityReview(audit, disposition);
  for (const serialized of [JSON.stringify(disposition), JSON.stringify(review)]) {
    assert.doesNotMatch(serialized, /targetUrl|targetBaseUrl|requestTemplate|requestBody|responseBody|snippet|metadata|openFindingIds|suppressedFindingIds|sources|location/iu);
  }
});
