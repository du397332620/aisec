import assert from "node:assert/strict";
import test from "node:test";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import { validateInterfaceVerificationQueue } from "../src/core/schema-validation.js";
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

test("interface queue selects exact open object reads without performing requests", async () => {
  const report = await fastApiReadReport();
  const before = structuredClone(report);
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("queue generation must never call fetch");
  }) as typeof fetch;
  try {
    const queue = createInterfaceVerificationQueue(report);
    assert.equal(fetchCalls, 0);
    assert.equal(queue.networkRequests, 0);
    assert.equal(queue.coverage, "complete");
    assert.equal(queue.coverageScope, "observed_route_cards_only");
    assert.deepEqual(queue.summary, {
      reviewedRoutes: 1,
      eligibleRoutes: 1,
      excludedRoutes: 0,
      emittedCandidates: 1,
      omittedCandidates: 0,
      emittedExclusions: 0,
      omittedExclusions: 0,
      omittedSourceRecords: 0,
      omittedFindingIds: 0,
      sourceOmissions: { routeAliases: 0, associations: 0 },
      exclusionReasons: [],
    });
    const candidate = queue.candidates[0];
    assert.equal(candidate?.framework, "FastAPI");
    assert.equal(candidate?.route, "POST /document/detail");
    assert.equal(candidate?.methodPolicy, "reviewed_read_post");
    assert.deepEqual(candidate?.eligibility, [
      "open_object_authorization_finding",
      "exact_route_provenance",
      "bola_read_compatible",
      "recorded_object_identifier",
    ]);
    assert.deepEqual(candidate?.objectIdFields, ["report_id"]);
    assert.ok(candidate?.requiredReviews.includes("confirm_post_read_only"));
    assert.equal(candidate?.sourceCount, 1);
    assert.equal(candidate?.sources[0]?.handler, "detail");
    assert.equal(candidate?.sources[0]?.location.path, "main.py");
    assert.ok((candidate?.sources[0]?.openFindingIds.length ?? 0) > 0);
    assert.ok(!("requestTemplate" in (candidate ?? {})));
    assert.equal(queue.nextCommand, "aisec draft-bola --scan <same-scan-id-or-report.json> --output bola-draft.json");
    assert.match(queue.disclaimer, /performs no network requests/u);
    assert.doesNotThrow(() => validateInterfaceVerificationQueue(queue));
    assert.deepEqual(report, before, "queue derivation must not mutate canonical evidence");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("interface queue distinguishes safe GET aliases from conditionally read-like POST routes", async () => {
  const report = await fastApiReadReport();
  const signal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(signal?.metadata);
  signal.metadata.routes = [String(signal.metadata.route), "GET /document/{report_id}"];

  const queue = createInterfaceVerificationQueue(report);
  assert.equal(queue.summary.eligibleRoutes, 2, "route-card aliases must be reviewed independently");
  const getCandidate = queue.candidates.find((candidate) => candidate.method === "GET");
  assert.equal(getCandidate?.route, "GET /document/{report_id}");
  assert.equal(getCandidate?.methodPolicy, "safe_get");
  assert.ok(!getCandidate?.requiredReviews.includes("confirm_post_read_only"));
  assert.equal(queue.candidates.find((candidate) => candidate.method === "POST")?.methodPolicy, "reviewed_read_post");
});

test("interface queue records deterministic reasons for mutation, unsupported, closed and incomplete evidence", async () => {
  const mutation = (await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
  const mutationQueue = createInterfaceVerificationQueue(mutation);
  assert.equal(mutationQueue.summary.eligibleRoutes, 0);
  assert.ok(mutationQueue.exclusions[0]?.reasons.includes("mutation_semantics"));

  const unsupported = (await scanProject(join(fixtures, "corpus", "python-dataflow", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
  const unsupportedQueue = createInterfaceVerificationQueue(unsupported);
  assert.equal(unsupportedQueue.summary.eligibleRoutes, 0);
  assert.ok(unsupportedQueue.exclusions.every((entry) => entry.reasons.includes("unsupported_verification_category")));

  const closed = await fastApiReadReport();
  closed.findings = closed.findings.map((finding) => ({
    ...finding,
    status: "suppressed" as const,
    suppression: { reason: "reviewed test suppression", expires: "2099-01-01" },
  }));
  const closedQueue = createInterfaceVerificationQueue(closed);
  assert.deepEqual(closedQueue.exclusions[0]?.reasons, [
    "no_open_finding",
    "no_open_object_authorization_finding",
  ]);

  const unproven = await fastApiReadReport();
  const unprovenSignal = unproven.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(unprovenSignal);
  unprovenSignal.locations = [{ path: "/absolute/untrusted.py", line: 1 }];
  assert.deepEqual(createInterfaceVerificationQueue(unproven).exclusions[0]?.reasons, ["unproven_route_source"]);

  const missingId = await fastApiReadReport();
  const missingIdSignal = missingId.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(missingIdSignal?.metadata);
  missingIdSignal.metadata.objectIdFields = [];
  assert.deepEqual(createInterfaceVerificationQueue(missingId).exclusions[0]?.reasons, ["missing_object_identifier"]);

  const ambiguous = await fastApiReadReport();
  const ambiguousSignal = ambiguous.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(ambiguousSignal?.metadata);
  ambiguousSignal.metadata.route = "POST /document/action";
  assert.deepEqual(createInterfaceVerificationQueue(ambiguous).exclusions[0]?.reasons, ["ambiguous_read_semantics"]);
});

test("interface queue bounds route details and reports partial coverage", async () => {
  const report = await fastApiReadReport();
  const sourceSignal = report.signals.find((item) => item.ruleId === "fastapi.authorization.object-without-ownership-check");
  const sourceFinding = report.findings.find((item) => sourceSignal && item.signalIds.includes(sourceSignal.id));
  assert.ok(sourceSignal);
  assert.ok(sourceFinding);
  const signals: Signal[] = [];
  const findings: Finding[] = [];
  for (let index = 0; index < 105; index += 1) {
    const suffix = index.toString(16).padStart(16, "0");
    const fingerprint = index.toString(16).padStart(64, "0");
    const signalId = `sig_${suffix}`;
    signals.push({
      ...structuredClone(sourceSignal),
      id: signalId,
      fingerprint,
      metadata: {
        ...structuredClone(sourceSignal.metadata),
        route: `GET /document/${index}/{report_id}`,
        handler: `detail_${index}`,
      },
    });
    findings.push({
      ...structuredClone(sourceFinding),
      id: `finding_${suffix}`,
      fingerprint,
      signalIds: [signalId],
    });
  }
  report.signals = signals;
  report.findings = findings;

  const queue = createInterfaceVerificationQueue(report);
  assert.equal(queue.coverage, "partial");
  assert.equal(queue.summary.reviewedRoutes, 105);
  assert.equal(queue.summary.eligibleRoutes, 105);
  assert.equal(queue.summary.emittedCandidates, 100);
  assert.equal(queue.summary.omittedCandidates, 5);
  assert.equal(queue.candidates.length, 100);
  assert.ok(queue.limitations.some((reason) => /5 eligible route detail/u.test(reason)));
  assert.doesNotThrow(() => validateInterfaceVerificationQueue(queue));
});

test("interface queue schema rejects contradictory counts, unsafe sources and duplicate route identities", async () => {
  const queue = createInterfaceVerificationQueue(await fastApiReadReport());

  const unknown = { ...queue, trustedByTarget: true };
  assert.throws(() => validateInterfaceVerificationQueue(unknown), /InterfaceVerificationQueue.*additional properties/u);

  const impossibleCount = structuredClone(queue);
  impossibleCount.summary.eligibleRoutes += 1;
  assert.throws(() => validateInterfaceVerificationQueue(impossibleCount), /route totals are inconsistent/u);

  const unsafeSource = structuredClone(queue);
  unsafeSource.candidates[0]!.sources[0]!.location.path = "../escape.py";
  assert.throws(() => validateInterfaceVerificationQueue(unsafeSource), /unsafe or non-normalized source path/u);

  const contradictoryPolicy = structuredClone(queue);
  contradictoryPolicy.candidates[0]!.methodPolicy = "safe_get";
  assert.throws(() => validateInterfaceVerificationQueue(contradictoryPolicy), /method policy is inconsistent/u);

  const duplicate = structuredClone(queue);
  duplicate.candidates.push(structuredClone(duplicate.candidates[0]!));
  duplicate.summary.emittedCandidates += 1;
  duplicate.summary.eligibleRoutes += 1;
  duplicate.summary.reviewedRoutes += 1;
  assert.throws(() => validateInterfaceVerificationQueue(duplicate), /duplicate route identity/u);

  const mutation = (await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
  const inconsistentReasons = createInterfaceVerificationQueue(mutation);
  inconsistentReasons.summary.exclusionReasons[0]!.routes += 1;
  assert.throws(() => validateInterfaceVerificationQueue(inconsistentReasons), /exclusion reason count is inconsistent/u);
});
