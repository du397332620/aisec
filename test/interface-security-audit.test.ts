import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import { validateInterfaceSecurityAudit } from "../src/core/schema-validation.js";
import { canonicalJson, sha256 } from "../src/core/utils.js";
import type { Finding, RouteSecurityCategory, ScanReport, Signal } from "../src/schema.js";
import {
  createInterfaceSecurityAudit,
  loadInterfaceSecurityScanReport,
  MAX_INTERFACE_SECURITY_SCAN_REPORT_BYTES,
} from "../src/web/interface-security-audit.js";

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

function reversedKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(reversedKeys);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>)
    .reverse()
    .map(([key, nested]) => [key, reversedKeys(nested)]));
}

function cloneEvidence(
  sourceSignal: Signal,
  sourceFinding: Finding,
  count: number,
  route: (index: number) => string,
): { signals: Signal[]; findings: Finding[] } {
  const signals: Signal[] = [];
  const findings: Finding[] = [];
  for (let index = 0; index < count; index += 1) {
    const suffix = index.toString(16).padStart(16, "0");
    const fingerprint = index.toString(16).padStart(64, "0");
    const signalId = `sig_${suffix}`;
    signals.push({
      ...structuredClone(sourceSignal),
      id: signalId,
      fingerprint,
      metadata: {
        ...structuredClone(sourceSignal.metadata),
        route: route(index),
        routes: [route(index)],
        handler: `audit_handler_${index}`,
      },
    });
    findings.push({
      ...structuredClone(sourceFinding),
      id: `finding_${suffix}`,
      fingerprint,
      signalIds: [signalId],
    });
  }
  return { signals, findings };
}

test("interface audit preserves every supported category without network or target execution", async () => {
  const reports = await Promise.all([
    fixtureReport("fastapi-auth", "positive"),
    fixtureReport("fastapi-authorization", "positive"),
    fixtureReport("node-api", "positive"),
    fixtureReport("python-dataflow", "positive"),
    fixtureReport("python-api-config", "positive"),
  ]);
  const categories = new Set<RouteSecurityCategory>();
  let fetchCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = (() => {
    fetchCalls += 1;
    throw new Error("interface audit generation must never call fetch");
  }) as typeof fetch;
  try {
    for (const report of reports) {
      const before = structuredClone(report);
      const audit = createInterfaceSecurityAudit(report);
      audit.entries.forEach((entry) => categories.add(entry.category));
      assert.equal(audit.scan.digestSha256, sha256(canonicalJson(report)));
      assert.equal(audit.scan.scanId, report.scanId);
      assert.equal(audit.scan.projectId, report.profile.projectId);
      assert.equal(audit.coverageScope, "observed_attributed_routes_only");
      assert.equal(audit.networkRequests, 0);
      assert.equal(audit.dnsLookups, 0);
      assert.equal(audit.credentialEnvironmentReads, 0);
      assert.equal(audit.targetCodeExecutions, 0);
      assert.doesNotThrow(() => validateInterfaceSecurityAudit(audit));
      assert.deepEqual(report, before, "audit derivation must not mutate canonical evidence");
    }
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(fetchCalls, 0);
  const fastApiAudit = createInterfaceSecurityAudit(reports[1]!);
  assert.ok(fastApiAudit.entries.some((entry) => entry.framework === "FastAPI"
    && entry.route === "POST /permissions/grant"
    && entry.category === "privileged_authorization"));
  assert.deepEqual([...categories].sort(), [
    "authentication",
    "credential_forwarding",
    "exception_disclosure",
    "object_authorization",
    "privileged_authorization",
    "sql_injection",
    "ssrf",
    "untrusted_file_path",
  ]);
});

test("interface audit identity uses canonical scan content and output excludes sensitive scan fields", async () => {
  const report = await fixtureReport("fastapi-authorization", "positive-read");
  const source = report.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(source?.metadata);
  source.metadata.privateToken = "audit-secret-must-not-leak";
  source.locations[0]!.snippet = "Authorization: Bearer audit-secret-must-not-leak";
  const audit = createInterfaceSecurityAudit(report);
  const reordered = createInterfaceSecurityAudit(reversedKeys(report) as ScanReport);
  assert.equal(audit.scan.digestSha256, reordered.scan.digestSha256);
  assert.equal(audit.auditId, reordered.auditId);
  assert.deepEqual(audit.entries, reordered.entries);
  const changedReport = structuredClone(report);
  changedReport.target = `${changedReport.target}-changed`;
  const changed = createInterfaceSecurityAudit(changedReport);
  assert.notEqual(audit.scan.digestSha256, changed.scan.digestSha256);
  assert.notEqual(audit.auditId, changed.auditId);

  const serialized = JSON.stringify(audit);
  assert.doesNotMatch(serialized, /audit-secret-must-not-leak/u);
  assert.doesNotMatch(serialized, /privateToken|snippet|metadata|targetBaseUrl|requestTemplate/u);
  assert.match(audit.disclaimer, /static evidence.*not.*vulnerability confirmation/iu);
});

test("interface audit report loader rejects malformed, oversized and non-regular inputs", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-audit-input-test-"));
  try {
    const malformed = join(temporary, "malformed.json");
    const oversized = join(temporary, "oversized.json");
    const directory = join(temporary, "directory.json");
    await writeFile(malformed, "{not-json}");
    await writeFile(oversized, "");
    await truncate(oversized, MAX_INTERFACE_SECURITY_SCAN_REPORT_BYTES + 1);
    await mkdir(directory);
    await assert.rejects(loadInterfaceSecurityScanReport(malformed), /must be valid JSON/u);
    await assert.rejects(loadInterfaceSecurityScanReport(oversized), /exceeds 67108864 bytes/u);
    await assert.rejects(loadInterfaceSecurityScanReport(directory), /must be a regular file/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("interface audit distinguishes open and suppressed-only route-category evidence", async () => {
  const report = await fixtureReport("fastapi-authorization", "positive-read");
  report.findings = report.findings.map((finding) => ({
    ...finding,
    status: "suppressed" as const,
    suppression: { reason: "reviewed test suppression", expires: "2099-01-01" },
  }));
  const audit = createInterfaceSecurityAudit(report);
  assert.equal(audit.summary.openEntries, 0);
  assert.equal(audit.summary.suppressedOnlyEntries, 1);
  assert.equal(audit.entries[0]?.findingStatus, "suppressed_only");
  assert.deepEqual(audit.entries[0]?.sources[0]?.openFindingIds, []);
  assert.ok((audit.entries[0]?.sources[0]?.suppressedFindingIds.length ?? 0) > 0);
  assert.doesNotThrow(() => validateInterfaceSecurityAudit(audit));
});

test("interface audit fails coverage partial when dangerous dataflow cannot be attributed to a route", async () => {
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

  const audit = createInterfaceSecurityAudit(report);
  assert.equal(audit.coverage, "partial");
  assert.equal(audit.summary.attribution.unattributedSignals, 1);
  assert.deepEqual(audit.summary.attribution.reasons, [{ reason: "request_origin_not_proven", signals: 1 }]);
  assert.ok(!audit.entries.some((entry) => entry.route === "POST /fetch"));
  assert.ok(audit.limitations.some((limitation) => /could not be attributed/u.test(limitation)));
});

test("interface audit bounds entries, sources and finding references and reports every omission", async () => {
  const base = await fixtureReport("fastapi-authorization", "positive-read");
  const sourceSignal = base.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  const sourceFinding = base.findings.find((finding) => sourceSignal && finding.signalIds.includes(sourceSignal.id));
  assert.ok(sourceSignal);
  assert.ok(sourceFinding);

  const routes = cloneEvidence(sourceSignal, sourceFinding, 205, (index) => `GET /audit/${index}/{report_id}`);
  base.signals = routes.signals;
  base.findings = routes.findings;
  const boundedEntries = createInterfaceSecurityAudit(base);
  assert.equal(boundedEntries.coverage, "partial");
  assert.equal(boundedEntries.summary.routeCategoryEntries, 205);
  assert.equal(boundedEntries.summary.emittedEntries, 200);
  assert.equal(boundedEntries.summary.omittedEntries, 5);
  assert.equal(boundedEntries.entries.length, 200);

  const shared = await fixtureReport("fastapi-authorization", "positive-read");
  const sharedSignal = shared.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  const sharedFinding = shared.findings.find((finding) => sharedSignal && finding.signalIds.includes(sharedSignal.id));
  assert.ok(sharedSignal);
  assert.ok(sharedFinding);
  const evidence = cloneEvidence(sharedSignal, sharedFinding, 25, () => "GET /audit/shared/{report_id}");
  const signalIds = evidence.signals.map((signal) => signal.id);
  evidence.findings = evidence.findings.map((finding) => ({ ...finding, signalIds }));
  shared.signals = evidence.signals;
  shared.findings = evidence.findings;
  const boundedEvidence = createInterfaceSecurityAudit(shared);
  const entry = boundedEvidence.entries[0];
  assert.equal(entry?.sourceCount, 25);
  assert.equal(entry?.sources.length, 20);
  assert.equal(entry?.omittedSources, 5);
  assert.equal(entry?.sources[0]?.openFindingIds.length, 20);
  assert.equal(entry?.sources[0]?.omittedOpenFindingIds, 5);
  assert.equal(boundedEvidence.summary.omittedSourceRecords, 5);
  assert.equal(boundedEvidence.summary.omittedFindingIdReferences, 125);
  assert.equal(boundedEvidence.coverage, "partial");
  assert.doesNotThrow(() => validateInterfaceSecurityAudit(boundedEvidence));
});

test("interface audit omits unsafe source locations and makes the evidence gap explicit", async () => {
  const report = await fixtureReport("fastapi-authorization", "positive-read");
  const source = report.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(source);
  source.locations = [{ path: "../outside/private.py", line: 3, snippet: "private" }];
  const audit = createInterfaceSecurityAudit(report);
  assert.equal(audit.coverage, "partial");
  assert.equal(audit.summary.unlocatedSourceRecords, 1);
  assert.ok(!("location" in audit.entries[0]!.sources[0]!));
  assert.doesNotMatch(JSON.stringify(audit), /outside\/private|private\.py/u);
});

test("interface audit schema rejects forged identities, mappings, counts, unsafe paths and extra fields", async () => {
  const audit = createInterfaceSecurityAudit(await fixtureReport("fastapi-authorization", "positive-read"));

  assert.throws(() => validateInterfaceSecurityAudit({ ...audit, targetUrl: "https://example.test" }), /InterfaceSecurityAudit.*additional properties/u);

  const forgedAuditId = structuredClone(audit);
  forgedAuditId.auditId = "interface_audit_0000000000000000";
  assert.throws(() => validateInterfaceSecurityAudit(forgedAuditId), /stable audit ID is inconsistent/u);

  const forgedEntryId = structuredClone(audit);
  forgedEntryId.entries[0]!.id = "interface_audit_entry_0000000000000000";
  assert.throws(() => validateInterfaceSecurityAudit(forgedEntryId), /stable entry ID is inconsistent/u);

  const wrongRule = structuredClone(audit);
  wrongRule.entries[0]!.sources[0]!.ruleId = "python.dataflow.ssrf";
  assert.throws(() => validateInterfaceSecurityAudit(wrongRule), /source category or framework is inconsistent/u);

  const unsafePath = structuredClone(audit);
  unsafePath.entries[0]!.sources[0]!.location = { path: "../escape.py" };
  assert.throws(() => validateInterfaceSecurityAudit(unsafePath), /unsafe or non-normalized source path/u);

  const impossibleCount = structuredClone(audit);
  impossibleCount.summary.openEntries += 1;
  assert.throws(() => validateInterfaceSecurityAudit(impossibleCount), /entry totals are inconsistent/u);

  const duplicate = structuredClone(audit);
  duplicate.entries.push(structuredClone(duplicate.entries[0]!));
  duplicate.summary.emittedEntries += 1;
  duplicate.summary.routeCategoryEntries += 1;
  duplicate.summary.openEntries += 1;
  duplicate.summary.categories[0]!.entries += 1;
  duplicate.summary.categories[0]!.openEntries += 1;
  assert.throws(() => validateInterfaceSecurityAudit(duplicate), /duplicate route-category identity/u);
});

test("interface-audit CLI reads one strict report, supports output and rejects active flags", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-interface-audit-test-"));
  try {
    const report = await fixtureReport("fastapi-authorization", "positive-read");
    const input = join(temporary, "scan.json");
    const output = join(temporary, "audit.json");
    await writeFile(input, `${JSON.stringify(report)}\n`);

    const stdout = spawnSync(process.execPath, [cli, "interface-audit", "--scan", input], {
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(stdout.status, 0, stdout.stderr);
    assert.equal(JSON.parse(stdout.stdout).schemaVersion, "1.0.0");

    const saved = spawnSync(process.execPath, [cli, "interface-audit", "--scan", input, "--output", output], {
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(saved.status, 0, saved.stderr);
    assert.equal(saved.stdout, "");
    assert.equal(JSON.parse(await readFile(output, "utf8")).scan.scanId, report.scanId);

    for (const args of [
      ["interface-audit"],
      ["interface-audit", "--scan", input, "--scan", input],
      ["interface-audit", "--scan", input, "--confirm"],
      ["interface-audit", input, "--scan", input],
    ]) {
      const rejected = spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 30_000 });
      assert.equal(rejected.status, 64, `${args.join(" ")} must fail closed`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
