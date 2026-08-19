import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import type { ScanReport } from "../src/schema.js";
import { scanProject } from "../src/core/scan.js";
import { validateCiReport } from "../src/core/schema-validation.js";
import { buildCiReport, renderGithubAnnotations, renderMarkdownSummary } from "../src/reporters/ci.js";
import { renderHtml } from "../src/reporters/html.js";
import { renderSarif } from "../src/reporters/sarif.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

async function vulnerableReport(): Promise<ScanReport> {
  return (await scanProject(join(fixtures, "vulnerable"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  })).report;
}

test("CiReport is a strict coverage-aware machine contract", async () => {
  const source = await vulnerableReport();
  const report = buildCiReport(source);
  assert.equal(validateCiReport(report), report);
  assert.equal(report.decision, "block");
  assert.equal(report.recommendedExitCode, 1);
  assert.equal(report.counts.open, report.counts.critical + report.counts.high + report.counts.medium + report.counts.low + report.counts.info);
  assert.equal(report.annotations.filter((item) => item.kind === "decision").length, 1);
  assert.ok(report.annotations.some((item) => item.kind === "finding" && item.blocksRelease && item.level === "error"));
  assert.ok(report.annotations.some((item) => item.kind === "finding" && item.evidenceLevel === "inferred" && item.level === "warning"));
  assert.deepEqual(report.policy.relaxations, ["source_only_profile", "external_engines_disabled"]);
  assert.deepEqual(report.rulePacks, []);

  const legacy = structuredClone(report);
  legacy.schemaVersion = "1.0.0";
  delete legacy.rulePacks;
  assert.equal(validateCiReport(legacy), legacy, "legacy CiReport 1.0.0 remains readable without rule-pack records");
  const missingRulePacks = structuredClone(report);
  delete missingRulePacks.rulePacks;
  assert.throws(() => validateCiReport(missingRulePacks), /CiReport.*rulePacks/);

  const incomplete = structuredClone(source);
  incomplete.decision = "incomplete";
  incomplete.decisionReasons = ["required synthetic coverage failed"];
  incomplete.coverage[0]!.status = "failed";
  incomplete.coverage[0]!.required = true;
  incomplete.coverage[0]!.reason = "synthetic failure";
  const incompleteCi = buildCiReport(incomplete);
  assert.equal(incompleteCi.recommendedExitCode, 2);
  assert.equal(incompleteCi.requiredCoverage.gaps.length, 1);
  assert.ok(incompleteCi.annotations.some((item) => item.kind === "coverage" && item.level === "error"));

  const badExit = structuredClone(report);
  badExit.recommendedExitCode = 0;
  assert.throws(() => validateCiReport(badExit), /requires recommendedExitCode 1/);
  const badCount = structuredClone(report);
  badCount.counts.open += 1;
  assert.throws(() => validateCiReport(badCount), /severity-count total/);
  const unsafePath = structuredClone(report);
  unsafePath.annotations.find((item) => item.kind === "finding")!.path = "../outside.ts";
  assert.throws(() => validateCiReport(unsafePath), /not a safe relative path/);
  const encodedTraversal = structuredClone(report);
  encodedTraversal.annotations.find((item) => item.kind === "finding")!.path = "%2e%2e/outside.ts";
  assert.throws(() => validateCiReport(encodedTraversal), /not a safe relative path/);
  const impossibleBaseline = structuredClone(report);
  impossibleBaseline.comparison = { baselineScanId: source.scanId, new: 0, remaining: 0, resolved: 0, notRechecked: 0 };
  impossibleBaseline.annotations.find((item) => item.kind === "finding")!.baselineState = "new";
  assert.throws(() => validateCiReport(impossibleBaseline), /baseline states exceed/);
  const weakenedDefaults = structuredClone(report);
  weakenedDefaults.policy.gate!.includeInferred = true;
  assert.throws(() => validateCiReport(weakenedDefaults), /built-in gate/);
  assert.throws(() => validateCiReport({ ...report, extraClaim: "secure" }), /CiReport.*additional properties/);
});

test("legacy ScanReport renders explicit not-recorded policy evidence", async () => {
  const legacy = structuredClone(await vulnerableReport());
  legacy.schemaVersion = "1.0.0";
  delete legacy.policy;
  delete legacy.rulePacks;
  const report = buildCiReport(legacy);
  assert.deepEqual(report.policy, {
    source: "not_recorded",
    targetConfiguration: "not_recorded",
    requiredEngines: [],
    suppressionCount: 0,
    suppressionApproval: "not_recorded",
    relaxations: [],
  });
  assert.match(renderMarkdownSummary(report), /Policy evidence was not recorded/);
});

test("CI, Markdown and HTML renderers neutralize hostile project-controlled text", async () => {
  const source = await vulnerableReport();
  const finding = source.findings.find((item) => item.signalIds.length === 1);
  assert.ok(finding);
  const signal = source.signals.find((item) => item.id === finding.signalIds[0]);
  assert.ok(signal);
  finding.title = "hostile\n::error file=owned.ts::pwn <script>alert(1)</script> [click](https://attacker.invalid) www.attacker.invalid @octocat | owned";
  signal.description = "description\r\n::warning::pwn %0A [image](https://attacker.invalid/pixel)";
  signal.locations = [{ path: "../.github/workflows/pwn.yml\n::error::owned", line: 1 }];

  const report = buildCiReport(source);
  const annotation = report.annotations.find((item) => item.fingerprint === finding.fingerprint);
  assert.ok(annotation);
  assert.equal(annotation.path, undefined, "unsafe target-controlled paths must not become annotations");
  assert.doesNotMatch(JSON.stringify(report), /[\r\n]::(?:error|warning)/);

  const github = renderGithubAnnotations(report);
  const lines = github.trimEnd().split("\n");
  assert.equal(lines.length, report.annotations.length);
  assert.ok(lines.every((line) => /^::(?:error|warning|notice) /u.test(line)));
  assert.doesNotMatch(github, /\n::error file=owned/u);
  assert.doesNotMatch(github, /\.\.\/\.github/u);

  const markdown = renderMarkdownSummary(report);
  assert.doesNotMatch(markdown, /<script>/iu);
  assert.doesNotMatch(markdown, /https:\/\/attacker\.invalid/iu);
  assert.doesNotMatch(markdown, /www\.attacker\.invalid|@octocat/iu);
  assert.match(markdown, /\\\| owned \|/u);
  assert.doesNotMatch(markdown, /(?<!\\)\| owned \|/u);

  const html = renderHtml(source);
  assert.doesNotMatch(html, /<script>/iu);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/u);
  assert.match(html, /Content-Security-Policy/u);
});

test("scan and rescan retain decision exits with CI output formats", async () => {
  const source = await vulnerableReport();
  const temporary = await mkdtemp(join(tmpdir(), "aisec-ci-exits-"));
  try {
    const baseline = join(temporary, "baseline.json");
    await writeFile(baseline, `${JSON.stringify(source)}\n`);
    const cli = join(here, "..", "src", "cli.js");
    const scan = spawnSync(process.execPath, [cli, "scan", join(fixtures, "vulnerable"), "--profile", "native", "--no-persist", "--format", "ci"], { encoding: "utf8", timeout: 30_000 });
    assert.equal(scan.status, 1, scan.stderr);
    const scanCi = validateCiReport(JSON.parse(scan.stdout));
    assert.equal(scanCi.decision, "block");
    assert.equal(scanCi.recommendedExitCode, 1);

    const rescan = spawnSync(process.execPath, [cli, "rescan", join(fixtures, "vulnerable"), "--baseline", baseline, "--profile", "native", "--no-persist", "--format", "github"], { encoding: "utf8", timeout: 30_000 });
    assert.equal(rescan.status, 1, rescan.stderr);
    assert.match(rescan.stdout, /^::error title=AIsec decision%3A block::/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("CI annotations have deterministic coverage and finding bounds", async () => {
  const source = await vulnerableReport();
  const template = source.findings.find((item) => item.status === "open");
  assert.ok(template);
  source.findings = Array.from({ length: 60 }, (_, index) => ({
    ...structuredClone(template),
    id: `finding_${(index + 1).toString(16).padStart(16, "0")}`,
    fingerprint: (index + 1).toString(16).padStart(64, "0"),
    title: `bounded finding ${index + 1}`,
    severity: "high" as const,
    evidenceLevel: "static_confirmed" as const,
    status: "open" as const,
  }));
  source.summary = { critical: 0, high: 60, medium: 0, low: 0, info: 0, attackPaths: source.attackPaths.length, suppressed: 0 };
  source.coverage.push(...Array.from({ length: 25 }, (_, index) => ({
    domain: `synthetic-domain-${index}`,
    engine: `synthetic-engine-${index}`,
    status: "failed" as const,
    required: true,
    reason: `bounded failure ${index}`,
  })));
  const report = buildCiReport(source);
  assert.equal(report.annotations.length, 71);
  assert.equal(report.annotations.filter((item) => item.kind === "coverage").length, 20);
  assert.equal(report.annotations.filter((item) => item.kind === "finding").length, 50);
  assert.deepEqual(report.omitted, { coverageAnnotations: 5, findingAnnotations: 10 });
  assert.equal(validateCiReport(report), report);
});

test("SARIF carries suppression, baseline, policy and coverage evidence", async () => {
  const source = await vulnerableReport();
  const finding = source.findings.find((item) => item.signalIds.length === 1 && item.status === "open");
  assert.ok(finding);
  finding.status = "suppressed";
  finding.suppression = { reason: "reviewed synthetic exception", expires: "2099-12-31" };
  source.summary[finding.severity] -= 1;
  source.summary.suppressed += 1;
  source.comparison = {
    baselineScanId: source.scanId,
    new: [finding.fingerprint],
    remaining: [],
    resolved: [],
    notRechecked: [],
  };
  const sarif = renderSarif(source) as {
    runs: Array<{
      automationDetails: { id: string };
      tool: { driver: { informationUri: string } };
      properties: { comparison: { new: number }; requiredCoverageGaps: unknown[] };
      results: Array<{
        properties: { findingId?: string };
        baselineState?: string;
        suppressions?: Array<{ status: string; justification: string }>;
        partialFingerprints: Record<string, string>;
      }>;
    }>;
  };
  const run = sarif.runs[0]!;
  const result = run.results.find((item) => item.properties.findingId === finding.id);
  assert.ok(result);
  assert.equal(run.automationDetails.id, source.scanId);
  assert.equal(run.tool.driver.informationUri, "https://github.com/du397332620/aisec");
  assert.equal(run.properties.comparison.new, 1);
  assert.deepEqual(run.properties.requiredCoverageGaps, []);
  assert.equal(result.baselineState, "new");
  assert.equal(result.suppressions?.[0]?.status, "accepted");
  assert.equal(result.suppressions?.[0]?.justification, "reviewed synthetic exception");
  assert.equal(result.partialFingerprints["aisecFinding/v1"], finding.fingerprint);
});

test("HTML and CLI formats expose decision, coverage and baseline summaries", async () => {
  const source = await vulnerableReport();
  source.decisionReasons = ["<img src=x onerror=alert(1)> required evidence"];
  source.coverage[0]!.status = "failed";
  source.coverage[0]!.required = true;
  source.coverage[0]!.reason = "fixture gap";
  source.comparison = {
    baselineScanId: source.scanId,
    new: [source.findings[0]!.fingerprint],
    remaining: [],
    resolved: ["f".repeat(64)],
    notRechecked: ["e".repeat(64)],
  };
  const html = renderHtml(source);
  assert.match(html, /<h2>Decision reasons<\/h2>/u);
  assert.match(html, /Required coverage gaps/u);
  assert.match(html, /<h2>Baseline comparison<\/h2>/u);
  assert.match(html, /New <span>1<\/span>/u);
  assert.match(html, /Resolved <span>1<\/span>/u);
  assert.doesNotMatch(html, /<img src=x/u);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/u);

  const temporary = await mkdtemp(join(tmpdir(), "aisec-report-formats-"));
  try {
    const input = join(temporary, "report.json");
    const markdownOutput = join(temporary, "summary.md");
    await writeFile(input, `${JSON.stringify(source)}\n`);
    const cli = join(here, "..", "src", "cli.js");
    const ci = spawnSync(process.execPath, [cli, "report", input, "--format", "ci"], { encoding: "utf8", timeout: 30_000 });
    assert.equal(ci.status, 0, ci.stderr);
    const parsedCi = JSON.parse(ci.stdout);
    assert.deepEqual(validateCiReport(parsedCi), parsedCi);
    const github = spawnSync(process.execPath, [cli, "report", input, "--format", "github"], { encoding: "utf8", timeout: 30_000 });
    assert.equal(github.status, 0, github.stderr);
    assert.match(github.stdout, /^::error /u);
    const markdown = spawnSync(process.execPath, [cli, "report", input, "--format", "markdown", "--output", markdownOutput], { encoding: "utf8", timeout: 30_000 });
    assert.equal(markdown.status, 0, markdown.stderr);
    assert.equal(markdown.stdout, "");
    assert.match(await readFile(markdownOutput, "utf8"), /^# AIsec security acceptance/u);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
