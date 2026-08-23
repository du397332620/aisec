import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import YAML from "yaml";
import type { SecurityPolicy } from "../src/schema.js";
import { validateScanReport, validateSecurityPolicy } from "../src/core/schema-validation.js";
import { loadTrustedPolicy, parseSecurityPolicy } from "../src/core/config.js";
import { inspectOnly, scanProject } from "../src/core/scan.js";
import { compareReports } from "../src/core/compare.js";
import { decide } from "../src/core/findings.js";
import { evaluateRouteSecurityBaselineGate } from "../src/core/route-security-gate.js";
import { createFixContract } from "../src/core/contracts.js";
import { renderTerminalReport } from "../src/reporters/terminal.js";
import { renderHtml } from "../src/reporters/html.js";
import { renderSarif } from "../src/reporters/sarif.js";
import { buildCiReport, renderMarkdownSummary } from "../src/reporters/ci.js";

const RULE_ID = "privacy.sensitive-logging";
const here = dirname(fileURLToPath(import.meta.url));

function policy(overrides: Partial<SecurityPolicy> = {}): SecurityPolicy {
  return {
    schemaVersion: "1.0.0",
    policyId: "aisec-release",
    expiresAt: "2099-12-31T23:59:59Z",
    profile: "predeploy",
    requiredEngines: ["gitleaks", "opengrep", "trivy"],
    gate: { minimumSeverity: "high", includeInferred: false, requireNoSuppressions: false },
    rules: { required: [RULE_ID], block: [] },
    suppressions: [],
    ...overrides,
  };
}

async function withUnavailableEngines<T>(directory: string, operation: () => Promise<T>): Promise<T> {
  const names = ["AISEC_GITLEAKS_PATH", "AISEC_OPENGREP_PATH", "AISEC_TRIVY_PATH"] as const;
  const previous = new Map(names.map((name) => [name, process.env[name]]));
  for (const name of names) process.env[name] = join(directory, `missing-${name.toLowerCase()}`);
  try {
    return await operation();
  } finally {
    for (const name of names) {
      const value = previous.get(name);
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}

test("security policy schema and catalog semantics reject weakening or ambiguous declarations", () => {
  const valid = policy();
  assert.equal(validateSecurityPolicy(valid), valid);

  const routeGate = policy({
    schemaVersion: "1.1.0",
    routeSecurityBaseline: { minimumSeverity: "medium", includeInferred: false, requireComplete: true },
  });
  assert.equal(validateSecurityPolicy(routeGate), routeGate);
  assert.throws(() => validateSecurityPolicy({
    ...routeGate,
    schemaVersion: "1.0.0",
  }), /SecurityPolicy.*routeSecurityBaseline/);
  assert.throws(() => validateSecurityPolicy({
    ...routeGate,
    routeSecurityBaseline: { ...routeGate.routeSecurityBaseline, minimumSeverity: "critical" },
  }), /SecurityPolicy.*routeSecurityBaseline.*minimumSeverity/);

  assert.throws(() => validateSecurityPolicy({ ...valid, allowMissingCoverage: true }), /SecurityPolicy.*additional properties.*allowMissingCoverage/);
  assert.throws(() => validateSecurityPolicy({ ...valid, gate: { ...valid.gate, minimumSeverity: "critical" } }), /SecurityPolicy.*minimumSeverity/);
  assert.throws(() => validateSecurityPolicy({ ...valid, requiredEngines: ["gitleaks", "opengrep"] }), /SecurityPolicy.*requiredEngines/);
  assert.throws(() => validateSecurityPolicy({ ...valid, rules: { required: ["unknown.rule"], block: [] } }), /unknown shipped rule/);
  assert.throws(() => validateSecurityPolicy({ ...valid, rules: { required: [], block: [RULE_ID] } }), /blocking rule must also be required/);

  const duplicateSuppressions = {
    ...valid,
    suppressions: [
      { fingerprint: "a".repeat(64), reason: "reviewed fixture", expires: "2099-12-31" },
      { fingerprint: "A".repeat(64), reason: "duplicate", expires: "2099-12-31" },
    ],
  };
  assert.throws(() => validateSecurityPolicy(duplicateSuppressions), /duplicate suppression fingerprint/);

  assert.throws(() => parseSecurityPolicy(YAML.stringify({ ...valid, expiresAt: "2020-01-01T00:00:00Z" }), new Date("2026-01-01T00:00:00Z")), /expired at/);
  assert.throws(() => parseSecurityPolicy(YAML.stringify({
    ...valid,
    suppressions: [{ fingerprint: "b".repeat(64), reason: "stale", expires: "2020-01-01" }],
  }), new Date("2026-01-01T00:00:00Z")), /expired suppression/);
  assert.throws(() => parseSecurityPolicy("x".repeat(256 * 1024 + 1)), /must not exceed 256 KiB/);
  assert.throws(() => parseSecurityPolicy("schemaVersion: [\n"), /not valid YAML/);
});

test("trusted policy loading rejects target-owned files and target-resolving symlinks", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-policy-path-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    const trusted = join(parent, "trusted-policy.yml");
    await writeFile(trusted, YAML.stringify(policy()));
    const loaded = await loadTrustedPolicy(trusted, target, new Date("2026-01-01T00:00:00Z"));
    assert.equal(loaded.policy.policyId, "aisec-release");
    assert.match(loaded.digestSha256, /^[a-f0-9]{64}$/);
    await assert.rejects(() => inspectOnly(target, { policyPath: trusted }), /does not evaluate release policies/);

    const targetPolicy = join(target, "policy.yml");
    await writeFile(targetPolicy, YAML.stringify(policy()));
    await assert.rejects(() => loadTrustedPolicy(targetPolicy, target), /outside the scanned target/);

    const link = join(parent, "target-policy-link.yml");
    await symlink(targetPolicy, link);
    await assert.rejects(() => loadTrustedPolicy(link, target), /outside the scanned target/);

    const targetLink = join(target, "external-policy-link.yml");
    await symlink(trusted, targetLink);
    await assert.rejects(() => loadTrustedPolicy(targetLink, target), /outside the scanned target/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("target configuration is ignored while an explicit external policy can suppress with report evidence", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-policy-suppression-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    await writeFile(join(target, "index.ts"), "console.log(accessToken);\n");
    const initial = (await scanProject(target, { profile: "native", nativeOnly: true, persist: false })).report;
    const finding = initial.findings.find((item) => item.signalIds.some((id) => initial.signals.find((signal) => signal.id === id)?.ruleId === RULE_ID));
    assert.ok(finding);
    assert.equal(initial.policy?.source, "defaults");
    assert.deepEqual(initial.policy?.relaxations, ["source_only_profile", "external_engines_disabled"]);

    await writeFile(join(target, ".aisec.yml"), YAML.stringify({
      version: 1,
      suppressions: [{ fingerprint: finding.fingerprint, reason: "target-controlled", expires: "2099-12-31" }],
    }));
    const ignored = (await scanProject(target, { profile: "native", nativeOnly: true, persist: false })).report;
    assert.equal(ignored.findings.find((item) => item.fingerprint === finding.fingerprint)?.status, "open");
    assert.equal(ignored.policy?.targetConfiguration, "ignored");

    const trustedPolicy = join(parent, "trusted-policy.yml");
    await writeFile(trustedPolicy, YAML.stringify(policy({
      suppressions: [{ fingerprint: finding.fingerprint, reason: "reviewed synthetic fixture", expires: "2099-12-31" }],
    })));
    await assert.rejects(() => scanProject(target, { policyPath: trustedPolicy, persist: false }), /--confirm-policy-suppressions/);
    const trusted = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      confirmPolicySuppressions: true,
      persist: false,
    })).report);
    assert.equal(trusted.findings.find((item) => item.fingerprint === finding.fingerprint)?.status, "suppressed");
    assert.equal(trusted.policy?.source, "operator");
    assert.equal(trusted.policy?.policyId, "aisec-release");
    assert.equal(trusted.policy?.targetConfiguration, "ignored");
    assert.equal(trusted.policy?.suppressionCount, 1);
    assert.equal(trusted.policy?.suppressionApproval, "explicit");
    assert.deepEqual(trusted.policy?.relaxations, []);
    assert.equal(trusted.decision, "incomplete", "missing required engines remain incomplete after a trusted suppression");
    assert.equal(validateScanReport(trusted), trusted);
    const suppressedContract = createFixContract(trusted, finding.fingerprint);
    assert.match(suppressedContract.rescan.command, /--policy "<same-trusted-policy\.yml>" --confirm-policy-suppressions/);

    await writeFile(trustedPolicy, YAML.stringify(policy({
      gate: { minimumSeverity: "high", includeInferred: false, requireNoSuppressions: true },
      suppressions: [{ fingerprint: finding.fingerprint, reason: "reviewed synthetic fixture", expires: "2099-12-31" }],
    })));
    const noSuppressions = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      confirmPolicySuppressions: true,
      persist: false,
    })).report);
    assert.equal(noSuppressions.decision, "block");
    assert.match(noSuppressions.decisionReasons[0] ?? "", /no-suppression gate/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("operator policy strengthens decisions and is visible in terminal, HTML, SARIF and fix contracts", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-policy-gate-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    await writeFile(join(target, "index.ts"), "console.warn(refreshToken);\n");
    await mkdir(join(target, "app", "api", "admin"), { recursive: true });
    await writeFile(join(target, "app", "api", "admin", "route.ts"), "export async function POST() { console.warn(refreshToken); }\n");
    const trustedPolicy = join(parent, "trusted-policy.yml");
    await writeFile(trustedPolicy, YAML.stringify(policy({
      gate: { minimumSeverity: "medium", includeInferred: true, requireNoSuppressions: false },
    })));
    const strengthened = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    })).report);
    assert.equal(strengthened.decision, "block");
    assert.match(strengthened.decisionReasons[0] ?? "", /met policy gate severity medium including inferred/);
    assert.ok(strengthened.signals.some((signal) => signal.ruleId === "auth.sensitive-route-without-visible-guard"), "rules.required must not disable unlisted shipped rules");

    await writeFile(trustedPolicy, YAML.stringify(policy({
      rules: { required: [RULE_ID], block: [RULE_ID] },
    })));
    const report = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    })).report);
    assert.equal(report.decision, "block");
    assert.match(report.decisionReasons[0] ?? "", /policy blocking rules/);
    const weakenedReport = structuredClone(report);
    weakenedReport.coverage.find((item) => item.engine === "gitleaks")!.required = false;
    assert.throws(() => validateScanReport(weakenedReport), /requires coverage from engine: gitleaks/);
    const unknownRuleReport = structuredClone(report);
    unknownRuleReport.policy!.requiredRuleIds = ["unknown.rule"];
    unknownRuleReport.policy!.blockingRuleIds = [];
    assert.throws(() => validateScanReport(unknownRuleReport), /unknown shipped rule/);
    assert.match(renderTerminalReport(report), /Policy: aisec-release.*sha256:/);
    assert.match(renderHtml(report), /<h2>Policy<\/h2>.*aisec-release/s);
    const sarif = renderSarif(report) as { runs: Array<{ properties: Record<string, unknown> }> };
    assert.equal(sarif.runs[0]?.properties.policyId, "aisec-release");
    const finding = report.findings.find((item) => item.status === "open");
    assert.ok(finding);
    const contract = createFixContract(report, finding.id);
    assert.match(contract.rescan.command, /--policy "<same-trusted-policy\.yml>"/);

    await assert.rejects(() => scanProject(target, {
      profile: "native",
      nativeOnly: true,
      policyPath: trustedPolicy,
      persist: false,
    }), /require profile predeploy/);
    await assert.rejects(() => scanProject(target, {
      profile: "native",
      nativeOnly: true,
      confirmPolicySuppressions: true,
      persist: false,
    }), /requires --policy/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("operator-policy baselines require the same explicit policy digest", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-policy-baseline-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    await writeFile(join(target, "index.ts"), "console.error(apiKey);\n");
    const trustedPolicy = join(parent, "trusted-policy.yml");
    const serialized = YAML.stringify(policy({
      gate: { minimumSeverity: "medium", includeInferred: true, requireNoSuppressions: false },
    }));
    await writeFile(trustedPolicy, serialized);
    const baseline = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    })).report);
    const baselinePath = join(parent, "baseline.json");
    await writeFile(baselinePath, `${JSON.stringify(baseline)}\n`);

    const same = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    }, baselinePath)).report);
    assert.equal(same.comparison?.baselineScanId, baseline.scanId);

    await writeFile(trustedPolicy, `${serialized}\n`);
    await assert.rejects(() => scanProject(target, { policyPath: trustedPolicy, persist: false }, baselinePath), /different operator policy digest/);
    await assert.rejects(() => scanProject(target, { persist: false }, baselinePath), /requires the same explicit --policy/);

    const defaultBaseline = (await scanProject(target, { profile: "native", nativeOnly: true, persist: false })).report;
    const defaultBaselinePath = join(parent, "default-baseline.json");
    await writeFile(defaultBaselinePath, `${JSON.stringify(defaultBaseline)}\n`);
    await assert.rejects(() => scanProject(target, { policyPath: trustedPolicy, persist: false }, defaultBaselinePath), /did not use the same operator policy/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("operator route-security baseline gate blocks new eligible routes and fails incomplete evidence closed", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-route-policy-gate-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    const source = (route: string, handler: string) => `
from fastapi import FastAPI

app = FastAPI()

@app.get("${route}")
async def ${handler}():
    try:
        return load_value()
    except Exception as error:
        return {"message": str(error)}
`;
    await writeFile(join(target, "main.py"), source("/legacy", "legacy"));
    const trustedPolicy = join(parent, "trusted-policy.yml");
    await writeFile(trustedPolicy, YAML.stringify(policy({
      schemaVersion: "1.1.0",
      routeSecurityBaseline: { minimumSeverity: "medium", includeInferred: false, requireComplete: true },
    })));

    const baseline = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    })).report);
    assert.equal(baseline.decision, "incomplete");
    assert.match(baseline.decisionReasons.join("\n"), /requires a baseline comparison/u);
    assert.deepEqual(baseline.policy?.routeSecurityBaseline, {
      minimumSeverity: "medium",
      includeInferred: false,
      requireComplete: true,
    });
    const routeOnlyIncomplete = structuredClone(baseline);
    for (const coverage of routeOnlyIncomplete.coverage) {
      if (!coverage.required) continue;
      coverage.status = "complete";
      delete coverage.reason;
    }
    const routeOnlyDecision = decide(
      routeOnlyIncomplete.findings,
      routeOnlyIncomplete.coverage,
      routeOnlyIncomplete.signals,
      routeOnlyIncomplete.policy,
      routeOnlyIncomplete.comparison,
    );
    routeOnlyIncomplete.decision = routeOnlyDecision.decision;
    routeOnlyIncomplete.decisionReasons = routeOnlyDecision.reasons;
    assert.equal(validateScanReport(routeOnlyIncomplete), routeOnlyIncomplete);
    const routeOnlyCi = buildCiReport(routeOnlyIncomplete);
    assert.equal(routeOnlyCi.decision, "incomplete");
    assert.equal(routeOnlyCi.recommendedExitCode, 2);
    assert.equal(routeOnlyCi.requiredCoverage.gaps.length, 0);
    assert.match(routeOnlyCi.decisionReasons.join("\n"), /requires a baseline comparison/u);
    assert.equal(decide(routeOnlyIncomplete.findings, routeOnlyIncomplete.coverage, routeOnlyIncomplete.signals, {
      ...routeOnlyIncomplete.policy!,
      routeSecurityBaseline: { ...routeOnlyIncomplete.policy!.routeSecurityBaseline!, requireComplete: false },
    }).decision, "incomplete", "best-effort comparison still requires a baseline to classify newly observed issues");
    const baselinePath = join(parent, "baseline.json");
    await writeFile(baselinePath, `${JSON.stringify(baseline)}\n`);

    await writeFile(join(target, "main.py"), `${source("/legacy", "legacy")}\n${source("/new", "new_route").replace("from fastapi import FastAPI\n\napp = FastAPI()\n\n", "")}`);
    const gated = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    }, baselinePath)).report);
    assert.equal(gated.decision, "block");
    assert.match(gated.decisionReasons[0] ?? "", /newly observed route-security issue.*severity medium/u);
    assert.ok(gated.comparison?.routeSecurity?.new.some((entry) => entry.route === "GET /new"));

    const evaluation = evaluateRouteSecurityBaselineGate(
      gated.signals,
      gated.findings,
      gated.comparison,
      gated.policy?.routeSecurityBaseline,
    );
    assert.ok(evaluation.blockingEntries.some((entry) => entry.route === "GET /new"));
    assert.ok(evaluation.blockingFindingFingerprints.length > 0);
    const ci = buildCiReport(gated);
    assert.deepEqual(ci.policy.routeSecurityBaseline, gated.policy?.routeSecurityBaseline);
    assert.ok(ci.annotations.some((annotation) => annotation.kind === "finding"
      && annotation.blocksRelease
      && evaluation.blockingFindingFingerprints.includes(annotation.fingerprint ?? "")
      && /newly observed route-security baseline issue/u.test(annotation.message)));
    assert.match(renderTerminalReport(gated), /Route-security baseline gate: medium\+/u);
    assert.match(renderMarkdownSummary(ci), /Route-security baseline gate: medium or higher/u);
    assert.match(renderHtml(gated), /Route-security baseline gate: minimum medium/u);
    const sarif = renderSarif(gated) as { runs: Array<{ properties: { routeSecurityBaselineGate?: unknown } }> };
    assert.deepEqual(sarif.runs[0]?.properties.routeSecurityBaselineGate, gated.policy?.routeSecurityBaseline);

    const suppressedFindings = structuredClone(gated.findings);
    for (const finding of suppressedFindings) {
      if (evaluation.blockingFindingFingerprints.includes(finding.fingerprint)) finding.status = "suppressed";
    }
    assert.equal(evaluateRouteSecurityBaselineGate(
      gated.signals,
      suppressedFindings,
      gated.comparison,
      gated.policy?.routeSecurityBaseline,
    ).blockingEntries.length, 0, "approved suppressions remain visible but do not block through the route gate");

    const inferredFindings = structuredClone(gated.findings);
    for (const finding of inferredFindings) {
      if (evaluation.blockingFindingFingerprints.includes(finding.fingerprint)) finding.evidenceLevel = "inferred";
    }
    assert.equal(evaluateRouteSecurityBaselineGate(
      gated.signals,
      inferredFindings,
      gated.comparison,
      gated.policy?.routeSecurityBaseline,
    ).blockingEntries.length, 0);
    assert.ok(evaluateRouteSecurityBaselineGate(
      gated.signals,
      inferredFindings,
      gated.comparison,
      { ...gated.policy!.routeSecurityBaseline!, includeInferred: true },
    ).blockingEntries.length > 0);

    const gatedPath = join(parent, "gated-baseline.json");
    await writeFile(gatedPath, `${JSON.stringify(gated)}\n`);
    const unchanged = await withUnavailableEngines(parent, async () => (await scanProject(target, {
      policyPath: trustedPolicy,
      persist: false,
    }, gatedPath)).report);
    assert.equal(unchanged.comparison?.routeSecurity?.new.length, 0);
    assert.doesNotMatch(unchanged.decisionReasons.join("\n"), /met baseline gate/u);

    const completeCoverage = unchanged.coverage.map((item) => ({ ...item, status: "complete" as const, reason: undefined }));
    const partialComparison = structuredClone(unchanged.comparison)!;
    partialComparison.routeSecurity!.complete = false;
    partialComparison.routeSecurity!.omittedAssociations = 1;
    const partial = decide(unchanged.findings, completeCoverage, unchanged.signals, unchanged.policy, partialComparison);
    assert.equal(partial.decision, "incomplete");
    assert.match(partial.reasons.join("\n"), /baseline comparison is partial/u);
    const bestEffort = decide(unchanged.findings, completeCoverage, unchanged.signals, {
      ...unchanged.policy!,
      routeSecurityBaseline: { ...unchanged.policy!.routeSecurityBaseline!, requireComplete: false },
    }, partialComparison);
    assert.notEqual(bestEffort.decision, "incomplete");

    const forged = structuredClone(gated);
    forged.decision = "review";
    forged.decisionReasons = ["forged weaker outcome"];
    assert.throws(() => validateScanReport(forged), /baseline blockers require a block decision/u);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("CLI accepts only an explicit policy outside the target", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-policy-cli-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    await writeFile(join(target, "index.ts"), "console.log(authorization);\n");
    const trustedPolicy = join(parent, "trusted-policy.yml");
    const configured = policy({
      gate: { minimumSeverity: "medium", includeInferred: true, requireNoSuppressions: false },
    });
    await writeFile(trustedPolicy, YAML.stringify(configured));
    const environment = {
      ...process.env,
      AISEC_GITLEAKS_PATH: join(parent, "missing-gitleaks"),
      AISEC_OPENGREP_PATH: join(parent, "missing-opengrep"),
      AISEC_TRIVY_PATH: join(parent, "missing-trivy"),
    };
    const cli = join(here, "..", "src", "cli.js");
    const accepted = spawnSync(process.execPath, [cli, "scan", target, "--policy", trustedPolicy, "--no-persist", "--format", "json"], {
      env: environment,
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(accepted.status, 1, accepted.stderr);
    assert.equal((JSON.parse(accepted.stdout) as { policy: { source: string } }).policy.source, "operator");

    const targetPolicy = join(target, "policy.yml");
    await writeFile(targetPolicy, YAML.stringify(configured));
    const rejected = spawnSync(process.execPath, [cli, "scan", target, "--policy", targetPolicy, "--no-persist", "--format", "json"], {
      env: environment,
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(rejected.status, 64);
    assert.match(rejected.stderr, /outside the scanned target/);
    assert.equal(rejected.stdout, "");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
