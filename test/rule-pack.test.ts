import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import YAML from "yaml";
import type { RulePack } from "../src/schema.js";
import { validateRulePack, validateScanReport } from "../src/core/schema-validation.js";
import { scanProject } from "../src/core/scan.js";
import type { ScanContext } from "../src/core/context.js";
import { loadTrustedRulePack, loadTrustedRulePacks, parseRulePack } from "../src/rules/pack.js";
import { MAX_RULE_PACK_LINE_EVALUATIONS, MAX_RULE_PACK_LITERAL_WORK_BYTES, runRulePacks } from "../src/detectors/rule-pack.js";
import { renderTerminalReport } from "../src/reporters/terminal.js";
import { renderHtml } from "../src/reporters/html.js";
import { renderSarif } from "../src/reporters/sarif.js";
import { buildCiReport, renderMarkdownSummary } from "../src/reporters/ci.js";
import { createFixContract } from "../src/core/contracts.js";

function rulePack(overrides: Partial<RulePack> = {}): RulePack {
  return {
    schemaVersion: "1.0.0",
    packId: "team.security",
    description: "Reviewed project-specific literal security checks",
    rules: [{
      ruleId: "custom.team.security.danger-flag",
      title: "Project danger flag is enabled",
      description: "A reviewed project-specific danger flag is enabled on this source line.",
      severity: "high",
      evidenceLevel: "static_confirmed",
      confidence: "high",
      cwe: ["CWE-16"],
      tags: ["configuration", "project-specific"],
      remediation: "Disable the project danger flag and add a regression test.",
      files: {
        extensions: [".ts"],
        pathPrefixes: ["src/"],
        excludePathPrefixes: ["src/fixtures/"],
      },
      match: {
        containsAny: ["dangerFlag = true"],
        containsAll: ["const"],
        excludes: ["aisec-reviewed-near-miss"],
        caseSensitive: true,
      },
    }],
    ...overrides,
  };
}

async function writePack(path: string, pack = rulePack()): Promise<void> {
  await writeFile(path, YAML.stringify(pack));
}

function absentRulePack(): RulePack {
  return {
    schemaVersion: "1.1.0",
    packId: "team.security",
    description: "Reviewed project-specific required security invariants",
    rules: [{
      ruleId: "custom.team.security.helmet-required",
      title: "Required HTTP security middleware is not visible",
      description: "The selected application security file lacks the reviewed middleware literal on any single line.",
      severity: "high",
      evidenceLevel: "inferred",
      confidence: "medium",
      cwe: ["CWE-693"],
      tags: ["configuration", "project-specific", "security-headers"],
      remediation: "Enable the reviewed middleware in every selected application security file and add a regression test.",
      files: {
        extensions: [".ts"],
        pathPrefixes: ["src/"],
        pathSuffixes: ["security.ts"],
        excludePathPrefixes: ["src/fixtures/"],
      },
      match: {
        containsAny: ["helmet("],
        containsAll: ["app.use("],
        excludes: ["aisec-reviewed-near-miss"],
        caseSensitive: false,
        emitWhen: "absent",
      },
    }],
  };
}

test("RulePack schema and semantics reject executable, ambiguous and unsafe declarations", () => {
  const valid = rulePack();
  assert.equal(validateRulePack(valid), valid);
  assert.equal(parseRulePack(YAML.stringify(valid)).rules[0]?.match.caseSensitive, true);
  assert.equal(parseRulePack(YAML.stringify(valid)).rules[0]?.match.emitWhen, undefined, "RulePack 1.0 remains unchanged");

  const absent = absentRulePack();
  assert.equal(validateRulePack(absent), absent);
  assert.equal(parseRulePack(YAML.stringify(absent)).rules[0]?.match.emitWhen, "absent");
  const legacyWithAbsent = structuredClone(absent);
  legacyWithAbsent.schemaVersion = "1.0.0";
  assert.throws(() => validateRulePack(legacyWithAbsent), /RulePack.*emitWhen/);
  const confirmedAbsent = structuredClone(absent);
  confirmedAbsent.rules[0]!.evidenceLevel = "static_confirmed";
  assert.throws(() => validateRulePack(confirmedAbsent), /absent rule.*must use inferred evidence/);
  const invalidEmit = structuredClone(absent) as unknown as { rules: Array<{ match: { emitWhen: string } }> };
  invalidEmit.rules[0]!.match.emitWhen = "sometimes";
  assert.throws(() => validateRulePack(invalidEmit), /RulePack.*emitWhen/);

  assert.throws(() => validateRulePack({ ...valid, script: "process.exit()" }), /RulePack.*additional properties.*script/);
  const regex = structuredClone(valid) as RulePack & { rules: Array<RulePack["rules"][number] & { match: RulePack["rules"][number]["match"] & { regex?: string } }> };
  regex.rules[0]!.match.regex = "(a+)+$";
  assert.throws(() => validateRulePack(regex), /RulePack.*additional properties.*regex/);

  const verified = structuredClone(valid) as unknown as { rules: Array<{ evidenceLevel: string }> };
  verified.rules[0]!.evidenceLevel = "verified";
  assert.throws(() => validateRulePack(verified), /RulePack.*evidenceLevel/);

  const wrongNamespace = structuredClone(valid);
  wrongNamespace.rules[0]!.ruleId = "custom.other.danger-flag";
  assert.throws(() => validateRulePack(wrongNamespace), /must start with custom\.team\.security\./);

  const duplicate = structuredClone(valid);
  duplicate.rules.push(structuredClone(duplicate.rules[0]!));
  assert.throws(() => validateRulePack(duplicate), /duplicate rule/);

  const traversal = structuredClone(valid);
  traversal.rules[0]!.files.pathPrefixes = ["src/../secrets/"];
  assert.throws(() => validateRulePack(traversal), /unsafe or ambiguous path segment/);
  const backslash = structuredClone(valid);
  backslash.rules[0]!.files.pathPrefixes = ["src\\private/"];
  assert.throws(() => validateRulePack(backslash), /backslashes or control characters/);
  const prefixWithoutSlash = structuredClone(valid);
  prefixWithoutSlash.rules[0]!.files.pathPrefixes = ["src"];
  assert.throws(() => validateRulePack(prefixWithoutSlash), /must end with/);

  const contradiction = structuredClone(valid);
  contradiction.rules[0]!.match.excludes = ["dangerFlag = true"];
  assert.throws(() => validateRulePack(contradiction), /both requires and excludes/);
  assert.throws(() => parseRulePack("x".repeat(256 * 1024 + 1)), /must not exceed 256 KiB/);
  assert.throws(() => parseRulePack("schemaVersion: [\n"), /not valid YAML/);
});

test("trusted rule-pack loading enforces the outside-target path boundary and unique IDs", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-path-"));
  try {
    const target = join(parent, "target");
    await mkdir(target);
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted);
    const loaded = await loadTrustedRulePack(trusted, target);
    assert.equal(loaded.pack.packId, "team.security");
    assert.match(loaded.digestSha256, /^[a-f0-9]{64}$/);

    const targetOwned = join(target, "rules.yml");
    await writePack(targetOwned);
    await assert.rejects(() => loadTrustedRulePack(targetOwned, target), /outside the scanned target/);
    const targetResolvingLink = join(parent, "target-rules-link.yml");
    await symlink(targetOwned, targetResolvingLink);
    await assert.rejects(() => loadTrustedRulePack(targetResolvingLink, target), /outside the scanned target/);
    await assert.rejects(() => loadTrustedRulePacks([trusted, trusted], target), /Duplicate rule-pack ID/);
    await assert.rejects(() => loadTrustedRulePacks(Array.from({ length: 9 }, () => trusted), target), /cannot exceed 8/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("declarative rule packs match bounded lines and expose digest evidence across reports", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-scan-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src", "fixtures"), { recursive: true });
    await mkdir(join(target, "test"));
    await writeFile(join(target, "src", "index.ts"), [
      "const safe = false;",
      "const dangerFlag = true; // token=supersecretvalue123",
      "const dangerFlag = true; // aisec-reviewed-near-miss",
    ].join("\n"));
    await writeFile(join(target, "src", "cross-line.ts"), "const marker = true;\ndangerFlag = true;\n");
    await writeFile(join(target, "src", "settings.ts"), "DEBUG_MODE=ENABLED\n");
    await writeFile(join(target, "src", "fixtures", "ignored.ts"), "const dangerFlag = true;\n");
    await writeFile(join(target, "test", "ignored.ts"), "const dangerFlag = true;\n");
    await writeFile(join(target, ".aisec-rules.yml"), "this target-owned file is never discovered\n");
    const trusted = join(parent, "trusted-rules.yml");
    const configured = rulePack();
    configured.rules.push({
      ruleId: "custom.team.security.debug-mode",
      title: "Project debug mode is enabled",
      description: "A case-insensitive reviewed literal enables debug mode in the selected settings file.",
      severity: "medium",
      evidenceLevel: "inferred",
      confidence: "medium",
      cwe: ["CWE-489"],
      tags: ["debug", "project-specific"],
      remediation: "Disable debug mode in deployed settings.",
      files: { extensions: [".ts"], pathPrefixes: ["src/"], pathSuffixes: ["settings.ts"] },
      match: { containsAny: ["debug_mode=enabled"], caseSensitive: false },
    });
    await writePack(trusted, configured);

    const withoutPack = (await scanProject(target, { profile: "native", nativeOnly: true, persist: false })).report;
    assert.deepEqual(withoutPack.rulePacks, []);
    assert.ok(!withoutPack.coverage.some((item) => item.engine === "aisec-rule-pack"));

    const report = (await scanProject(target, {
      profile: "native",
      nativeOnly: true,
      persist: false,
      rulePackPaths: [trusted],
    })).report;
    assert.equal(report.schemaVersion, "1.4.0");
    assert.equal(report.decision, "block");
    assert.equal(report.rulePacks?.length, 1);
    assert.equal(report.rulePacks?.[0]?.packId, "team.security");
    assert.equal(report.rulePacks?.[0]?.ruleCount, 2);
    assert.match(report.rulePacks?.[0]?.digestSha256 ?? "", /^[a-f0-9]{64}$/);
    const custom = report.signals.filter((signal) => signal.engine === "aisec-rule-pack");
    assert.equal(custom.length, 2);
    const danger = custom.find((signal) => signal.ruleId === "custom.team.security.danger-flag");
    const debug = custom.find((signal) => signal.ruleId === "custom.team.security.debug-mode");
    assert.ok(danger);
    assert.ok(debug);
    assert.equal(danger.locations[0]?.path, "src/index.ts");
    assert.equal(danger.locations[0]?.line, 2);
    assert.doesNotMatch(danger.locations[0]?.snippet ?? "", /supersecretvalue123/);
    assert.match(danger.locations[0]?.snippet ?? "", /token=sup…123/);
    assert.equal(debug.locations[0]?.path, "src/settings.ts");
    assert.equal(report.coverage.find((item) => item.domain === "rule-pack:team.security")?.status, "complete");
    assert.equal(validateScanReport(report), report);
    const forgedCoverageDigest = structuredClone(report);
    forgedCoverageDigest.coverage.find((item) => item.domain === "rule-pack:team.security")!.version = "0".repeat(64);
    assert.throws(() => validateScanReport(forgedCoverageDigest), /requires exactly one required coverage record/);
    const forgedSignalDigest = structuredClone(report);
    forgedSignalDigest.signals.find((item) => item.engine === "aisec-rule-pack")!.metadata!.rulePackDigestSha256 = "0".repeat(64);
    assert.throws(() => validateScanReport(forgedSignalDigest), /does not match a declared rule-pack ID and digest/);
    const forgedEvidence = structuredClone(report);
    forgedEvidence.signals.find((item) => item.engine === "aisec-rule-pack")!.evidenceLevel = "verified";
    assert.throws(() => validateScanReport(forgedEvidence), /cannot claim verified evidence/);
    const duplicateRecord = structuredClone(report);
    duplicateRecord.rulePacks!.push(structuredClone(duplicateRecord.rulePacks![0]!));
    assert.throws(() => validateScanReport(duplicateRecord), /duplicate rule pack|uniqueItems/);

    const serialized = JSON.stringify(report);
    assert.doesNotMatch(serialized, new RegExp(trusted.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    const terminal = renderTerminalReport(report);
    assert.match(terminal, /Rule packs: team\.security sha256:/);
    const html = renderHtml(report);
    assert.match(html, /Declarative rule packs/);
    assert.match(html, /team\.security/);
    const sarif = renderSarif(report) as { runs: Array<{ properties: { rulePacks: unknown[] } }> };
    assert.equal(sarif.runs[0]?.properties.rulePacks.length, 1);
    const ci = buildCiReport(report);
    assert.equal(ci.schemaVersion, "1.4.0");
    assert.equal(ci.rulePacks?.[0]?.packId, "team.security");
    assert.match(renderMarkdownSummary(ci), /## Declarative rule packs[\s\S]*team\.security/);
    const contract = createFixContract(report, report.findings.find((finding) => finding.signalIds.includes(danger.id))!.id);
    assert.match(contract.rescan.command, /--rule-pack "<same-trusted-rule-pack-team\.security\.yml>"/);
    assert.doesNotMatch(contract.rescan.command, new RegExp(trusted.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("baseline rescans require the same declarative rule-pack ID and digest set", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-baseline-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src"), { recursive: true });
    await writeFile(join(target, "src", "index.ts"), "const dangerFlag = true;\n");
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted);
    const baseline = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    })).report;
    const baselinePath = join(parent, "baseline.json");
    await writeFile(baselinePath, `${JSON.stringify(baseline)}\n`);

    const same = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    }, baselinePath)).report;
    assert.equal(same.comparison?.remaining.length, 1);
    await assert.rejects(() => scanProject(target, {
      profile: "native", nativeOnly: true, persist: false,
    }, baselinePath), /different operator rule-pack set/);

    const changed = structuredClone(rulePack());
    changed.description = "Deliberately changed reviewed rule pack";
    await writePack(trusted, changed);
    await assert.rejects(() => scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    }, baselinePath), /different operator rule-pack set/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("RulePack 1.1 reports missing required literals without fabricating evidence", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-absent-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src", "fixtures"), { recursive: true });
    await writeFile(join(target, "src", "security.ts"), "const app = createApplication();\n");
    await writeFile(join(target, "src", "secure-security.ts"), "APP.USE(HELMET());\n");
    await writeFile(join(target, "src", "fixtures", "fixture-security.ts"), "const app = createApplication();\n");
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted, absentRulePack());

    const missing = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    })).report;
    const signals = missing.signals.filter((signal) => signal.ruleId === "custom.team.security.helmet-required");
    assert.equal(signals.length, 1);
    assert.equal(signals[0]?.evidenceLevel, "inferred");
    assert.equal(signals[0]?.metadata?.rulePackMatch, "absent");
    assert.deepEqual(signals[0]?.locations, [{ path: "src/security.ts" }]);
    assert.equal(missing.coverage.find((item) => item.domain === "rule-pack:team.security")?.status, "complete");
    assert.equal(missing.decision, "review");
    assert.equal(validateScanReport(missing), missing);
    const forged = structuredClone(missing);
    forged.signals.find((signal) => signal.ruleId === "custom.team.security.helmet-required")!.evidenceLevel = "static_confirmed";
    assert.throws(() => validateScanReport(forged), /absent custom signal.*must use inferred evidence/);
    const forgedLocation = structuredClone(missing);
    forgedLocation.signals.find((signal) => signal.ruleId === "custom.team.security.helmet-required")!.locations[0]!.line = 1;
    assert.throws(() => validateScanReport(forgedLocation), /absent custom signal.*path-only location/);
    const forgedMode = structuredClone(missing);
    forgedMode.signals.find((signal) => signal.ruleId === "custom.team.security.helmet-required")!.metadata!.rulePackMatch = "sometimes";
    assert.throws(() => validateScanReport(forgedMode), /unsupported rule-pack match mode/);

    await writeFile(join(target, "src", "security.ts"), "app.use(helmet());\n");
    const satisfied = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    })).report;
    assert.equal(satisfied.signals.filter((signal) => signal.ruleId === "custom.team.security.helmet-required").length, 0);
    assert.equal(satisfied.coverage.find((item) => item.domain === "rule-pack:team.security")?.status, "complete");
    assert.equal(satisfied.decision, "no_blockers_found");

    const driftedSelector = absentRulePack();
    driftedSelector.rules[0]!.files.pathSuffixes = ["missing-security.ts"];
    await writePack(trusted, driftedSelector);
    const unselected = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    })).report;
    assert.equal(unselected.signals.filter((signal) => signal.ruleId === "custom.team.security.helmet-required").length, 0);
    const coverage = unselected.coverage.find((item) => item.domain === "rule-pack:team.security");
    assert.equal(coverage?.status, "partial");
    assert.match(coverage?.reason ?? "", /absent rule.*selected no files/);
    assert.equal(unselected.decision, "incomplete");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("custom finding floods are capped and make rule-pack coverage partial", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-limit-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src"), { recursive: true });
    await writeFile(join(target, "src", "many.ts"), `${Array.from({ length: 2001 }, (_, index) => `const dangerFlag = true; // ${index}`).join("\n")}\n`);
    const pack = rulePack();
    pack.rules[0]!.severity = "info";
    pack.rules[0]!.evidenceLevel = "inferred";
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted, pack);
    const report = (await scanProject(target, {
      profile: "native", nativeOnly: true, persist: false, rulePackPaths: [trusted],
    })).report;
    assert.equal(report.signals.filter((signal) => signal.engine === "aisec-rule-pack").length, 2000);
    const coverage = report.coverage.find((item) => item.domain === "rule-pack:team.security");
    assert.equal(coverage?.status, "partial");
    assert.match(coverage?.reason ?? "", /2000.*signal safety limit/);
    assert.equal(report.decision, "incomplete");
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

function boundedContext(content: string): ScanContext {
  return {
    root: "/operator-test-target",
    inventory: {
      files: [{ absolutePath: "/operator-test-target/src/input.ts", relativePath: "src/input.ts", size: Buffer.byteLength(content), content }],
      totalBytes: Buffer.byteLength(content),
      skippedFiles: 0,
      skippedReasons: {},
    },
    profile: {
      root: "/operator-test-target", projectId: "bounded-test", detectedAt: new Date(0).toISOString(), languages: [], frameworks: [], packageManagers: [],
      baas: [], mobilePlatforms: [], llmProviders: [], manifests: [], artifacts: [], routes: [], fileCount: 1, skippedFiles: 0,
    },
    assetGraph: { nodes: [], edges: [] },
    options: {
      profile: "native", artifacts: [], nativeOnly: true, includeGitHistory: false, maxFiles: 1, maxFileBytes: 16 * 1024 * 1024,
      maxTotalBytes: 16 * 1024 * 1024, timeoutMs: 120_000, persist: false, confirmPolicySuppressions: false, rulePackPaths: [],
    },
  };
}

test("RulePack coverage inherits unsafe inventory gaps but not expected exclusions", async () => {
  const expectedExclusion = boundedContext("const dangerFlag = true;\n");
  expectedExclusion.inventory.skippedFiles = 1;
  expectedExclusion.inventory.skippedReasons = { excluded_directory: 1 };
  const excludedResult = await runRulePacks(expectedExclusion, [{ pack: rulePack(), digestSha256: "0".repeat(64) }]);
  assert.equal(excludedResult.coverage[0]?.status, "complete");
  assert.equal(excludedResult.coverage[0]?.reason, undefined);
  assert.equal(excludedResult.signals.length, 1);

  const partialInventory = boundedContext("const dangerFlag = true;\n");
  partialInventory.inventory.skippedFiles = 2;
  partialInventory.inventory.skippedReasons = { oversized_file: 1, symbolic_link: 1 };
  const partialResult = await runRulePacks(partialInventory, [{ pack: rulePack(), digestSha256: "1".repeat(64) }]);
  assert.equal(partialResult.coverage[0]?.status, "partial");
  assert.match(partialResult.coverage[0]?.reason ?? "", /project inventory is partial: oversized_file: 1, symbolic_link: 1/);
  assert.equal(partialResult.signals.length, excludedResult.signals.length, "inventory coverage must not fabricate or suppress findings");
});

test("custom literal and line evaluation work is bounded before it can amplify scan cost", async () => {
  const manyLiterals = rulePack();
  manyLiterals.rules[0]!.match.containsAny = Array.from({ length: 32 }, (_, index) => `not-present-${index}`);
  const workContent = "x".repeat(Math.floor(MAX_RULE_PACK_LITERAL_WORK_BYTES / 32) + 1);
  const workResult = await runRulePacks(boundedContext(workContent), [{ pack: manyLiterals, digestSha256: "1".repeat(64) }]);
  assert.equal(workResult.signals.length, 0);
  assert.equal(workResult.coverage[0]?.status, "partial");
  assert.match(workResult.coverage[0]?.reason ?? "", /literal-byte shared work limit/);

  const lineContent = "x\n".repeat(MAX_RULE_PACK_LINE_EVALUATIONS + 1);
  const linePack = absentRulePack();
  delete linePack.rules[0]!.files.pathSuffixes;
  const lineResult = await runRulePacks(boundedContext(lineContent), [{ pack: linePack, digestSha256: "2".repeat(64) }]);
  assert.equal(lineResult.signals.length, 0);
  assert.equal(lineResult.coverage[0]?.status, "partial");
  assert.match(lineResult.coverage[0]?.reason ?? "", /shared line evaluation limit/);

  const floodContext = boundedContext("");
  floodContext.inventory.files = Array.from({ length: 2001 }, (_, index) => ({
    absolutePath: `/operator-test-target/src/input-${index}.ts`,
    relativePath: `src/input-${index}.ts`,
    size: 1,
    content: "x",
  }));
  floodContext.inventory.totalBytes = 2001;
  const floodPack = absentRulePack();
  delete floodPack.rules[0]!.files.pathSuffixes;
  const floodResult = await runRulePacks(floodContext, [{ pack: floodPack, digestSha256: "3".repeat(64) }]);
  assert.equal(floodResult.signals.length, 2000);
  assert.equal(floodResult.coverage[0]?.status, "partial");
  assert.match(floodResult.coverage[0]?.reason ?? "", /2000.*signal safety limit/);
});
