import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import YAML from "yaml";
import type { FileInventory } from "../src/core/files.js";
import { validateRulePackPreview } from "../src/core/schema-validation.js";
import type { RulePack, RulePackRule } from "../src/schema.js";
import type { LoadedRulePack } from "../src/rules/pack.js";
import {
  buildRulePackPreview,
  MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE,
  MAX_RULE_PACK_PREVIEW_PATHS_TOTAL,
  previewRulePacks,
  renderRulePackPreview,
} from "../src/rules/preview.js";
import { MAX_RULE_PACK_SELECTOR_EVALUATIONS } from "../src/rules/selection.js";

const here = dirname(fileURLToPath(import.meta.url));

function previewRule(ruleId: string, overrides: Partial<RulePackRule> = {}): RulePackRule {
  return {
    ruleId,
    title: `Preview selector for ${ruleId}`,
    description: "A reviewed project-specific selector used by the preview test.",
    severity: "medium",
    evidenceLevel: "inferred",
    confidence: "medium",
    cwe: ["CWE-693"],
    tags: ["preview", "project-specific"],
    remediation: "Review the selected project files.",
    files: { extensions: [".ts"], pathPrefixes: ["src/"], excludePathPrefixes: ["src/fixtures/"] },
    match: { containsAny: ["preview-secret-literal"], caseSensitive: true },
    ...overrides,
  };
}

function previewPack(rules?: RulePackRule[]): RulePack {
  return {
    schemaVersion: "1.1.0",
    packId: "team.preview",
    description: "Reviewed selector preview rules",
    rules: rules ?? [
      previewRule("custom.team.preview.present-check"),
      previewRule("custom.team.preview.security-required", {
        files: { extensions: [".ts"], pathPrefixes: ["src/"], pathSuffixes: ["security.ts"], excludePathPrefixes: ["src/fixtures/"] },
        match: { containsAny: ["helmet("], emitWhen: "absent" },
      }),
    ],
  };
}

async function writePack(path: string, pack = previewPack()): Promise<void> {
  await writeFile(path, YAML.stringify(pack));
}

function loadedPack(rules: RulePackRule[]): LoadedRulePack {
  return { pack: previewPack(rules), digestSha256: "a".repeat(64) };
}

function syntheticInventory(count: number, skippedReasons: Record<string, number> = {}): FileInventory {
  return {
    files: Array.from({ length: count }, (_, index) => ({
      absolutePath: `/operator-preview-target/src/file-${String(index).padStart(5, "0")}.ts`,
      relativePath: `src/file-${String(index).padStart(5, "0")}.ts`,
      size: 1,
      content: "x",
    })),
    totalBytes: count,
    skippedFiles: Object.values(skippedReasons).reduce((total, value) => total + value, 0),
    skippedReasons,
  };
}

test("RulePack preview validates packs and reports deterministic selector reach without literals or pack paths", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-preview-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src", "fixtures"), { recursive: true });
    await writeFile(join(target, "src", "index.ts"), "const marker = 'preview-secret-literal';\n");
    await writeFile(join(target, "src", "security.ts"), "const app = createApplication();\n");
    await writeFile(join(target, "src", "fixtures", "fixture-security.ts"), "const fixture = true;\n");
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted);

    const preview = await previewRulePacks(target, { rulePackPaths: [trusted] });
    assert.equal(preview.schemaVersion, "1.0.0");
    assert.equal(preview.status, "complete");
    assert.equal(preview.rulePacks[0]?.packId, "team.preview");
    assert.deepEqual(preview.rulePacks[0]?.rules.map((rule) => rule.ruleId), [
      "custom.team.preview.present-check",
      "custom.team.preview.security-required",
    ]);
    assert.deepEqual(preview.rulePacks[0]?.rules[0]?.selectedFiles, ["src/index.ts", "src/security.ts"]);
    assert.deepEqual(preview.rulePacks[0]?.rules[1]?.selectedFiles, ["src/security.ts"]);
    assert.equal(preview.rulePacks[0]?.rules[1]?.emitWhen, "absent");
    assert.equal(validateRulePackPreview(preview), preview);
    const serialized = JSON.stringify(preview);
    assert.doesNotMatch(serialized, /preview-secret-literal|helmet\(/);
    assert.doesNotMatch(serialized, new RegExp(trusted.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    const terminal = renderRulePackPreview(preview);
    assert.match(terminal, /RULE PACK PREVIEW COMPLETE/);
    assert.match(terminal, /custom\.team\.preview\.security-required/);
    assert.doesNotMatch(terminal, /preview-secret-literal|helmet\(/);

    await assert.rejects(() => previewRulePacks(target, { rulePackPaths: [] }), /requires at least one rule-pack path/);
    await assert.rejects(() => previewRulePacks(target, { rulePackPaths: [trusted], unexpected: true } as never), /unsupported option/);
    const targetOwned = join(target, "rules.yml");
    await writePack(targetOwned);
    await assert.rejects(() => previewRulePacks(target, { rulePackPaths: [targetOwned] }), /outside the scanned target/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("RulePack preview fails partial for empty absent selectors but keeps empty present selectors complete", () => {
  const inventory = syntheticInventory(1);
  const absent = previewRule("custom.team.preview.absent-empty", {
    files: { extensions: [".ts"], pathSuffixes: ["missing-security.ts"] },
    match: { containsAny: ["helmet("], emitWhen: "absent" },
  });
  const absentPreview = buildRulePackPreview("/operator-preview-target", inventory, [loadedPack([absent])]);
  assert.equal(absentPreview.status, "partial");
  assert.equal(absentPreview.rulePacks[0]?.rules[0]?.selectedFileCount, 0);
  assert.match(absentPreview.rulePacks[0]?.rules[0]?.reasons[0] ?? "", /absent rule selected no existing inventory files/);

  const present = previewRule("custom.team.preview.present-empty", {
    files: { extensions: [".ts"], pathSuffixes: ["missing-security.ts"] },
  });
  const presentPreview = buildRulePackPreview("/operator-preview-target", inventory, [loadedPack([present])]);
  assert.equal(presentPreview.status, "complete");
  assert.equal(presentPreview.rulePacks[0]?.rules[0]?.selectedFileCount, 0);

  const forgedCount = structuredClone(absentPreview);
  forgedCount.rulePacks[0]!.rules[0]!.selectedFileCount = 1;
  assert.throws(() => validateRulePackPreview(forgedCount), /selected-file counts are inconsistent/);
  const forgedStatus = structuredClone(absentPreview);
  forgedStatus.rulePacks[0]!.rules[0]!.status = "complete";
  assert.throws(() => validateRulePackPreview(forgedStatus), /status must agree with its reasons/);
  const forgedPath = structuredClone(presentPreview);
  forgedPath.rulePacks[0]!.rules[0]!.selectedFileCount = 1;
  forgedPath.rulePacks[0]!.rules[0]!.selectedFiles = ["../operator-secret.yml"];
  assert.throws(() => validateRulePackPreview(forgedPath), /unsafe or non-normalized selected path/);
  assert.throws(() => validateRulePackPreview({ ...absentPreview, vulnerabilityConfirmed: true }), /additional properties/);
});

test("RulePack preview bounds inventory trust, selected paths and selector work", () => {
  const rule = previewRule("custom.team.preview.path-bound");
  const pathBound = buildRulePackPreview("/operator-preview-target", syntheticInventory(MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE + 1), [loadedPack([rule])]);
  const pathRule = pathBound.rulePacks[0]!.rules[0]!;
  assert.equal(pathBound.status, "partial");
  assert.equal(pathRule.selectedFileCount, MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE + 1);
  assert.equal(pathRule.selectedFiles.length, MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE);
  assert.equal(pathRule.omittedSelectedFileCount, 1);

  const totalRules = Array.from({ length: 21 }, (_, index) => previewRule(`custom.team.preview.total-${String(index).padStart(2, "0")}`));
  const totalBound = buildRulePackPreview("/operator-preview-target", syntheticInventory(100), [loadedPack(totalRules)]);
  assert.equal(totalBound.rulePacks[0]!.rules.flatMap((item) => item.selectedFiles).length, MAX_RULE_PACK_PREVIEW_PATHS_TOTAL);
  assert.equal(totalBound.rulePacks[0]!.rules.at(-1)!.omittedSelectedFileCount, 100);
  assert.equal(totalBound.status, "partial");

  const inventoryPartial = buildRulePackPreview("/operator-preview-target", syntheticInventory(1, { file_limit: 1 }), [loadedPack([rule])]);
  assert.equal(inventoryPartial.inventory.status, "partial");
  assert.equal(inventoryPartial.rulePacks[0]?.status, "partial");
  assert.match(inventoryPartial.inventory.reasons[0] ?? "", /file_limit: 1/);

  const maximumSkipped = buildRulePackPreview("/operator-preview-target", syntheticInventory(0, { excluded_directory: 100_000, entry_limit: 1 }), [loadedPack([rule])]);
  assert.equal(maximumSkipped.inventory.skippedFiles, 100_001);
  assert.equal(maximumSkipped.status, "partial");

  const workRules = Array.from({ length: 100 }, (_, index) => previewRule(`custom.team.preview.work-${String(index).padStart(2, "0")}`));
  const workInventory = syntheticInventory(Math.floor(MAX_RULE_PACK_SELECTOR_EVALUATIONS / 100) + 1);
  const workBound = buildRulePackPreview("/operator-preview-target", workInventory, [loadedPack(workRules)]);
  const finalRule = workBound.rulePacks[0]!.rules.at(-1)!;
  assert.equal(workBound.status, "partial");
  assert.ok(finalRule.evaluatedFileCount < workInventory.files.length);
  assert.match(finalRule.reasons.join(" "), /1000000 shared rule-file limit/);
});

test("rule-pack check CLI returns stable complete, partial and invalid exit codes", async () => {
  const parent = await mkdtemp(join(tmpdir(), "aisec-rule-pack-preview-cli-"));
  try {
    const target = join(parent, "target");
    await mkdir(join(target, "src"), { recursive: true });
    await writeFile(join(target, "src", "security.ts"), "const app = createApplication();\n");
    const trusted = join(parent, "trusted-rules.yml");
    await writePack(trusted);
    const cli = join(here, "..", "src", "cli.js");
    const json = spawnSync(process.execPath, [cli, "rule-pack", "check", target, "--rule-pack", trusted, "--format", "json"], { encoding: "utf8" });
    assert.equal(json.status, 0, json.stderr);
    const preview = JSON.parse(json.stdout);
    assert.equal(preview.status, "complete");
    assert.equal(preview.rulePacks[0].packId, "team.preview");

    const empty = previewPack([previewRule("custom.team.preview.empty-required", {
      files: { extensions: [".ts"], pathSuffixes: ["missing.ts"] },
      match: { containsAny: ["helmet("], emitWhen: "absent" },
    })]);
    await writePack(trusted, empty);
    const partial = spawnSync(process.execPath, [cli, "rule-pack", "check", target, "--rule-pack", trusted], { encoding: "utf8" });
    assert.equal(partial.status, 2, partial.stderr);
    assert.match(partial.stdout, /RULE PACK PREVIEW PARTIAL/);
    assert.match(partial.stdout, /selected no existing inventory files/);

    const invalid = spawnSync(process.execPath, [cli, "rule-pack", "check", target], { encoding: "utf8" });
    assert.equal(invalid.status, 64);
    assert.match(invalid.stderr, /requires at least one --rule-pack/);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});
