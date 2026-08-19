import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parse } from "yaml";
import type { RuleCatalog } from "../src/schema.js";
import { validateRuleCatalog } from "../src/core/schema-validation.js";
import { VERIFIED_ENGINE_VERSIONS } from "../src/engines/compatibility.js";
import { loadRuleCatalog, renderRuleCatalog } from "../src/rules/catalog.js";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(here, "..", "..");
const catalogPath = join(repositoryRoot, "rules", "catalog.json");

test("the public rule catalog is strict, complete and semantically linked", () => {
  const catalog = loadRuleCatalog(catalogPath);
  assert.equal(validateRuleCatalog(catalog), catalog);
  assert.equal(catalog.rules.length, 58);
  assert.equal(catalog.rules.filter((rule) => rule.source === "native").length, 55);
  assert.equal(catalog.rules.filter((rule) => rule.source === "bundled_opengrep").length, 3);
  assert.ok(catalog.rules.every((rule) => rule.cwe.length > 0
    && rule.applicability.length > 0 && rule.falsePositiveModes.length > 0 && rule.reviewGuidance.length > 0));
  assert.ok(catalog.applicabilityProfiles.every((profile) => profile.technologies.every((technology) => technology.versionRange.length > 0)));

  const unknownField = structuredClone(catalog) as RuleCatalog & { securityCertified?: boolean };
  unknownField.securityCertified = true;
  assert.throws(() => validateRuleCatalog(unknownField), /RuleCatalog.*additional properties.*securityCertified/);

  const duplicateProfile = structuredClone(catalog);
  duplicateProfile.applicabilityProfiles.push(structuredClone(duplicateProfile.applicabilityProfiles[0]!));
  assert.throws(() => validateRuleCatalog(duplicateProfile), /duplicate applicability profile/);

  const duplicateRule = structuredClone(catalog);
  duplicateRule.rules.push(structuredClone(duplicateRule.rules[0]!));
  assert.throws(() => validateRuleCatalog(duplicateRule), /duplicate rule/);

  const missingProfile = structuredClone(catalog);
  missingProfile.rules[0]!.applicability = ["missing-profile"];
  assert.throws(() => validateRuleCatalog(missingProfile), /references unknown applicability profile/);

  const invalidCwe = structuredClone(catalog) as RuleCatalog;
  invalidCwe.rules[0]!.cwe = ["CWE-0"];
  assert.throws(() => validateRuleCatalog(invalidCwe), /RuleCatalog.*cwe/);
});

test("the benchmark cases consume the native catalog without a second embedded catalog", async () => {
  const catalog = loadRuleCatalog(catalogPath);
  const native = new Map(catalog.rules.filter((rule) => rule.source === "native").map((rule) => [rule.ruleId, rule]));
  const manifest = JSON.parse(await readFile(join(repositoryRoot, "benchmark", "manifest.json"), "utf8")) as {
    schemaVersion: number;
    ruleCatalog?: unknown;
    cases: Array<{ id: string; category: string; variant: "positive" | "near_miss"; expectedRuleIds: string[]; nearMissRuleIds?: string[] }>;
  };
  assert.equal(manifest.schemaVersion, 3);
  assert.equal(manifest.ruleCatalog, undefined);
  const positive = new Set(manifest.cases.flatMap((item) => item.expectedRuleIds));
  const nearMiss = new Set(manifest.cases.flatMap((item) => item.nearMissRuleIds ?? []));
  assert.deepEqual([...positive].sort(), [...native.keys()].sort());
  assert.deepEqual([...nearMiss].sort(), [...native.keys()].sort());
  for (const item of manifest.cases) {
    for (const ruleId of [...item.expectedRuleIds, ...(item.nearMissRuleIds ?? [])]) {
      assert.equal(native.get(ruleId)?.category, item.category, `${ruleId} category must match ${item.id}`);
    }
  }
});

test("bundled Opengrep YAML cannot drift from catalog ids, languages, CWE or verified engine version", async () => {
  const catalog = loadRuleCatalog(catalogPath);
  const profiles = new Map(catalog.applicabilityProfiles.map((profile) => [profile.id, profile]));
  const bundled = new Map(catalog.rules.filter((rule) => rule.source === "bundled_opengrep").map((rule) => [rule.ruleId, rule]));
  const config = parse(await readFile(join(repositoryRoot, "rules", "opengrep", "security.yml"), "utf8")) as {
    rules: Array<{ id: string; languages: string[]; metadata?: { cwe?: string | string[] } }>;
  };
  assert.deepEqual(config.rules.map((rule) => rule.id).sort(), [...bundled.keys()].sort());
  for (const configured of config.rules) {
    const entry = bundled.get(configured.id)!;
    const languages = new Set(entry.applicability.flatMap((id) => profiles.get(id)!.languages).map((language) => language.toLowerCase()));
    assert.deepEqual([...languages].sort(), [...configured.languages].sort());
    const cwe = Array.isArray(configured.metadata?.cwe) ? configured.metadata.cwe : [configured.metadata?.cwe].filter((value): value is string => Boolean(value));
    assert.deepEqual([...entry.cwe].sort(), [...cwe].sort());
    for (const profileId of entry.applicability) {
      for (const technology of profiles.get(profileId)!.technologies) {
        assert.equal(technology.basis, "engine");
        assert.ok(VERIFIED_ENGINE_VERSIONS.opengrep.includes(technology.versionRange));
      }
    }
  }
});

test("RULES.md is the deterministic rendering of the machine-readable catalog", async () => {
  const catalog = loadRuleCatalog(catalogPath);
  assert.equal(await readFile(join(repositoryRoot, "RULES.md"), "utf8"), renderRuleCatalog(catalog));
});
