import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { RuleApplicabilityProfile, RuleCatalog, RuleCatalogEntry } from "../schema.js";
import { validateRuleCatalog } from "../core/schema-validation.js";

function defaultCatalogPath(): string {
  return fileURLToPath(new URL("../../../rules/catalog.json", import.meta.url));
}

export function loadRuleCatalog(path = defaultCatalogPath()): RuleCatalog {
  return validateRuleCatalog(JSON.parse(readFileSync(path, "utf8")) as unknown);
}

function markdownCell(value: string): string {
  return value.replaceAll("|", "\\|").replace(/[\r\n]+/g, " ").trim();
}

function applicabilityText(rule: RuleCatalogEntry, profiles: Map<string, RuleApplicabilityProfile>): string {
  return rule.applicability.flatMap((id) => {
    const profile = profiles.get(id);
    if (!profile) throw new Error(`Rule ${rule.ruleId} references unknown applicability profile: ${id}`);
    return profile.technologies.map((technology) => `${technology.name} ${technology.versionRange} (${technology.basis})`);
  }).join("; ");
}

export function renderRuleCatalog(catalog: RuleCatalog): string {
  validateRuleCatalog(catalog);
  const profiles = new Map(catalog.applicabilityProfiles.map((profile) => [profile.id, profile]));
  const nativeCount = catalog.rules.filter((rule) => rule.source === "native").length;
  const opengrepCount = catalog.rules.filter((rule) => rule.source === "bundled_opengrep").length;
  const lines = [
    "# AIsec rule catalog",
    "",
    "<!-- Generated from rules/catalog.json by scripts/rule-catalog.mjs. Do not edit by hand. -->",
    "",
    catalog.description,
    "",
    `Catalog version \`${catalog.schemaVersion}\`: ${catalog.rules.length} shipped deterministic rules (${nativeCount} native, ${opengrepCount} bundled Opengrep).`,
    "",
    "A version range of `*` is not a full-framework support claim. It means AIsec does not gate that rule on dependency semver; only the bounded syntax, configuration, artifact format or bundled engine rule described by the applicability profile is covered.",
    "",
    "## Applicability profiles",
    "",
    "| Profile | Languages/formats | Technologies and versions | Version statement |",
    "| --- | --- | --- | --- |",
    ...catalog.applicabilityProfiles.map((profile) => `| \`${markdownCell(profile.id)}\` | ${profile.languages.map(markdownCell).join(", ")} | ${profile.technologies.map((technology) => `${markdownCell(technology.name)} \`${markdownCell(technology.versionRange)}\` (${technology.basis})`).join("; ")} | ${markdownCell(profile.versionStatement)} |`),
    "",
    "## Rules",
    "",
  ];
  const categories = [...new Set(catalog.rules.map((rule) => rule.category))];
  for (const category of categories) {
    lines.push(
      `### ${category}`,
      "",
      "| Rule | Source | Default evidence | CWE | Applicability | Summary | Known false-positive modes | Review guidance |",
      "| --- | --- | --- | --- | --- | --- | --- | --- |",
      ...catalog.rules.filter((rule) => rule.category === category).map((rule) => `| \`${markdownCell(rule.ruleId)}\` | ${rule.source} | \`${rule.defaultEvidenceLevel}\` | ${rule.cwe.map((cwe) => `\`${cwe}\``).join(", ")} | ${markdownCell(applicabilityText(rule, profiles))} | ${markdownCell(rule.summary)} | ${rule.falsePositiveModes.map(markdownCell).join("<br>")} | ${markdownCell(rule.reviewGuidance)} |`),
      "",
    );
  }
  lines.push(
    "## Boundary",
    "",
    "This catalog documents shipped deterministic checks and their intended review context. It does not establish exploitability, complete framework coverage, a tested-semver guarantee or security certification. External Gitleaks and Trivy rule IDs are upstream runtime data and are not enumerated here.",
  );
  return `${lines.join("\n")}\n`;
}
