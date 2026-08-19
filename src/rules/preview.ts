import type { FileInventory } from "../core/files.js";
import { collectProjectFiles, inventoryCoverage } from "../core/files.js";
import { DEFAULT_SCAN_OPTIONS, normalizeScanOptions } from "../core/scan.js";
import { validateRulePackPreview } from "../core/schema-validation.js";
import { TOOL_VERSION } from "../core/constants.js";
import { resolveSafeRoot } from "../core/utils.js";
import { safeRelativePath, singleLine } from "../reporters/safety.js";
import { RULE_PACK_PREVIEW_SCHEMA_VERSION, type RulePackPreview, type RulePackPreviewRecord, type RulePackRulePreview } from "../schema.js";
import { loadTrustedRulePacks, type LoadedRulePack } from "./pack.js";
import { MAX_RULE_PACK_SELECTOR_EVALUATIONS, rulePackFileSelected } from "./selection.js";

export const MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE = 100;
export const MAX_RULE_PACK_PREVIEW_PATHS_TOTAL = 2_000;

export interface RulePackPreviewOptions {
  rulePackPaths: string[];
  maxFiles?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
}

const PREVIEW_OPTION_KEYS = new Set(["rulePackPaths", "maxFiles", "maxFileBytes", "maxTotalBytes"]);

function normalizePreviewOptions(value: RulePackPreviewOptions): Required<RulePackPreviewOptions> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Rule-pack preview options must be an object");
  for (const key of Object.keys(value)) {
    if (!PREVIEW_OPTION_KEYS.has(key)) throw new Error(`Rule-pack preview contains unsupported option: ${key}`);
  }
  if (!Array.isArray(value.rulePackPaths) || value.rulePackPaths.length === 0) {
    throw new Error("Rule-pack preview requires at least one rule-pack path");
  }
  const normalized = normalizeScanOptions({
    profile: "native",
    nativeOnly: true,
    persist: false,
    rulePackPaths: [...value.rulePackPaths],
    maxFiles: value.maxFiles ?? DEFAULT_SCAN_OPTIONS.maxFiles,
    maxFileBytes: value.maxFileBytes ?? DEFAULT_SCAN_OPTIONS.maxFileBytes,
    maxTotalBytes: value.maxTotalBytes ?? DEFAULT_SCAN_OPTIONS.maxTotalBytes,
  });
  return {
    rulePackPaths: [...normalized.rulePackPaths],
    maxFiles: normalized.maxFiles,
    maxFileBytes: normalized.maxFileBytes,
    maxTotalBytes: normalized.maxTotalBytes,
  };
}

function status<T extends { reasons: string[] }>(value: T): T & { status: "complete" | "partial" } {
  return { ...value, status: value.reasons.length > 0 ? "partial" : "complete" };
}

function summary(first: string, count: number, suffix: string): string {
  return count > 1 ? `${first}; ${count - 1} additional ${suffix}` : first;
}

export function buildRulePackPreview(target: string, inventory: FileInventory, loadedPacks: readonly LoadedRulePack[]): RulePackPreview {
  const inventoryResult = inventoryCoverage(inventory);
  const inventoryReasons = inventoryResult.status === "partial"
    ? [`project inventory is partial${inventoryResult.reason ? `: ${inventoryResult.reason}` : ""}`]
    : [];
  const previewInventory = {
    status: inventoryResult.status,
    fileCount: inventory.files.length,
    totalBytes: inventory.totalBytes,
    skippedFiles: inventory.skippedFiles,
    skippedReasons: Object.fromEntries(Object.entries(inventory.skippedReasons).sort(([left], [right]) => left.localeCompare(right))),
    reasons: inventoryReasons,
  } as const;
  let selectorEvaluations = 0;
  let selectorLimitReached = false;
  let listedPaths = 0;
  const rulePacks: RulePackPreviewRecord[] = [];

  for (const loaded of loadedPacks) {
    const rules: RulePackRulePreview[] = [];
    for (const rule of [...loaded.pack.rules].sort((left, right) => left.ruleId.localeCompare(right.ruleId))) {
      const emitWhen = rule.match.emitWhen ?? "present";
      const selectedFiles: string[] = [];
      let evaluatedFileCount = 0;
      let selectedFileCount = 0;
      let selectionComplete = !selectorLimitReached;
      if (!selectorLimitReached) {
        for (const file of inventory.files) {
          if (selectorEvaluations >= MAX_RULE_PACK_SELECTOR_EVALUATIONS) {
            selectorLimitReached = true;
            selectionComplete = false;
            break;
          }
          selectorEvaluations += 1;
          evaluatedFileCount += 1;
          if (!rulePackFileSelected(file.relativePath, rule.files)) continue;
          selectedFileCount += 1;
          const path = safeRelativePath(file.relativePath);
          if (path && selectedFiles.length < MAX_RULE_PACK_PREVIEW_PATHS_PER_RULE && listedPaths < MAX_RULE_PACK_PREVIEW_PATHS_TOTAL) {
            selectedFiles.push(path);
            listedPaths += 1;
          }
        }
      }
      const omittedSelectedFileCount = selectedFileCount - selectedFiles.length;
      const reasons: string[] = [];
      if (!selectionComplete) reasons.push(`selector evaluation did not complete within the ${MAX_RULE_PACK_SELECTOR_EVALUATIONS} shared rule-file limit`);
      if (omittedSelectedFileCount > 0) {
        reasons.push(`selected path preview omitted ${omittedSelectedFileCount} path(s) because path output is bounded or unsafe`);
      }
      if (selectionComplete && emitWhen === "absent" && selectedFileCount === 0) {
        reasons.push("absent rule selected no existing inventory files; a scan would mark this rule pack coverage partial");
      }
      rules.push(status({
        ruleId: rule.ruleId,
        title: rule.title,
        emitWhen,
        evaluatedFileCount,
        selectedFileCount,
        selectedFiles,
        omittedSelectedFileCount,
        reasons,
      }));
    }

    const packReasons: string[] = [];
    if (previewInventory.status === "partial") packReasons.push("project inventory is partial, so selector reach may be incomplete");
    const partialRules = rules.filter((rule) => rule.status === "partial");
    if (partialRules.length > 0) {
      packReasons.push(summary(`rule ${partialRules[0]!.ruleId} preview is partial`, partialRules.length, "rule preview(s) are partial"));
    }
    rulePacks.push(status({
      packId: loaded.pack.packId,
      digestSha256: loaded.digestSha256,
      ruleCount: loaded.pack.rules.length,
      rules,
      reasons: packReasons,
    }));
  }

  const reasons: string[] = [];
  if (previewInventory.status === "partial") reasons.push("project inventory is partial");
  const partialPacks = rulePacks.filter((pack) => pack.status === "partial");
  if (partialPacks.length > 0) reasons.push(summary(`rule pack ${partialPacks[0]!.packId} preview is partial`, partialPacks.length, "rule-pack preview(s) are partial"));
  return validateRulePackPreview(status({
    schemaVersion: RULE_PACK_PREVIEW_SCHEMA_VERSION,
    toolVersion: TOOL_VERSION,
    target,
    inventory: previewInventory,
    rulePacks,
    reasons,
    disclaimer: "This read-only preview reports bounded selector reach only. It does not evaluate rule literals, emit vulnerability findings, or prove that a project is secure or vulnerable.",
  }));
}

export async function previewRulePacks(inputPath: string, options: RulePackPreviewOptions): Promise<RulePackPreview> {
  if (typeof inputPath !== "string" || !inputPath.trim()) throw new Error("Rule-pack preview target must be a non-empty path");
  const normalized = normalizePreviewOptions(options);
  const root = await resolveSafeRoot(inputPath);
  const loadedPacks = await loadTrustedRulePacks(normalized.rulePackPaths, root);
  const inventory = await collectProjectFiles(root, normalized);
  return buildRulePackPreview(root, inventory, loadedPacks);
}

export function renderRulePackPreview(value: RulePackPreview): string {
  const preview = validateRulePackPreview(value);
  const lines = [
    `AIsec ${preview.toolVersion} — RULE PACK PREVIEW ${preview.status.toUpperCase()}`,
    `Target: ${singleLine(preview.target, 4096)}`,
    `Inventory: ${preview.inventory.fileCount} files · ${preview.inventory.totalBytes} bytes · ${preview.inventory.skippedFiles} skipped`,
    "",
  ];
  for (const pack of preview.rulePacks) {
    lines.push(`Rule pack ${pack.packId} · ${pack.status} · sha256:${pack.digestSha256.slice(0, 12)}… · ${pack.ruleCount} rules`);
    for (const rule of pack.rules) {
      lines.push(`  ${rule.status.padEnd(8)} ${rule.emitWhen.padEnd(7)} ${rule.ruleId} — ${rule.selectedFileCount} selected`);
      lines.push(`    ${singleLine(rule.title, 200)}`);
      for (const path of rule.selectedFiles) lines.push(`    - ${safeRelativePath(path) ?? "[unsafe path omitted]"}`);
      if (rule.omittedSelectedFileCount > 0) lines.push(`    … ${rule.omittedSelectedFileCount} selected path(s) omitted`);
      for (const reason of rule.reasons) lines.push(`    ! ${singleLine(reason, 1000)}`);
    }
    for (const reason of pack.reasons) lines.push(`  ! ${singleLine(reason, 1000)}`);
    lines.push("");
  }
  if (preview.reasons.length > 0) {
    lines.push("Preview limitations", ...preview.reasons.map((reason) => `  - ${singleLine(reason, 1000)}`), "");
  }
  lines.push(preview.disclaimer);
  return lines.join("\n");
}
