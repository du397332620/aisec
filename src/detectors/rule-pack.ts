import { extname } from "node:path";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import { createSignal, makeLocation } from "../core/utils.js";
import type { ScanContext } from "../core/context.js";
import type { CoverageRecord, RulePackRule, Signal, SourceLocation } from "../schema.js";
import type { LoadedRulePack } from "../rules/pack.js";

export const MAX_RULE_PACK_EVALUATED_BYTES = 256 * 1024 * 1024;
export const MAX_RULE_PACK_LITERAL_WORK_BYTES = 256 * 1024 * 1024;
export const MAX_RULE_PACK_LINE_EVALUATIONS = 2_000_000;
export const MAX_RULE_PACK_SELECTOR_EVALUATIONS = 1_000_000;

function fileSelected(path: string, extensions: readonly string[], prefixes: readonly string[], suffixes: readonly string[], excluded: readonly string[]): boolean {
  if (!extensions.includes(extname(path).toLowerCase())) return false;
  if (prefixes.length > 0 && !prefixes.some((prefix) => path.startsWith(prefix))) return false;
  if (suffixes.length > 0 && !suffixes.some((suffix) => path.endsWith(suffix))) return false;
  return !excluded.some((prefix) => path.startsWith(prefix));
}

function lineMatches(line: string, any: readonly string[], all: readonly string[], excluded: readonly string[], caseSensitive: boolean): boolean {
  const candidate = caseSensitive ? line : line.toLowerCase();
  if (excluded.some((literal) => candidate.includes(literal))) return false;
  if (!any.some((literal) => candidate.includes(literal))) return false;
  return all.every((literal) => candidate.includes(literal));
}

function rulePackSignal(
  loaded: LoadedRulePack,
  rule: RulePackRule,
  emitWhen: "present" | "absent",
  locations: SourceLocation[],
): Signal {
  return createSignal({
    engine: "aisec-rule-pack",
    ruleId: rule.ruleId,
    title: rule.title,
    description: rule.description,
    severity: rule.severity,
    evidenceLevel: rule.evidenceLevel,
    confidence: rule.confidence,
    locations,
    cwe: [...rule.cwe],
    tags: [...new Set([...rule.tags, "custom-rule"])],
    remediation: rule.remediation,
    metadata: {
      rulePackId: loaded.pack.packId,
      rulePackDigestSha256: loaded.digestSha256,
      rulePackMatch: emitWhen,
    },
  });
}

export async function runRulePacks(
  context: ScanContext,
  loadedPacks: readonly LoadedRulePack[],
): Promise<{ signals: Signal[]; coverage: CoverageRecord[] }> {
  const signals: Signal[] = [];
  const coverage: CoverageRecord[] = [];
  let limitReason: string | undefined;
  let evaluatedBytes = 0;
  let literalWorkBytes = 0;
  let lineEvaluations = 0;
  let selectorEvaluations = 0;

  for (const loaded of loadedPacks) {
    const started = Date.now();
    let packTruncated = limitReason !== undefined;
    let missingSelectionCount = 0;
    let firstMissingSelectionRule: string | undefined;
    if (!limitReason) {
      for (const rule of [...loaded.pack.rules].sort((left, right) => left.ruleId.localeCompare(right.ruleId))) {
        const prefixes = rule.files.pathPrefixes ?? [];
        const suffixes = rule.files.pathSuffixes ?? [];
        const excludedPrefixes = rule.files.excludePathPrefixes ?? [];
        const caseSensitive = rule.match.caseSensitive ?? true;
        const normalize = (literal: string): string => caseSensitive ? literal : literal.toLowerCase();
        const any = rule.match.containsAny.map(normalize);
        const all = (rule.match.containsAll ?? []).map(normalize);
        const excluded = (rule.match.excludes ?? []).map(normalize);
        const emitWhen = rule.match.emitWhen ?? "present";
        let selectedFiles = 0;
        for (const file of context.inventory.files) {
          selectorEvaluations += 1;
          if (selectorEvaluations > MAX_RULE_PACK_SELECTOR_EVALUATIONS) {
            limitReason = `custom rule selection reached the ${MAX_RULE_PACK_SELECTOR_EVALUATIONS} shared rule-file evaluation limit`;
            packTruncated = true;
            break;
          }
          if (!fileSelected(file.relativePath, rule.files.extensions, prefixes, suffixes, excludedPrefixes)) continue;
          selectedFiles += 1;
          if (evaluatedBytes + file.size > MAX_RULE_PACK_EVALUATED_BYTES) {
            limitReason = `custom rule evaluation reached the ${MAX_RULE_PACK_EVALUATED_BYTES} byte shared work limit`;
            packTruncated = true;
            break;
          }
          const fileLiteralWork = file.size * Math.max(1, any.length + all.length + excluded.length);
          if (!Number.isSafeInteger(fileLiteralWork) || literalWorkBytes + fileLiteralWork > MAX_RULE_PACK_LITERAL_WORK_BYTES) {
            limitReason = `custom rule evaluation reached the ${MAX_RULE_PACK_LITERAL_WORK_BYTES} literal-byte shared work limit`;
            packTruncated = true;
            break;
          }
          evaluatedBytes += file.size;
          literalWorkBytes += fileLiteralWork;
          let offset = 0;
          let matched = false;
          while (offset <= file.content.length) {
            const newline = file.content.indexOf("\n", offset);
            const end = newline === -1 ? file.content.length : newline;
            const line = file.content.slice(offset, end).replace(/\r$/u, "");
            lineEvaluations += 1;
            if (lineEvaluations > MAX_RULE_PACK_LINE_EVALUATIONS) {
              limitReason = `custom rule evaluation reached the ${MAX_RULE_PACK_LINE_EVALUATIONS} shared line evaluation limit`;
              packTruncated = true;
              break;
            }
            if (lineMatches(line, any, all, excluded, caseSensitive)) {
              matched = true;
              if (emitWhen === "absent") break;
              if (signals.length < MAX_SIGNALS_PER_DETECTOR) {
                signals.push(rulePackSignal(loaded, rule, emitWhen, [makeLocation(file.relativePath, file.content, offset, line)]));
              } else {
                limitReason = `custom rule output reached the ${MAX_SIGNALS_PER_DETECTOR} shared signal safety limit`;
                packTruncated = true;
                break;
              }
            }
            if (limitReason || newline === -1) break;
            offset = newline + 1;
          }
          if (limitReason) break;
          if (emitWhen === "absent" && !matched) {
            if (signals.length < MAX_SIGNALS_PER_DETECTOR) {
              signals.push(rulePackSignal(loaded, rule, emitWhen, [{ path: file.relativePath }]));
            } else {
              limitReason = `custom rule output reached the ${MAX_SIGNALS_PER_DETECTOR} shared signal safety limit`;
              packTruncated = true;
              break;
            }
          }
        }
        if (limitReason) break;
        if (emitWhen === "absent" && selectedFiles === 0) {
          missingSelectionCount += 1;
          firstMissingSelectionRule ??= rule.ruleId;
        }
      }
    }
    const missingSelectionReason = missingSelectionCount > 0
      ? `custom absent rule ${firstMissingSelectionRule} selected no files${missingSelectionCount > 1 ? `; ${missingSelectionCount - 1} additional absent rule(s) also selected no files` : ""}`
      : undefined;
    const reasons = [missingSelectionReason, packTruncated ? limitReason : undefined].filter((reason): reason is string => Boolean(reason));
    coverage.push({
      domain: `rule-pack:${loaded.pack.packId}`,
      engine: "aisec-rule-pack",
      status: reasons.length > 0 ? "partial" : "complete",
      required: true,
      version: loaded.digestSha256,
      reason: reasons.length > 0 ? reasons.join("; ") : undefined,
      durationMs: Date.now() - started,
    });
  }
  return { signals, coverage };
}
