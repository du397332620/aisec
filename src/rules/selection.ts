import { extname } from "node:path";
import type { RulePackFileSelector } from "../schema.js";

export const MAX_RULE_PACK_SELECTOR_EVALUATIONS = 1_000_000;

export function rulePackFileSelected(path: string, selector: RulePackFileSelector): boolean {
  if (!selector.extensions.includes(extname(path).toLowerCase())) return false;
  const prefixes = selector.pathPrefixes ?? [];
  if (prefixes.length > 0 && !prefixes.some((prefix) => path.startsWith(prefix))) return false;
  const suffixes = selector.pathSuffixes ?? [];
  if (suffixes.length > 0 && !suffixes.some((suffix) => path.endsWith(suffix))) return false;
  return !(selector.excludePathPrefixes ?? []).some((prefix) => path.startsWith(prefix));
}
