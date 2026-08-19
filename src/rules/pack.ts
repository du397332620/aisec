import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import YAML from "yaml";
import type { RulePack } from "../schema.js";
import { validateRulePack } from "../core/schema-validation.js";
import { sha256 } from "../core/utils.js";

export const MAX_RULE_PACKS = 8;
export const MAX_RULE_PACK_BYTES = 256 * 1024;
export const MAX_TOTAL_RULE_PACK_RULES = 256;

export interface LoadedRulePack {
  pack: RulePack;
  digestSha256: string;
}

function pathIsInside(root: string, candidate: string): boolean {
  const result = relative(root, candidate);
  return result === "" || (result !== ".." && !result.startsWith(`..${sep}`) && !isAbsolute(result));
}

export function parseRulePack(text: string): RulePack {
  if (Buffer.byteLength(text, "utf8") > MAX_RULE_PACK_BYTES) throw new Error("Rule pack must not exceed 256 KiB");
  let parsed: unknown;
  try {
    parsed = YAML.parse(text, { maxAliasCount: 20, merge: false, prettyErrors: false, stringKeys: true }) as unknown;
  } catch (error) {
    throw new Error(`Rule pack is not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  const pack = validateRulePack(parsed);
  return {
    ...pack,
    rules: pack.rules.map((rule) => ({
      ...rule,
      cwe: [...rule.cwe],
      tags: [...rule.tags],
      files: {
        extensions: [...rule.files.extensions],
        ...(rule.files.pathPrefixes ? { pathPrefixes: [...rule.files.pathPrefixes] } : {}),
        ...(rule.files.pathSuffixes ? { pathSuffixes: [...rule.files.pathSuffixes] } : {}),
        ...(rule.files.excludePathPrefixes ? { excludePathPrefixes: [...rule.files.excludePathPrefixes] } : {}),
      },
      match: {
        containsAny: [...rule.match.containsAny],
        ...(rule.match.containsAll ? { containsAll: [...rule.match.containsAll] } : {}),
        ...(rule.match.excludes ? { excludes: [...rule.match.excludes] } : {}),
        caseSensitive: rule.match.caseSensitive ?? true,
      },
    })),
  };
}

export async function loadTrustedRulePack(rulePackPath: string, targetRoot: string): Promise<LoadedRulePack> {
  if (!rulePackPath.trim()) throw new Error("Rule-pack path must be a non-empty string");
  const root = await realpath(resolve(targetRoot));
  const requested = resolve(rulePackPath);
  let resolvedFile: string;
  let resolvedParent: string;
  try {
    [resolvedFile, resolvedParent] = await Promise.all([realpath(requested), realpath(dirname(requested))]);
  } catch {
    throw new Error(`Rule-pack file not found: ${requested}`);
  }
  if (pathIsInside(root, resolvedParent) || pathIsInside(root, resolvedFile)) {
    throw new Error("Rule pack must be operator-owned and located outside the scanned target");
  }
  const handle = await open(resolvedFile, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error("Rule pack must be a regular file");
    if (info.size > MAX_RULE_PACK_BYTES) throw new Error("Rule pack must not exceed 256 KiB");
    const raw = await handle.readFile();
    if (raw.byteLength > MAX_RULE_PACK_BYTES) throw new Error("Rule pack must not exceed 256 KiB");
    return { pack: parseRulePack(raw.toString("utf8")), digestSha256: sha256(raw) };
  } finally {
    await handle.close();
  }
}

export async function loadTrustedRulePacks(rulePackPaths: readonly string[], targetRoot: string): Promise<LoadedRulePack[]> {
  if (rulePackPaths.length > MAX_RULE_PACKS) throw new Error(`Rule packs cannot exceed ${MAX_RULE_PACKS}`);
  const loaded = await Promise.all(rulePackPaths.map((path) => loadTrustedRulePack(path, targetRoot)));
  const packIds = new Set<string>();
  const ruleIds = new Set<string>();
  let ruleCount = 0;
  for (const item of loaded) {
    if (packIds.has(item.pack.packId)) throw new Error(`Duplicate rule-pack ID: ${item.pack.packId}`);
    packIds.add(item.pack.packId);
    ruleCount += item.pack.rules.length;
    if (ruleCount > MAX_TOTAL_RULE_PACK_RULES) throw new Error(`Rule packs cannot contain more than ${MAX_TOTAL_RULE_PACK_RULES} rules in total`);
    for (const rule of item.pack.rules) {
      if (ruleIds.has(rule.ruleId)) throw new Error(`Duplicate custom rule ID across rule packs: ${rule.ruleId}`);
      ruleIds.add(rule.ruleId);
    }
  }
  return loaded.sort((left, right) => left.pack.packId.localeCompare(right.pack.packId));
}
