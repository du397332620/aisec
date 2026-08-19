import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import YAML from "yaml";
import type {
  ScanPolicyRecord,
  SecurityPolicy,
  SecurityPolicyEngine,
  SecurityPolicyGate,
} from "../schema.js";
import { validateSecurityPolicy } from "./schema-validation.js";
import { sha256 } from "./utils.js";

export const REQUIRED_POLICY_ENGINES: readonly SecurityPolicyEngine[] = ["gitleaks", "opengrep", "trivy"];
export const DEFAULT_POLICY_GATE: Readonly<SecurityPolicyGate> = {
  minimumSeverity: "high",
  includeInferred: false,
  requireNoSuppressions: false,
};

const MAX_POLICY_BYTES = 256 * 1024;

export interface LoadedSecurityPolicy {
  policy: SecurityPolicy;
  digestSha256: string;
}

function expirationTime(value: string): number {
  return Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value}T23:59:59.999Z` : value);
}

function assertActivePolicy(policy: SecurityPolicy, now: Date): void {
  const current = now.getTime();
  if (!Number.isFinite(current)) throw new Error("Security policy validation time is invalid");
  if (expirationTime(policy.expiresAt) <= current) {
    throw new Error(`Security policy ${policy.policyId} expired at ${policy.expiresAt}`);
  }
  for (const suppression of policy.suppressions) {
    if (expirationTime(suppression.expires) <= current) {
      throw new Error(`Security policy ${policy.policyId} contains an expired suppression: ${suppression.fingerprint.toLowerCase()}`);
    }
  }
}

export function parseSecurityPolicy(text: string, now = new Date()): SecurityPolicy {
  if (Buffer.byteLength(text, "utf8") > MAX_POLICY_BYTES) throw new Error("Security policy must not exceed 256 KiB");
  let parsed: unknown;
  try {
    parsed = YAML.parse(text, { maxAliasCount: 20, merge: false, prettyErrors: false, stringKeys: true }) as unknown;
  } catch (error) {
    throw new Error(`Security policy is not valid YAML: ${error instanceof Error ? error.message : String(error)}`);
  }
  const policy = validateSecurityPolicy(parsed);
  assertActivePolicy(policy, now);
  return {
    ...policy,
    requiredEngines: [...policy.requiredEngines],
    gate: { ...policy.gate },
    rules: { required: [...policy.rules.required], block: [...policy.rules.block] },
    suppressions: policy.suppressions.map((suppression) => ({
      fingerprint: suppression.fingerprint.toLowerCase(),
      reason: suppression.reason.trim(),
      expires: suppression.expires,
    })),
  };
}

function pathIsInside(root: string, candidate: string): boolean {
  const result = relative(root, candidate);
  return result === "" || (result !== ".." && !result.startsWith(`..${sep}`) && !isAbsolute(result));
}

export async function loadTrustedPolicy(policyPath: string, targetRoot: string, now = new Date()): Promise<LoadedSecurityPolicy> {
  if (!policyPath.trim()) throw new Error("Security policy path must be a non-empty string");
  const root = await realpath(resolve(targetRoot));
  const requestedPolicy = resolve(policyPath);
  let resolvedPolicy: string;
  let resolvedParent: string;
  try {
    [resolvedPolicy, resolvedParent] = await Promise.all([
      realpath(requestedPolicy),
      realpath(dirname(requestedPolicy)),
    ]);
  } catch {
    throw new Error(`Security policy file not found: ${requestedPolicy}`);
  }
  if (pathIsInside(root, resolvedParent) || pathIsInside(root, resolvedPolicy)) {
    throw new Error("Security policy must be operator-owned and located outside the scanned target");
  }
  const handle = await open(resolvedPolicy, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new Error("Security policy must be a regular file");
    if (info.size > MAX_POLICY_BYTES) throw new Error("Security policy must not exceed 256 KiB");
    const raw = await handle.readFile();
    if (raw.byteLength > MAX_POLICY_BYTES) throw new Error("Security policy must not exceed 256 KiB");
    return { policy: parseSecurityPolicy(raw.toString("utf8"), now), digestSha256: sha256(raw) };
  } finally {
    await handle.close();
  }
}

export function createScanPolicyRecord(
  loaded: LoadedSecurityPolicy | undefined,
  options: { profile: "predeploy" | "native"; nativeOnly: boolean; confirmPolicySuppressions: boolean },
  targetConfiguration: "absent" | "ignored",
): ScanPolicyRecord {
  if (loaded) {
    return {
      source: "operator",
      targetConfiguration,
      policyId: loaded.policy.policyId,
      digestSha256: loaded.digestSha256,
      expiresAt: loaded.policy.expiresAt,
      gate: { ...loaded.policy.gate },
      requiredEngines: [...loaded.policy.requiredEngines].sort(),
      requiredRuleIds: [...loaded.policy.rules.required].sort(),
      blockingRuleIds: [...loaded.policy.rules.block].sort(),
      suppressionCount: loaded.policy.suppressions.length,
      suppressionApproval: loaded.policy.suppressions.length > 0 && options.confirmPolicySuppressions ? "explicit" : "not_applicable",
      relaxations: [],
    };
  }
  const relaxations: ScanPolicyRecord["relaxations"] = [];
  if (options.profile === "native") relaxations.push("source_only_profile");
  if (options.nativeOnly) relaxations.push("external_engines_disabled");
  return {
    source: "defaults",
    targetConfiguration,
    gate: { ...DEFAULT_POLICY_GATE },
    requiredEngines: options.profile === "predeploy" && !options.nativeOnly ? [...REQUIRED_POLICY_ENGINES] : [],
    requiredRuleIds: [],
    blockingRuleIds: [],
    suppressionCount: 0,
    suppressionApproval: "not_applicable",
    relaxations,
  };
}
