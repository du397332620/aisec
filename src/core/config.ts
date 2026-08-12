import YAML from "yaml";

export interface Suppression {
  fingerprint: string;
  reason: string;
  expires: string;
}

export interface AisecConfig {
  version: 1;
  suppressions: Suppression[];
}

export function parseConfig(text?: string): AisecConfig {
  if (text === undefined) return { version: 1, suppressions: [] };
  if (Buffer.byteLength(text, "utf8") > 256 * 1024) throw new Error(".aisec.yml must not exceed 256 KiB");
  const parsed = YAML.parse(text, { maxAliasCount: 20, merge: false, prettyErrors: false, stringKeys: true }) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(".aisec.yml must contain an object");
  const value = parsed as Record<string, unknown>;
  if (value.version !== 1) throw new Error(".aisec.yml must contain version: 1");
  const unexpected = Object.keys(value).filter((key) => !["version", "suppressions"].includes(key));
  if (unexpected.length > 0) throw new Error(`Unsupported .aisec.yml key(s): ${unexpected.join(", ")}`);
  const rawSuppressions = value.suppressions ?? [];
  if (!Array.isArray(rawSuppressions) || rawSuppressions.length > 1000) throw new Error(".aisec.yml suppressions must be an array with at most 1000 entries");
  const suppressions: Suppression[] = [];
  for (const [index, raw] of rawSuppressions.entries()) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`Invalid suppression at index ${index}: expected an object`);
    const item = raw as Record<string, unknown>;
    const keys = Object.keys(item);
    if (keys.some((key) => !["fingerprint", "reason", "expires"].includes(key))) throw new Error(`Invalid suppression at index ${index}: unsupported key`);
    if (typeof item.fingerprint !== "string" || !/^[a-f0-9]{64}$/i.test(item.fingerprint)) throw new Error(`Invalid suppression at index ${index}: fingerprint must be a SHA-256 value`);
    if (typeof item.reason !== "string" || !item.reason.trim() || item.reason.length > 500) throw new Error(`Invalid suppression at index ${index}: reason must contain 1 through 500 characters`);
    if (typeof item.expires !== "string" || !/^\d{4}-\d{2}-\d{2}(?:T[^\s]+)?$/.test(item.expires) || Number.isNaN(Date.parse(item.expires))) {
      throw new Error(`Invalid suppression expiry at index ${index}: ${String(item.expires)}`);
    }
    suppressions.push({ fingerprint: item.fingerprint.toLowerCase(), reason: item.reason.trim(), expires: item.expires });
  }
  return { version: 1, suppressions };
}
