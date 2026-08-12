import { createHash, randomUUID } from "node:crypto";
import { access, mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { constants } from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { Signal, SourceLocation } from "../schema.js";

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

export function stableId(prefix: string, ...parts: Array<string | undefined>): string {
  return `${prefix}_${sha256(parts.filter(Boolean).join("\u0000")).slice(0, 16)}`;
}

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function normalizeRelative(root: string, path: string): string {
  const rel = relative(root, path).split(sep).join("/");
  return rel || ".";
}

export function lineNumberAt(text: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i += 1) if (text.charCodeAt(i) === 10) line += 1;
  return line;
}

export function redact(value: string): string {
  if (value.length <= 8) return "[REDACTED]";
  return `${value.slice(0, 3)}…${value.slice(-3)}`;
}

export function redactSnippet(snippet: string): string {
  return snippet
    .replace(/\b(sk_(?:live|test)_[A-Za-z0-9_-]{8,})\b/g, (_m, key: string) => redact(key))
    .replace(/\b(AKIA[0-9A-Z]{12,})\b/g, (_m, key: string) => redact(key))
    .replace(/\b(gh[pousr]_[A-Za-z0-9]{12,})\b/g, (_m, key: string) => redact(key))
    .replace(/\b(sk-[A-Za-z0-9_-]{12,})\b/g, (_m, key: string) => redact(key))
    .replace(/\b([A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PRIVATE_KEY|SERVICE_ROLE_KEY|API_KEY)[A-Z0-9_]*)(\s*=\s*)([^\s#]+)/g,
      (_m, name: string, separator: string, secret: string) => `${name}${separator}${redact(secret.replace(/^['"]|['"]$/g, ""))}`)
    .replace(/(password|passwd|secret|token|api[_-]?key)(\s*[:=]\s*)["']?([^\s"']{6,})/gi,
      (_m, name: string, separator: string, secret: string) => `${name}${separator}${redact(secret)}`);
}

export function makeLocation(path: string, text: string, offset: number, snippet?: string): SourceLocation {
  return {
    path,
    line: lineNumberAt(text, offset),
    snippet: snippet ? redactSnippet(snippet.trim().slice(0, 300)) : undefined,
  };
}

export function createSignal(input: Omit<Signal, "id" | "fingerprint">): Signal {
  const primary = input.locations[0];
  const semanticSnippet = (primary?.snippet ?? "")
    .replace(/\s+/g, " ")
    .replace(/\b\d+\b/g, "#")
    .trim()
    .toLowerCase();
  const fingerprint = sha256([
    input.engine,
    input.ruleId,
    primary?.path ?? "",
    semanticSnippet,
  ].join("\u0000"));
  const occurrence = sha256(`${fingerprint}\u0000${primary?.line ?? ""}\u0000${primary?.column ?? ""}`).slice(0, 16);
  return { ...input, fingerprint, id: `sig_${occurrence}` };
}

export function dataDir(): string {
  const override = process.env.AISEC_DATA_DIR;
  if (override) return resolve(override);
  if (platform() === "darwin") return join(homedir(), "Library", "Application Support", "aisec");
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "aisec");
}

export async function ensureDir(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
}

export async function writeJson(path: string, value: unknown): Promise<void> {
  await ensureDir(dirname(path));
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

export async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

export async function executableExists(command: string): Promise<boolean> {
  const pathValue = process.env.PATH ?? "";
  const candidates = command.includes(sep)
    ? [command]
    : pathValue.split(sep === "\\" ? ";" : ":").filter(Boolean).map((part) => join(part, command));
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.X_OK);
      return true;
    } catch {
      // Try the next PATH entry.
    }
  }
  return false;
}

export async function resolveSafeRoot(input: string): Promise<string> {
  const absolute = resolve(input);
  const info = await stat(absolute);
  if (!info.isDirectory()) throw new Error(`Scan target is not a directory: ${absolute}`);
  return realpath(absolute);
}

export function assertPathInside(root: string, candidate: string): void {
  const resolvedRoot = resolve(root);
  const resolvedCandidate = resolve(candidate);
  if (resolvedCandidate !== resolvedRoot && !resolvedCandidate.startsWith(`${resolvedRoot}${sep}`)) {
    throw new Error(`Path escapes scan root: ${candidate}`);
  }
}

export function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) throw new Error(`Expected a positive integer, received: ${value}`);
  return parsed;
}

export function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}

export function sortSignals(signals: Signal[]): Signal[] {
  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 } as const;
  return [...signals].sort((a, b) => rank[b.severity] - rank[a.severity]
    || a.ruleId.localeCompare(b.ruleId)
    || (a.locations[0]?.path ?? "").localeCompare(b.locations[0]?.path ?? ""));
}

export async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export function isAbsoluteUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

export function projectFileUrl(relativePath: string): string {
  return isAbsolute(relativePath) ? relativePath : relativePath.split(sep).join("/");
}
