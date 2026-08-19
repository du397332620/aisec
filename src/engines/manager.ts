import { chmod, copyFile, readFile, rename, rm, stat } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { basename, join, resolve } from "node:path";
import type { Stats } from "node:fs";
import { commandVersion, sanitizedProcessEnv } from "./process.js";
import { dataDir, ensureDir, executableExists, fileExists, readJson, sha256, writeJson } from "../core/utils.js";
import { engineCompatibility } from "./compatibility.js";

export const ENGINE_NAMES = ["gitleaks", "opengrep", "trivy"] as const;
export type EngineName = typeof ENGINE_NAMES[number];

interface ManagedEngineRecord {
  name: EngineName;
  sourceName: string;
  sha256: string;
  installedAt: string;
  version?: string;
}

interface ManagedEngineLock {
  schemaVersion: 1;
  engines: Partial<Record<EngineName, ManagedEngineRecord>>;
}

function engineDirectory(): string { return join(dataDir(), "engines"); }
function enginePath(name: EngineName): string { return join(engineDirectory(), name); }
function lockPath(): string { return join(engineDirectory(), "engines.lock.json"); }

function isEngineName(value: string): value is EngineName {
  return (ENGINE_NAMES as readonly string[]).includes(value);
}

export async function resolveEngineCommand(name: EngineName): Promise<string | undefined> {
  const override = process.env[`AISEC_${name.toUpperCase()}_PATH`];
  if (override) {
    const resolved = resolve(override);
    if (!(await executableExists(resolved))) throw new Error(`Configured ${name} executable is not runnable: ${resolved}`);
    return resolved;
  }
  const managed = enginePath(name);
  if (await executableExists(managed)) {
    const lock = await loadLock();
    const record = lock.engines[name];
    if (!record?.sha256) throw new Error(`Managed ${name} has no pinned digest; reinstall it with engines install`);
    const actual = sha256(await readFile(managed));
    if (actual !== record.sha256) throw new Error(`Managed ${name} failed its SHA-256 integrity check; refusing to execute it`);
    return managed;
  }
  if (await executableExists(name)) return name;
  return undefined;
}

export function sanitizedEngineEnv(name: EngineName): NodeJS.ProcessEnv {
  const prefixes = name === "trivy" ? ["TRIVY_"] : name === "gitleaks" ? ["GITLEAKS_"] : ["SEMGREP_", "OPENGREP_"];
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(sanitizedProcessEnv())) {
    if (prefixes.some((prefix) => key.toUpperCase().startsWith(prefix))) continue;
    env[key] = value;
  }
  return env;
}

async function loadLock(): Promise<ManagedEngineLock> {
  if (!(await fileExists(lockPath()))) return { schemaVersion: 1, engines: {} };
  return readJson<ManagedEngineLock>(lockPath());
}

export async function installManagedEngine(nameValue: string, source: string, expectedSha256: string): Promise<ManagedEngineRecord> {
  if (!isEngineName(nameValue)) throw new Error(`Unsupported engine: ${nameValue}. Expected one of ${ENGINE_NAMES.join(", ")}`);
  if (!/^[a-f0-9]{64}$/i.test(expectedSha256)) throw new Error("--sha256 must be a 64-character hexadecimal digest");
  const sourcePath = resolve(source);
  let info: Stats;
  try { info = await stat(sourcePath); } catch { throw new Error(`Engine binary not found: ${sourcePath}`); }
  if (!info.isFile() || info.size === 0 || info.size > 500 * 1024 * 1024) throw new Error("Engine source must be a non-empty regular file no larger than 500 MiB");
  const actual = sha256(await readFile(sourcePath));
  if (actual.toLowerCase() !== expectedSha256.toLowerCase()) throw new Error(`SHA-256 mismatch for ${sourcePath}: expected ${expectedSha256}, got ${actual}`);
  await ensureDir(engineDirectory());
  const destination = enginePath(nameValue);
  const temporary = `${destination}.install-${randomUUID()}`;
  try {
    await copyFile(sourcePath, temporary);
    await chmod(temporary, 0o700);
    const copied = sha256(await readFile(temporary));
    if (copied !== actual) throw new Error(`Copied ${nameValue} binary failed its post-copy SHA-256 check`);
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true }).catch(() => undefined);
  }
  const version = await commandVersion(destination);
  const record: ManagedEngineRecord = { name: nameValue, sourceName: basename(sourcePath), sha256: actual, installedAt: new Date().toISOString(), version };
  const lock = await loadLock();
  lock.engines[nameValue] = record;
  await writeJson(lockPath(), lock);
  return record;
}

export async function engineStatus(): Promise<Array<{ name: EngineName; source: "env" | "managed" | "path" | "missing" | "invalid"; command?: string; version?: string; compatible?: boolean; verifiedVersions?: readonly string[]; pinnedSha256?: string; error?: string }>> {
  const lock = await loadLock();
  const statuses = [];
  for (const name of ENGINE_NAMES) {
    const override = process.env[`AISEC_${name.toUpperCase()}_PATH`];
    const managed = enginePath(name);
    let source: "env" | "managed" | "path" | "missing" | "invalid" = "missing";
    let command: string | undefined;
    let error: string | undefined;
    try {
      command = await resolveEngineCommand(name);
      if (override && command === resolve(override)) source = "env";
      else if (command === managed) source = "managed";
      else if (command) source = "path";
    } catch (caught) {
      source = "invalid";
      error = caught instanceof Error ? caught.message : String(caught);
    }
    const version = command ? await commandVersion(command) : undefined;
    const compatibility = command ? engineCompatibility(name, version) : undefined;
    statuses.push({ name, source, command, version, compatible: compatibility?.supported, verifiedVersions: compatibility?.verified, pinnedSha256: source === "managed" ? lock.engines[name]?.sha256 : undefined, error: error ?? compatibility?.reason });
  }
  return statuses;
}
