import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { dataDir, ensureDir, fileExists, redactSnippet } from "../core/utils.js";
import { inspectEngineCompatibility } from "./compatibility.js";
import { resolveEngineCommand, sanitizedEngineEnv } from "./manager.js";
import { runProcess } from "./process.js";

export const TRIVY_DB_REPOSITORIES = [
  "public.ecr.aws/aquasecurity/trivy-db:2",
  "ghcr.io/aquasecurity/trivy-db:2",
  "mirror.gcr.io/aquasec/trivy-db:2",
] as const;

interface TrivyDatabaseMetadata {
  Version?: number;
  NextUpdate?: string;
  UpdatedAt?: string;
  DownloadedAt?: string;
}

export interface TrivyDatabaseStatus {
  state: "ready" | "missing" | "invalid" | "stale";
  cacheDir: string;
  schemaVersion?: number;
  updatedAt?: string;
  downloadedAt?: string;
  nextUpdate?: string;
  reason?: string;
}

export function trivyCacheDir(): string {
  return join(dataDir(), "trivy-cache");
}

export async function trivyDatabaseStatus(): Promise<TrivyDatabaseStatus> {
  const cacheDir = trivyCacheDir();
  const metadataPath = join(cacheDir, "db", "metadata.json");
  const databasePath = join(cacheDir, "db", "trivy.db");
  if (!(await fileExists(metadataPath)) || !(await fileExists(databasePath))) {
    return { state: "missing", cacheDir, reason: "Trivy vulnerability database is missing; run `aisec engines prepare trivy`" };
  }
  try {
    const database = await stat(databasePath);
    if (!database.isFile() || database.size === 0) {
      return { state: "invalid", cacheDir, reason: "Trivy vulnerability database is empty or not a regular file; run `aisec engines prepare trivy`" };
    }
  } catch {
    return { state: "invalid", cacheDir, reason: "Trivy vulnerability database cannot be read; run `aisec engines prepare trivy`" };
  }
  let metadata: TrivyDatabaseMetadata;
  try { metadata = JSON.parse(await readFile(metadataPath, "utf8")) as TrivyDatabaseMetadata; } catch {
    return { state: "invalid", cacheDir, reason: "Trivy vulnerability database metadata is invalid; run `aisec engines prepare trivy`" };
  }
  if (metadata.Version !== 2 || !metadata.NextUpdate || Number.isNaN(Date.parse(metadata.NextUpdate))) {
    return { state: "invalid", cacheDir, reason: "Trivy vulnerability database metadata is incomplete or unsupported" };
  }
  const common = {
    cacheDir,
    schemaVersion: metadata.Version,
    updatedAt: metadata.UpdatedAt,
    downloadedAt: metadata.DownloadedAt,
    nextUpdate: metadata.NextUpdate,
  };
  if (Date.parse(metadata.NextUpdate) <= Date.now()) {
    return { state: "stale", ...common, reason: "Trivy vulnerability database is stale; run `aisec engines prepare trivy`" };
  }
  return { state: "ready", ...common };
}

export async function prepareTrivyDatabase(timeoutMs = 10 * 60_000): Promise<TrivyDatabaseStatus & { engineVersion: string; repositories: readonly string[] }> {
  const command = await resolveEngineCommand("trivy");
  if (!command) throw new Error("trivy executable not installed");
  const compatibility = await inspectEngineCompatibility("trivy", command);
  if (!compatibility.supported) throw new Error(compatibility.reason);
  const cacheDir = trivyCacheDir();
  await ensureDir(cacheDir);
  const repositoryArgs = TRIVY_DB_REPOSITORIES.flatMap((repository) => ["--db-repository", repository]);
  const result = await runProcess(command, [
    "filesystem", "--download-db-only", "--cache-dir", cacheDir,
    ...repositoryArgs,
    "--no-progress", "--disable-telemetry", "--skip-version-check",
  ], { timeoutMs, maxOutputBytes: 2 * 1024 * 1024, env: sanitizedEngineEnv("trivy") });
  if (result.timedOut) throw new Error("Trivy database preparation timed out");
  if (result.truncated) throw new Error("Trivy database preparation output exceeded the safety limit");
  if (result.exitCode !== 0) throw new Error(redactSnippet(result.stderr || `trivy exited ${result.exitCode}`));
  const status = await trivyDatabaseStatus();
  if (status.state !== "ready") throw new Error(status.reason ?? `Trivy database preparation ended in state ${status.state}`);
  return { ...status, engineVersion: compatibility.detected!, repositories: TRIVY_DB_REPOSITORIES };
}
