import { dirname, isAbsolute, join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { fileURLToPath } from "node:url";
import type { DetectorResult } from "../detectors/types.js";
import type { ScanContext } from "../core/context.js";
import { normalizeRelative, redactSnippet } from "../core/utils.js";
import { runProcess } from "./process.js";
import { externalSignal, isOptionalArrayOf, isOptionalFiniteNumber, isOptionalString, isRecord, isString, normalizeSeverity } from "./common.js";
import { resolveEngineCommand, sanitizedEngineEnv } from "./manager.js";
import { inspectEngineCompatibility } from "./compatibility.js";

interface OpengrepResult {
  check_id?: string;
  path?: string;
  start?: { line?: number; col?: number };
  end?: { line?: number; col?: number };
  extra?: {
    message?: string;
    severity?: string;
    lines?: string;
    metadata?: { cwe?: string | string[]; category?: string; technology?: string[] };
  };
}

function isPosition(value: unknown): boolean {
  return value === undefined || (isRecord(value)
    && isOptionalFiniteNumber(value.line)
    && isOptionalFiniteNumber(value.col));
}

function isMetadata(value: unknown): boolean {
  if (value === undefined) return true;
  if (!isRecord(value)) return false;
  const cwe = value.cwe;
  return (cwe === undefined || typeof cwe === "string" || (Array.isArray(cwe) && cwe.every(isString)))
    && isOptionalString(value.category)
    && isOptionalArrayOf(value.technology, isString);
}

function isExtra(value: unknown): boolean {
  return value === undefined || (isRecord(value)
    && isOptionalString(value.message)
    && isOptionalString(value.severity)
    && isOptionalString(value.lines)
    && isMetadata(value.metadata));
}

function isOpengrepResult(value: unknown): value is OpengrepResult {
  return isRecord(value)
    && isOptionalString(value.check_id)
    && isOptionalString(value.path)
    && isPosition(value.start)
    && isPosition(value.end)
    && isExtra(value.extra);
}

function rulesPath(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  return join(here, "..", "..", "..", "rules", "opengrep", "security.yml");
}

export function normalizeOpengrepRuleId(checkId: string | undefined): string {
  if (!checkId) return "opengrep.unknown";
  const bundledRule = /(?:^|[./])(aisec\.[a-z0-9][a-z0-9._-]*)$/i.exec(checkId);
  return bundledRule?.[1] ?? checkId;
}

export async function runOpengrep(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const command = await resolveEngineCommand("opengrep");
  if (!command) {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "not_run", required: !context.options.nativeOnly, reason: "opengrep executable not installed", durationMs: Date.now() - started } };
  }
  const compatibility = await inspectEngineCompatibility("opengrep", command);
  if (!compatibility.supported) {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "failed", required: !context.options.nativeOnly, version: compatibility.rawVersion, reason: compatibility.reason, durationMs: Date.now() - started } };
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-opengrep-"));
  const trustedIgnore = join(temporary, "semgrepignore");
  await writeFile(trustedIgnore, "# AIsec intentionally accepts no target-controlled path suppressions.\n", { mode: 0o600 });
  let result;
  try {
    result = await runProcess(command, ["scan", "--json", "--disable-version-check", "--no-git-ignore", "--disable-nosem", "--oss-only", "--experimental", "--semgrepignore-filename", trustedIgnore, "-f", rulesPath(), context.root], {
      timeoutMs: context.options.timeoutMs,
      maxOutputBytes: 25 * 1024 * 1024,
      env: sanitizedEngineEnv("opengrep"),
    });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  if (result.timedOut || result.truncated) {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "failed", required: !context.options.nativeOnly, reason: result.timedOut ? "opengrep timed out" : "opengrep output exceeded safety limit", durationMs: result.durationMs } };
  }
  if (result.exitCode !== 0) {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "failed", required: !context.options.nativeOnly, reason: redactSnippet(result.stderr || `opengrep exited ${result.exitCode}`), durationMs: result.durationMs } };
  }
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "failed", required: !context.options.nativeOnly, reason: redactSnippet(result.stderr || "opengrep returned invalid JSON"), durationMs: result.durationMs } };
  }
  if (!isRecord(value)
    || !Array.isArray(value.results)
    || !value.results.every(isOpengrepResult)
    || (value.errors !== undefined && !Array.isArray(value.errors))) {
    return { signals: [], coverage: { domain: "sast-general", engine: "opengrep", status: "failed", required: !context.options.nativeOnly, reason: "opengrep returned an unexpected JSON schema", durationMs: result.durationMs } };
  }
  const parsed = value as { results: OpengrepResult[]; errors?: unknown[] };
  const signals = (parsed.results ?? []).map((finding) => {
    const ruleId = normalizeOpengrepRuleId(finding.check_id);
    return externalSignal({
      engine: "opengrep",
      ruleId,
      title: finding.extra?.message ?? ruleId,
      description: finding.extra?.message ?? "Opengrep matched a security rule.",
      severity: normalizeSeverity(finding.extra?.severity),
      locations: [{ path: finding.path ? (isAbsolute(finding.path) ? normalizeRelative(context.root, finding.path) : finding.path) : ".", line: finding.start?.line, column: finding.start?.col, endLine: finding.end?.line, snippet: finding.extra?.lines ? redactSnippet(finding.extra.lines) : undefined }],
      cwe: Array.isArray(finding.extra?.metadata?.cwe) ? finding.extra.metadata.cwe : finding.extra?.metadata?.cwe ? [finding.extra.metadata.cwe] : undefined,
      tags: ["sast", "opengrep", ...(finding.extra?.metadata?.technology ?? [])],
    });
  });
  const status = (parsed.errors?.length ?? 0) > 0 ? "partial" : "complete";
  return { signals, coverage: { domain: "sast-general", engine: "opengrep", status, required: !context.options.nativeOnly, version: compatibility.rawVersion, reason: status === "partial" ? `${parsed.errors?.length} parse or scan errors` : undefined, durationMs: result.durationMs } };
}
