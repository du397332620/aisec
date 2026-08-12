import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DetectorResult } from "../detectors/types.js";
import type { ScanContext } from "../core/context.js";
import { isAbsolute } from "node:path";
import { normalizeRelative, redactSnippet } from "../core/utils.js";
import { runProcess } from "./process.js";
import { externalSignal, isOptionalFiniteNumber, isOptionalString, isRecord } from "./common.js";
import { resolveEngineCommand, sanitizedEngineEnv } from "./manager.js";
import { inspectEngineCompatibility } from "./compatibility.js";

interface GitleaksFinding {
  Description?: string;
  StartLine?: number;
  File?: string;
  RuleID?: string;
  Secret?: string;
  Match?: string;
  Commit?: string;
}

function isGitleaksFinding(value: unknown): value is GitleaksFinding {
  if (!isRecord(value)) return false;
  return isOptionalString(value.Description)
    && isOptionalFiniteNumber(value.StartLine)
    && isOptionalString(value.File)
    && isOptionalString(value.RuleID)
    && isOptionalString(value.Secret)
    && isOptionalString(value.Match)
    && isOptionalString(value.Commit);
}

export async function runGitleaks(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const command = await resolveEngineCommand("gitleaks");
  if (!command) {
    return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "not_run", required: !context.options.nativeOnly, reason: "gitleaks executable not installed", durationMs: Date.now() - started } };
  }
  const compatibility = await inspectEngineCompatibility("gitleaks", command);
  if (!compatibility.supported) {
    return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, version: compatibility.rawVersion, reason: compatibility.reason, durationMs: Date.now() - started } };
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-gitleaks-"));
  const reportPath = join(temporary, "report.json");
  try {
    const configPath = join(temporary, "gitleaks.toml");
    const ignorePath = join(temporary, "gitleaksignore");
    await writeFile(configPath, "title = \"AIsec trusted defaults\"\n[extend]\nuseDefault = true\n", { mode: 0o600 });
    await writeFile(ignorePath, "# AIsec intentionally accepts no target-controlled suppressions.\n", { mode: 0o600 });
    const args = ["detect", "--source", context.root, "--config", configPath, "--gitleaks-ignore-path", ignorePath, "--ignore-gitleaks-allow", "--report-format", "json", "--report-path", reportPath, "--redact", "--no-banner"];
    if (!context.options.includeGitHistory) args.push("--no-git");
    const result = await runProcess(command, args, { timeoutMs: context.options.timeoutMs, maxOutputBytes: 2 * 1024 * 1024, env: sanitizedEngineEnv("gitleaks") });
    if (result.timedOut || result.truncated) return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: result.timedOut ? "gitleaks timed out" : "gitleaks output exceeded safety limit", durationMs: result.durationMs } };
    if (![0, 1].includes(result.exitCode ?? -1)) {
      return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: redactSnippet(result.stderr || `gitleaks exited ${result.exitCode}`), durationMs: result.durationMs } };
    }
    let parsed: GitleaksFinding[] = [];
    let reportText: string | undefined;
    try { reportText = await readFile(reportPath, "utf8"); } catch {
      return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: "gitleaks did not produce a JSON report", durationMs: result.durationMs } };
    }
    let value: unknown;
    try { value = JSON.parse(reportText); } catch {
      return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: "gitleaks produced invalid JSON", durationMs: result.durationMs } };
    }
    if (!Array.isArray(value) || !value.every(isGitleaksFinding)) {
      return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: "gitleaks returned an unexpected JSON schema", durationMs: result.durationMs } };
    }
    parsed = value as GitleaksFinding[];
    if (result.exitCode === 1 && parsed.length === 0) {
      return { signals: [], coverage: { domain: "secrets-history", engine: "gitleaks", status: "failed", required: !context.options.nativeOnly, reason: "gitleaks did not produce a valid JSON report", durationMs: result.durationMs } };
    }
    const signals = parsed.map((finding) => externalSignal({
      engine: "gitleaks",
      ruleId: finding.RuleID || "gitleaks.secret",
      title: finding.Description || "Secret detected by Gitleaks",
      description: "Gitleaks detected credential-shaped material. The raw value is deliberately excluded from AIsec reports.",
      severity: "critical",
      locations: [{
        path: finding.File ? (isAbsolute(finding.File) ? normalizeRelative(context.root, finding.File) : finding.File) : ".",
        line: finding.StartLine,
        snippet: finding.Match ? redactSnippet(finding.Match) : "[REDACTED]",
      }],
      cwe: ["CWE-798"],
      tags: ["secret", "gitleaks", finding.Commit ? "git-history" : "working-tree"],
      remediation: "Revoke the credential, remove it from source and history, then provision a least-privileged replacement.",
    }));
    return { signals, coverage: { domain: "secrets-history", engine: "gitleaks", status: "complete", required: !context.options.nativeOnly, version: compatibility.rawVersion, durationMs: result.durationMs } };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}
