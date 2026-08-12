import { isAbsolute, join } from "node:path";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import type { DetectorResult } from "../detectors/types.js";
import type { Signal } from "../schema.js";
import type { ScanContext } from "../core/context.js";
import { normalizeRelative, redactSnippet } from "../core/utils.js";
import { runProcess } from "./process.js";
import { externalSignal, isOptionalArrayOf, isOptionalFiniteNumber, isOptionalString, isRecord, normalizeSeverity } from "./common.js";
import { resolveEngineCommand, sanitizedEngineEnv } from "./manager.js";
import { inspectEngineCompatibility } from "./compatibility.js";
import { trivyCacheDir, trivyDatabaseStatus } from "./trivy-db.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

interface TrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
}
interface TrivyMisconfiguration {
  ID?: string;
  Title?: string;
  Description?: string;
  Message?: string;
  Severity?: string;
  Resolution?: string;
  CauseMetadata?: { StartLine?: number; EndLine?: number; Code?: { Lines?: Array<{ Content?: string }> } };
}
interface TrivySecret {
  RuleID?: string;
  Category?: string;
  Title?: string;
  Severity?: string;
  StartLine?: number;
  EndLine?: number;
  Match?: string;
}
interface TrivyResult {
  Target?: string;
  Vulnerabilities?: TrivyVulnerability[];
  Misconfigurations?: TrivyMisconfiguration[];
  Secrets?: TrivySecret[];
}

function isTrivyVulnerability(value: unknown): value is TrivyVulnerability {
  if (!isRecord(value)) return false;
  return ["VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "Title", "Description", "PrimaryURL"]
    .every((key) => isOptionalString(value[key]));
}

function isTrivyMisconfiguration(value: unknown): value is TrivyMisconfiguration {
  if (!isRecord(value)
    || !["ID", "Title", "Description", "Message", "Severity", "Resolution"].every((key) => isOptionalString(value[key]))) return false;
  if (value.CauseMetadata === undefined) return true;
  if (!isRecord(value.CauseMetadata)
    || !isOptionalFiniteNumber(value.CauseMetadata.StartLine)
    || !isOptionalFiniteNumber(value.CauseMetadata.EndLine)) return false;
  if (value.CauseMetadata.Code === undefined) return true;
  return isRecord(value.CauseMetadata.Code)
    && isOptionalArrayOf(value.CauseMetadata.Code.Lines, (line): line is { Content?: string } => isRecord(line) && isOptionalString(line.Content));
}

function isTrivySecret(value: unknown): value is TrivySecret {
  if (!isRecord(value)) return false;
  return ["RuleID", "Category", "Title", "Severity", "Match"].every((key) => isOptionalString(value[key]))
    && isOptionalFiniteNumber(value.StartLine)
    && isOptionalFiniteNumber(value.EndLine);
}

function isTrivyResult(value: unknown): value is TrivyResult {
  return isRecord(value)
    && isOptionalString(value.Target)
    && isOptionalArrayOf(value.Vulnerabilities, isTrivyVulnerability)
    && isOptionalArrayOf(value.Misconfigurations, isTrivyMisconfiguration)
    && isOptionalArrayOf(value.Secrets, isTrivySecret);
}

export async function runTrivy(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const command = await resolveEngineCommand("trivy");
  if (!command) {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "not_run", required: !context.options.nativeOnly, reason: "trivy executable not installed", durationMs: Date.now() - started } };
  }
  const compatibility = await inspectEngineCompatibility("trivy", command);
  if (!compatibility.supported) {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, version: compatibility.rawVersion, reason: compatibility.reason, durationMs: Date.now() - started } };
  }
  const database = await trivyDatabaseStatus();
  if (database.state !== "ready") {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, version: compatibility.rawVersion, reason: database.reason, durationMs: Date.now() - started } };
  }
  const targetInlineSuppressions = context.inventory.files.reduce((count, file) => count + (file.content.match(/trivy:ignore(?::|\b)/gi)?.length ?? 0), 0);
  const temporary = await mkdtemp(join(tmpdir(), "aisec-trivy-"));
  const configPath = join(temporary, "trivy.yaml");
  const ignorePath = join(temporary, "trivyignore");
  const secretConfigPath = join(temporary, "trivy-secret.yaml");
  await writeFile(configPath, "# AIsec trusted empty config; all policy is passed as explicit flags.\n", { mode: 0o600 });
  await writeFile(ignorePath, "# AIsec intentionally accepts no target-controlled suppressions.\n", { mode: 0o600 });
  await writeFile(secretConfigPath, "# Keep all Trivy built-in secret and allow rules while overriding target trivy-secret.yaml.\ndisable-rules: []\ndisable-allow-rules: []\n", { mode: 0o600 });
  const args = ["--config", configPath, "filesystem", "--cache-dir", trivyCacheDir(), "--format", "json", "--scanners", "vuln,misconfig,secret", "--ignorefile", ignorePath, "--secret-config", secretConfigPath, "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-vex-repo-update", "--disable-telemetry", "--skip-version-check", "--quiet", context.root];
  let result;
  try {
    result = await runProcess(command, args, { timeoutMs: context.options.timeoutMs, maxOutputBytes: 35 * 1024 * 1024, env: sanitizedEngineEnv("trivy") });
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
  if (result.timedOut || result.truncated) {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, reason: result.timedOut ? "trivy timed out" : "trivy output exceeded safety limit", durationMs: result.durationMs } };
  }
  if (result.exitCode !== 0) {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, reason: redactSnippet(result.stderr || `trivy exited ${result.exitCode}`), durationMs: result.durationMs } };
  }
  let value: unknown;
  try { value = JSON.parse(result.stdout) as unknown; } catch {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, reason: redactSnippet(result.stderr || "trivy returned invalid JSON; its offline database may be missing"), durationMs: result.durationMs } };
  }
  if (!isRecord(value)
    || value.SchemaVersion !== 2
    || (value.Results !== undefined && !Array.isArray(value.Results))
    || (Array.isArray(value.Results) && !value.Results.every(isTrivyResult))) {
    return { signals: [], coverage: { domain: "dependencies-iac", engine: "trivy", status: "failed", required: !context.options.nativeOnly, reason: "trivy returned an unexpected JSON schema", durationMs: result.durationMs } };
  }
  const parsed = value as { Results?: TrivyResult[] };
  const signals: Signal[] = [];
  let signalsTruncated = false;
  const add = (signal: ReturnType<typeof externalSignal>): boolean => {
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { signalsTruncated = true; return false; }
    signals.push(signal);
    return true;
  };
  targets: for (const target of parsed.Results ?? []) {
    const path = target.Target ? (isAbsolute(target.Target) ? normalizeRelative(context.root, target.Target) : target.Target) : ".";
    for (const vuln of target.Vulnerabilities ?? []) {
      if (!add(externalSignal({
        engine: "trivy", ruleId: vuln.VulnerabilityID ?? "trivy.vulnerability", title: vuln.Title ?? `${vuln.VulnerabilityID ?? "Vulnerability"} in ${vuln.PkgName ?? "dependency"}`,
        description: vuln.Description ?? "A dependency matches a known vulnerability advisory.", severity: normalizeSeverity(vuln.Severity), locations: [{ path }],
        tags: ["sca", "dependency", vuln.PkgName ?? "unknown"], remediation: vuln.FixedVersion ? `Upgrade ${vuln.PkgName ?? "the package"} to ${vuln.FixedVersion} or later after compatibility testing.` : "Remove, isolate, or replace the dependency; no fixed version was reported.",
        metadata: { package: vuln.PkgName ?? "unknown", installedVersion: vuln.InstalledVersion ?? "unknown", fixedVersion: vuln.FixedVersion ?? "unknown", advisory: vuln.PrimaryURL ?? "" },
      }))) break targets;
    }
    for (const misconfig of target.Misconfigurations ?? []) {
      if (!add(externalSignal({
        engine: "trivy", ruleId: misconfig.ID ?? "trivy.misconfiguration", title: misconfig.Title ?? misconfig.ID ?? "Infrastructure misconfiguration",
        description: misconfig.Message ?? misconfig.Description ?? "Trivy detected an infrastructure configuration risk.", severity: normalizeSeverity(misconfig.Severity),
        locations: [{ path, line: misconfig.CauseMetadata?.StartLine, endLine: misconfig.CauseMetadata?.EndLine, snippet: redactSnippet((misconfig.CauseMetadata?.Code?.Lines ?? []).map((line) => line.Content ?? "").join("\n")) }],
        tags: ["iac", "misconfiguration"], remediation: misconfig.Resolution,
      }))) break targets;
    }
    for (const secret of target.Secrets ?? []) {
      if (!add(externalSignal({
        engine: "trivy", ruleId: secret.RuleID ?? "trivy.secret", title: secret.Title ?? secret.Category ?? "Secret detected by Trivy",
        description: "Trivy detected credential-shaped material. AIsec redacts the raw value.", severity: normalizeSeverity(secret.Severity, "high"),
        locations: [{ path, line: secret.StartLine, endLine: secret.EndLine, snippet: secret.Match ? redactSnippet(secret.Match) : "[REDACTED]" }],
        cwe: ["CWE-798"], tags: ["secret", "trivy"], remediation: "Revoke the credential and move the replacement into an appropriate secret store.",
      }))) break targets;
    }
  }
  return { signals, coverage: {
    domain: "dependencies-iac",
    engine: "trivy",
    status: targetInlineSuppressions > 0 || signalsTruncated ? "partial" : "complete",
    required: !context.options.nativeOnly,
    version: compatibility.rawVersion,
    reason: [targetInlineSuppressions > 0 ? `${targetInlineSuppressions} target-controlled trivy:ignore directive(s) may suppress engine results` : undefined, signalsTruncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined].filter(Boolean).join("; ") || undefined,
    durationMs: result.durationMs,
  } };
}
