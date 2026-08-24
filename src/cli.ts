#!/usr/bin/env node
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs, booleanFlag, flag, flags, requireFlag } from "./cli/args.js";
import { inspectOnly, scanProject } from "./core/scan.js";
import { createFixContract } from "./core/contracts.js";
import { loadReport } from "./core/store.js";
import { engineStatus, installManagedEngine } from "./engines/manager.js";
import { runMcpServer } from "./mcp/server.js";
import { emitReport, type OutputFormat } from "./reporters/index.js";
import { renderFixContract } from "./reporters/terminal.js";
import { verifyWeb } from "./web/verify.js";
import { verifyBola } from "./web/bola.js";
import { draftBola } from "./web/bola-draft.js";
import { checkBola, prepareBola } from "./web/bola-preflight.js";
import { interfaceVerificationQueue } from "./web/interface-verification-queue.js";
import { TOOL_VERSION } from "./core/constants.js";
import { parsePositiveInt } from "./core/utils.js";
import { prepareTrivyDatabase, trivyDatabaseStatus } from "./engines/trivy-db.js";
import { previewRulePacks, renderRulePackPreview } from "./rules/preview.js";
import { runLocalGate } from "./core/local-gate.js";

const HELP = `AIsec ${TOOL_VERSION} — local-first security acceptance for AI-built applications

Usage:
  aisec inspect [path] [--artifact app.apk]
  aisec scan [path] [--profile predeploy|native] [--policy trusted-policy.yml] [--rule-pack trusted-rules.yml] [--native-only] [--artifact app.apk] [--format terminal|json|html|sarif|ci|github|markdown] [--output file]
  aisec rescan [path] --baseline <scan-id|report.json> [scan options]
  aisec local-gate [path] --policy <trusted-policy.yml> --state-dir <private-directory> [gate scan options]
  aisec report <scan-id|report.json> [--format terminal|json|html|sarif|ci|github|markdown] [--output file]
  aisec fix-contract --scan <scan-id|report.json> --finding <id|fingerprint> [--format terminal|json] [--output file]
  aisec interface-queue --scan <scan-id|report.json> [--output file]
  aisec draft-bola --scan <scan-id|report.json> [--candidate interface-candidate-id ...] [--output file]
  aisec prepare-bola --draft <selected-bola-draft.json> [--output file]
  aisec check-bola --authorization <completed-manifest.yml> [--template same-template.json] [--output file]
  aisec verify-web --authorization <manifest.yml> --confirm [--output file]
  aisec verify-bola --authorization <manifest.yml> --template <same-template.json> --check <authorization-check.json> --confirm [--output file]
  aisec rule-pack check [path] --rule-pack <trusted-rules.yml> [--format terminal|json] [--output file]
  aisec doctor [--json]
  aisec engines status [--json]
  aisec engines prepare trivy [--timeout-ms 600000]
  aisec engines install <gitleaks|opengrep|trivy> --from <local-binary> --sha256 <digest>
  aisec mcp

Scan safety:
  Project files are read only. AIsec never runs package installation, build scripts,
  repository executables, Gradle, or CocoaPods. External scanners are not bundled.
  Use --profile native for a source-only first pass. --native-only disables external
  engines without changing the selected profile's artifact policy.
  Defaults: --max-files 20000, --max-file-bytes 2097152,
  --max-total-bytes 67108864, --timeout-ms 120000, at most 10 artifacts.
  prepare-bola and every BOLA manifest/template/check input accept at most 1 MiB.
  Preflight reads no credential values, resolves no DNS and sends no requests.
  verify-bola recomputes the saved bound check before crossing that boundary.

Scan options:
  --profile predeploy|native  Acceptance scan (default) or source-only first pass
  --policy <file>            Explicit operator-owned release policy outside target
  --rule-pack <file>         Repeatable operator-owned declarative rule pack outside target
  --confirm-policy-suppressions  Confirm reviewed suppressions in that policy
  --native-only              Disable Gitleaks, Opengrep and Trivy for this scan
  --artifact <apk|ipa>       Repeatable; at most 10 mobile artifacts
  --git-history              Include Git history in Gitleaks coverage
  --max-files <count>        Selected text-file limit (default 20000)
  --max-file-bytes <bytes>   Per-file read limit (default 2097152)
  --max-total-bytes <bytes>  Aggregate candidate-input limit (default 67108864)
  --timeout-ms <ms>          External engine/artifact timeout (default 120000)
  --no-persist               Do not store the generated report

Local gate:
  Requires an operator SecurityPolicy 1.1.0 routeSecurityBaseline gate and a
  private state directory outside the target. The first run pins baseline.json;
  later runs rescan it and never advance it automatically. Use a new empty state
  directory for a deliberately reviewed policy or baseline change.

Rule-pack preview:
  Validates explicit RulePack 1.0/1.1 files and lists bounded selected project
  paths without evaluating literals or producing vulnerability findings.
  Uses the scan inventory limits and the same outside-target trust boundary.

Decision exit codes:
  Scans/local gate: 0 no_blockers_found/review, 1 block, 2 incomplete
  Rule-pack preview: 0 complete, 2 partial; 64 invalid usage/error
`;

function formatValue(value: string | undefined): OutputFormat {
  const format = value ?? "terminal";
  if (!["terminal", "json", "html", "sarif", "ci", "github", "markdown"].includes(format)) throw new Error(`Unsupported output format: ${format}`);
  return format as OutputFormat;
}

function scanExitCode(decision: string): number {
  if (decision === "block") return 1;
  if (decision === "incomplete") return 2;
  return 0;
}

function scanProfile(value: string | undefined): "predeploy" | "native" {
  if (value === undefined || value === "predeploy") return "predeploy";
  if (value === "native") return "native";
  throw new Error(`Unsupported scan profile: ${value}`);
}

function rulePackPreviewFormat(value: string | undefined): "terminal" | "json" {
  const format = value ?? "terminal";
  if (format !== "terminal" && format !== "json") throw new Error(`Unsupported rule-pack preview format: ${format}`);
  return format;
}

function pathFlags(parsed: ReturnType<typeof parseArgs>, name: string): string[] {
  const values = flags(parsed, name);
  if (values.some((value) => value === "true" || !value.trim())) throw new Error(`--${name} requires a file path`);
  return values;
}

function assertSimpleFileCommand(
  parsed: ReturnType<typeof parseArgs>,
  command: string,
  required: string,
): { input: string; output?: string } {
  if (parsed.positionals.length > 0) throw new Error(`${command} does not accept positional arguments`);
  const allowed = new Set([required, "output"]);
  for (const name of parsed.flags.keys()) {
    if (!allowed.has(name)) throw new Error(`${command} does not support --${name}`);
  }
  for (const name of allowed) {
    if (flags(parsed, name).length > 1) throw new Error(`${command} accepts --${name} at most once`);
  }
  const output = flag(parsed, "output");
  if (output === "true" || (output !== undefined && !output.trim())) throw new Error("--output requires a file path");
  return { input: requireFlag(parsed, required), ...(output === undefined ? {} : { output }) };
}

function assertCheckBolaCommand(parsed: ReturnType<typeof parseArgs>): {
  input: string;
  template?: string;
  output?: string;
} {
  if (parsed.positionals.length > 0) throw new Error("check-bola does not accept positional arguments");
  const allowed = new Set(["authorization", "template", "output"]);
  for (const name of parsed.flags.keys()) {
    if (!allowed.has(name)) throw new Error(`check-bola does not support --${name}`);
  }
  for (const name of allowed) {
    if (flags(parsed, name).length > 1) throw new Error(`check-bola accepts --${name} at most once`);
  }
  const template = flag(parsed, "template");
  const output = flag(parsed, "output");
  if (template === "true" || (template !== undefined && !template.trim())) {
    throw new Error("--template requires a file path");
  }
  if (output === "true" || (output !== undefined && !output.trim())) {
    throw new Error("--output requires a file path");
  }
  return {
    input: requireFlag(parsed, "authorization"),
    ...(template === undefined ? {} : { template }),
    ...(output === undefined ? {} : { output }),
  };
}

function assertVerifyBolaCommand(parsed: ReturnType<typeof parseArgs>): {
  authorization: string;
  template: string;
  check: string;
  confirmed: boolean;
  output?: string;
} {
  if (parsed.positionals.length > 0) throw new Error("verify-bola does not accept positional arguments");
  const allowed = new Set(["authorization", "template", "check", "confirm", "output"]);
  for (const name of parsed.flags.keys()) {
    if (!allowed.has(name)) throw new Error(`verify-bola does not support --${name}`);
  }
  for (const name of allowed) {
    if (flags(parsed, name).length > 1) throw new Error(`verify-bola accepts --${name} at most once`);
  }
  const output = flag(parsed, "output");
  if (output === "true" || (output !== undefined && !output.trim())) {
    throw new Error("--output requires a file path");
  }
  return {
    authorization: requireFlag(parsed, "authorization"),
    template: requireFlag(parsed, "template"),
    check: requireFlag(parsed, "check"),
    confirmed: booleanFlag(parsed, "confirm"),
    ...(output === undefined ? {} : { output }),
  };
}

async function writeOrStdout(value: string, output?: string): Promise<void> {
  if (output) await writeFile(resolve(output), value, { mode: 0o600 });
  else process.stdout.write(value);
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));
  if (!parsed.command || ["help", "--help", "-h"].includes(parsed.command)) {
    process.stdout.write(HELP);
    return;
  }
  if (["version", "--version", "-v"].includes(parsed.command)) {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return;
  }

  if (parsed.command === "inspect") {
    const result = await inspectOnly(parsed.positionals[0] ?? ".", { artifacts: flags(parsed, "artifact") });
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, flag(parsed, "output"));
    return;
  }

  if (parsed.command === "scan" || parsed.command === "rescan") {
    const baseline = parsed.command === "rescan" ? requireFlag(parsed, "baseline") : flag(parsed, "baseline");
    const profile = scanProfile(flag(parsed, "profile"));
    const result = await scanProject(parsed.positionals[0] ?? ".", {
      profile,
      artifacts: flags(parsed, "artifact"),
      nativeOnly: booleanFlag(parsed, "native-only") || profile === "native",
      includeGitHistory: booleanFlag(parsed, "git-history"),
      maxFiles: parsePositiveInt(flag(parsed, "max-files"), 20_000),
      maxFileBytes: parsePositiveInt(flag(parsed, "max-file-bytes"), 2 * 1024 * 1024),
      maxTotalBytes: parsePositiveInt(flag(parsed, "max-total-bytes"), 64 * 1024 * 1024),
      timeoutMs: parsePositiveInt(flag(parsed, "timeout-ms"), 120_000),
      persist: !booleanFlag(parsed, "no-persist"),
      policyPath: flag(parsed, "policy"),
      confirmPolicySuppressions: booleanFlag(parsed, "confirm-policy-suppressions"),
      rulePackPaths: pathFlags(parsed, "rule-pack"),
    }, baseline);
    await emitReport(result.report, formatValue(flag(parsed, "format")), flag(parsed, "output"));
    if (result.storedAt && !flag(parsed, "output") && formatValue(flag(parsed, "format")) === "terminal") process.stderr.write(`Stored report: ${result.storedAt}\n`);
    process.exitCode = scanExitCode(result.report.decision);
    return;
  }

  if (parsed.command === "local-gate") {
    if (parsed.positionals.length > 1) throw new Error("local-gate accepts at most one target path");
    for (const unsupported of ["profile", "native-only", "no-persist", "baseline", "output"] as const) {
      if (parsed.flags.has(unsupported)) throw new Error(`local-gate manages --${unsupported} internally; remove that option`);
    }
    const allowed = new Set([
      "policy", "state-dir", "rule-pack", "confirm-policy-suppressions", "artifact",
      "git-history", "max-files", "max-file-bytes", "max-total-bytes", "timeout-ms", "format",
    ]);
    for (const name of parsed.flags.keys()) {
      if (!allowed.has(name)) throw new Error(`local-gate does not support --${name}`);
    }
    for (const singleton of [
      "policy", "state-dir", "confirm-policy-suppressions", "git-history", "max-files",
      "max-file-bytes", "max-total-bytes", "timeout-ms", "format",
    ] as const) {
      if (flags(parsed, singleton).length > 1) throw new Error(`local-gate accepts --${singleton} at most once`);
    }
    const result = await runLocalGate(parsed.positionals[0] ?? ".", {
      policyPath: requireFlag(parsed, "policy"),
      stateDirectory: requireFlag(parsed, "state-dir"),
      artifacts: flags(parsed, "artifact"),
      includeGitHistory: booleanFlag(parsed, "git-history"),
      maxFiles: parsePositiveInt(flag(parsed, "max-files"), 20_000),
      maxFileBytes: parsePositiveInt(flag(parsed, "max-file-bytes"), 2 * 1024 * 1024),
      maxTotalBytes: parsePositiveInt(flag(parsed, "max-total-bytes"), 64 * 1024 * 1024),
      timeoutMs: parsePositiveInt(flag(parsed, "timeout-ms"), 120_000),
      confirmPolicySuppressions: booleanFlag(parsed, "confirm-policy-suppressions"),
      rulePackPaths: pathFlags(parsed, "rule-pack"),
    });
    await emitReport(result.report, formatValue(flag(parsed, "format")));
    if (result.mode === "initialized") {
      process.stderr.write(`Local gate baseline initialized: ${result.baselinePath}\nBootstrap is fail-closed; review the pinned baseline before relying on later checks.\n`);
    } else {
      process.stderr.write(`Local gate baseline (unchanged): ${result.baselinePath}\nLatest report: ${result.latestPath}\n`);
    }
    process.exitCode = result.exitCode;
    return;
  }

  if (parsed.command === "report") {
    const reference = parsed.positionals[0];
    if (!reference) throw new Error("report requires a scan id or report path");
    await emitReport(await loadReport(reference), formatValue(flag(parsed, "format")), flag(parsed, "output"));
    return;
  }

  if (parsed.command === "fix-contract") {
    const contract = createFixContract(await loadReport(requireFlag(parsed, "scan")), requireFlag(parsed, "finding"));
    const output = flag(parsed, "format") === "json" ? `${JSON.stringify(contract, null, 2)}\n` : `${renderFixContract(contract)}\n`;
    await writeOrStdout(output, flag(parsed, "output"));
    return;
  }

  if (parsed.command === "interface-queue") {
    const result = await interfaceVerificationQueue(requireFlag(parsed, "scan"));
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, flag(parsed, "output"));
    return;
  }

  if (parsed.command === "draft-bola") {
    const candidateIds = flags(parsed, "candidate");
    if (candidateIds.some((candidateId) => candidateId === "true" || !candidateId.trim())) {
      throw new Error("--candidate requires an interface candidate ID");
    }
    const result = candidateIds.length === 0
      ? await draftBola(requireFlag(parsed, "scan"))
      : await draftBola(requireFlag(parsed, "scan"), candidateIds);
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, flag(parsed, "output"));
    return;
  }

  if (parsed.command === "prepare-bola") {
    const options = assertSimpleFileCommand(parsed, "prepare-bola", "draft");
    const result = await prepareBola(options.input);
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, options.output);
    return;
  }

  if (parsed.command === "check-bola") {
    const options = assertCheckBolaCommand(parsed);
    const result = await checkBola(options.input, options.template);
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, options.output);
    return;
  }

  if (parsed.command === "verify-web") {
    const result = await verifyWeb(requireFlag(parsed, "authorization"), booleanFlag(parsed, "confirm"));
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, flag(parsed, "output"));
    process.exitCode = result.signals.some((signal) => ["critical", "high"].includes(signal.severity)) ? 1 : 0;
    return;
  }

  if (parsed.command === "verify-bola") {
    const options = assertVerifyBolaCommand(parsed);
    const result = await verifyBola(options.authorization, {
      confirmed: options.confirmed,
      templatePath: options.template,
      checkPath: options.check,
    });
    await writeOrStdout(`${JSON.stringify(result, null, 2)}\n`, options.output);
    if (result.signals.some((signal) => ["critical", "high"].includes(signal.severity))) process.exitCode = 1;
    else if (result.coverage.some((item) => item.required && item.status !== "complete")) process.exitCode = 2;
    else process.exitCode = 0;
    return;
  }

  if (parsed.command === "rule-pack" && parsed.subcommand === "check") {
    if (parsed.positionals.length > 1) throw new Error("rule-pack check accepts at most one target path");
    const rulePackPaths = pathFlags(parsed, "rule-pack");
    if (rulePackPaths.length === 0) throw new Error("rule-pack check requires at least one --rule-pack <file>");
    const preview = await previewRulePacks(parsed.positionals[0] ?? ".", {
      rulePackPaths,
      maxFiles: parsePositiveInt(flag(parsed, "max-files"), 20_000),
      maxFileBytes: parsePositiveInt(flag(parsed, "max-file-bytes"), 2 * 1024 * 1024),
      maxTotalBytes: parsePositiveInt(flag(parsed, "max-total-bytes"), 64 * 1024 * 1024),
    });
    const format = rulePackPreviewFormat(flag(parsed, "format"));
    const output = format === "json" ? `${JSON.stringify(preview, null, 2)}\n` : `${renderRulePackPreview(preview)}\n`;
    await writeOrStdout(output, flag(parsed, "output"));
    process.exitCode = preview.status === "partial" ? 2 : 0;
    return;
  }

  if (parsed.command === "doctor" || (parsed.command === "engines" && parsed.subcommand === "status")) {
    const status = await engineStatus();
    const trivyDatabase = await trivyDatabaseStatus();
    if (booleanFlag(parsed, "json")) process.stdout.write(`${JSON.stringify({ node: process.version, platform: process.platform, engines: status, trivyDatabase }, null, 2)}\n`);
    else {
      process.stdout.write(`Node ${process.version} · ${process.platform}/${process.arch}\n`);
      for (const item of status) process.stdout.write(`${item.name.padEnd(10)} ${item.source.padEnd(7)} ${item.error ?? item.version ?? item.command ?? "not installed"}${item.pinnedSha256 ? ` · sha256:${item.pinnedSha256.slice(0, 12)}…` : ""}\n`);
      process.stdout.write(`trivy-db  ${trivyDatabase.state.padEnd(7)} ${trivyDatabase.reason ?? `updated ${trivyDatabase.updatedAt}; next update ${trivyDatabase.nextUpdate}`}\n`);
      process.stdout.write("MobSF is a user-managed GPL service and is not bundled by AIsec.\n");
    }
    return;
  }

  if (parsed.command === "engines" && parsed.subcommand === "prepare") {
    const name = parsed.positionals[0];
    if (name !== "trivy") throw new Error("engines prepare currently supports only trivy");
    const result = await prepareTrivyDatabase(parsePositiveInt(flag(parsed, "timeout-ms"), 10 * 60_000));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }

  if (parsed.command === "engines" && parsed.subcommand === "install") {
    const name = parsed.positionals[0];
    if (!name) throw new Error("engines install requires an engine name");
    const record = await installManagedEngine(name, requireFlag(parsed, "from"), requireFlag(parsed, "sha256"));
    process.stdout.write(`${JSON.stringify(record, null, 2)}\n`);
    return;
  }

  if (parsed.command === "mcp") {
    await runMcpServer();
    return;
  }
  throw new Error(`Unknown command: ${parsed.command}\n\n${HELP}`);
}

main().catch((error) => {
  process.stderr.write(`aisec: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 64;
});
