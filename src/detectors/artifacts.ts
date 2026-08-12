import { basename } from "node:path";
import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { createSignal, executableExists, makeLocation, redactSnippet } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import { runProcess } from "../engines/process.js";

const INTERESTING_ENTRY = /(?:Info\.plist|AndroidManifest\.xml|network_security_config\.xml|main\.jsbundle|index\.android\.bundle|assets\/.*\.(?:js|json|xml|plist|txt))$/i;
const UNSAFE_ENTRY = /(?:^\/|^[A-Za-z]:\/|(?:^|\/)\.\.(?:\/|$)|\\|\u0000)/;
const MAX_ARCHIVE_ENTRIES = 200_000;
const MAX_SELECTED_ENTRIES = 25;
const MAX_ARCHIVE_ENTRY_BYTES = 512 * 1024;
const MAX_ARCHIVE_TEXT_BYTES = 8 * 1024 * 1024;

async function inspectArchive(path: string, deadline: number): Promise<{ text: string; partialReason?: string }> {
  if (!(await executableExists("unzip"))) return { text: "", partialReason: "unzip is not installed" };
  const remainingTimeout = (): number => Math.max(1, deadline - Date.now());
  if (deadline <= Date.now()) return { text: "", partialReason: "artifact inspection exceeded its aggregate time limit" };
  const listing = await runProcess("unzip", ["-Z1", path], { timeoutMs: remainingTimeout(), maxOutputBytes: 2 * 1024 * 1024 });
  if (listing.exitCode !== 0 || listing.timedOut || listing.truncated) return { text: "", partialReason: "archive listing failed or exceeded limits" };
  const entries = listing.stdout.split("\n").filter(Boolean);
  if (entries.length > MAX_ARCHIVE_ENTRIES) return { text: "", partialReason: "archive contains too many entries to inspect safely" };
  if (entries.some((entry) => UNSAFE_ENTRY.test(entry))) return { text: "", partialReason: "archive contains unsafe paths and was not inspected" };
  const interesting = entries.filter((entry) => INTERESTING_ENTRY.test(entry));
  const selected = interesting.slice(0, MAX_SELECTED_ENTRIES);
  const chunks: string[] = [];
  const reasons: string[] = [];
  let capturedBytes = 0;
  if (interesting.length > selected.length) reasons.push(`only ${MAX_SELECTED_ENTRIES} of ${interesting.length} supported archive entries were inspected`);
  for (const entry of selected) {
    if (deadline <= Date.now()) {
      reasons.push("artifact inspection exceeded its aggregate time limit");
      break;
    }
    const remaining = MAX_ARCHIVE_TEXT_BYTES - capturedBytes;
    if (remaining <= 0) {
      reasons.push("archive text exceeded the aggregate safety limit");
      break;
    }
    const result = await runProcess("unzip", ["-p", path, entry], { timeoutMs: Math.min(remainingTimeout(), 20_000), maxOutputBytes: Math.min(MAX_ARCHIVE_ENTRY_BYTES, remaining) });
    if (result.timedOut) reasons.push(`${entry} timed out while reading`);
    else if (result.truncated) reasons.push(`${entry} exceeded the per-entry or aggregate safety limit`);
    else if (result.exitCode !== 0) reasons.push(`${entry} could not be read`);
    else if (result.stdout.includes("\u0000")) reasons.push(`${entry} contained binary data and was skipped`);
    else {
      const chunk = `\n--- ${entry} ---\n${result.stdout}`;
      capturedBytes += Buffer.byteLength(chunk);
      chunks.push(chunk);
    }
  }
  if (deadline > Date.now() && await executableExists("strings")) {
    const remaining = MAX_ARCHIVE_TEXT_BYTES - capturedBytes;
    if (remaining <= 0) reasons.push("printable strings were skipped after reaching the aggregate safety limit");
    else {
      const result = await runProcess("strings", ["-a", path], { timeoutMs: Math.min(remainingTimeout(), 20_000), maxOutputBytes: Math.min(2 * 1024 * 1024, remaining) });
      if (result.timedOut) reasons.push("printable strings inspection timed out");
      else if (result.truncated) reasons.push("printable strings exceeded the safety limit");
      else if (result.exitCode !== 0) reasons.push("printable strings inspection failed");
      else chunks.push(`\n--- printable strings ---\n${result.stdout}`);
    }
  }
  if (selected.length === 0) reasons.push("no supported text resources found; only printable strings were inspected");
  return { text: chunks.join("\n"), partialReason: reasons.join("; ") || undefined };
}

function artifactSignal(path: string, corpus: string, match: RegExpMatchArray, input: {
  ruleId: string; title: string; description: string; severity: "critical" | "high" | "medium"; tags: string[]; remediation: string;
}): Signal {
  return createSignal({
    engine: "aisec-artifact",
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    evidenceLevel: "static_confirmed",
    confidence: "high",
    locations: [makeLocation(basename(path), corpus, match.index ?? 0, redactSnippet(match[0]))],
    cwe: input.ruleId.includes("secret") ? ["CWE-798"] : ["CWE-319"],
    tags: input.tags,
    remediation: input.remediation,
  });
}

export async function runArtifactDetector(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const signals: Signal[] = [];
  const reasons: string[] = [];
  let signalLimitReached = false;
  const deadline = Date.now() + context.options.timeoutMs;
  for (const artifact of context.profile.artifacts) {
    const inspected = await inspectArchive(artifact.path, deadline);
    if (inspected.partialReason) reasons.push(`${basename(artifact.path)}: ${inspected.partialReason}`);
    const corpus = inspected.text;
    const secrets = [
      /\bsk_live_[A-Za-z0-9]{12,}\b/g,
      /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
      /\bAKIA[0-9A-Z]{16}\b/g,
      /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
      /(?:service_role|SUPABASE_SERVICE_ROLE_KEY)["'=:,\s]+[A-Za-z0-9._-]{20,}/gi,
    ];
    for (const pattern of secrets) {
      for (const match of corpus.matchAll(pattern)) {
        if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { signalLimitReached = true; break; }
        signals.push(artifactSignal(artifact.path, corpus, match, {
          ruleId: "artifact.embedded-secret", title: "Credential embedded in a distributed mobile artifact",
          description: "A credential-shaped value is recoverable from the APK or IPA and must be considered public.", severity: "critical", tags: ["mobile", "artifact", "secret"],
          remediation: "Revoke the credential and move privileged operations behind an authenticated server endpoint; mobile applications cannot keep shared secrets.",
        }));
      }
      if (signalLimitReached) break;
    }
    for (const match of signalLimitReached ? [] : corpus.matchAll(/["'`]http:\/\/(?!localhost\b|127\.0\.0\.1\b|10\.0\.2\.2\b|example\.(?:com|org)\b)[^"'`\s]+/g)) {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { signalLimitReached = true; break; }
      signals.push(artifactSignal(artifact.path, corpus, match, {
        ruleId: "artifact.cleartext-endpoint", title: "Cleartext endpoint embedded in a mobile artifact",
        description: "A recoverable production-looking HTTP URL may expose application traffic to interception.", severity: "high", tags: ["mobile", "artifact", "network"],
        remediation: "Use HTTPS, enforce certificate validation and remove cleartext production fallbacks before rebuilding the artifact.",
      }));
    }
    for (const match of signalLimitReached ? [] : corpus.matchAll(/NSAllowsArbitraryLoads[\s\S]{0,80}<true\s*\/>/g)) {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { signalLimitReached = true; break; }
      signals.push(artifactSignal(artifact.path, corpus, match, {
        ruleId: "artifact.ios-ats-disabled", title: "Packaged iOS app disables App Transport Security",
        description: "The packaged Info.plist permits arbitrary insecure network loads.", severity: "high", tags: ["ios", "artifact", "network"],
        remediation: "Remove NSAllowsArbitraryLoads and use narrowly scoped exceptions only when unavoidable.",
      }));
    }
    if (signalLimitReached) break;
  }
  if (signalLimitReached) reasons.push(`finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit`);

  const expected = context.profile.mobilePlatforms.length > 0 || context.profile.artifacts.length > 0;
  const noArtifacts = context.profile.artifacts.length === 0;
  return {
    signals,
    coverage: {
      domain: "mobile-artifact-static",
      engine: "aisec-artifact",
      status: noArtifacts ? "not_run" : reasons.length > 0 ? "partial" : "complete",
      required: expected && context.options.profile === "predeploy",
      reason: noArtifacts ? "No APK or IPA supplied; pass --artifact <path> for pre-deploy mobile coverage" : reasons.join("; ") || undefined,
      durationMs: Date.now() - started,
    },
  };
}
