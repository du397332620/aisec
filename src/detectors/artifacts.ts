import { basename } from "node:path";
import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { createSignal, executableExists, makeLocation, redactSnippet } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import { runProcess, runProcessBuffer } from "../engines/process.js";
import { binaryPlistSearchText } from "./binary-plist.js";

const TEXT_ENTRY = /(?:network_security_config\.xml|main\.jsbundle|index\.android\.bundle|(?:assets|res\/raw)\/.*\.(?:html|js|json|xml|plist|txt)|Payload\/[^/]+\.app\/.*\.(?:html|js|json|xml|plist|txt))$/i;
const ANDROID_BINARY_ENTRY = /(?:^|\/)(?:classes\d*\.dex|resources\.arsc)$/i;
const UNSAFE_ENTRY = /(?:^\/|^[A-Za-z]:\/|(?:^|\/)\.\.(?:\/|$)|\\|\u0000)/;
const MAX_ARCHIVE_ENTRIES = 200_000;
const MAX_SELECTED_ENTRIES = 25;
const MAX_ARCHIVE_ENTRY_BYTES = 8 * 1024 * 1024;
const MAX_ARCHIVE_INPUT_BYTES = 16 * 1024 * 1024;
const MAX_ARCHIVE_TEXT_BYTES = 8 * 1024 * 1024;

interface SelectedEntry {
  name: string;
  binary: boolean;
  priority: number;
  index: number;
}

function classifyEntry(name: string, index: number): SelectedEntry | undefined {
  if (/^(?:AndroidManifest\.xml|Info\.plist|Payload\/[^/]+\.app\/Info\.plist)$/i.test(name) || /network_security_config\.xml$/i.test(name)) {
    return { name, binary: /AndroidManifest\.xml$/i.test(name), priority: 0, index };
  }
  const mainExecutable = name.match(/^Payload\/([^/]+)\.app\/([^/]+)$/i);
  if (ANDROID_BINARY_ENTRY.test(name) || (mainExecutable && mainExecutable[1] === mainExecutable[2])) {
    return { name, binary: true, priority: 1, index };
  }
  if (/(?:main\.jsbundle|index\.android\.bundle|resources\.arsc)$/i.test(name)) {
    return { name, binary: true, priority: 2, index };
  }
  if (TEXT_ENTRY.test(name)) return { name, binary: false, priority: /Info\.plist$/i.test(name) ? 4 : 3, index };
  return undefined;
}

function boundedUtf8(value: string, maxBytes: number): { text: string; truncated: boolean } {
  const encoded = Buffer.from(value, "utf8");
  if (encoded.length <= maxBytes) return { text: value, truncated: false };
  return { text: encoded.subarray(0, maxBytes).toString("utf8"), truncated: true };
}

function recoverPrintableText(value: Buffer, maxBytes: number): { text: string; truncated: boolean } {
  const source = value.toString("latin1");
  const recovered: string[] = [];
  const seen = new Set<string>();
  let bytes = 0;
  let truncated = false;
  const add = (candidate: string): void => {
    const normalized = candidate.replaceAll("\u0000", "").trim();
    if (normalized.length < 4 || seen.has(normalized) || truncated) return;
    const size = Buffer.byteLength(normalized) + 1;
    if (bytes + size > maxBytes) {
      truncated = true;
      return;
    }
    seen.add(normalized);
    recovered.push(normalized);
    bytes += size;
  };
  for (const match of source.matchAll(/[ -~]{4,}/g)) add(match[0]);
  for (const match of source.matchAll(/(?:[ -~]\u0000){4,}/g)) add(match[0]);
  for (const match of source.matchAll(/(?:\u0000[ -~]){4,}/g)) add(match[0]);
  return { text: recovered.join("\n"), truncated };
}

function archiveEntryText(value: Buffer, forcePrintable: boolean, maxBytes: number): { text: string; truncated: boolean; partialReason?: string } {
  if (value.subarray(0, 8).toString("ascii") === "bplist00") {
    try {
      return binaryPlistSearchText(value, maxBytes);
    } catch {
      return { ...recoverPrintableText(value, maxBytes), partialReason: "binary plist semantic decoding failed" };
    }
  }
  if (forcePrintable || value.includes(0)) {
    return recoverPrintableText(value, maxBytes);
  }
  return boundedUtf8(value.toString("utf8"), maxBytes);
}

async function inspectArchive(path: string, deadline: number): Promise<{ text: string; partialReason?: string }> {
  if (!(await executableExists("unzip"))) return { text: "", partialReason: "unzip is not installed" };
  const remainingTimeout = (): number => Math.max(1, deadline - Date.now());
  if (deadline <= Date.now()) return { text: "", partialReason: "artifact inspection exceeded its aggregate time limit" };
  const listing = await runProcess("unzip", ["-Z1", path], { timeoutMs: remainingTimeout(), maxOutputBytes: 2 * 1024 * 1024 });
  if (listing.exitCode !== 0 || listing.timedOut || listing.truncated) return { text: "", partialReason: "archive listing failed or exceeded limits" };
  const entries = listing.stdout.split("\n").filter(Boolean);
  if (entries.length > MAX_ARCHIVE_ENTRIES) return { text: "", partialReason: "archive contains too many entries to inspect safely" };
  if (entries.some((entry) => UNSAFE_ENTRY.test(entry))) return { text: "", partialReason: "archive contains unsafe paths and was not inspected" };
  const interesting = entries
    .map((entry, index) => classifyEntry(entry, index))
    .filter((entry): entry is SelectedEntry => entry !== undefined)
    .sort((left, right) => left.priority - right.priority || left.index - right.index);
  const selected = interesting.slice(0, MAX_SELECTED_ENTRIES);
  const chunks: string[] = [];
  const reasons: string[] = [];
  let capturedInputBytes = 0;
  let capturedTextBytes = 0;
  if (interesting.length > selected.length) reasons.push(`only ${MAX_SELECTED_ENTRIES} of ${interesting.length} supported archive entries were inspected`);
  for (const entry of selected) {
    if (deadline <= Date.now()) {
      reasons.push("artifact inspection exceeded its aggregate time limit");
      break;
    }
    const remainingInput = MAX_ARCHIVE_INPUT_BYTES - capturedInputBytes;
    const remainingText = MAX_ARCHIVE_TEXT_BYTES - capturedTextBytes;
    if (remainingInput <= 0) {
      reasons.push("archive input exceeded the aggregate safety limit");
      break;
    }
    if (remainingText <= 0) {
      reasons.push("archive text exceeded the aggregate safety limit");
      break;
    }
    const result = await runProcessBuffer("unzip", ["-p", path, entry.name], {
      timeoutMs: Math.min(remainingTimeout(), 20_000),
      maxOutputBytes: Math.min(MAX_ARCHIVE_ENTRY_BYTES, remainingInput),
    });
    capturedInputBytes += result.stdout.length + result.stderr.length;
    if (result.timedOut) {
      reasons.push(`${entry.name} timed out while reading`);
      continue;
    }
    if (result.truncated) reasons.push(`${entry.name} exceeded the per-entry or aggregate safety limit`);
    else if (result.exitCode !== 0) {
      reasons.push(`${entry.name} could not be read`);
      continue;
    }
    const header = `\n--- ${entry.name} ---\n`;
    const headerBytes = Buffer.byteLength(header);
    if (headerBytes >= remainingText) {
      reasons.push("archive text exceeded the aggregate safety limit");
      break;
    }
    const recovered = archiveEntryText(result.stdout, entry.binary, remainingText - headerBytes);
    if (recovered.partialReason) reasons.push(`${entry.name} ${recovered.partialReason}`);
    if (recovered.truncated) reasons.push(`${entry.name} printable text exceeded the aggregate safety limit`);
    const chunk = `${header}${recovered.text}`;
    capturedTextBytes += Buffer.byteLength(chunk);
    chunks.push(chunk);
  }
  if (selected.length === 0) reasons.push("no supported static resources were found in the archive");
  return { text: chunks.join("\n"), partialReason: reasons.join("; ") || undefined };
}

const IGNORED_HTTP_HOSTS = new Set([
  "schemas.android.com", "www.w3.org", "www.apache.org", "www.gnu.org", "opensource.org",
  "xml.org", "purl.org", "ns.adobe.com", "www.apple.com", "crl.apple.com", "ocsp.apple.com",
]);

function ignoredHttpEndpoint(value: string): boolean {
  try {
    const hostname = new URL(value).hostname.toLowerCase();
    if (!hostname.includes(".") && !hostname.includes(":")) return true;
    if (hostname === "localhost" || hostname.startsWith("127.") || hostname === "10.0.2.2") return true;
    if (["example.com", "example.org", "example.net"].some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))) return true;
    return IGNORED_HTTP_HOSTS.has(hostname);
  } catch {
    return true;
  }
}

function cleartextEndpointMatches(corpus: string): RegExpMatchArray[] {
  const matches = corpus.matchAll(/http:\/\/(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::\d{1,5})?(?:\/[^\s"'`<>\u0000]*)?/g);
  return [...matches].filter((match) => !ignoredHttpEndpoint(match[0]));
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
    for (const match of signalLimitReached ? [] : cleartextEndpointMatches(corpus)) {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { signalLimitReached = true; break; }
      signals.push(artifactSignal(artifact.path, corpus, match, {
        ruleId: "artifact.cleartext-endpoint", title: "Cleartext endpoint embedded in a mobile artifact",
        description: "A recoverable production-looking HTTP URL may expose application traffic to interception.", severity: "high", tags: ["mobile", "artifact", "network"],
        remediation: "Use HTTPS, enforce certificate validation and remove cleartext production fallbacks before rebuilding the artifact.",
      }));
    }
    for (const match of signalLimitReached ? [] : corpus.matchAll(/(?:<key>\s*NSAllowsArbitraryLoads\s*<\/key>|(?:^|\n)NSAllowsArbitraryLoads(?:\n|$))[\s\S]{0,40}<true\s*\/>/gm)) {
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
