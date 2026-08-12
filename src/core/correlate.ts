import type { AssetGraph, AttackPath, EvidenceLevel, Severity, Signal } from "../schema.js";
import { sha256, stableId } from "./utils.js";

function evidence(signals: Signal[]): EvidenceLevel {
  if (signals.every((signal) => signal.evidenceLevel === "verified")) return "verified";
  if (signals.every((signal) => signal.evidenceLevel !== "inferred")) return "static_confirmed";
  return "inferred";
}

function path(input: Omit<AttackPath, "id" | "fingerprint">, relatedSignals: Signal[]): AttackPath {
  const fingerprint = sha256([input.title, ...relatedSignals.map((signal) => signal.fingerprint).sort()].join("\u0000"));
  return { ...input, fingerprint, id: `path_${fingerprint.slice(0, 16)}` };
}

function assetId(graph: AssetGraph, kind: string, fallback: string): string {
  return graph.nodes.find((node) => node.kind === kind)?.id ?? stableId("asset", kind, fallback);
}

function matching(signals: Signal[], rule: RegExp): Signal[] {
  return signals.filter((signal) => rule.test(signal.ruleId));
}

export function correlateAttackPaths(signals: Signal[], graph: AssetGraph): AttackPath[] {
  const paths: AttackPath[] = [];
  const clientSecrets = matching(signals, /(?:client-public-privileged|artifact\.embedded-secret)/);
  const supabaseOpen = matching(signals, /supabase\.(?:table-without-rls|permissive-rls-policy)/);
  const firebaseOpen = matching(signals, /firebase\.unconditional-access/);
  const openBaas = [...supabaseOpen, ...firebaseOpen];
  if (clientSecrets.length > 0 && openBaas.length > 0) {
    const related = [...clientSecrets, ...openBaas];
    paths.push(path({
      title: "Public client credential combines with an under-protected BaaS data plane",
      summary: "A credential or privileged value can be recovered from client-distributed code while database authorization is absent or overly broad. An unauthenticated attacker may be able to access application data directly.",
      severity: "critical",
      evidenceLevel: evidence(related),
      signalIds: related.map((signal) => signal.id),
      steps: [
        { assetId: assetId(graph, "client", "client"), action: "Attacker obtains a client-distributed credential", signalIds: clientSecrets.map((signal) => signal.id) },
        { assetId: assetId(graph, "database", "baas"), action: "Credential reaches tables without effective row-level authorization", signalIds: openBaas.map((signal) => signal.id) },
      ],
      remediation: "Revoke privileged credentials, move privileged operations server-side, enable deny-by-default row-level rules, and verify access with two low-privilege accounts.",
    }, related));
  }

  const modelSink = matching(signals, /ai\.model-output-dangerous-sink/);
  for (const signal of modelSink) {
    paths.push(path({
      title: "Prompt-controlled model output can reach a privileged execution primitive",
      summary: "An attacker who influences model output may convert prompt injection into code execution, command execution, or arbitrary database operations.",
      severity: "critical",
      evidenceLevel: signal.evidenceLevel,
      signalIds: [signal.id],
      steps: [
        { assetId: assetId(graph, "llm", "llm"), action: "Attacker influences model output", signalIds: [signal.id] },
        { assetId: assetId(graph, "server", "server"), action: "Application executes model-controlled content with server privileges", signalIds: [signal.id] },
      ],
      remediation: "Use typed tools, strict schemas and allowlists, least-privileged execution, bounded operations and explicit user confirmation for consequential actions.",
    }, [signal]));
  }

  const unauthenticated = matching(signals, /auth\.sensitive-route-without-visible-guard/);
  const injection = matching(signals, /dataflow\.(?:sql-injection|command-injection)/);
  if (unauthenticated.length > 0 && injection.length > 0) {
    const related = [...unauthenticated, ...injection];
    paths.push(path({
      title: "Potentially unauthenticated API surface reaches an injection sink",
      summary: "A sensitive route lacks a locally visible guard and request data reaches a database or command execution sink. Confirm middleware coverage before treating the route as remotely exploitable.",
      severity: "critical" as Severity,
      evidenceLevel: "inferred",
      signalIds: related.map((signal) => signal.id),
      steps: [
        { assetId: assetId(graph, "api_route", "api"), action: "Attacker calls a sensitive route without a proven guard", signalIds: unauthenticated.map((signal) => signal.id) },
        { assetId: assetId(graph, "server", "server"), action: "Request-controlled value reaches an execution sink", signalIds: injection.map((signal) => signal.id) },
      ],
      remediation: "Enforce authentication and object/role authorization at the route boundary, then remove the injection sink through parameterization or fixed argument vectors.",
    }, related));
  }
  return paths;
}
