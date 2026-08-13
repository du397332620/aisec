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

function routeMetadata(signal: Signal): string {
  const value = signal.metadata?.route;
  return typeof value === "string" ? value : "";
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

  const fastApiUnguarded = matching(signals, /fastapi\.auth\.sensitive-route-without-guard/);
  const publishedUnguarded = matching(signals, /docker\.config\.unguarded-service-published/);
  const pythonNetworkImpact = matching(signals, /python\.dataflow\.(?:ssrf|client-url-with-server-secret)/);
  const networkFunctions = new Set(pythonNetworkImpact.map((signal) => String(signal.metadata?.function ?? "")));
  const networkUnguarded = fastApiUnguarded.filter((signal) => {
    const handler = String(signal.metadata?.handler ?? "");
    const route = routeMetadata(signal);
    return networkFunctions.has(handler)
      || (/(?:generate)/i.test(route) && [...networkFunctions].some((name) => /generation|generate/i.test(name)))
      || (/(?:review)/i.test(route) && [...networkFunctions].some((name) => /review/i.test(name)));
  });
  if (networkUnguarded.length > 0 && publishedUnguarded.length > 0 && pythonNetworkImpact.length > 0) {
    const related = [...networkUnguarded, ...publishedUnguarded, ...pythonNetworkImpact];
    paths.push(path({
      title: "Published unauthenticated Python service reaches attacker-selected network destinations",
      summary: "Production deployment publishes a FastAPI service with no locally visible authentication guard, and request-derived data can reach a server-side network client. Where a server credential is attached, the same path can also disclose that credential.",
      severity: "critical",
      evidenceLevel: "inferred",
      signalIds: related.map((signal) => signal.id),
      steps: [
        { assetId: assetId(graph, "api_route", "api"), action: "Attacker reaches a published API route without a proven identity boundary", signalIds: [...networkUnguarded, ...publishedUnguarded].map((signal) => signal.id) },
        { assetId: assetId(graph, "server", "server"), action: "Request-controlled destination reaches a server network client and may receive server credentials", signalIds: pythonNetworkImpact.map((signal) => signal.id) },
      ],
      remediation: "Remove public port publication for internal services, require service authentication in the application, allowlist destinations server-side, and bind each outbound credential to a fixed origin.",
    }, related));
  }

  const whitelistedSensitive = matching(signals, /fastapi\.auth\.whitelisted-sensitive-route/);
  const objectAuthorization = matching(signals, /fastapi\.authorization\.object-without-ownership-check/);
  const whitelistedRoots = new Set(whitelistedSensitive.map((signal) => routeMetadata(signal).split(" ").at(-1)?.split("/").filter(Boolean)[0] ?? ""));
  const relatedObjectAuthorization = objectAuthorization.filter((signal) => {
    const root = routeMetadata(signal).split(" ").at(-1)?.split("/").filter(Boolean)[0] ?? "";
    return root && whitelistedRoots.has(root);
  });
  if (whitelistedSensitive.length > 0 && relatedObjectAuthorization.length > 0) {
    const related = [...whitelistedSensitive, ...relatedObjectAuthorization];
    paths.push(path({
      title: "Broad authentication bypass combines with missing object-level authorization",
      summary: "Sensitive routes are reachable through an authentication whitelist while other object operations accept identifiers without a visible owner, tenant, or role constraint. An attacker may be able to enumerate or modify data across accounts.",
      severity: "critical",
      evidenceLevel: "inferred",
      signalIds: related.map((signal) => signal.id),
      steps: [
        { assetId: assetId(graph, "auth", "authentication"), action: "Attacker enters through an exact or prefix authentication whitelist", signalIds: whitelistedSensitive.map((signal) => signal.id) },
        { assetId: assetId(graph, "database", "application-data"), action: "Attacker substitutes object identifiers without a proven ownership boundary", signalIds: relatedObjectAuthorization.map((signal) => signal.id) },
      ],
      remediation: "Narrow the authentication whitelist, then enforce object ownership or privileged roles in every object query and mutation. Verify cross-account denial with two low-privilege test identities.",
    }, related));
  }
  return paths;
}
