import type { Signal } from "../schema.js";
import type { Detector } from "./types.js";
import { createSignal, makeLocation } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

interface SecretPattern {
  id: string;
  title: string;
  pattern: RegExp;
  severity: "critical" | "high";
  tags: string[];
}

const PATTERNS: SecretPattern[] = [
  { id: "secret.stripe-live", title: "Stripe live secret key in source", pattern: /\bsk_live_[A-Za-z0-9]{12,}\b/g, severity: "critical", tags: ["secret", "payment"] },
  { id: "secret.openai", title: "OpenAI API key in source", pattern: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g, severity: "high", tags: ["secret", "llm"] },
  { id: "secret.aws-access-key", title: "AWS access key in source", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: "critical", tags: ["secret", "cloud"] },
  { id: "secret.github-token", title: "GitHub token in source", pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g, severity: "critical", tags: ["secret", "scm"] },
  { id: "secret.private-key", title: "Private key material committed to the project", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severity: "critical", tags: ["secret", "crypto"] },
];

const TEST_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|__snapshots__)(?:\/|$)/i;

export const secretDetector: Detector = {
  name: "native-secrets",
  async run(context) {
    const started = Date.now();
    const signals: Signal[] = [];
    let truncated = false;
    const add = (signal: ReturnType<typeof createSignal>): boolean => {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { truncated = true; return false; }
      signals.push(signal);
      return true;
    };
    for (const file of context.inventory.files) {
      for (const definition of PATTERNS) {
        definition.pattern.lastIndex = 0;
        for (const match of file.content.matchAll(definition.pattern)) {
          const inTest = TEST_PATH.test(file.relativePath);
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: definition.id,
            title: definition.title,
            description: inTest
              ? "Credential-like material appears in a test or fixture. Confirm it is synthetic and cannot authenticate."
              : "A credential is embedded in a tracked project file and may be copied into source history or a client bundle.",
            severity: inTest ? "medium" : definition.severity,
            evidenceLevel: "static_confirmed",
            confidence: inTest ? "medium" : "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
            cwe: ["CWE-798"],
            owasp: ["A02:2021"],
            tags: definition.tags,
            remediation: "Revoke the credential, remove it from source and history, and load a least-privileged replacement from a server-side secret store.",
          }))) break;
        }
        if (truncated) break;
      }

      const publicSecret = /\b((?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|ADMIN|PASSWORD)[A-Z0-9_]*)\s*=\s*([^\s#]+)/g;
      for (const match of truncated ? [] : file.content.matchAll(publicSecret)) {
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "secret.client-public-privileged-variable",
          title: "Privileged value exposed through a client-public environment variable",
          description: `${match[1]} uses a framework prefix that intentionally embeds the value into client-distributed code.`,
          severity: "critical",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
          cwe: ["CWE-200", "CWE-798"],
          owasp: ["A02:2021"],
          tags: ["secret", "client", "baas"],
          remediation: "Move privileged operations to a server-side route and expose only an anonymous/public client key to the application bundle.",
          metadata: { variable: match[1] ?? "unknown" },
        }))) break;
      }
      const publicSecretReference = /(?:process\.env\.|import\.meta\.env\.)(?:NEXT_PUBLIC|VITE|EXPO_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE|ADMIN|PASSWORD)[A-Z0-9_]*/g;
      for (const match of truncated ? [] : file.content.matchAll(publicSecretReference)) {
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "secret.client-public-privileged-reference",
          title: "Client code references a public-prefixed privileged variable",
          description: "The framework prefix embeds this value into distributed client code even if the value itself is supplied only at build time.",
          severity: "critical",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
          cwe: ["CWE-200", "CWE-798"],
          owasp: ["A02:2021"],
          tags: ["secret", "client", "configuration"],
          remediation: "Rename and move the privileged value to a server-only environment variable, then expose a narrow authenticated server operation to the client.",
        }))) break;
      }
      if (truncated) break;
    }
    return {
      signals,
      coverage: { domain: "secrets", engine: "aisec-native", status: truncated ? "partial" : "complete", required: true, reason: truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined, durationMs: Date.now() - started },
    };
  },
};
