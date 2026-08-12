import type { Detector } from "./types.js";
import { createSignal, makeLocation } from "../core/utils.js";
import type { Signal } from "../schema.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const AUTH_MARKERS = /(?:auth\s*\(|getServerSession|getSession|getUser\s*\(|currentUser|requireAuth|withAuth|verifyToken|verifySession|authorization|auth\.uid|clerkClient)/i;
const HANDLER_MARKERS = /export\s+(?:async\s+)?function\s+(?:GET|POST|PUT|PATCH|DELETE)|export\s+const\s+(?:GET|POST|PUT|PATCH|DELETE)/;

export const appConfigDetector: Detector = {
  name: "native-app-config",
  async run(context) {
    const started = Date.now();
    const signals: Signal[] = [];
    let truncated = false;
    const add = (signal: Signal): boolean => {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { truncated = true; return false; }
      signals.push(signal);
      return true;
    };
    for (const file of context.inventory.files) {
      if (truncated) break;
      if (/app\/api\/(?:admin|internal|manage|users|billing|payments)(?:\/|.*\/)?route\.(?:js|jsx|ts|tsx)$/.test(file.relativePath)
        && HANDLER_MARKERS.test(file.content) && !AUTH_MARKERS.test(file.content)) {
        add(createSignal({
          engine: "aisec-native",
          ruleId: "auth.sensitive-route-without-visible-guard",
          title: "Sensitive API route has no visible authentication guard",
          description: "The route path and exported handler indicate a sensitive server operation, but no recognized authentication or authorization check appears in this file. Framework middleware may still protect it.",
          severity: "high",
          evidenceLevel: "inferred",
          confidence: "medium",
          locations: [makeLocation(file.relativePath, file.content, 0, file.content.split("\n").find((line) => HANDLER_MARKERS.test(line)) ?? file.relativePath)],
          cwe: ["CWE-306"],
          owasp: ["A01:2021", "A07:2021"],
          tags: ["auth", "api", "nextjs"],
          remediation: "Require a server-verified session and an explicit role/ownership check inside the handler or in provably applied middleware; add unauthenticated and wrong-role tests.",
        }));
      }

      if (/\.github\/workflows\/.*\.ya?ml$/.test(file.relativePath)) {
        const injection = /run:\s*(?:\||>)?[\s\S]{0,500}?\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion|head_commit)[^}]*\}\}/gi;
        for (const match of file.content.matchAll(injection)) {
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "ci.github-expression-command-injection",
            title: "Untrusted GitHub event data is interpolated into a shell step",
            description: "Event-controlled text is expanded directly inside a run script and may inject shell syntax.",
            severity: "critical",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
            cwe: ["CWE-78"],
            owasp: ["A03:2021", "A08:2021"],
            tags: ["ci", "github-actions", "injection", "supply-chain"],
            remediation: "Assign the expression to an environment variable, quote it as data, and avoid running untrusted fork code with write tokens or secrets.",
          }))) break;
        }
      }

      const sensitiveLog = /console\.(?:log|info|debug|warn|error)\s*\([^\n;]*(?:password|accessToken|refreshToken|authorization|cookie|secret|apiKey)/gi;
      for (const match of truncated ? [] : file.content.matchAll(sensitiveLog)) {
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "privacy.sensitive-logging",
          title: "Potential credential or session data written to logs",
          description: "A logging call includes a variable or property with a sensitive name.",
          severity: "medium",
          evidenceLevel: "inferred",
          confidence: "medium",
          locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
          cwe: ["CWE-532"],
          owasp: ["A09:2021"],
          tags: ["privacy", "logging", "secret"],
          remediation: "Remove sensitive fields or apply structured redaction before logging; test that production logs never contain credentials.",
        }))) break;
      }
    }
    return {
      signals,
      coverage: { domain: "application-config", engine: "aisec-native", status: truncated ? "partial" : "complete", required: true, reason: truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined, durationMs: Date.now() - started },
    };
  },
};
