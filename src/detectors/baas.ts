import type { Detector } from "./types.js";
import { createSignal, makeLocation } from "../core/utils.js";
import type { Signal } from "../schema.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

function normalizeTable(value: string): string {
  return value.replace(/["'`]/g, "").toLowerCase();
}

export const baasDetector: Detector = {
  name: "native-baas",
  async run(context) {
    const started = Date.now();
    const signals: Signal[] = [];
    let truncated = false;
    const add = (signal: Signal): boolean => {
      if (signals.length >= MAX_SIGNALS_PER_DETECTOR) { truncated = true; return false; }
      signals.push(signal);
      return true;
    };
    const sqlFiles = context.inventory.files.filter((file) => file.relativePath.endsWith(".sql"));
    const sqlCorpus = sqlFiles.map((file) => file.content).join("\n");
    const rlsTables = new Set<string>();
    const rlsPattern = /alter\s+table(?:\s+only)?\s+([\w."`]+)\s+enable\s+row\s+level\s+security/gi;
    for (const match of sqlCorpus.matchAll(rlsPattern)) if (match[1]) rlsTables.add(normalizeTable(match[1]));

    if (context.profile.baas.includes("Supabase")) {
      const createPattern = /create\s+table(?:\s+if\s+not\s+exists)?\s+([\w."`]+)\s*\(/gi;
      for (const file of sqlFiles) {
        for (const match of file.content.matchAll(createPattern)) {
          const table = normalizeTable(match[1] ?? "unknown");
          if (table.startsWith("auth.") || table.startsWith("storage.") || rlsTables.has(table)) continue;
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.table-without-rls",
            title: `Supabase table ${table} is created without enabling RLS`,
            description: "The migration creates an application table, but no matching ENABLE ROW LEVEL SECURITY statement was found in the scanned migrations.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
            cwe: ["CWE-862"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization"],
            remediation: `Enable RLS on ${table} and add explicit least-privilege SELECT/INSERT/UPDATE/DELETE policies for authenticated roles.`,
            metadata: { table },
          }))) break;
        }

        const permissivePolicy = /create\s+policy[\s\S]{0,500}?(?:using|with\s+check)\s*\(\s*true\s*\)/gi;
        for (const match of truncated ? [] : file.content.matchAll(permissivePolicy)) {
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.permissive-rls-policy",
            title: "Supabase RLS policy unconditionally allows access",
            description: "A policy uses USING (true) or WITH CHECK (true), which may grant every member of the target role access to every row.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
            cwe: ["CWE-863"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization"],
            remediation: "Bind policy predicates to auth.uid(), tenant membership, or another server-controlled ownership claim.",
          }))) break;
        }
        if (truncated) break;
      }
    }

    const firebaseFiles = context.inventory.files.filter((file) => /(?:firestore|storage)\.rules$/.test(file.relativePath));
    for (const file of truncated ? [] : firebaseFiles) {
      const openRule = /allow\s+(?:read|write|read\s*,\s*write|create|update|delete)(?:\s*,\s*\w+)*\s*:\s*if\s+true\s*;/gi;
      for (const match of file.content.matchAll(openRule)) {
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "firebase.unconditional-access",
          title: "Firebase security rule grants unconditional access",
          description: "The matching resource can be accessed without authentication or ownership checks.",
          severity: "critical",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, match.index ?? 0, match[0])],
          cwe: ["CWE-862"],
          owasp: ["A01:2021"],
          tags: ["firebase", "baas", "authorization"],
          remediation: "Require request.auth and enforce ownership or tenant membership for each operation and path.",
        }))) break;
      }
    }

    const relevant = context.profile.baas.length > 0;
    const missingConfiguration: string[] = [];
    if (context.profile.baas.includes("Supabase") && sqlFiles.length === 0) missingConfiguration.push("Supabase detected but no SQL migrations were available");
    if (context.profile.baas.includes("Firebase") && firebaseFiles.length === 0) missingConfiguration.push("Firebase detected but no Firestore/Storage rules were available");
    return {
      signals,
      coverage: {
        domain: "baas-authorization",
        engine: "aisec-native",
        status: relevant ? (missingConfiguration.length > 0 || truncated ? "partial" : "complete") : "not_run",
        required: relevant,
        reason: relevant ? [...missingConfiguration, truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined].filter(Boolean).join("; ") || undefined : "No supported BaaS configuration detected",
        durationMs: Date.now() - started,
      },
    };
  },
};
