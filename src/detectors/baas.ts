import type { Detector } from "./types.js";
import { createSignal, makeLocation } from "../core/utils.js";
import type { Signal } from "../schema.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import {
  analyzeFirebaseRules,
  analyzeSupabaseSql,
  supabasePolicyIsAuthenticationOnly,
  supabasePolicyIsUnconditional,
  supabasePolicyUsesUserMetadata,
} from "./baas-policy.js";

const MAX_BAAS_COVERAGE_REASONS = 50;

function tableHasRls(table: string, rlsTables: Set<string>): boolean {
  const unqualified = table.split(".").at(-1) ?? table;
  if (rlsTables.has(table) || rlsTables.has(unqualified)) return true;
  if (!table.includes(".")) return rlsTables.has(`public.${table}`);
  return false;
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
    const partialReasons: string[] = [];
    const sqlFiles = context.inventory.files.filter((file) => file.relativePath.endsWith(".sql"));
    const sqlAnalyses = sqlFiles.map((file) => ({ file, analysis: analyzeSupabaseSql(file.content) }));
    const rlsTables = new Set(sqlAnalyses.flatMap(({ analysis }) => analysis.rlsTables));

    if (context.profile.baas.includes("Supabase")) {
      for (const { file, analysis } of sqlAnalyses) {
        partialReasons.push(...analysis.partialReasons.map((reason) => `${file.relativePath}: ${reason}`));
        for (const declaration of analysis.createdTables) {
          const table = declaration.table;
          if (table.startsWith("auth.") || table.startsWith("storage.") || tableHasRls(table, rlsTables)) continue;
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.table-without-rls",
            title: `Supabase table ${table} is created without enabling RLS`,
            description: "The migration creates an application table, but no matching ENABLE ROW LEVEL SECURITY statement was found in the scanned migrations.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, declaration.start, declaration.text)],
            cwe: ["CWE-862"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization"],
            remediation: `Enable RLS on ${table} and add explicit least-privilege SELECT/INSERT/UPDATE/DELETE policies for authenticated roles.`,
            metadata: { table },
          }))) break;
        }
        for (const policy of truncated ? [] : analysis.policies) {
          if (!supabasePolicyIsUnconditional(policy)) continue;
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.permissive-rls-policy",
            title: "Supabase RLS policy unconditionally allows access",
            description: "A policy uses USING (true) or WITH CHECK (true), which may grant every member of the target role access to every row.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, policy.start, policy.text)],
            cwe: ["CWE-863"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization"],
            remediation: "Bind policy predicates to auth.uid(), tenant membership, or another server-controlled ownership claim.",
            metadata: { table: policy.table, command: policy.command, roles: policy.roles.join(",") },
          }))) break;
        }
        for (const policy of truncated ? [] : analysis.policies) {
          if (!supabasePolicyIsAuthenticationOnly(policy)) continue;
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.authenticated-policy-without-row-filter",
            title: `Supabase policy on ${policy.table} authenticates callers without filtering rows`,
            description: "A permissive client policy proves only that the caller is signed in; it does not bind access to a row owner, tenant or other row-specific authorization value. Other permissive policies cannot narrow it because applicable permissive policies compose with OR.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, policy.start, policy.text)],
            cwe: ["CWE-862"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization", "multi-tenant"],
            remediation: "Add an owner, membership or tenant predicate tied to auth.uid() or trusted app_metadata; review every permissive policy for the same role and command because they compose with OR.",
            metadata: { table: policy.table, command: policy.command, roles: policy.roles.join(",") },
          }))) break;
        }
        for (const policy of truncated ? [] : analysis.policies) {
          if (!supabasePolicyUsesUserMetadata(policy)) continue;
          if (!add(createSignal({
            engine: "aisec-native",
            ruleId: "supabase.user-metadata-authorization",
            title: `Supabase policy on ${policy.table} trusts user-editable JWT metadata`,
            description: "The policy derives authorization from user_metadata/raw_user_meta_data exposed through auth.jwt(). Authenticated users can modify that metadata, so it is not a trusted role, owner or tenant claim.",
            severity: "high",
            evidenceLevel: "static_confirmed",
            confidence: "high",
            locations: [makeLocation(file.relativePath, file.content, policy.start, policy.text)],
            cwe: ["CWE-863"],
            owasp: ["A01:2021"],
            tags: ["supabase", "database", "authorization", "multi-tenant"],
            remediation: "Move authorization claims to server-controlled app_metadata or a protected membership table, bind them to the row tenant, and require token refresh when memberships change.",
            metadata: { table: policy.table, command: policy.command, roles: policy.roles.join(",") },
          }))) break;
        }
        if (truncated) break;
      }
    }

    const firebaseFiles = context.inventory.files.filter((file) => /(?:firestore|storage)\.rules$/.test(file.relativePath));
    for (const file of truncated ? [] : firebaseFiles) {
      const analysis = analyzeFirebaseRules(file.content);
      partialReasons.push(...analysis.partialReasons.map((reason) => `${file.relativePath}: ${reason}`));
      for (const allow of analysis.allows) {
        if (!allow.unconditional) continue;
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "firebase.unconditional-access",
          title: "Firebase security rule grants unconditional access",
          description: "The matching resource can be accessed without authentication or ownership checks.",
          severity: "critical",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, allow.start, allow.text)],
          cwe: ["CWE-862"],
          owasp: ["A01:2021"],
          tags: ["firebase", "baas", "authorization"],
          remediation: "Require request.auth and enforce ownership or tenant membership for each operation and path.",
          metadata: { service: analysis.service, methods: allow.methods.join(",") },
        }))) break;
      }
      for (const allow of truncated ? [] : analysis.allows) {
        if (!allow.authenticationOnly) continue;
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "firebase.authenticated-access-without-resource-check",
          title: "Firebase rule authenticates callers without authorizing the resource",
          description: "The allow condition proves only that the caller is signed in; it does not bind access to a document/file owner, path variable, tenant or protected entitlement. A narrower overlapping match cannot revoke this grant because matching allow expressions compose with OR.",
          severity: "high",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, allow.start, allow.text)],
          cwe: ["CWE-862"],
          owasp: ["A01:2021"],
          tags: ["firebase", "baas", "authorization", "multi-tenant"],
          remediation: "Require request.auth and compare request.auth.uid or a trusted custom claim with the matched path, existing resource, incoming resource or protected membership document.",
          metadata: { service: analysis.service, methods: allow.methods.join(",") },
        }))) break;
      }
      for (const allow of truncated ? [] : analysis.allows) {
        if (!allow.storageUploadWithoutSizeLimit) continue;
        if (!add(createSignal({
          engine: "aisec-native",
          ruleId: "firebase.storage-upload-without-size-limit",
          title: "Firebase Storage upload rule has no visible file-size ceiling",
          description: "A Storage create/update/write grant has no visible upper bound on request.resource.size, allowing authorized clients to consume excessive storage or processing resources within platform limits.",
          severity: "medium",
          evidenceLevel: "static_confirmed",
          confidence: "high",
          locations: [makeLocation(file.relativePath, file.content, allow.start, allow.text)],
          cwe: ["CWE-770"],
          tags: ["firebase", "storage", "authorization", "resource-limit"],
          remediation: "Add a strict request.resource.size upper bound appropriate for the path and validate contentType/file metadata where the application expects a constrained format.",
          metadata: { service: analysis.service, methods: allow.methods.join(",") },
        }))) break;
      }
    }

    const relevant = context.profile.baas.length > 0;
    const missingConfiguration: string[] = [];
    if (context.profile.baas.includes("Supabase") && sqlFiles.length === 0) missingConfiguration.push("Supabase detected but no SQL migrations were available");
    if (context.profile.baas.includes("Firebase") && firebaseFiles.length === 0) missingConfiguration.push("Firebase detected but no Firestore/Storage rules were available");
    const uniquePartialReasons = [...new Set(partialReasons)];
    const displayedPartialReasons = uniquePartialReasons.slice(0, MAX_BAAS_COVERAGE_REASONS);
    if (uniquePartialReasons.length > displayedPartialReasons.length) {
      displayedPartialReasons.push(`${uniquePartialReasons.length - displayedPartialReasons.length} additional BaaS coverage reason(s) omitted`);
    }
    return {
      signals,
      coverage: {
        domain: "baas-authorization",
        engine: "aisec-native",
        status: relevant ? (missingConfiguration.length > 0 || partialReasons.length > 0 || truncated ? "partial" : "complete") : "not_run",
        required: relevant,
        reason: relevant ? [...missingConfiguration, ...displayedPartialReasons, truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined].filter(Boolean).join("; ") || undefined : "No supported BaaS configuration detected",
        durationMs: Date.now() - started,
      },
    };
  },
};
