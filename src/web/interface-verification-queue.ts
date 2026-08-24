import { SEVERITY_RANK } from "../core/constants.js";
import { ROUTE_SECURITY_RULES, routeSecurityAliases } from "../core/route-security.js";
import { validateInterfaceVerificationQueue } from "../core/schema-validation.js";
import { loadReport } from "../core/store.js";
import { stableId } from "../core/utils.js";
import { buildRouteSecurityReview, type RouteSecurityCard, type RouteSecurityEvidence } from "../reporters/route-security-cards.js";
import { safeRelativePath } from "../reporters/safety.js";
import {
  INTERFACE_VERIFICATION_QUEUE_SCHEMA_VERSION,
  type Finding,
  type InterfaceVerificationCandidate,
  type InterfaceVerificationExclusion,
  type InterfaceVerificationExclusionReason,
  type InterfaceVerificationQueue,
  type InterfaceVerificationRequiredReview,
  type InterfaceVerificationSource,
  type ScanReport,
  type Severity,
  type Signal,
} from "../schema.js";
import { classifyBolaStaticRoute } from "./bola-policy.js";

const ROUTE = /^([A-Z]+)\s+(\/\S+)$/u;
const IDENTIFIER = /^[A-Za-z_]\w*$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const MAX_ROUTE_ENTRIES = 100;
const MAX_SOURCES_PER_CANDIDATE = 20;
const MAX_IDS_PER_ENTRY = 20;

const EXCLUSION_REASON_ORDER: readonly InterfaceVerificationExclusionReason[] = [
  "no_open_finding",
  "no_open_object_authorization_finding",
  "unsupported_verification_category",
  "mutation_semantics",
  "ambiguous_read_semantics",
  "unproven_route_source",
  "missing_object_identifier",
];

function parseRoute(route: string): { method: string; path: string } {
  const match = ROUTE.exec(route);
  if (!match?.[1] || !match[2]) throw new Error(`Route-security card contains an invalid route: ${route}`);
  return { method: match[1], path: match[2] };
}

function identifiers(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => (
    typeof item === "string" && item.length <= 100 && IDENTIFIER.test(item)
  )))].sort();
}

function safeHandler(value: unknown): string | undefined {
  if (typeof value !== "string" || value !== value.trim() || !value || value.length > 300 || CONTROL_CHARACTER.test(value)) return undefined;
  return value;
}

function openFindings(evidence: RouteSecurityEvidence): Finding[] {
  return evidence.findings.filter((finding) => finding.status === "open");
}

function uniqueFindings(evidence: readonly RouteSecurityEvidence[], openOnly: boolean): Finding[] {
  return [...new Map(evidence
    .flatMap((item) => item.findings)
    .filter((finding) => !openOnly || finding.status === "open")
    .map((finding) => [finding.id, finding])).values()]
    .sort((left, right) => left.id.localeCompare(right.id));
}

function highestSeverity(findings: readonly Finding[], fallback: Severity): Severity {
  return findings.reduce<Severity>((highest, finding) => (
    SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest
  ), fallback);
}

function sourceLocation(signal: Signal): InterfaceVerificationSource["location"] | undefined {
  for (const location of signal.locations) {
    const path = safeRelativePath(location.path);
    if (!path) continue;
    return {
      path,
      ...(location.line === undefined ? {} : { line: location.line }),
      ...(location.column === undefined ? {} : { column: location.column }),
    };
  }
  return undefined;
}

function exactSource(
  evidence: RouteSecurityEvidence,
  card: RouteSecurityCard,
): InterfaceVerificationSource | undefined {
  const presentation = ROUTE_SECURITY_RULES[evidence.signal.ruleId];
  if (presentation?.category !== "object_authorization" || presentation.framework !== card.framework) return undefined;
  if (!routeSecurityAliases(evidence.signal).routes.includes(card.route)) return undefined;
  const handler = safeHandler(evidence.signal.metadata?.handler);
  const location = sourceLocation(evidence.signal);
  const findings = openFindings(evidence);
  if (!handler || !location || findings.length === 0) return undefined;
  const findingIds = [...new Set(findings.map((finding) => finding.id))].sort();
  return {
    signalId: evidence.signal.id,
    ruleId: evidence.signal.ruleId,
    fingerprint: evidence.signal.fingerprint,
    evidenceLevel: evidence.signal.evidenceLevel,
    handler,
    objectIdFields: identifiers(evidence.signal.metadata?.objectIdFields),
    openFindingIds: findingIds.slice(0, MAX_IDS_PER_ENTRY),
    omittedOpenFindingIds: Math.max(0, findingIds.length - MAX_IDS_PER_ENTRY),
    location,
  };
}

function compareRouteEntries(
  left: Pick<InterfaceVerificationCandidate, "severity" | "framework" | "route">,
  right: Pick<InterfaceVerificationCandidate, "severity" | "framework" | "route">,
): number {
  return SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.framework.localeCompare(right.framework)
    || left.route.localeCompare(right.route);
}

function candidateFor(card: RouteSecurityCard): {
  candidate?: InterfaceVerificationCandidate;
  exclusion?: InterfaceVerificationExclusion;
  omittedSourceRecords: number;
  omittedFindingIds: number;
} {
  const { method, path } = parseRoute(card.route);
  const objectEvidence = card.evidence.filter((evidence) => evidence.category === "object_authorization");
  const openObjectEvidence = objectEvidence.filter((evidence) => openFindings(evidence).length > 0);
  const exactSources = [...new Map(openObjectEvidence
    .map((evidence) => exactSource(evidence, card))
    .filter((source): source is InterfaceVerificationSource => Boolean(source))
    .map((source) => [source.signalId, source])).values()]
    .sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.signalId.localeCompare(right.signalId));
  const objectIdFields = [...new Set(exactSources.flatMap((source) => source.objectIdFields))].sort();
  const routeClassification = classifyBolaStaticRoute(method, path);
  const reasons: InterfaceVerificationExclusionReason[] = [];

  if (!card.hasOpenFinding) reasons.push("no_open_finding");
  if (objectEvidence.length === 0) reasons.push("unsupported_verification_category");
  else if (openObjectEvidence.length === 0) reasons.push("no_open_object_authorization_finding");
  if (routeClassification.classification === "mutation_excluded") reasons.push("mutation_semantics");
  else if (routeClassification.classification === "manual_review") reasons.push("ambiguous_read_semantics");
  if (openObjectEvidence.length > 0 && exactSources.length === 0) reasons.push("unproven_route_source");
  if (openObjectEvidence.length > 0 && exactSources.length > 0 && objectIdFields.length === 0) reasons.push("missing_object_identifier");

  const orderedReasons = EXCLUSION_REASON_ORDER.filter((reason) => reasons.includes(reason));
  if (orderedReasons.length === 0) {
    if (method !== "GET" && method !== "POST") throw new Error(`Read-compatible route used an unsupported method: ${method}`);
    const sources = exactSources.slice(0, MAX_SOURCES_PER_CANDIDATE);
    const omittedSources = exactSources.length - sources.length;
    const requiredReviews: InterfaceVerificationRequiredReview[] = [
      "confirm_route_and_fixture_match",
      "confirm_response_evidence",
      ...(method === "POST" ? ["confirm_post_read_only" as const] : []),
    ];
    return {
      candidate: {
        id: stableId("interface_candidate", card.framework, card.route, "two_account_object_read"),
        framework: card.framework,
        route: card.route,
        method,
        path,
        severity: highestSeverity(uniqueFindings(openObjectEvidence, true), card.severity),
        categories: [...card.categories],
        verification: "two_account_object_read",
        methodPolicy: method === "GET" ? "safe_get" : "reviewed_read_post",
        eligibility: [
          "open_object_authorization_finding",
          "exact_route_provenance",
          "bola_read_compatible",
          "recorded_object_identifier",
        ],
        objectIdFields,
        sourceCount: exactSources.length,
        sources,
        omittedSources,
        requiredReviews,
      },
      omittedSourceRecords: omittedSources,
      omittedFindingIds: exactSources.reduce((total, source) => total + source.omittedOpenFindingIds, 0),
    };
  }

  const allSignalIds = [...new Set(card.evidence.map((evidence) => evidence.signal.id))].sort();
  const allOpenFindingIds = uniqueFindings(card.evidence, true).map((finding) => finding.id);
  return {
    exclusion: {
      id: stableId("interface_exclusion", card.framework, card.route),
      framework: card.framework,
      route: card.route,
      method,
      path,
      severity: card.severity,
      categories: [...card.categories],
      reasons: orderedReasons,
      signalCount: allSignalIds.length,
      signalIds: allSignalIds.slice(0, MAX_IDS_PER_ENTRY),
      omittedSignals: Math.max(0, allSignalIds.length - MAX_IDS_PER_ENTRY),
      openFindingCount: allOpenFindingIds.length,
      openFindingIds: allOpenFindingIds.slice(0, MAX_IDS_PER_ENTRY),
      omittedOpenFindings: Math.max(0, allOpenFindingIds.length - MAX_IDS_PER_ENTRY),
    },
    omittedSourceRecords: Math.max(0, allSignalIds.length - MAX_IDS_PER_ENTRY),
    omittedFindingIds: Math.max(0, allOpenFindingIds.length - MAX_IDS_PER_ENTRY),
  };
}

export function createInterfaceVerificationQueue(report: ScanReport): InterfaceVerificationQueue {
  const review = buildRouteSecurityReview(report);
  const evaluated = review.cards.map(candidateFor);
  const allCandidates = evaluated.flatMap((entry) => entry.candidate ? [entry.candidate] : []).sort(compareRouteEntries);
  const allExclusions = evaluated.flatMap((entry) => entry.exclusion ? [entry.exclusion] : []).sort(compareRouteEntries);
  const candidates = allCandidates.slice(0, MAX_ROUTE_ENTRIES);
  const exclusions = allExclusions.slice(0, MAX_ROUTE_ENTRIES);
  const omittedCandidates = allCandidates.length - candidates.length;
  const omittedExclusions = allExclusions.length - exclusions.length;
  const omittedSourceRecords = evaluated.reduce((total, entry) => total + entry.omittedSourceRecords, 0);
  const omittedFindingIds = evaluated.reduce((total, entry) => total + entry.omittedFindingIds, 0);
  const exclusionReasons = EXCLUSION_REASON_ORDER.flatMap((reason) => {
    const routes = allExclusions.filter((entry) => entry.reasons.includes(reason)).length;
    return routes > 0 ? [{ reason, routes }] : [];
  });
  const isPartial = review.omittedRouteAliases > 0
    || review.omittedAssociations > 0
    || omittedCandidates > 0
    || omittedExclusions > 0
    || omittedSourceRecords > 0
    || omittedFindingIds > 0;
  const limitations = [
    "Static route evidence cannot prove reachability, exploitability, deployed behavior or operational read-only semantics.",
    "Only two-account object-read preparation is eligible; other interface-security categories remain static findings for manual review.",
    ...(review.omittedRouteAliases > 0 ? [`${review.omittedRouteAliases} route alias(es) were omitted by the source review bound.`] : []),
    ...(review.omittedAssociations > 0 ? [`${review.omittedAssociations} route association(s) were omitted by the source review bound.`] : []),
    ...(omittedCandidates > 0 ? [`${omittedCandidates} eligible route detail(s) were omitted by the 100-candidate output bound.`] : []),
    ...(omittedExclusions > 0 ? [`${omittedExclusions} excluded route detail(s) were omitted by the 100-exclusion output bound.`] : []),
    ...(omittedSourceRecords > 0 ? [`${omittedSourceRecords} source record(s) were omitted by per-route output bounds.`] : []),
    ...(omittedFindingIds > 0 ? [`${omittedFindingIds} finding ID reference(s) were omitted by per-source output bounds.`] : []),
  ];

  return validateInterfaceVerificationQueue({
    schemaVersion: INTERFACE_VERIFICATION_QUEUE_SCHEMA_VERSION,
    queueId: stableId(
      "interface_queue",
      report.scanId,
      ...allCandidates.map((candidate) => candidate.id),
      ...allExclusions.map((exclusion) => exclusion.id),
    ),
    scanId: report.scanId,
    projectId: report.profile.projectId,
    generatedAt: new Date().toISOString(),
    status: "review_required",
    coverage: isPartial ? "partial" : "complete",
    coverageScope: "observed_route_cards_only",
    networkRequests: 0,
    summary: {
      reviewedRoutes: review.cards.length,
      eligibleRoutes: allCandidates.length,
      excludedRoutes: allExclusions.length,
      emittedCandidates: candidates.length,
      omittedCandidates,
      emittedExclusions: exclusions.length,
      omittedExclusions,
      omittedSourceRecords,
      omittedFindingIds,
      sourceOmissions: {
        routeAliases: review.omittedRouteAliases,
        associations: review.omittedAssociations,
      },
      exclusionReasons,
    },
    candidates,
    exclusions,
    prerequisites: [
      "authorized_non_production_target",
      "two_distinct_low_privilege_accounts",
      "precreated_synthetic_owner_object",
      "exact_object_id_no_enumeration",
      "review_response_evidence",
      "manual_manifest_review_and_confirm",
    ],
    limitations,
    nextCommand: "aisec draft-bola --scan <same-scan-id-or-report.json> --output bola-draft.json",
    disclaimer: "This is a bounded static planning queue, not an authorization manifest or vulnerability confirmation. It performs no network requests and cannot prove that an endpoint is safe, reachable or exploitable.",
  });
}

export async function interfaceVerificationQueue(reference: string): Promise<InterfaceVerificationQueue> {
  return createInterfaceVerificationQueue(await loadReport(reference));
}
