import { SEVERITY_RANK } from "../core/constants.js";
import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  ROUTE_SECURITY_CATEGORY_ORDER,
} from "../core/route-security.js";
import {
  validateInterfaceSecurityAudit,
  validateScanReport,
} from "../core/schema-validation.js";
import { reportPath } from "../core/store.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import {
  buildRouteSecurityReview,
  type RouteSecurityCard,
  type RouteSecurityEvidence,
} from "../reporters/route-security-cards.js";
import { safeRelativePath } from "../reporters/safety.js";
import {
  INTERFACE_SECURITY_AUDIT_SCHEMA_VERSION,
  type Finding,
  type InterfaceSecurityAudit,
  type InterfaceSecurityAuditEntry,
  type InterfaceSecurityAuditSource,
  type RouteSecurityCategory,
  type ScanReport,
  type Severity,
  type Signal,
} from "../schema.js";

const ROUTE = /^(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE|ALL)\s+(\/\S+)$/u;
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const MAX_ROUTE_CATEGORY_ENTRIES = 200;
const MAX_SOURCES_PER_ENTRY = 20;
const MAX_FINDING_IDS_PER_STATUS = 20;

export const MAX_INTERFACE_SECURITY_SCAN_REPORT_BYTES = 64 * 1024 * 1024;

interface EvaluatedEntry {
  entry: InterfaceSecurityAuditEntry;
  omittedSourceRecords: number;
  omittedFindingIdReferences: number;
  unlocatedSourceRecords: number;
}

function parseRoute(route: string): { method: string; path: string } {
  const match = ROUTE.exec(route);
  if (!match?.[1] || !match[2]) throw new Error(`Route-security card contains an invalid route: ${route}`);
  return { method: match[1], path: match[2] };
}

function safeHandler(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const handler = value.trim();
  return handler && !CONTROL_CHARACTER.test(handler) && [...handler].length <= 300
    ? handler
    : undefined;
}

function sourceLocation(signal: Signal): InterfaceSecurityAuditSource["location"] | undefined {
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

function uniqueFindings(evidence: readonly RouteSecurityEvidence[]): Finding[] {
  return [...new Map(evidence
    .flatMap((item) => item.findings)
    .map((finding) => [finding.id, finding])).values()];
}

function highestSeverity(findings: readonly Finding[]): Severity {
  const open = findings.filter((finding) => finding.status === "open");
  const candidates = open.length > 0 ? open : findings;
  return candidates.reduce<Severity>((highest, finding) => (
    SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest
  ), "info");
}

function exactSource(evidence: RouteSecurityEvidence): InterfaceSecurityAuditSource {
  const openFindingIds = [...new Set(evidence.findings
    .filter((finding) => finding.status === "open")
    .map((finding) => finding.id))].sort();
  const suppressedFindingIds = [...new Set(evidence.findings
    .filter((finding) => finding.status === "suppressed")
    .map((finding) => finding.id))].sort();
  const handler = safeHandler(evidence.handler);
  const location = sourceLocation(evidence.signal);
  return {
    signalId: evidence.signal.id,
    ruleId: evidence.signal.ruleId,
    fingerprint: evidence.signal.fingerprint,
    evidenceLevel: evidence.signal.evidenceLevel,
    ...(handler ? { handler } : {}),
    ...(location ? { location } : {}),
    openFindingIds: openFindingIds.slice(0, MAX_FINDING_IDS_PER_STATUS),
    omittedOpenFindingIds: Math.max(0, openFindingIds.length - MAX_FINDING_IDS_PER_STATUS),
    suppressedFindingIds: suppressedFindingIds.slice(0, MAX_FINDING_IDS_PER_STATUS),
    omittedSuppressedFindingIds: Math.max(0, suppressedFindingIds.length - MAX_FINDING_IDS_PER_STATUS),
  };
}

function evaluateEntry(
  report: ScanReport,
  card: RouteSecurityCard,
  category: RouteSecurityCategory,
): EvaluatedEntry {
  const { method, path } = parseRoute(card.route);
  const categoryEvidence = card.evidence.filter((evidence) => evidence.category === category);
  const exactSources = [...new Map(categoryEvidence
    .map(exactSource)
    .map((source) => [source.signalId, source])).values()]
    .sort((left, right) => left.ruleId.localeCompare(right.ruleId) || left.signalId.localeCompare(right.signalId));
  if (exactSources.length === 0) {
    throw new Error(`Route-security card lacks exact evidence for ${card.framework} ${card.route} ${category}`);
  }
  const findings = uniqueFindings(categoryEvidence);
  const hasOpenFinding = findings.some((finding) => finding.status === "open");
  const sources = exactSources.slice(0, MAX_SOURCES_PER_ENTRY);
  return {
    entry: {
      id: stableId("interface_audit_entry", report.scanId, card.framework, card.route, category),
      framework: card.framework,
      route: card.route,
      method,
      path,
      category,
      severity: highestSeverity(findings),
      findingStatus: hasOpenFinding ? "open" : "suppressed_only",
      sourceCount: exactSources.length,
      sources,
      omittedSources: exactSources.length - sources.length,
    },
    omittedSourceRecords: Math.max(0, exactSources.length - MAX_SOURCES_PER_ENTRY),
    omittedFindingIdReferences: exactSources.reduce((total, source) => (
      total + source.omittedOpenFindingIds + source.omittedSuppressedFindingIds
    ), 0),
    unlocatedSourceRecords: exactSources.filter((source) => !source.location).length,
  };
}

function compareEntries(left: InterfaceSecurityAuditEntry, right: InterfaceSecurityAuditEntry): number {
  return (left.findingStatus === right.findingStatus ? 0 : left.findingStatus === "open" ? -1 : 1)
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.framework.localeCompare(right.framework)
    || left.route.localeCompare(right.route)
    || ROUTE_SECURITY_CATEGORY_ORDER.indexOf(left.category) - ROUTE_SECURITY_CATEGORY_ORDER.indexOf(right.category);
}

export function createInterfaceSecurityAudit(reportValue: ScanReport): InterfaceSecurityAudit {
  const report = validateScanReport(reportValue);
  const review = buildRouteSecurityReview(report);
  const evaluated = review.cards
    .flatMap((card) => card.categories.map((category) => evaluateEntry(report, card, category)))
    .sort((left, right) => compareEntries(left.entry, right.entry));
  const allEntries = evaluated.map((item) => item.entry);
  const entries = allEntries.slice(0, MAX_ROUTE_CATEGORY_ENTRIES);
  const omittedEntries = allEntries.length - entries.length;
  const omittedSourceRecords = evaluated.reduce((total, item) => total + item.omittedSourceRecords, 0);
  const omittedFindingIdReferences = evaluated.reduce((total, item) => total + item.omittedFindingIdReferences, 0);
  const unlocatedSourceRecords = evaluated.reduce((total, item) => total + item.unlocatedSourceRecords, 0);
  const openEntries = allEntries.filter((entry) => entry.findingStatus === "open").length;
  const categories = ROUTE_SECURITY_CATEGORY_ORDER.flatMap((category) => {
    const matching = allEntries.filter((entry) => entry.category === category);
    return matching.length > 0 ? [{
      category,
      entries: matching.length,
      openEntries: matching.filter((entry) => entry.findingStatus === "open").length,
    }] : [];
  });
  const isPartial = review.omittedRouteAliases > 0
    || review.omittedAssociations > 0
    || omittedEntries > 0
    || omittedSourceRecords > 0
    || omittedFindingIdReferences > 0
    || unlocatedSourceRecords > 0
    || review.attribution.unattributedSignals > 0;
  const limitations = [
    "Only observed route evidence with exact static attribution is included; this is not complete API discovery.",
    "Static evidence cannot prove reachability, deployed behavior, exploitability or the absence of interface-security flaws.",
    "Deployment context is aggregate evidence and is never assigned to an individual route without source proof.",
    ...(review.omittedRouteAliases > 0 ? [`${review.omittedRouteAliases} route alias(es) were omitted by the source review bound.`] : []),
    ...(review.omittedAssociations > 0 ? [`${review.omittedAssociations} route association(s) were omitted by the source review bound.`] : []),
    ...(omittedEntries > 0 ? [`${omittedEntries} route-category entry detail(s) were omitted by the 200-entry output bound.`] : []),
    ...(omittedSourceRecords > 0 ? [`${omittedSourceRecords} source record(s) were omitted by the 20-source per-entry bound.`] : []),
    ...(omittedFindingIdReferences > 0 ? [`${omittedFindingIdReferences} finding ID reference(s) were omitted by per-source bounds.`] : []),
    ...(unlocatedSourceRecords > 0 ? [`${unlocatedSourceRecords} source record(s) lacked a safe relative location and were emitted without one.`] : []),
    ...(review.attribution.unattributedSignals > 0 ? [`${review.attribution.unattributedSignals} dangerous-dataflow signal(s) could not be attributed to a route.`] : []),
  ];
  const scanDigestSha256 = sha256(canonicalJson(report));

  return validateInterfaceSecurityAudit({
    schemaVersion: INTERFACE_SECURITY_AUDIT_SCHEMA_VERSION,
    auditId: stableId(
      "interface_audit",
      report.schemaVersion,
      report.scanId,
      report.profile.projectId,
      scanDigestSha256,
    ),
    generatedAt: new Date().toISOString(),
    status: "review_required",
    scan: {
      schemaVersion: report.schemaVersion,
      scanId: report.scanId,
      projectId: report.profile.projectId,
      digestSha256: scanDigestSha256,
    },
    coverage: isPartial ? "partial" : "complete",
    coverageScope: "observed_attributed_routes_only",
    networkRequests: 0,
    dnsLookups: 0,
    credentialEnvironmentReads: 0,
    targetCodeExecutions: 0,
    summary: {
      reviewedRoutes: review.cards.length,
      routeCategoryEntries: allEntries.length,
      openEntries,
      suppressedOnlyEntries: allEntries.length - openEntries,
      emittedEntries: entries.length,
      omittedEntries,
      omittedSourceRecords,
      omittedFindingIdReferences,
      unlocatedSourceRecords,
      sourceOmissions: {
        routeAliases: review.omittedRouteAliases,
        associations: review.omittedAssociations,
      },
      categories,
      attribution: {
        ...review.attribution,
        reasons: review.attribution.reasons.map((reason) => ({ ...reason })),
      },
      deploymentContexts: {
        observed: review.deploymentContexts.length,
        open: review.deploymentContexts.filter((context) => context.hasOpenFinding).length,
      },
    },
    entries,
    limitations,
    disclaimer: "This local ledger summarizes bounded static evidence for human review; it is not a vulnerability confirmation, exploitability proof, active test result or assurance that an endpoint is safe. Generation performs no network requests or target-code execution.",
  });
}

export async function loadInterfaceSecurityScanReport(reference: string): Promise<ScanReport> {
  const path = reference.endsWith(".json") || reference.includes("/")
    ? reference
    : reportPath(reference);
  const text = await readBoundedUtf8File(
    path,
    MAX_INTERFACE_SECURITY_SCAN_REPORT_BYTES,
    "Interface security scan report",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("Interface security scan report must be valid JSON");
  }
  return validateScanReport(parsed);
}

export async function interfaceSecurityAudit(reference: string): Promise<InterfaceSecurityAudit> {
  return createInterfaceSecurityAudit(await loadInterfaceSecurityScanReport(reference));
}
