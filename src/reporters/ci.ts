import type {
  CiAnnotation,
  CiBaselineState,
  CiPolicySummary,
  CiReport,
  CiRouteSecurityComparisonSummary,
  Finding,
  RouteSecurityComparison,
  ScanPolicyRecord,
  ScanReport,
  SecurityPolicyGate,
  Signal,
} from "../schema.js";
import { CI_REPORT_SCHEMA_VERSION } from "../schema.js";
import { SEVERITY_RANK } from "../core/constants.js";
import { validateCiReport, validateScanReport } from "../core/schema-validation.js";
import { githubData, githubProperty, markdownText, safeRelativePath, singleLine } from "./safety.js";
import { buildRouteSecurityReview, ROUTE_ATTRIBUTION_GAP_LABELS, ROUTE_SECURITY_CATEGORY_LABELS } from "./route-security-cards.js";

const DEFAULT_GATE: Readonly<SecurityPolicyGate> = {
  minimumSeverity: "high",
  includeInferred: false,
  requireNoSuppressions: false,
};
const MAX_COVERAGE_ANNOTATIONS = 20;
const MAX_FINDING_ANNOTATIONS = 50;
const MAX_ROUTE_COMPARISON_ENTRIES = 200;

function recommendedExitCode(decision: ScanReport["decision"]): 0 | 1 | 2 {
  if (decision === "block") return 1;
  if (decision === "incomplete") return 2;
  return 0;
}

function policySummary(policy: ScanPolicyRecord | undefined): CiPolicySummary {
  if (!policy) {
    return {
      source: "not_recorded",
      targetConfiguration: "not_recorded",
      requiredEngines: [],
      suppressionCount: 0,
      suppressionApproval: "not_recorded",
      relaxations: [],
    };
  }
  return {
    source: policy.source,
    targetConfiguration: policy.targetConfiguration,
    ...(policy.policyId ? { policyId: policy.policyId } : {}),
    ...(policy.digestSha256 ? { digestSha256: policy.digestSha256 } : {}),
    ...(policy.expiresAt ? { expiresAt: policy.expiresAt } : {}),
    gate: { ...policy.gate },
    requiredEngines: [...policy.requiredEngines],
    suppressionCount: policy.suppressionCount,
    suppressionApproval: policy.suppressionApproval,
    relaxations: [...policy.relaxations],
  };
}

function findingSignals(report: ScanReport, finding: Finding): Signal[] {
  const ids = new Set(finding.signalIds);
  return report.signals.filter((signal) => ids.has(signal.id));
}

function findingBlocksRelease(report: ScanReport, finding: Finding, signals: Signal[]): boolean {
  const policy = report.policy;
  const blockingRuleIds = new Set(policy?.blockingRuleIds ?? []);
  if (signals.some((signal) => blockingRuleIds.has(signal.ruleId))) return true;
  if (finding.status === "suppressed") return policy?.gate.requireNoSuppressions === true;
  const gate = policy?.gate ?? DEFAULT_GATE;
  return SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[gate.minimumSeverity]
    && (gate.includeInferred || finding.evidenceLevel !== "inferred");
}

function findingBaselineState(report: ScanReport, finding: Finding): CiBaselineState | undefined {
  if (report.comparison?.new.includes(finding.fingerprint)) return "new";
  if (report.comparison?.remaining.includes(finding.fingerprint)) return "unchanged";
  return undefined;
}

function findingAnnotation(report: ScanReport, finding: Finding): CiAnnotation {
  const signals = findingSignals(report, finding);
  const signal = signals[0];
  const location = signals.flatMap((item) => item.locations).find((item) => safeRelativePath(item.path));
  const path = safeRelativePath(location?.path);
  const blocksRelease = findingBlocksRelease(report, finding, signals);
  const level = blocksRelease ? "error" : SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.medium ? "warning" : "notice";
  const ruleIds = [...new Set(signals.map((item) => item.ruleId))].slice(0, 5).join(", ");
  const description = signal?.description ?? report.attackPaths.find((item) => item.id === finding.attackPathId)?.summary ?? "Correlated security evidence";
  return {
    kind: "finding",
    level,
    title: singleLine(finding.title, 200, "AIsec finding"),
    message: singleLine(`${finding.severity}/${finding.evidenceLevel}/${finding.status}${ruleIds ? ` · ${ruleIds}` : ""} · ${description}`, 2000, "AIsec finding"),
    ...(path ? { path } : {}),
    ...(path && location?.line ? { startLine: location.line } : {}),
    ...(path && location?.column ? { startColumn: location.column } : {}),
    ...(path && location?.endLine ? { endLine: location.endLine } : {}),
    findingId: finding.id,
    fingerprint: finding.fingerprint,
    severity: finding.severity,
    evidenceLevel: finding.evidenceLevel,
    findingStatus: finding.status,
    blocksRelease,
    ...(findingBaselineState(report, finding) ? { baselineState: findingBaselineState(report, finding) } : {}),
  };
}

function findingPriority(report: ScanReport, finding: Finding): [number, number, number, string] {
  const signals = findingSignals(report, finding);
  const blocks = findingBlocksRelease(report, finding, signals) ? 1 : 0;
  const isNew = report.comparison?.new.includes(finding.fingerprint) ? 1 : 0;
  return [blocks, isNew, SEVERITY_RANK[finding.severity], finding.title];
}

function routeSecurityComparisonSummary(comparison: RouteSecurityComparison | undefined): CiRouteSecurityComparisonSummary {
  if (!comparison) {
    return {
      recorded: false,
      complete: false,
      new: 0,
      remaining: 0,
      resolved: 0,
      notRechecked: 0,
      omittedRouteAliases: 0,
      omittedAssociations: 0,
      entries: [],
      omittedEntries: 0,
    };
  }
  const allEntries = [
    ...comparison.new.map((entry) => ({ ...entry, state: "new" as const })),
    ...comparison.notRechecked.map((entry) => ({ ...entry, state: "not_rechecked" as const })),
    ...comparison.resolved.map((entry) => ({ ...entry, state: "resolved" as const })),
    ...comparison.remaining.map((entry) => ({ ...entry, state: "remaining" as const })),
  ];
  return {
    recorded: true,
    complete: comparison.complete,
    new: comparison.new.length,
    remaining: comparison.remaining.length,
    resolved: comparison.resolved.length,
    notRechecked: comparison.notRechecked.length,
    omittedRouteAliases: comparison.omittedRouteAliases,
    omittedAssociations: comparison.omittedAssociations,
    entries: allEntries.slice(0, MAX_ROUTE_COMPARISON_ENTRIES),
    omittedEntries: Math.max(0, allEntries.length - MAX_ROUTE_COMPARISON_ENTRIES),
  };
}

export function buildCiReport(report: ScanReport): CiReport {
  validateScanReport(report);
  const routeSecurity = buildRouteSecurityReview(report);
  const requiredCoverage = report.coverage.filter((item) => item.required);
  const gaps = requiredCoverage.filter((item) => item.status !== "complete").map((item) => ({
    domain: singleLine(item.domain, 200, "unknown-domain"),
    engine: singleLine(item.engine, 200, "unknown-engine"),
    status: item.status as "partial" | "not_run" | "failed",
    ...(item.reason ? { reason: singleLine(item.reason, 1000) } : {}),
  }));
  const decisionLevel = report.decision === "block" || report.decision === "incomplete"
    ? "error"
    : report.decision === "review" ? "warning" : "notice";
  const decisionReasons = report.decisionReasons.slice(0, 64).map((reason) => singleLine(reason, 1000));
  const annotations: CiAnnotation[] = [{
    kind: "decision",
    level: decisionLevel,
    title: `AIsec decision: ${report.decision}`,
    message: singleLine(decisionReasons.join("; "), 2000, report.decision),
  }];
  for (const gap of gaps.slice(0, MAX_COVERAGE_ANNOTATIONS)) {
    annotations.push({
      kind: "coverage",
      level: "error",
      title: singleLine(`Required coverage ${gap.status}: ${gap.domain}`, 200),
      message: singleLine(`${gap.engine}${gap.reason ? ` · ${gap.reason}` : ""}`, 2000),
    });
  }

  const candidates = report.findings
    .filter((finding) => finding.status === "open" || findingBlocksRelease(report, finding, findingSignals(report, finding)))
    .sort((left, right) => {
      const a = findingPriority(report, left);
      const b = findingPriority(report, right);
      return b[0] - a[0] || b[1] - a[1] || b[2] - a[2] || a[3].localeCompare(b[3]);
    });
  for (const finding of candidates.slice(0, MAX_FINDING_ANNOTATIONS)) annotations.push(findingAnnotation(report, finding));

  const ciReport: CiReport = {
    schemaVersion: CI_REPORT_SCHEMA_VERSION,
    toolVersion: report.toolVersion,
    scanId: report.scanId,
    profileName: report.profileName,
    decision: report.decision,
    recommendedExitCode: recommendedExitCode(report.decision),
    decisionReasons,
    counts: {
      ...report.summary,
      open: report.summary.critical + report.summary.high + report.summary.medium + report.summary.low + report.summary.info,
    },
    requiredCoverage: {
      total: requiredCoverage.length,
      complete: requiredCoverage.length - gaps.length,
      gaps,
    },
    policy: policySummary(report.policy),
    rulePacks: (report.rulePacks ?? []).map((pack) => ({ ...pack })),
    routeAttribution: {
      eligibleSignals: routeSecurity.attribution.eligibleSignals,
      attributedSignals: routeSecurity.attribution.attributedSignals,
      unattributedSignals: routeSecurity.attribution.unattributedSignals,
      unattributedFindings: routeSecurity.attribution.unattributedFindings,
      reasons: routeSecurity.attribution.reasons.map((reason) => ({ ...reason })),
    },
    ...(report.comparison ? {
      comparison: {
        baselineScanId: report.comparison.baselineScanId,
        new: report.comparison.new.length,
        remaining: report.comparison.remaining.length,
        resolved: report.comparison.resolved.length,
        notRechecked: report.comparison.notRechecked.length,
        routeSecurity: routeSecurityComparisonSummary(report.comparison.routeSecurity),
      },
    } : {}),
    annotations,
    omitted: {
      coverageAnnotations: Math.max(0, gaps.length - MAX_COVERAGE_ANNOTATIONS),
      findingAnnotations: Math.max(0, candidates.length - MAX_FINDING_ANNOTATIONS),
    },
    disclaimer: singleLine(report.disclaimer, 2000),
  };
  return validateCiReport(ciReport);
}

export function renderGithubAnnotations(report: CiReport): string {
  validateCiReport(report);
  return `${report.annotations.map((annotation) => {
    const properties = [`title=${githubProperty(annotation.title)}`];
    if (annotation.path) properties.push(`file=${githubProperty(annotation.path)}`);
    if (annotation.startLine) properties.push(`line=${annotation.startLine}`);
    if (annotation.endLine) properties.push(`endLine=${annotation.endLine}`);
    if (annotation.startColumn) properties.push(`col=${annotation.startColumn}`);
    if (annotation.endColumn) properties.push(`endColumn=${annotation.endColumn}`);
    return `::${annotation.level} ${properties.join(",")}::${githubData(annotation.message)}`;
  }).join("\n")}\n`;
}

export function renderMarkdownSummary(report: CiReport): string {
  validateCiReport(report);
  const lines = [
    "# AIsec security acceptance",
    "",
    `**Decision:** ${markdownText(report.decision, 80)}  `,
    `**Scan:** ${markdownText(report.scanId, 100)}  `,
    `**Profile:** ${markdownText(report.profileName, 40)}  `,
    `**Risk:** ${report.counts.critical} critical · ${report.counts.high} high · ${report.counts.medium} medium · ${report.counts.low} low · ${report.counts.info} info`,
    "",
    "## Decision reasons",
    "",
    ...report.decisionReasons.map((reason) => `- ${markdownText(reason, 1000)}`),
    "",
    "## Required coverage",
    "",
  ];
  if (report.requiredCoverage.gaps.length === 0) lines.push(`All ${report.requiredCoverage.total} required coverage records are complete.`);
  else {
    lines.push("| Domain | Engine | Status | Reason |", "| --- | --- | --- | --- |");
    for (const gap of report.requiredCoverage.gaps) {
      lines.push(`| ${markdownText(gap.domain, 200)} | ${markdownText(gap.engine, 200)} | ${markdownText(gap.status, 40)} | ${markdownText(gap.reason ?? "not recorded", 1000)} |`);
    }
  }
  lines.push("", "## Route attribution", "");
  if (!report.routeAttribution) lines.push("Route-attribution evidence was not recorded by this legacy CI report producer.");
  else if (report.routeAttribution.eligibleSignals === 0) lines.push("No FastAPI dangerous-dataflow signals were eligible for route attribution.");
  else {
    lines.push(`${report.routeAttribution.attributedSignals} of ${report.routeAttribution.eligibleSignals} eligible signals have proven routes; ${report.routeAttribution.unattributedSignals} signals across ${report.routeAttribution.unattributedFindings} findings remain unattributed.`);
    if (report.routeAttribution.reasons.length > 0) {
      lines.push("", "| Unattributed reason | Signals |", "| --- | ---: |");
      for (const reason of report.routeAttribution.reasons) {
        lines.push(`| ${markdownText(ROUTE_ATTRIBUTION_GAP_LABELS[reason.reason], 120)} | ${reason.signals} |`);
      }
    }
  }
  lines.push("", "## Policy", "");
  if (report.policy.source === "not_recorded") lines.push("Policy evidence was not recorded by this legacy report producer.");
  else {
    lines.push(`- Source: ${markdownText(report.policy.source, 40)}`);
    if (report.policy.policyId) lines.push(`- Policy ID: ${markdownText(report.policy.policyId, 128)}`);
    if (report.policy.digestSha256) lines.push(`- SHA-256: ${markdownText(report.policy.digestSha256, 64)}`);
    if (report.policy.expiresAt) lines.push(`- Expires: ${markdownText(report.policy.expiresAt, 80)}`);
    lines.push(`- Target configuration: ${markdownText(report.policy.targetConfiguration, 40)}`);
    if (report.policy.gate) {
      lines.push(`- Gate: ${markdownText(report.policy.gate.minimumSeverity, 20)} or higher; inferred ${report.policy.gate.includeInferred ? "included" : "excluded"}; suppressions ${report.policy.gate.requireNoSuppressions ? "block" : "allowed"}`);
    }
    lines.push(`- Required engines: ${report.policy.requiredEngines.length > 0 ? report.policy.requiredEngines.map((item) => markdownText(item, 40)).join(", ") : "none"}`);
    lines.push(`- Suppressions: ${report.policy.suppressionCount} \(${markdownText(report.policy.suppressionApproval, 40)}\)`);
    if (report.policy.relaxations.length > 0) lines.push(`- Relaxations: ${report.policy.relaxations.map((item) => markdownText(item, 80)).join(", ")}`);
  }
  const rulePacks = report.rulePacks ?? [];
  lines.push("", "## Declarative rule packs", "");
  if (rulePacks.length === 0) lines.push("None.");
  else {
    for (const pack of rulePacks) {
      lines.push(`- ${markdownText(pack.packId, 80)} · SHA-256 ${markdownText(pack.digestSha256, 64)} · ${pack.ruleCount} rule(s)`);
    }
  }
  if (report.comparison) {
    lines.push("", "## Baseline comparison", "", `Baseline ${markdownText(report.comparison.baselineScanId, 100)}: ${report.comparison.new} new · ${report.comparison.remaining} remaining · ${report.comparison.resolved} resolved · ${report.comparison.notRechecked} not rechecked`);
    const routeComparison = report.comparison.routeSecurity;
    lines.push("", "### Route security comparison", "");
    if (!routeComparison?.recorded) {
      lines.push("Route-security comparison evidence was not recorded by this legacy report producer.");
    } else {
      lines.push(`${routeComparison.new} newly observed · ${routeComparison.remaining} remaining · ${routeComparison.resolved} resolved · ${routeComparison.notRechecked} not rechecked · ${routeComparison.complete ? "complete" : "partial"}`);
      if (routeComparison.entries.length > 0) {
        lines.push("", "| State | Risk | Framework | Route | Observed gap |", "| --- | --- | --- | --- | --- |");
        for (const entry of routeComparison.entries) {
          lines.push(`| ${markdownText(entry.state, 40)} | ${markdownText(entry.severity, 20)} | ${markdownText(entry.framework, 40)} | ${markdownText(entry.route, 512)} | ${markdownText(ROUTE_SECURITY_CATEGORY_LABELS[entry.category], 120)} |`);
        }
      }
      if (routeComparison.omittedEntries > 0 || routeComparison.omittedRouteAliases > 0 || routeComparison.omittedAssociations > 0) {
        lines.push("", `_Route comparison omissions: ${routeComparison.omittedEntries} CI entries · ${routeComparison.omittedRouteAliases} route aliases · ${routeComparison.omittedAssociations} associations._`);
      }
    }
  }
  const findings = report.annotations.filter((item) => item.kind === "finding");
  lines.push("", "## Findings", "");
  if (findings.length === 0) lines.push("No finding annotations were emitted.");
  else {
    lines.push("| Level | Finding | Location | Evidence | Baseline |", "| --- | --- | --- | --- | --- |");
    for (const finding of findings) {
      const location = finding.path ? `${finding.path}${finding.startLine ? `:${finding.startLine}` : ""}` : "not recorded";
      lines.push(`| ${markdownText(finding.level, 20)} | ${markdownText(finding.title, 200)} | ${markdownText(location, 1100)} | ${markdownText(`${finding.severity}/${finding.evidenceLevel}/${finding.findingStatus}`, 120)} | ${markdownText(finding.baselineState ?? "not compared", 40)} |`);
    }
  }
  if (report.omitted.coverageAnnotations || report.omitted.findingAnnotations) {
    lines.push("", `_Omitted annotations: ${report.omitted.coverageAnnotations} coverage · ${report.omitted.findingAnnotations} findings._`);
  }
  lines.push("", `> ${markdownText(report.disclaimer, 2000)}`, "");
  return lines.join("\n");
}
