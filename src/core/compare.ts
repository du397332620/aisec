import type { RouteSecurityComparison, ScanComparison, ScanReport, Signal } from "../schema.js";
import {
  buildRouteSecuritySnapshot,
  compareRouteSecurityEntries,
  routeSecurityIssueKey,
  ROUTE_SECURITY_RULES,
} from "./route-security.js";

function coverageComplete(report: ScanReport, domain: string): boolean {
  return report.coverage.some((item) => item.domain === domain && item.status === "complete");
}

function signalWasRechecked(current: ScanReport, signal: Signal): boolean {
  const routeRule = ROUTE_SECURITY_RULES[signal.ruleId];
  if (routeRule) return coverageComplete(current, routeRule.coverageDomain);
  if (signal.engine === "trivy") return coverageComplete(current, "dependencies-iac");
  if (signal.engine === "gitleaks") return coverageComplete(current, "secrets-history");
  if (signal.engine === "opengrep") return coverageComplete(current, "sast-general");
  if (signal.engine === "aisec-artifact") return coverageComplete(current, "mobile-artifact-static");
  if (signal.engine === "aisec-typescript") return coverageComplete(current, "js-ts-dataflow");
  if (signal.engine === "aisec-rule-pack") {
    const packId = typeof signal.metadata?.rulePackId === "string" ? signal.metadata.rulePackId : undefined;
    return Boolean(packId && coverageComplete(current, `rule-pack:${packId}`));
  }
  if (signal.engine === "aisec-native") {
    if (signal.tags.includes("supabase") || signal.tags.includes("firebase") || signal.tags.includes("baas")) return coverageComplete(current, "baas-authorization");
    if (signal.tags.some((tag) => ["mobile", "android", "ios", "flutter", "react-native"].includes(tag))) return coverageComplete(current, "mobile-source-config");
    if (signal.tags.includes("secret") && signal.ruleId.startsWith("secret.")) return coverageComplete(current, "secrets");
    return coverageComplete(current, "application-config");
  }
  return false;
}

function compareRouteSecurity(current: ScanReport, baseline: ScanReport): RouteSecurityComparison {
  const previousSnapshot = buildRouteSecuritySnapshot(baseline);
  const currentSnapshot = buildRouteSecuritySnapshot(current);
  const previous = new Map(previousSnapshot.issues.map((issue) => [routeSecurityIssueKey(issue.entry), issue]));
  const now = new Map(currentSnapshot.issues.map((issue) => [routeSecurityIssueKey(issue.entry), issue]));
  const baselineSnapshotComplete = previousSnapshot.omittedRouteAliases === 0 && previousSnapshot.omittedAssociations === 0;
  const currentSnapshotComplete = currentSnapshot.omittedRouteAliases === 0 && currentSnapshot.omittedAssociations === 0;
  const newEntries: RouteSecurityComparison["new"] = [];
  const remaining: RouteSecurityComparison["remaining"] = [];
  const resolved: RouteSecurityComparison["resolved"] = [];
  const notRechecked: RouteSecurityComparison["notRechecked"] = [];

  for (const [key, issue] of now) {
    if (previous.has(key)) remaining.push({ ...issue.entry });
    else if (baselineSnapshotComplete) newEntries.push({ ...issue.entry });
    else notRechecked.push({ ...issue.entry });
  }
  for (const [key, issue] of previous) {
    if (now.has(key)) continue;
    if (currentSnapshotComplete && issue.coverageDomains.every((domain) => coverageComplete(current, domain))) {
      resolved.push({ ...issue.entry });
    } else {
      notRechecked.push({ ...issue.entry });
    }
  }

  newEntries.sort(compareRouteSecurityEntries);
  remaining.sort(compareRouteSecurityEntries);
  resolved.sort(compareRouteSecurityEntries);
  notRechecked.sort(compareRouteSecurityEntries);
  const omittedRouteAliases = previousSnapshot.omittedRouteAliases + currentSnapshot.omittedRouteAliases;
  const omittedAssociations = previousSnapshot.omittedAssociations + currentSnapshot.omittedAssociations;
  return {
    complete: notRechecked.length === 0 && omittedRouteAliases === 0 && omittedAssociations === 0,
    omittedRouteAliases,
    omittedAssociations,
    new: newEntries,
    remaining,
    resolved,
    notRechecked,
  };
}

export function compareReports(current: ScanReport, baseline: ScanReport): ScanComparison {
  const previous = new Map(baseline.findings
    .filter((finding) => finding.status === "open")
    .map((finding) => [finding.fingerprint, finding]));
  const now = new Map(current.findings
    .filter((finding) => finding.status === "open")
    .map((finding) => [finding.fingerprint, finding]));
  const newFindings = [...now.keys()].filter((fingerprint) => !previous.has(fingerprint));
  const remaining = [...now.keys()].filter((fingerprint) => previous.has(fingerprint));
  const uncheckedSignals = new Set(baseline.signals
    .filter((signal) => !signalWasRechecked(current, signal))
    .map((signal) => signal.id));
  const notRechecked = baseline.findings
    .filter((finding) => finding.status === "open" && finding.signalIds.some((id) => uncheckedSignals.has(id)) && !now.has(finding.fingerprint))
    .map((finding) => finding.fingerprint);
  const resolved = [...previous.keys()].filter((fingerprint) => !now.has(fingerprint) && !notRechecked.includes(fingerprint));
  return {
    baselineScanId: baseline.scanId,
    new: newFindings,
    remaining,
    resolved,
    notRechecked,
    routeSecurity: compareRouteSecurity(current, baseline),
  };
}
