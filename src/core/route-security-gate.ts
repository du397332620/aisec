import type {
  Finding,
  RouteSecurityBaselineGate,
  RouteSecurityComparisonEntry,
  ScanComparison,
  Signal,
} from "../schema.js";
import { SEVERITY_RANK } from "./constants.js";
import {
  buildRouteSecuritySnapshotFromEvidence,
  compareRouteSecurityEntries,
  routeSecurityIssueKey,
} from "./route-security.js";

export interface RouteSecurityBaselineGateEvaluation {
  blockingEntries: RouteSecurityComparisonEntry[];
  blockingFindingFingerprints: string[];
  incompleteReason?: string;
}

function incompleteComparisonReason(comparison: NonNullable<ScanComparison["routeSecurity"]>): string {
  return `Route-security baseline comparison is partial: ${comparison.notRechecked.length} not rechecked, ${comparison.omittedRouteAliases} route aliases omitted, ${comparison.omittedAssociations} associations omitted`;
}

export function evaluateRouteSecurityBaselineGate(
  signals: readonly Signal[],
  findings: readonly Finding[],
  comparison: ScanComparison | undefined,
  gate: RouteSecurityBaselineGate | undefined,
): RouteSecurityBaselineGateEvaluation {
  if (!gate) return { blockingEntries: [], blockingFindingFingerprints: [] };
  const routeComparison = comparison?.routeSecurity;
  if (!routeComparison) {
    return {
      blockingEntries: [],
      blockingFindingFingerprints: [],
      incompleteReason: "Route-security baseline gate requires a baseline comparison; persist a baseline scan, then run aisec rescan",
    };
  }

  const eligibleFindings = findings.filter((finding) => finding.status === "open"
    && (gate.includeInferred || finding.evidenceLevel !== "inferred"));
  const snapshot = buildRouteSecuritySnapshotFromEvidence(signals, eligibleFindings);
  const newIdentities = new Set(routeComparison.new.map(routeSecurityIssueKey));
  const blockingIssues = snapshot.issues.filter((issue) => newIdentities.has(routeSecurityIssueKey(issue.entry))
    && SEVERITY_RANK[issue.entry.severity] >= SEVERITY_RANK[gate.minimumSeverity]);
  const blockingSignalIds = new Set(blockingIssues.flatMap((issue) => issue.signalIds));
  const blockingFindingFingerprints = eligibleFindings
    .filter((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[gate.minimumSeverity]
      && finding.signalIds.some((signalId) => blockingSignalIds.has(signalId)))
    .map((finding) => finding.fingerprint)
    .sort();

  return {
    blockingEntries: blockingIssues.map((issue) => ({ ...issue.entry })).sort(compareRouteSecurityEntries),
    blockingFindingFingerprints: [...new Set(blockingFindingFingerprints)],
    ...(gate.requireComplete && !routeComparison.complete
      ? { incompleteReason: incompleteComparisonReason(routeComparison) }
      : {}),
  };
}
