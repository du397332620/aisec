import type { Finding, ScanReport, Signal } from "../schema.js";
import { buildCiReport } from "./ci.js";
import { sarifArtifactUri, singleLine } from "./safety.js";

function sarifLevel(severity: Signal["severity"]): "error" | "warning" | "note" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function baselineState(report: ScanReport, finding: Finding | undefined): "new" | "unchanged" | undefined {
  if (!finding || !report.comparison) return undefined;
  if (report.comparison.new.includes(finding.fingerprint)) return "new";
  if (report.comparison.remaining.includes(finding.fingerprint)) return "unchanged";
  return undefined;
}

export function renderSarif(report: ScanReport): object {
  const ci = buildCiReport(report);
  const findingBySignal = new Map<string, Finding>();
  for (const finding of report.findings) {
    for (const signalId of finding.signalIds) if (!findingBySignal.has(signalId)) findingBySignal.set(signalId, finding);
  }
  const rules = new Map<string, {
    id: string;
    name: string;
    shortDescription: { text: string };
    help: { text: string };
    properties: { tags: string[] };
  }>();
  for (const signal of report.signals) {
    if (!rules.has(signal.ruleId)) rules.set(signal.ruleId, {
      id: signal.ruleId,
      name: signal.ruleId,
      shortDescription: { text: singleLine(signal.title, 500, signal.ruleId) },
      help: { text: singleLine(signal.remediation ?? signal.description, 4000, "Review the AIsec evidence and apply a constrained fix.") },
      properties: { tags: [...new Set([...signal.tags, ...(signal.cwe ?? [])])] },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      automationDetails: { id: report.scanId },
      tool: {
        driver: {
          name: "AIsec",
          semanticVersion: report.toolVersion,
          informationUri: "https://github.com/du397332620/aisec",
          rules: [...rules.values()],
        },
      },
      invocations: [{
        executionSuccessful: true,
        properties: {
          decision: report.decision,
          recommendedExitCode: ci.recommendedExitCode,
          requiredCoverageTotal: ci.requiredCoverage.total,
          requiredCoverageComplete: ci.requiredCoverage.complete,
        },
      }],
      properties: {
        decision: report.decision,
        decisionReasons: ci.decisionReasons,
        policySource: ci.policy.source,
        ...(ci.policy.policyId ? { policyId: ci.policy.policyId } : {}),
        ...(ci.policy.digestSha256 ? { policyDigestSha256: ci.policy.digestSha256 } : {}),
        targetConfiguration: ci.policy.targetConfiguration,
        policySuppressionCount: ci.policy.suppressionCount,
        policySuppressionApproval: ci.policy.suppressionApproval,
        policyRelaxations: ci.policy.relaxations,
        ...(ci.policy.routeSecurityBaseline ? { routeSecurityBaselineGate: ci.policy.routeSecurityBaseline } : {}),
        rulePacks: ci.rulePacks ?? [],
        requiredCoverageGaps: ci.requiredCoverage.gaps,
        ...(ci.comparison ? { comparison: ci.comparison } : {}),
      },
      results: report.signals.map((signal) => {
        const finding = findingBySignal.get(signal.id);
        const state = baselineState(report, finding);
        const locations = signal.locations.flatMap((location) => {
          const uri = sarifArtifactUri(location.path);
          if (!uri) return [];
          return [{
            physicalLocation: {
              artifactLocation: { uri },
              region: {
                startLine: location.line ?? 1,
                startColumn: location.column ?? 1,
                ...(location.endLine && location.endLine >= (location.line ?? 1) ? { endLine: location.endLine } : {}),
              },
            },
          }];
        });
        return {
          ruleId: signal.ruleId,
          level: sarifLevel(signal.severity),
          message: { text: singleLine(`${signal.title}: ${signal.description}`, 4000, signal.ruleId) },
          partialFingerprints: {
            "aisecSignal/v1": signal.fingerprint,
            ...(finding ? { "aisecFinding/v1": finding.fingerprint } : {}),
          },
          ...(state ? { baselineState: state } : {}),
          ...(finding?.status === "suppressed" ? {
            suppressions: [{
              kind: "external",
              status: "accepted",
              justification: singleLine(finding.suppression?.reason ?? "Suppressed by the explicit operator policy", 1000),
            }],
          } : {}),
          ...(locations.length > 0 ? { locations } : {}),
          properties: {
            severity: signal.severity,
            evidenceLevel: signal.evidenceLevel,
            engine: signal.engine,
            tags: signal.tags,
            signalFingerprint: signal.fingerprint,
            ...(finding ? {
              findingId: finding.id,
              findingFingerprint: finding.fingerprint,
              findingStatus: finding.status,
            } : {}),
          },
        };
      }),
    }],
  };
}
