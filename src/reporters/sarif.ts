import type { ScanReport } from "../schema.js";

export function renderSarif(report: ScanReport): object {
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; help: { text: string } }>();
  for (const signal of report.signals) {
    if (!rules.has(signal.ruleId)) rules.set(signal.ruleId, {
      id: signal.ruleId,
      name: signal.ruleId,
      shortDescription: { text: signal.title },
      help: { text: signal.remediation ?? signal.description },
    });
  }
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "AIsec", semanticVersion: report.toolVersion, informationUri: "https://github.com/aisec/aisec", rules: [...rules.values()] } },
      properties: {
        decision: report.decision,
        policySource: report.policy?.source ?? "not_recorded",
        policyId: report.policy?.policyId,
        policyDigestSha256: report.policy?.digestSha256,
        targetConfiguration: report.policy?.targetConfiguration,
        policySuppressionCount: report.policy?.suppressionCount ?? 0,
        policySuppressionApproval: report.policy?.suppressionApproval ?? "not_recorded",
        policyRelaxations: report.policy?.relaxations ?? [],
      },
      results: report.signals.map((signal) => ({
        ruleId: signal.ruleId,
        level: signal.severity === "critical" || signal.severity === "high" ? "error" : signal.severity === "medium" ? "warning" : "note",
        message: { text: `${signal.title}: ${signal.description}` },
        partialFingerprints: { "aisec/v1": signal.fingerprint },
        locations: signal.locations.map((location) => ({
          physicalLocation: {
            artifactLocation: { uri: location.path },
            region: { startLine: location.line ?? 1, startColumn: location.column ?? 1, endLine: location.endLine },
          },
        })),
        properties: { severity: signal.severity, evidenceLevel: signal.evidenceLevel, engine: signal.engine, tags: signal.tags },
      })),
    }],
  };
}
