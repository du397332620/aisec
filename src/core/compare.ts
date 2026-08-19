import type { ScanComparison, ScanReport } from "../schema.js";

export function compareReports(current: ScanReport, baseline: ScanReport): ScanComparison {
  const previous = new Map(baseline.findings
    .filter((finding) => finding.status === "open")
    .map((finding) => [finding.fingerprint, finding]));
  const now = new Map(current.findings
    .filter((finding) => finding.status === "open")
    .map((finding) => [finding.fingerprint, finding]));
  const newFindings = [...now.keys()].filter((fingerprint) => !previous.has(fingerprint));
  const remaining = [...now.keys()].filter((fingerprint) => previous.has(fingerprint));
  const coverageComplete = (domain: string): boolean => current.coverage.some((item) => item.domain === domain && item.status === "complete");
  const uncheckedSignals = new Set(baseline.signals
    .filter((signal) => {
      if (signal.engine === "trivy") return !coverageComplete("dependencies-iac");
      if (signal.engine === "gitleaks") return !coverageComplete("secrets-history");
      if (signal.engine === "opengrep") return !coverageComplete("sast-general");
      if (signal.engine === "aisec-artifact") return !coverageComplete("mobile-artifact-static");
      if (signal.engine === "aisec-typescript") return !coverageComplete("js-ts-dataflow");
      if (signal.engine === "aisec-rule-pack") {
        const packId = typeof signal.metadata?.rulePackId === "string" ? signal.metadata.rulePackId : undefined;
        return !packId || !coverageComplete(`rule-pack:${packId}`);
      }
      if (signal.engine === "aisec-native") {
        if (signal.tags.includes("supabase") || signal.tags.includes("firebase") || signal.tags.includes("baas")) return !coverageComplete("baas-authorization");
        if (signal.tags.some((tag) => ["mobile", "android", "ios", "flutter", "react-native"].includes(tag))) return !coverageComplete("mobile-source-config");
        if (signal.tags.includes("secret") && signal.ruleId.startsWith("secret.")) return !coverageComplete("secrets");
        return !coverageComplete("application-config");
      }
      return true;
    })
    .map((signal) => signal.id));
  const notRechecked = baseline.findings
    .filter((finding) => finding.status === "open" && finding.signalIds.some((id) => uncheckedSignals.has(id)) && !now.has(finding.fingerprint))
    .map((finding) => finding.fingerprint);
  const resolved = [...previous.keys()].filter((fingerprint) => !now.has(fingerprint) && !notRechecked.includes(fingerprint));
  return { baselineScanId: baseline.scanId, new: newFindings, remaining, resolved, notRechecked };
}
