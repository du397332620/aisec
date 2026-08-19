import { DEFAULT_POLICY_GATE } from "./config.js";
import type { AttackPath, CoverageRecord, Decision, Finding, PolicySuppression, ScanPolicyRecord, ScanSummary, Signal } from "../schema.js";
import { SEVERITY_RANK } from "./constants.js";

export function buildFindings(signals: Signal[], attackPaths: AttackPath[], suppressions: readonly PolicySuppression[] = []): Finding[] {
  const signalById = new Map(signals.map((signal) => [signal.id, signal]));
  const consumed = new Set(attackPaths.flatMap((attackPath) => attackPath.signalIds.filter((signalId) => {
    const signal = signalById.get(signalId);
    // A lower-confidence correlation must never hide stronger component evidence.
    return attackPath.evidenceLevel !== "inferred" || signal?.evidenceLevel === "inferred";
  })));
  const findingsByFingerprint = new Map<string, Finding>();
  const addFinding = (finding: Finding): void => {
    const existing = findingsByFingerprint.get(finding.fingerprint);
    if (!existing) {
      findingsByFingerprint.set(finding.fingerprint, finding);
      return;
    }
    existing.signalIds = [...new Set([...existing.signalIds, ...finding.signalIds])];
  };
  for (const attackPath of attackPaths) {
    addFinding({
      id: `finding_${attackPath.fingerprint.slice(0, 16)}`,
      fingerprint: attackPath.fingerprint,
      title: attackPath.title,
      severity: attackPath.severity,
      evidenceLevel: attackPath.evidenceLevel,
      status: "open",
      signalIds: attackPath.signalIds,
      attackPathId: attackPath.id,
    });
  }
  for (const signal of signals.filter((candidate) => !consumed.has(candidate.id))) {
    const fingerprint = signal.fingerprint;
    addFinding({
      id: `finding_${fingerprint.slice(0, 16)}`,
      fingerprint,
      title: signal.title,
      severity: signal.severity,
      evidenceLevel: signal.evidenceLevel,
      status: "open",
      signalIds: [signal.id],
    });
  }

  const findings = [...findingsByFingerprint.values()];

  const now = Date.now();
  for (const finding of findings) {
    const suppression = suppressions.find((item) => item.fingerprint === finding.fingerprint
      && Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(item.expires) ? `${item.expires}T23:59:59.999Z` : item.expires) > now);
    if (suppression) {
      finding.status = "suppressed";
      finding.suppression = { reason: suppression.reason, expires: suppression.expires };
    }
  }
  return findings.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.title.localeCompare(b.title));
}

export function decide(findings: Finding[], coverage: CoverageRecord[], signals: Signal[] = [], policy?: ScanPolicyRecord): { decision: Decision; reasons: string[] } {
  const signalById = new Map(signals.map((signal) => [signal.id, signal]));
  const blockingRuleIds = new Set(policy?.blockingRuleIds ?? []);
  const selectedRuleBlockers = blockingRuleIds.size === 0 ? [] : findings.filter((finding) => finding.signalIds.some((id) => {
    const ruleId = signalById.get(id)?.ruleId;
    return ruleId !== undefined && blockingRuleIds.has(ruleId);
  }));
  if (selectedRuleBlockers.length > 0) {
    return { decision: "block", reasons: [`${selectedRuleBlockers.length} finding(s) matched policy blocking rules`] };
  }
  const suppressed = findings.filter((finding) => finding.status === "suppressed");
  if (policy?.gate.requireNoSuppressions && suppressed.length > 0) {
    return { decision: "block", reasons: [`${suppressed.length} suppression(s) violate the policy no-suppression gate`] };
  }
  const open = findings.filter((finding) => finding.status === "open");
  const gate = policy?.gate ?? DEFAULT_POLICY_GATE;
  const blockers = open.filter((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK[gate.minimumSeverity]
    && (gate.includeInferred || finding.evidenceLevel !== "inferred"));
  if (blockers.length > 0) {
    const reason = policy?.source === "operator"
      ? `${blockers.length} finding(s) met policy gate severity ${gate.minimumSeverity}${gate.includeInferred ? " including inferred evidence" : " with evidence-backed results only"}`
      : `${blockers.length} high or critical evidence-backed finding(s)`;
    return { decision: "block", reasons: [reason] };
  }
  const incomplete = coverage.filter((item) => item.required && ["failed", "not_run", "partial"].includes(item.status));
  if (incomplete.length > 0) return { decision: "incomplete", reasons: incomplete.map((item) => `${item.domain}: ${item.status}${item.reason ? ` (${item.reason})` : ""}`) };
  const reviews = open.filter((finding) => SEVERITY_RANK[finding.severity] >= SEVERITY_RANK.medium);
  if (reviews.length > 0) return { decision: "review", reasons: [`${reviews.length} medium-risk or inferred finding(s) require review`] };
  return { decision: "no_blockers_found", reasons: ["No blocking findings were detected within the completed coverage"] };
}

export function summarize(findings: Finding[], attackPaths: AttackPath[]): ScanSummary {
  const open = findings.filter((finding) => finding.status === "open");
  return {
    critical: open.filter((finding) => finding.severity === "critical").length,
    high: open.filter((finding) => finding.severity === "high").length,
    medium: open.filter((finding) => finding.severity === "medium").length,
    low: open.filter((finding) => finding.severity === "low").length,
    info: open.filter((finding) => finding.severity === "info").length,
    attackPaths: attackPaths.length,
    suppressed: findings.length - open.length,
  };
}
