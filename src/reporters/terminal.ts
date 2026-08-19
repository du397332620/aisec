import type { FixContract, ScanReport } from "../schema.js";

const ICON = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" } as const;

export function renderTerminalReport(report: ScanReport): string {
  const stack = [...new Set([...report.profile.frameworks, ...report.profile.baas, ...report.profile.mobilePlatforms])];
  const policy = report.policy?.source === "operator"
    ? `${report.policy.policyId} · sha256:${report.policy.digestSha256?.slice(0, 12)}… · expires ${report.policy.expiresAt}`
    : report.policy ? "trusted defaults" : "not recorded by this report producer";
  const lines = [
    `AIsec ${report.toolVersion} — ${report.decision.toUpperCase()}`,
    `Target: ${report.target}`,
    `Scan:   ${report.scanId}`,
    `Policy: ${policy}`,
    ...(report.policy?.suppressionCount ? [`Policy suppressions: ${report.policy.suppressionCount} · ${report.policy.suppressionApproval}`] : []),
    ...(report.policy?.targetConfiguration === "ignored" ? ["Target policy: ignored (target-owned configuration is untrusted)"] : []),
    ...(report.policy?.relaxations.length ? [`Relaxations: ${report.policy.relaxations.join(", ")}`] : []),
    `Rule packs: ${(report.rulePacks ?? []).length > 0
      ? (report.rulePacks ?? []).map((pack) => `${pack.packId} sha256:${pack.digestSha256.slice(0, 12)}… (${pack.ruleCount})`).join(", ")
      : "none"}`,
    `Stack:  ${stack.join(", ") || "unclassified"}`,
    `Risk:   ${report.summary.critical} critical · ${report.summary.high} high · ${report.summary.medium} medium · ${report.summary.low} low`,
    "",
  ];
  if (report.attackPaths.length > 0) {
    lines.push("Attack paths");
    for (const attackPath of report.attackPaths) {
      lines.push(`  [${ICON[attackPath.severity]}] ${attackPath.title} (${attackPath.evidenceLevel})`);
      lines.push(`    ${attackPath.summary}`);
    }
    lines.push("");
  }
  const open = report.findings.filter((finding) => finding.status === "open");
  if (open.length > 0) {
    lines.push("Findings");
    for (const finding of open.slice(0, 50)) {
      const firstSignal = report.signals.find((signal) => signal.id === finding.signalIds[0]);
      const location = firstSignal?.locations[0];
      lines.push(`  [${ICON[finding.severity]}] ${finding.id} ${finding.title}`);
      if (location) lines.push(`    ${location.path}${location.line ? `:${location.line}` : ""} · ${finding.evidenceLevel}`);
    }
    if (open.length > 50) lines.push(`  … ${open.length - 50} additional findings are available in JSON/HTML output.`);
    lines.push("");
  } else {
    lines.push("No open findings in the executed coverage.", "");
  }
  lines.push("Coverage");
  for (const item of report.coverage) {
    lines.push(`  ${item.status.padEnd(8)} ${item.domain} (${item.engine})${item.reason ? ` — ${item.reason}` : ""}`);
  }
  if (report.comparison) {
    lines.push("", `Baseline ${report.comparison.baselineScanId}: ${report.comparison.new.length} new · ${report.comparison.remaining.length} remaining · ${report.comparison.resolved.length} resolved · ${report.comparison.notRechecked.length} not rechecked`);
  }
  lines.push("", `Decision: ${report.decision}`, ...report.decisionReasons.map((reason) => `  - ${reason}`), "", report.disclaimer);
  return lines.join("\n");
}

export function renderFixContract(contract: FixContract): string {
  return [
    `Fix contract ${contract.contractId}`,
    contract.title,
    "",
    contract.agentPrompt,
  ].join("\n");
}
