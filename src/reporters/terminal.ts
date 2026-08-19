import type { FixContract, ScanReport } from "../schema.js";
import { partitionFindingGroups } from "./finding-groups.js";
import { safeRelativePath, singleLine } from "./safety.js";

const ICON = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" } as const;
const MAX_GROUPS = 20;
const MAX_GROUP_MEMBERS = 3;

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
  const { groups, ungrouped } = partitionFindingGroups(report, open);
  if (groups.length > 0) {
    lines.push("Grouped findings");
    for (const group of groups.slice(0, MAX_GROUPS)) {
      const path = safeRelativePath(group.path) ?? "path not recorded";
      const findingLabel = group.findingCount === 1 ? "finding" : "findings";
      lines.push(`  [${ICON[group.severity]}] ${singleLine(group.title, 200)}`);
      lines.push(`    ${path} · ${group.members.length} occurrences · ${group.findingCount} ${findingLabel} · ${group.handlers.length} handlers · ${group.routes.length} routes`);
      if (group.patterns.length > 0) lines.push(`    Patterns: ${singleLine(group.patterns.join(", "), 240)}`);
      for (const member of group.members.slice(0, MAX_GROUP_MEMBERS)) {
        const route = member.routes.length > 0 ? member.routes.join(", ") : "route not recorded";
        const detail = [route, member.handler, member.location.line ? `line ${member.location.line}` : undefined, member.finding.id].filter(Boolean).join(" · ");
        lines.push(`    - ${singleLine(detail, 420)}`);
      }
      if (group.members.length > MAX_GROUP_MEMBERS) {
        lines.push(`    … ${group.members.length - MAX_GROUP_MEMBERS} additional grouped occurrences are available in JSON/HTML output.`);
      }
    }
    if (groups.length > MAX_GROUPS) lines.push(`  … ${groups.length - MAX_GROUPS} additional groups are available in JSON/HTML output.`);
    lines.push("");
  }
  if (ungrouped.length > 0) {
    lines.push("Findings");
    for (const finding of ungrouped.slice(0, 50)) {
      const firstSignal = report.signals.find((signal) => signal.id === finding.signalIds[0]);
      const location = firstSignal?.locations[0];
      lines.push(`  [${ICON[finding.severity]}] ${finding.id} ${finding.title}`);
      if (location) lines.push(`    ${location.path}${location.line ? `:${location.line}` : ""} · ${finding.evidenceLevel}`);
    }
    if (ungrouped.length > 50) lines.push(`  … ${ungrouped.length - 50} additional findings are available in JSON/HTML output.`);
    lines.push("");
  } else if (groups.length === 0) {
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
