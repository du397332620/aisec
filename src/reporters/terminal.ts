import type { FixContract, ScanReport } from "../schema.js";
import { partitionFindingGroups } from "./finding-groups.js";
import { buildRouteSecurityReview, ROUTE_SECURITY_CATEGORY_LABELS } from "./route-security-cards.js";
import { safeRelativePath, singleLine } from "./safety.js";

const ICON = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", info: "INFO" } as const;
const MAX_GROUPS = 20;
const MAX_GROUP_MEMBERS = 3;
const MAX_ROUTE_CARDS = 20;
const MAX_ROUTE_EVIDENCE = 3;
const MAX_DEPLOYMENT_CONTEXTS = 5;

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
  const routeSecurity = buildRouteSecurityReview(report, open);
  if (routeSecurity.cards.length > 0 || routeSecurity.deploymentContexts.length > 0) {
    lines.push("Route security review");
    lines.push("  Evidence-only summary: shown categories are detected gaps; an absent category is not a passed control.");
    if (routeSecurity.deploymentContexts.length > 0) {
      lines.push("  Project deployment context (not attributed to a specific route)");
      for (const context of routeSecurity.deploymentContexts.slice(0, MAX_DEPLOYMENT_CONTEXTS)) {
        const location = context.signal.locations[0];
        const path = safeRelativePath(location?.path) ?? "path not recorded";
        const service = context.service ? `service ${singleLine(context.service, 120)}` : "service not recorded";
        const ports = context.publishedPorts.length > 0 ? `ports ${singleLine(context.publishedPorts.join(", "), 160)}` : "ports not recorded";
        const findingIds = singleLine(context.findings.map((finding) => finding.id).join(", "), 260);
        lines.push(`    [${ICON[context.severity]}] ${singleLine(context.signal.title, 200)}`);
        lines.push(`      ${service} · ${ports} · ${path}${location?.line ? `:${location.line}` : ""} · ${findingIds}`);
      }
      if (routeSecurity.deploymentContexts.length > MAX_DEPLOYMENT_CONTEXTS) {
        lines.push(`    … ${routeSecurity.deploymentContexts.length - MAX_DEPLOYMENT_CONTEXTS} additional deployment contexts are available in JSON/HTML output.`);
      }
    }
    for (const card of routeSecurity.cards.slice(0, MAX_ROUTE_CARDS)) {
      const findingLabel = card.findingCount === 1 ? "finding" : "findings";
      const signalLabel = card.signalCount === 1 ? "signal" : "signals";
      const categories = card.categories.map((category) => ROUTE_SECURITY_CATEGORY_LABELS[category]).join(", ");
      lines.push(`  [${ICON[card.severity]}] ${card.framework} · ${singleLine(card.route, 500)}`);
      lines.push(`    ${categories} · ${card.signalCount} ${signalLabel} · ${card.findingCount} ${findingLabel}`);
      for (const evidence of card.evidence.slice(0, MAX_ROUTE_EVIDENCE)) {
        const location = evidence.signal.locations[0];
        const path = safeRelativePath(location?.path) ?? "path not recorded";
        const handler = evidence.handler ? ` · ${singleLine(evidence.handler, 160)}` : "";
        const findingIds = singleLine(evidence.findings.map((finding) => finding.id).join(", "), 260);
        lines.push(`    - ${ROUTE_SECURITY_CATEGORY_LABELS[evidence.category]}: ${singleLine(evidence.signal.title, 200)}`);
        lines.push(`      ${path}${location?.line ? `:${location.line}` : ""}${handler} · ${findingIds}`);
      }
      if (card.evidence.length > MAX_ROUTE_EVIDENCE) {
        lines.push(`    … ${card.evidence.length - MAX_ROUTE_EVIDENCE} additional route evidence entries remain in the finding views.`);
      }
    }
    if (routeSecurity.cards.length > MAX_ROUTE_CARDS) {
      lines.push(`  … ${routeSecurity.cards.length - MAX_ROUTE_CARDS} additional route cards are available in HTML output.`);
    }
    if (routeSecurity.omittedRouteAliases > 0 || routeSecurity.omittedAssociations > 0) {
      lines.push(`  Presentation bounds omitted ${routeSecurity.omittedRouteAliases} route aliases and ${routeSecurity.omittedAssociations} route-evidence associations; canonical findings remain unchanged.`);
    }
    lines.push("");
  }
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
