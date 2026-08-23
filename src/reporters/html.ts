import type { Finding, ScanReport, Signal } from "../schema.js";
import { buildCiReport } from "./ci.js";
import { partitionFindingGroups } from "./finding-groups.js";
import { buildRouteSecurityReview, ROUTE_ATTRIBUTION_GAP_LABELS, ROUTE_SECURITY_CATEGORY_LABELS, type RouteSecurityEvidence } from "./route-security-cards.js";
import { safeRelativePath, singleLine } from "./safety.js";

const MAX_HTML_ROUTE_CARDS = 500;
const MAX_HTML_ROUTE_EVIDENCE = 50;
const MAX_HTML_DEPLOYMENT_CONTEXTS = 50;
const MAX_HTML_ROUTE_ATTRIBUTION_GAPS = 200;
const MAX_HTML_ROUTE_COMPARISON_ENTRIES = 500;

function escape(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function comparisonState(report: ScanReport, fingerprint: string): string {
  if (report.comparison?.new.includes(fingerprint)) return "new";
  if (report.comparison?.remaining.includes(fingerprint)) return "remaining";
  return "not compared";
}

function comparisonList(report: ScanReport, title: string, fingerprints: string[]): string {
  const items = fingerprints.slice(0, 20).map((fingerprint) => {
    const finding = report.findings.find((item) => item.fingerprint === fingerprint);
    return `<li>${finding ? escape(finding.title) : "fingerprint"} <code>${escape(fingerprint.slice(0, 16))}…</code></li>`;
  }).join("");
  const omitted = fingerprints.length > 20 ? `<li>${fingerprints.length - 20} additional entries omitted from this view</li>` : "";
  return `<section class="comparison-card"><h3>${escape(title)} <span>${fingerprints.length}</span></h3>${items || omitted ? `<ul>${items}${omitted}</ul>` : "<p>None</p>"}</section>`;
}

function routeSecurityComparisonHtml(report: ScanReport): string {
  const comparison = report.comparison?.routeSecurity;
  if (!report.comparison) return "";
  if (!comparison) return "<h3>Route security comparison</h3><p>Not recorded by this legacy report producer.</p>";
  const entries = [
    ...comparison.new.map((entry) => ({ state: "newly observed", entry })),
    ...comparison.notRechecked.map((entry) => ({ state: "not rechecked", entry })),
    ...comparison.resolved.map((entry) => ({ state: "resolved", entry })),
    ...comparison.remaining.map((entry) => ({ state: "remaining", entry })),
  ];
  const rows = entries.slice(0, MAX_HTML_ROUTE_COMPARISON_ENTRIES).map(({ state, entry }) => `<tr><td><strong>${escape(state)}</strong></td><td><span class="severity ${escape(entry.severity)}">${escape(entry.severity)}</span></td><td>${escape(entry.framework)}</td><td><code>${escape(entry.route)}</code></td><td>${escape(ROUTE_SECURITY_CATEGORY_LABELS[entry.category])}</td></tr>`).join("\n");
  const omittedEntries = Math.max(0, entries.length - MAX_HTML_ROUTE_COMPARISON_ENTRIES);
  const omissions = omittedEntries > 0 || comparison.omittedRouteAliases > 0 || comparison.omittedAssociations > 0
    ? `<p><small>Omissions: ${omittedEntries} HTML entries, ${comparison.omittedRouteAliases} route aliases, and ${comparison.omittedAssociations} associations.</small></p>`
    : "";
  return `<h3>Route security comparison</h3><p>${comparison.new.length} newly observed · ${comparison.remaining.length} remaining · ${comparison.resolved.length} resolved · ${comparison.notRechecked.length} not rechecked · <strong>${comparison.complete ? "complete" : "partial"}</strong></p>${rows ? `<table><thead><tr><th>State</th><th>Risk</th><th>Framework</th><th>Route</th><th>Observed gap</th></tr></thead><tbody>${rows}</tbody></table>` : "<p>No route-security differences were recorded.</p>"}${omissions}`;
}

function findingRow(report: ScanReport, finding: Finding, signal?: Signal): string {
  const evidence = signal ?? report.signals.find((candidate) => finding.signalIds.includes(candidate.id));
  const location = evidence?.locations[0];
  const baseline = comparisonState(report, finding.fingerprint);
  return `<tr class="finding-${escape(finding.status)}"><td><span class="severity ${escape(finding.severity)}">${escape(finding.severity)}</span></td><td><strong>${escape(finding.title)}</strong><br><small>${escape(finding.id)} · ${escape(finding.evidenceLevel)}</small></td><td><span class="status">${escape(finding.status)}</span><br><small>${escape(baseline)}</small></td><td><code>${escape(location?.path ?? "not recorded")}${location?.line ? `:${location.line}` : ""}</code></td><td>${escape(evidence?.description ?? "Correlated attack path")}</td></tr>`;
}

function routeSummary(routes: string[]): string {
  const visible = routes.slice(0, 4).map((route) => singleLine(route, 240));
  if (routes.length <= 4) return visible.join(", ") || "route not recorded";
  return `${visible.join(", ")} (+${routes.length - 4} more)`;
}

function routeEvidenceFindings(report: ScanReport, evidence: RouteSecurityEvidence): string {
  return evidence.findings.map((finding) => `<code>${escape(finding.id)}</code><br><small>${escape(finding.status)} · ${escape(comparisonState(report, finding.fingerprint))}</small>`).join("<br>");
}

function signalLocation(signal: Signal): string {
  const location = signal.locations[0];
  const path = safeRelativePath(location?.path) ?? "path not recorded";
  return `<code>${escape(path)}${location?.line ? `:${location.line}` : ""}</code>`;
}

export function renderHtml(report: ScanReport): string {
  const ci = buildCiReport(report);
  const routeSecurity = buildRouteSecurityReview(report);
  const routeCards = routeSecurity.cards.slice(0, MAX_HTML_ROUTE_CARDS).map((card) => {
    const findingLabel = card.findingCount === 1 ? "finding" : "findings";
    const signalLabel = card.signalCount === 1 ? "signal" : "signals";
    const categories = card.categories.map((category) => `<span class="route-category">${escape(ROUTE_SECURITY_CATEGORY_LABELS[category])}</span>`).join(" ");
    const evidenceRows = card.evidence.slice(0, MAX_HTML_ROUTE_EVIDENCE).map((evidence) => `<tr><td>${escape(ROUTE_SECURITY_CATEGORY_LABELS[evidence.category])}</td><td><strong>${escape(evidence.signal.title)}</strong><br><small><code>${escape(evidence.signal.ruleId)}</code> · ${escape(evidence.signal.evidenceLevel)}${evidence.handler ? ` · handler <code>${escape(singleLine(evidence.handler, 200))}</code>` : ""}</small></td><td>${routeEvidenceFindings(report, evidence)}</td><td>${signalLocation(evidence.signal)}</td></tr>`).join("\n");
    const omittedEvidence = card.evidence.length > MAX_HTML_ROUTE_EVIDENCE
      ? `<p><small>${card.evidence.length - MAX_HTML_ROUTE_EVIDENCE} additional evidence entries are omitted from this card and remain available in the canonical finding views.</small></p>`
      : "";
    return `<details class="route-security-card ${card.hasOpenFinding ? "finding-open" : "finding-suppressed"}"><summary><span class="severity ${escape(card.severity)}">${escape(card.severity)}</span> <strong>${escape(card.framework)}</strong> · <code>${escape(card.route)}</code> — ${card.signalCount} ${signalLabel} / ${card.findingCount} ${findingLabel}</summary><p class="route-categories">${categories}</p><table><thead><tr><th>Observed gap</th><th>Evidence</th><th>Canonical findings</th><th>Location</th></tr></thead><tbody>${evidenceRows}</tbody></table>${omittedEvidence}</details>`;
  }).join("\n");
  const deploymentContexts = routeSecurity.deploymentContexts.slice(0, MAX_HTML_DEPLOYMENT_CONTEXTS).map((context) => {
    const service = context.service ? `<code>${escape(singleLine(context.service, 200))}</code>` : "not recorded";
    const ports = context.publishedPorts.length > 0 ? `<code>${escape(singleLine(context.publishedPorts.join(", "), 300))}</code>` : "not recorded";
    const findings = context.findings.map((finding) => `<code>${escape(finding.id)}</code> <small>${escape(finding.status)} · ${escape(comparisonState(report, finding.fingerprint))}</small>`).join(", ");
    return `<article class="deployment-context ${context.hasOpenFinding ? "finding-open" : "finding-suppressed"}"><h3><span class="severity ${escape(context.severity)}">${escape(context.severity)}</span> ${escape(context.signal.title)}</h3><p>Service: ${service} · Published ports: ${ports}<br>Location: ${signalLocation(context.signal)}<br>Canonical findings: ${findings}</p></article>`;
  }).join("\n");
  const routeAttributionGaps = routeSecurity.attributionGaps.slice(0, MAX_HTML_ROUTE_ATTRIBUTION_GAPS).map((gap) => {
    const findings = gap.findings.map((finding) => `<code>${escape(finding.id)}</code> <small>${escape(finding.status)} · ${escape(comparisonState(report, finding.fingerprint))}</small>`).join(", ");
    const functionName = gap.functionName ? `<code>${escape(singleLine(gap.functionName, 200))}</code>` : "not recorded";
    return `<tr><td>${escape(ROUTE_ATTRIBUTION_GAP_LABELS[gap.reason])}</td><td>${escape(ROUTE_SECURITY_CATEGORY_LABELS[gap.category])}<br><small><code>${escape(gap.signal.ruleId)}</code></small></td><td>${functionName}</td><td>${signalLocation(gap.signal)}</td><td>${findings}</td></tr>`;
  }).join("\n");
  const routePresentationBounds = [
    routeSecurity.cards.length > MAX_HTML_ROUTE_CARDS ? `${routeSecurity.cards.length - MAX_HTML_ROUTE_CARDS} additional route cards` : undefined,
    routeSecurity.deploymentContexts.length > MAX_HTML_DEPLOYMENT_CONTEXTS ? `${routeSecurity.deploymentContexts.length - MAX_HTML_DEPLOYMENT_CONTEXTS} additional deployment contexts` : undefined,
    routeSecurity.omittedRouteAliases > 0 ? `${routeSecurity.omittedRouteAliases} route aliases` : undefined,
    routeSecurity.omittedAssociations > 0 ? `${routeSecurity.omittedAssociations} route-evidence associations` : undefined,
    routeSecurity.attributionGaps.length > MAX_HTML_ROUTE_ATTRIBUTION_GAPS ? `${routeSecurity.attributionGaps.length - MAX_HTML_ROUTE_ATTRIBUTION_GAPS} attribution gaps` : undefined,
  ].filter((value): value is string => Boolean(value));
  const routeAttributionSummary = routeSecurity.attribution.eligibleSignals > 0
    ? `<p><strong>Route attribution:</strong> ${routeSecurity.attribution.attributedSignals} of ${routeSecurity.attribution.eligibleSignals} eligible signals have proven routes; ${routeSecurity.attribution.unattributedSignals} signals across ${routeSecurity.attribution.unattributedFindings} findings remain unattributed.</p>`
    : "";
  const routeSecuritySection = routeCards || deploymentContexts || routeAttributionGaps ? `<section><h2>Route security review</h2><p><strong>Evidence-only view:</strong> shown categories are detected gaps. An absent category is not evidence that the control passed.</p>${routeAttributionSummary}${deploymentContexts ? `<h3>Project deployment context</h3><p>This evidence is not attributed to a specific route because static project co-occurrence does not prove service-to-route ownership.</p>${deploymentContexts}` : ""}${routeAttributionGaps ? `<h3>Unattributed FastAPI data-flow evidence</h3><p>These canonical findings remain reviewable, but static analysis did not prove an exact request route. Reasons describe the attribution boundary, not exploitability.</p><table><thead><tr><th>Reason</th><th>Observed gap</th><th>Function</th><th>Location</th><th>Canonical findings</th></tr></thead><tbody>${routeAttributionGaps}</tbody></table>` : ""}${routeCards ? `<h3>Route cards</h3>${routeCards}` : ""}${routePresentationBounds.length > 0 ? `<p><small>Presentation bounds omitted ${escape(routePresentationBounds.join(", "))}; canonical findings remain unchanged.</small></p>` : ""}</section>` : "";
  const { groups: findingGroups, ungrouped: ungroupedFindings } = partitionFindingGroups(report);
  const findingRows = ungroupedFindings.map((finding) => findingRow(report, finding)).join("\n");
  const groupedFindingSections = findingGroups.map((group) => {
    const findingLabel = group.findingCount === 1 ? "finding" : "findings";
    const memberRows = group.members.map((member) => `<tr class="finding-${escape(member.finding.status)}"><td><code>${escape(routeSummary(member.routes))}</code>${member.handler ? `<br><small>${escape(singleLine(member.handler, 200))}</small>` : ""}</td><td><code>${escape(member.location.path)}${member.location.line ? `:${member.location.line}` : ""}</code></td><td>${escape(member.pattern ?? "not classified")}</td><td><span class="status">${escape(member.finding.status)}</span><br><small>${escape(member.finding.id)} · ${escape(comparisonState(report, member.finding.fingerprint))}</small></td></tr>`).join("\n");
    return `<details class="finding-group finding-${escape(group.status)}"><summary><span class="severity ${escape(group.severity)}">${escape(group.severity)}</span> <strong>${escape(group.title)}</strong> — <code>${escape(group.path)}</code> · ${group.members.length} occurrences / ${group.findingCount} ${findingLabel}</summary><p>${group.handlers.length} handlers · ${group.routes.length} routes${group.patterns.length ? ` · ${escape(group.patterns.join(", "))}` : ""}</p><table><thead><tr><th>Route / handler</th><th>Location</th><th>Pattern</th><th>Status</th></tr></thead><tbody>${memberRows}</tbody></table></details>`;
  }).join("\n");
  const coverageRows = report.coverage.map((item) => `<tr class="coverage-${escape(item.status)}"><td>${escape(item.domain)}</td><td>${escape(item.engine)}</td><td>${escape(item.required ? "required" : "optional")}</td><td>${escape(item.status)}</td><td>${escape(item.reason ?? "")}</td></tr>`).join("\n");
  const paths = report.attackPaths.map((item) => `<article><h3>${escape(item.title)}</h3><p>${escape(item.summary)}</p><ol>${item.steps.map((step) => `<li>${escape(step.action)}</li>`).join("")}</ol><p><strong>Remediation:</strong> ${escape(item.remediation)}</p></article>`).join("\n");
  const policy = ci.policy.source === "operator"
    ? `${escape(ci.policy.policyId)} · sha256:${escape(ci.policy.digestSha256)} · expires ${escape(ci.policy.expiresAt)}`
    : ci.policy.source === "defaults" ? "trusted built-in defaults" : "not recorded by this report producer";
  const gate = ci.policy.gate
    ? `minimum ${escape(ci.policy.gate.minimumSeverity)} · inferred ${ci.policy.gate.includeInferred ? "included" : "review only"} · no suppressions ${ci.policy.gate.requireNoSuppressions ? "required" : "not required"}`
    : "not recorded";
  const routeBaselineGate = ci.policy.routeSecurityBaseline
    ? `minimum ${escape(ci.policy.routeSecurityBaseline.minimumSeverity)} · inferred ${ci.policy.routeSecurityBaseline.includeInferred ? "included" : "excluded"} · complete comparison ${ci.policy.routeSecurityBaseline.requireComplete ? "required" : "not required"}`
    : "disabled";
  const coverageAlert = ci.requiredCoverage.gaps.length > 0
    ? `<section class="alert error"><h2>Required coverage gaps</h2><ul>${ci.requiredCoverage.gaps.map((gap) => `<li><strong>${escape(gap.domain)}</strong> (${escape(gap.engine)}): ${escape(gap.status)}${gap.reason ? ` — ${escape(gap.reason)}` : ""}</li>`).join("")}</ul></section>`
    : `<section class="alert success"><strong>Required coverage:</strong> all ${ci.requiredCoverage.total} records complete.</section>`;
  const comparison = report.comparison ? `<section><h2>Baseline comparison</h2><p><code>${escape(report.comparison.baselineScanId)}</code></p><div class="comparison-grid">${comparisonList(report, "New", report.comparison.new)}${comparisonList(report, "Remaining", report.comparison.remaining)}${comparisonList(report, "Resolved", report.comparison.resolved)}${comparisonList(report, "Not rechecked", report.comparison.notRechecked)}</div>${routeSecurityComparisonHtml(report)}</section>` : "";
  const rulePacks = (report.rulePacks ?? []).length > 0
    ? `<ul>${(report.rulePacks ?? []).map((pack) => `<li><code>${escape(pack.packId)}</code> · SHA-256 <code>${escape(pack.digestSha256)}</code> · ${pack.ruleCount} rule(s)</li>`).join("")}</ul>`
    : "<p>None.</p>";
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>AIsec report ${escape(report.scanId)}</title><style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1200px;margin:0 auto;padding:2rem;line-height:1.45}header{display:flex;justify-content:space-between;gap:2rem;align-items:flex-start}.decision{font-size:1.35rem;font-weight:700;padding:.55rem .85rem;border:2px solid;border-radius:.5rem}.decision.block,.decision.incomplete{color:#e5484d}.decision.review{color:#d6a300}.decision.no_blockers_found{color:#2f9e44}.metrics,.comparison-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.8rem}.metric,.comparison-card,.alert,article,.finding-group,.route-security-card{border:1px solid #8885;padding:1rem;border-radius:.5rem}.metric strong{display:block;font-size:1.5rem}.alert{margin:1rem 0}.alert.error{border-color:#e5484d}.alert.success{border-color:#2f9e44}table{width:100%;border-collapse:collapse;margin:1rem 0 2rem}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #8885;padding:.6rem}.severity,.status{font-weight:700}.critical,.high,.coverage-failed,.coverage-not_run{color:#e5484d}.medium,.coverage-partial{color:#d6a300}.low{color:#3e63dd}.finding-suppressed{opacity:.7}.finding-group,.route-security-card{margin:0 0 .8rem}.finding-group summary,.route-security-card summary{cursor:pointer}.finding-group table,.route-security-card table{margin-bottom:0}.route-category{display:inline-block;border:1px solid #8888;border-radius:999px;padding:.15rem .5rem;margin:.15rem .2rem .15rem 0}.route-categories{margin-bottom:.5rem}.deployment-context{margin:.5rem 0}.deployment-context h3{margin-top:0}.comparison-card h3{display:flex;justify-content:space-between;margin-top:0}.comparison-card ul{padding-left:1.2rem}small{opacity:.75}code{overflow-wrap:anywhere}h2{margin-top:2rem}</style></head>
<body><header><div><h1>AIsec security acceptance report</h1><p><code>${escape(report.target)}</code><br>${escape(report.scanId)} · ${escape(report.completedAt)}</p></div><div class="decision ${escape(report.decision)}">${escape(report.decision)}</div></header>
<p>${escape(report.disclaimer)}</p><section class="alert"><h2>Decision reasons</h2><ul>${ci.decisionReasons.map((reason) => `<li>${escape(reason)}</li>`).join("")}</ul></section>${coverageAlert}
<h2>Summary</h2><div class="metrics"><div class="metric"><strong>${ci.counts.critical}</strong>critical</div><div class="metric"><strong>${ci.counts.high}</strong>high</div><div class="metric"><strong>${ci.counts.medium}</strong>medium</div><div class="metric"><strong>${ci.counts.open}</strong>open</div><div class="metric"><strong>${ci.counts.suppressed}</strong>suppressed</div><div class="metric"><strong>${ci.counts.attackPaths}</strong>attack paths</div></div>
<h2>Policy</h2><p>${policy}</p><ul><li>Gate: ${gate}</li><li>Route-security baseline gate: ${routeBaselineGate}</li><li>Required engines: ${ci.policy.requiredEngines.length ? escape(ci.policy.requiredEngines.join(", ")) : "none recorded"}</li><li>Target configuration: ${escape(ci.policy.targetConfiguration)}</li><li>Suppressions: ${ci.policy.suppressionCount} (${escape(ci.policy.suppressionApproval)})</li><li>Relaxations: ${ci.policy.relaxations.length ? escape(ci.policy.relaxations.join(", ")) : "none"}</li></ul>
<h2>Declarative rule packs</h2>${rulePacks}
${comparison}${paths ? `<h2>Attack paths</h2>${paths}` : ""}${routeSecuritySection}${groupedFindingSections ? `<h2>Grouped findings</h2>${groupedFindingSections}` : ""}${findingRows ? `<h2>${groupedFindingSections ? "Other findings" : "Findings"}</h2><table><thead><tr><th>Risk</th><th>Finding</th><th>Status</th><th>Location</th><th>Evidence</th></tr></thead><tbody>${findingRows}</tbody></table>` : groupedFindingSections ? "" : "<h2>Findings</h2><p>No findings in the executed coverage.</p>"}
<h2>Coverage</h2><table><thead><tr><th>Domain</th><th>Engine</th><th>Requirement</th><th>Status</th><th>Reason</th></tr></thead><tbody>${coverageRows}</tbody></table></body></html>`;
}
