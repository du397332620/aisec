import type { ScanReport } from "../schema.js";

function escape(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

export function renderHtml(report: ScanReport): string {
  const findingRows = report.findings.map((finding) => {
    const signal = report.signals.find((candidate) => candidate.id === finding.signalIds[0]);
    const location = signal?.locations[0];
    return `<tr><td><span class="severity ${escape(finding.severity)}">${escape(finding.severity)}</span></td><td><strong>${escape(finding.title)}</strong><br><small>${escape(finding.id)} · ${escape(finding.evidenceLevel)}</small></td><td>${escape(location?.path ?? "")}${location?.line ? `:${location.line}` : ""}</td><td>${escape(signal?.description ?? "Correlated attack path")}</td></tr>`;
  }).join("\n");
  const coverageRows = report.coverage.map((item) => `<tr><td>${escape(item.domain)}</td><td>${escape(item.engine)}</td><td>${escape(item.status)}</td><td>${escape(item.reason ?? "")}</td></tr>`).join("\n");
  const paths = report.attackPaths.map((item) => `<article><h3>${escape(item.title)}</h3><p>${escape(item.summary)}</p><ol>${item.steps.map((step) => `<li>${escape(step.action)}</li>`).join("")}</ol><p><strong>Remediation:</strong> ${escape(item.remediation)}</p></article>`).join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AIsec report ${escape(report.scanId)}</title><style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:1200px;margin:0 auto;padding:2rem;line-height:1.45}header{display:flex;justify-content:space-between;gap:2rem;align-items:flex-start}.decision{font-size:1.4rem;padding:.5rem .8rem;border:2px solid;border-radius:.5rem}table{width:100%;border-collapse:collapse;margin:1rem 0 2rem}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #8885;padding:.6rem}.severity{font-weight:700}.critical{color:#e5484d}.high{color:#f76b15}.medium{color:#d6a300}.low{color:#3e63dd}article{border:1px solid #8885;padding:1rem;margin:1rem 0;border-radius:.5rem}small{opacity:.75}code{overflow-wrap:anywhere}</style></head>
<body><header><div><h1>AIsec security acceptance report</h1><p><code>${escape(report.target)}</code><br>${escape(report.scanId)} · ${escape(report.completedAt)}</p></div><div class="decision">${escape(report.decision)}</div></header>
<p>${escape(report.disclaimer)}</p><h2>Summary</h2><p>${report.summary.critical} critical · ${report.summary.high} high · ${report.summary.medium} medium · ${report.summary.low} low · ${report.summary.attackPaths} attack paths</p>
${paths ? `<h2>Attack paths</h2>${paths}` : ""}<h2>Findings</h2><table><thead><tr><th>Risk</th><th>Finding</th><th>Location</th><th>Evidence</th></tr></thead><tbody>${findingRows}</tbody></table>
<h2>Coverage</h2><table><thead><tr><th>Domain</th><th>Engine</th><th>Status</th><th>Reason</th></tr></thead><tbody>${coverageRows}</tbody></table></body></html>`;
}
