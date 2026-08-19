import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ScanReport } from "../schema.js";
import { renderHtml } from "./html.js";
import { renderSarif } from "./sarif.js";
import { renderTerminalReport } from "./terminal.js";
import { buildCiReport, renderGithubAnnotations, renderMarkdownSummary } from "./ci.js";
import { validateScanReport } from "../core/schema-validation.js";

export type OutputFormat = "terminal" | "json" | "html" | "sarif" | "ci" | "github" | "markdown";

export function serializeReport(report: ScanReport, format: OutputFormat): string {
  validateScanReport(report);
  if (format === "json") return `${JSON.stringify(report, null, 2)}\n`;
  if (format === "html") return renderHtml(report);
  if (format === "sarif") return `${JSON.stringify(renderSarif(report), null, 2)}\n`;
  const ciReport = buildCiReport(report);
  if (format === "ci") return `${JSON.stringify(ciReport, null, 2)}\n`;
  if (format === "github") return renderGithubAnnotations(ciReport);
  if (format === "markdown") return renderMarkdownSummary(ciReport);
  return `${renderTerminalReport(report)}\n`;
}

export async function emitReport(report: ScanReport, format: OutputFormat, output?: string): Promise<void> {
  const rendered = serializeReport(report, format);
  if (output) {
    await writeFile(resolve(output), rendered, { mode: 0o600 });
  } else {
    process.stdout.write(rendered);
  }
}
