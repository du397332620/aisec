import { join, resolve } from "node:path";
import type { ScanReport } from "../schema.js";
import { dataDir, fileExists, readJson, writeJson } from "./utils.js";
import { validateScanReport } from "./schema-validation.js";

export function reportPath(scanId: string): string {
  if (!/^scan_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(scanId)) throw new Error(`Invalid scan id: ${scanId}`);
  return join(dataDir(), "scans", `${scanId}.json`);
}

export async function saveReport(report: ScanReport): Promise<string> {
  validateScanReport(report);
  const path = reportPath(report.scanId);
  await writeJson(path, report);
  await writeJson(join(dataDir(), "projects", report.profile.projectId, "latest.json"), report);
  return path;
}

export async function loadReport(reference: string): Promise<ScanReport> {
  const candidates = reference.endsWith(".json") || reference.includes("/")
    ? [resolve(reference)]
    : [reportPath(reference)];
  for (const candidate of candidates) if (await fileExists(candidate)) return validateScanReport(await readJson<unknown>(candidate));
  throw new Error(`Scan report not found: ${reference}`);
}
