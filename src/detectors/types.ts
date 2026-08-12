import type { CoverageRecord, Signal } from "../schema.js";
import type { ScanContext } from "../core/context.js";

export interface DetectorResult {
  signals: Signal[];
  coverage: CoverageRecord;
}

export interface Detector {
  name: string;
  run(context: ScanContext): Promise<DetectorResult>;
}

export function nativeCoverage(
  domain: string,
  status: CoverageRecord["status"],
  durationMs: number,
  reason?: string,
): CoverageRecord {
  return { domain, engine: "aisec-native", status, required: true, durationMs, reason };
}
