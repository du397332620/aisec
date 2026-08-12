import type { EvidenceLevel, Severity, Signal, SourceLocation } from "../schema.js";
import { createSignal } from "../core/utils.js";

export function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

export function isOptionalString(value: unknown): boolean {
  return value === undefined || typeof value === "string";
}

export function isOptionalFiniteNumber(value: unknown): boolean {
  return value === undefined || (typeof value === "number" && Number.isFinite(value));
}

export function isOptionalArrayOf<T>(value: unknown, predicate: (item: unknown) => item is T): boolean {
  return value === undefined || (Array.isArray(value) && value.every(predicate));
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function normalizeSeverity(value: unknown, fallback: Severity = "medium"): Severity {
  const normalized = String(value ?? "").toLowerCase();
  if (["critical", "error"].includes(normalized)) return normalized === "critical" ? "critical" : "high";
  if (["high", "warning", "warn"].includes(normalized)) return normalized === "high" ? "high" : "medium";
  if (normalized === "medium" || normalized === "moderate") return "medium";
  if (normalized === "low" || normalized === "note") return "low";
  if (normalized === "info" || normalized === "informational") return "info";
  return fallback;
}

export function externalSignal(input: {
  engine: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  locations: SourceLocation[];
  evidenceLevel?: EvidenceLevel;
  cwe?: string[];
  tags?: string[];
  remediation?: string;
  metadata?: Record<string, string | number | boolean | string[]>;
}): Signal {
  return createSignal({
    engine: input.engine,
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    evidenceLevel: input.evidenceLevel ?? "static_confirmed",
    confidence: "high",
    locations: input.locations,
    cwe: input.cwe,
    tags: input.tags ?? [input.engine],
    remediation: input.remediation,
    metadata: input.metadata,
  });
}
