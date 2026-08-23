import { SEVERITY_RANK } from "./constants.js";
import type {
  Finding,
  RouteSecurityCategory,
  RouteSecurityComparisonEntry,
  RouteSecurityFramework,
  ScanReport,
  Severity,
  Signal,
} from "../schema.js";

export interface RouteSecurityRulePresentation {
  category: RouteSecurityCategory;
  framework: RouteSecurityFramework;
  coverageDomain: string;
}

export const ROUTE_SECURITY_RULES: Readonly<Record<string, RouteSecurityRulePresentation>> = {
  "fastapi.auth.whitelisted-sensitive-route": { category: "authentication", framework: "FastAPI", coverageDomain: "fastapi-authentication" },
  "fastapi.auth.sensitive-route-without-guard": { category: "authentication", framework: "FastAPI", coverageDomain: "fastapi-authentication" },
  "fastapi.authorization.object-without-ownership-check": { category: "object_authorization", framework: "FastAPI", coverageDomain: "fastapi-object-authorization" },
  "fastapi.config.route-raw-exception-response": { category: "exception_disclosure", framework: "FastAPI", coverageDomain: "python-api-configuration" },
  "python.dataflow.sql-injection": { category: "sql_injection", framework: "FastAPI", coverageDomain: "python-dataflow" },
  "python.dataflow.ssrf": { category: "ssrf", framework: "FastAPI", coverageDomain: "python-dataflow" },
  "python.dataflow.untrusted-file-path": { category: "untrusted_file_path", framework: "FastAPI", coverageDomain: "python-dataflow" },
  "python.dataflow.client-url-with-server-secret": { category: "credential_forwarding", framework: "FastAPI", coverageDomain: "python-dataflow" },
  "express.auth.sensitive-route-without-guard": { category: "authentication", framework: "Express", coverageDomain: "node-api-security" },
  "express.authorization.object-without-ownership-check": { category: "object_authorization", framework: "Express", coverageDomain: "node-api-security" },
  "express.authorization.privileged-operation-without-role-check": { category: "privileged_authorization", framework: "Express", coverageDomain: "node-api-security" },
  "nestjs.auth.sensitive-route-without-guard": { category: "authentication", framework: "NestJS", coverageDomain: "node-api-security" },
  "nestjs.authorization.object-without-ownership-check": { category: "object_authorization", framework: "NestJS", coverageDomain: "node-api-security" },
  "nestjs.authorization.privileged-operation-without-role-check": { category: "privileged_authorization", framework: "NestJS", coverageDomain: "node-api-security" },
};

export const ROUTE_SECURITY_CATEGORY_ORDER: readonly RouteSecurityCategory[] = [
  "authentication",
  "object_authorization",
  "privileged_authorization",
  "sql_injection",
  "ssrf",
  "untrusted_file_path",
  "credential_forwarding",
  "exception_disclosure",
];

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ROUTE_PATTERN = /^(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE|ALL) +(\/[^\s\u007f]{0,480})$/u;
const MAX_ROUTE_ALIASES_PER_SIGNAL = 128;
const MAX_ROUTE_ASSOCIATIONS = 10_000;

function metadataStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && Boolean(item.trim()));
}

function normalizedRoute(value: unknown): string | undefined {
  if (typeof value !== "string" || CONTROL_CHARACTER.test(value) || [...value].length > 512) return undefined;
  const match = ROUTE_PATTERN.exec(value.trim());
  return match ? `${match[1]} ${match[2]}` : undefined;
}

export function routeSecurityAliases(signal: Signal): { routes: string[]; omitted: number } {
  const values = [signal.metadata?.route, ...metadataStrings(signal.metadata?.routes)];
  const routes: string[] = [];
  const seen = new Set<string>();
  let omitted = 0;
  for (const value of values) {
    const route = normalizedRoute(value);
    if (!route || seen.has(route)) continue;
    seen.add(route);
    if (routes.length < MAX_ROUTE_ALIASES_PER_SIGNAL) routes.push(route);
    else omitted += 1;
  }
  return { routes, omitted };
}

export function routeSecurityIssueKey(entry: Pick<RouteSecurityComparisonEntry, "framework" | "route" | "category">): string {
  return `${entry.framework}\u0000${entry.route}\u0000${entry.category}`;
}

export function compareRouteSecurityEntries(left: RouteSecurityComparisonEntry, right: RouteSecurityComparisonEntry): number {
  return SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.framework.localeCompare(right.framework)
    || left.route.localeCompare(right.route)
    || ROUTE_SECURITY_CATEGORY_ORDER.indexOf(left.category) - ROUTE_SECURITY_CATEGORY_ORDER.indexOf(right.category);
}

function highestSeverity(findings: readonly Finding[]): Severity {
  return findings.reduce<Severity>((highest, finding) => (
    SEVERITY_RANK[finding.severity] > SEVERITY_RANK[highest] ? finding.severity : highest
  ), "info");
}

function findingIndex(findings: readonly Finding[]): Map<string, Finding[]> {
  const result = new Map<string, Finding[]>();
  for (const finding of findings) {
    for (const signalId of new Set(finding.signalIds)) {
      const existing = result.get(signalId);
      if (existing) existing.push(finding);
      else result.set(signalId, [finding]);
    }
  }
  return result;
}

export interface RouteSecuritySnapshotIssue {
  entry: RouteSecurityComparisonEntry;
  signalIds: string[];
  coverageDomains: string[];
}

export interface RouteSecuritySnapshot {
  issues: RouteSecuritySnapshotIssue[];
  omittedRouteAliases: number;
  omittedAssociations: number;
}

export function buildRouteSecuritySnapshot(
  report: ScanReport,
  findings: readonly Finding[] = report.findings,
): RouteSecuritySnapshot {
  return buildRouteSecuritySnapshotFromEvidence(report.signals, findings);
}

export function buildRouteSecuritySnapshotFromEvidence(
  signals: readonly Signal[],
  findings: readonly Finding[],
): RouteSecuritySnapshot {
  const findingsBySignal = findingIndex(findings);
  const issues = new Map<string, {
    entry: RouteSecurityComparisonEntry;
    signalIds: Set<string>;
    coverageDomains: Set<string>;
  }>();
  let omittedRouteAliases = 0;
  let associations = 0;
  let omittedAssociations = 0;

  for (const signal of signals) {
    const presentation = ROUTE_SECURITY_RULES[signal.ruleId];
    const associatedFindings = findingsBySignal.get(signal.id);
    if (!presentation || !associatedFindings || associatedFindings.length === 0) continue;
    const aliases = routeSecurityAliases(signal);
    omittedRouteAliases += aliases.omitted;
    for (const route of aliases.routes) {
      if (associations >= MAX_ROUTE_ASSOCIATIONS) {
        omittedAssociations += 1;
        continue;
      }
      associations += 1;
      const entry: RouteSecurityComparisonEntry = {
        framework: presentation.framework,
        route,
        category: presentation.category,
        severity: highestSeverity(associatedFindings),
      };
      const key = routeSecurityIssueKey(entry);
      const existing = issues.get(key);
      if (existing) {
        if (SEVERITY_RANK[entry.severity] > SEVERITY_RANK[existing.entry.severity]) existing.entry.severity = entry.severity;
        existing.signalIds.add(signal.id);
        existing.coverageDomains.add(presentation.coverageDomain);
      } else {
        issues.set(key, {
          entry,
          signalIds: new Set([signal.id]),
          coverageDomains: new Set([presentation.coverageDomain]),
        });
      }
    }
  }

  return {
    issues: [...issues.values()].map((issue) => ({
      entry: issue.entry,
      signalIds: [...issue.signalIds].sort(),
      coverageDomains: [...issue.coverageDomains].sort(),
    })).sort((left, right) => compareRouteSecurityEntries(left.entry, right.entry)),
    omittedRouteAliases,
    omittedAssociations,
  };
}
