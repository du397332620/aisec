import { SEVERITY_RANK } from "../core/constants.js";
import type { Finding, ScanReport, Severity, Signal } from "../schema.js";

export type RouteSecurityCategory =
  | "authentication"
  | "object_authorization"
  | "privileged_authorization"
  | "exception_disclosure";

export const ROUTE_SECURITY_CATEGORY_LABELS: Record<RouteSecurityCategory, string> = {
  authentication: "authentication gap",
  object_authorization: "object authorization gap",
  privileged_authorization: "privileged authorization gap",
  exception_disclosure: "exception disclosure",
};

export type RouteSecurityFramework = "FastAPI" | "Express" | "NestJS";

interface RouteRulePresentation {
  category: RouteSecurityCategory;
  framework: RouteSecurityFramework;
}

const ROUTE_RULES: Readonly<Record<string, RouteRulePresentation>> = {
  "fastapi.auth.whitelisted-sensitive-route": { category: "authentication", framework: "FastAPI" },
  "fastapi.auth.sensitive-route-without-guard": { category: "authentication", framework: "FastAPI" },
  "fastapi.authorization.object-without-ownership-check": { category: "object_authorization", framework: "FastAPI" },
  "fastapi.config.route-raw-exception-response": { category: "exception_disclosure", framework: "FastAPI" },
  "express.auth.sensitive-route-without-guard": { category: "authentication", framework: "Express" },
  "express.authorization.object-without-ownership-check": { category: "object_authorization", framework: "Express" },
  "express.authorization.privileged-operation-without-role-check": { category: "privileged_authorization", framework: "Express" },
  "nestjs.auth.sensitive-route-without-guard": { category: "authentication", framework: "NestJS" },
  "nestjs.authorization.object-without-ownership-check": { category: "object_authorization", framework: "NestJS" },
  "nestjs.authorization.privileged-operation-without-role-check": { category: "privileged_authorization", framework: "NestJS" },
};

const CATEGORY_ORDER: readonly RouteSecurityCategory[] = [
  "authentication",
  "object_authorization",
  "privileged_authorization",
  "exception_disclosure",
];
const CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;
const ROUTE_PATTERN = /^(CONNECT|DELETE|GET|HEAD|OPTIONS|PATCH|POST|PUT|TRACE|ALL) +(\/[^\s\u007f]{0,480})$/u;
const MAX_ROUTE_ALIASES_PER_SIGNAL = 128;
const MAX_ROUTE_ASSOCIATIONS = 10_000;

export interface RouteSecurityEvidence {
  category: RouteSecurityCategory;
  signal: Signal;
  findings: Finding[];
  handler?: string;
}

export interface RouteSecurityCard {
  key: string;
  framework: RouteSecurityFramework;
  route: string;
  severity: Severity;
  hasOpenFinding: boolean;
  categories: RouteSecurityCategory[];
  evidence: RouteSecurityEvidence[];
  findingCount: number;
  signalCount: number;
}

export interface RouteSecurityDeploymentContext {
  signal: Signal;
  findings: Finding[];
  severity: Severity;
  hasOpenFinding: boolean;
  service?: string;
  publishedPorts: string[];
}

export interface RouteSecurityReview {
  cards: RouteSecurityCard[];
  deploymentContexts: RouteSecurityDeploymentContext[];
  omittedRouteAliases: number;
  omittedAssociations: number;
}

function metadataString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function metadataStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && Boolean(item.trim()));
}

function normalizedRoute(value: unknown): string | undefined {
  if (typeof value !== "string" || CONTROL_CHARACTER.test(value) || [...value].length > 512) return undefined;
  const match = ROUTE_PATTERN.exec(value.trim());
  return match ? `${match[1]} ${match[2]}` : undefined;
}

function routeAliases(signal: Signal): { routes: string[]; omitted: number } {
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

function handlerFor(signal: Signal): string | undefined {
  const handler = metadataString(signal.metadata?.handler);
  return handler && [...handler].length <= 256 ? handler : undefined;
}

function highestSeverity(findings: readonly Finding[]): Severity {
  const open = findings.filter((finding) => finding.status === "open");
  const candidates = open.length > 0 ? open : findings;
  return candidates.reduce<Severity>((highest, finding) => (
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

function compareFindings(left: Finding, right: Finding): number {
  return (left.status === right.status ? 0 : left.status === "open" ? -1 : 1)
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.id.localeCompare(right.id);
}

export function buildRouteSecurityReview(
  report: ScanReport,
  findings: readonly Finding[] = report.findings,
): RouteSecurityReview {
  const findingsBySignal = findingIndex(findings);
  const cardsByKey = new Map<string, Omit<RouteSecurityCard, "severity" | "hasOpenFinding" | "categories" | "findingCount" | "signalCount">>();
  let omittedRouteAliases = 0;
  let associations = 0;
  let omittedAssociations = 0;

  for (const signal of report.signals) {
    const presentation = ROUTE_RULES[signal.ruleId];
    const associatedFindings = findingsBySignal.get(signal.id);
    if (!presentation || !associatedFindings || associatedFindings.length === 0) continue;
    const aliases = routeAliases(signal);
    omittedRouteAliases += aliases.omitted;
    for (const route of aliases.routes) {
      if (associations >= MAX_ROUTE_ASSOCIATIONS) {
        omittedAssociations += 1;
        continue;
      }
      associations += 1;
      const key = `${presentation.framework}\u0000${route}`;
      const existing = cardsByKey.get(key);
      const handler = handlerFor(signal);
      const evidence: RouteSecurityEvidence = {
        category: presentation.category,
        signal,
        findings: [...associatedFindings].sort(compareFindings),
        ...(handler ? { handler } : {}),
      };
      if (existing) existing.evidence.push(evidence);
      else cardsByKey.set(key, {
        key,
        framework: presentation.framework,
        route,
        evidence: [evidence],
      });
    }
  }

  const cards: RouteSecurityCard[] = [...cardsByKey.values()].map((card) => {
    const allFindings = [...new Map(card.evidence.flatMap((item) => item.findings).map((finding) => [finding.id, finding])).values()]
      .sort(compareFindings);
    const categories = CATEGORY_ORDER.filter((category) => card.evidence.some((item) => item.category === category));
    card.evidence.sort((left, right) => CATEGORY_ORDER.indexOf(left.category) - CATEGORY_ORDER.indexOf(right.category)
      || SEVERITY_RANK[highestSeverity(right.findings)] - SEVERITY_RANK[highestSeverity(left.findings)]
      || left.signal.ruleId.localeCompare(right.signal.ruleId)
      || left.signal.id.localeCompare(right.signal.id));
    return {
      ...card,
      severity: highestSeverity(allFindings),
      hasOpenFinding: allFindings.some((finding) => finding.status === "open"),
      categories,
      findingCount: allFindings.length,
      signalCount: card.evidence.length,
    };
  });
  cards.sort((left, right) => (left.hasOpenFinding === right.hasOpenFinding ? 0 : left.hasOpenFinding ? -1 : 1)
    || right.categories.length - left.categories.length
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.framework.localeCompare(right.framework)
    || left.route.localeCompare(right.route));

  const deploymentContexts = report.signals
    .filter((signal) => signal.ruleId === "docker.config.unguarded-service-published")
    .flatMap((signal): RouteSecurityDeploymentContext[] => {
      const associatedFindings = findingsBySignal.get(signal.id);
      if (!associatedFindings || associatedFindings.length === 0) return [];
      const sortedFindings = [...associatedFindings].sort(compareFindings);
      const service = metadataString(signal.metadata?.service);
      return [{
        signal,
        findings: sortedFindings,
        severity: highestSeverity(sortedFindings),
        hasOpenFinding: sortedFindings.some((finding) => finding.status === "open"),
        ...(service && [...service].length <= 256 ? { service } : {}),
        publishedPorts: [...new Set(metadataStrings(signal.metadata?.publishedPorts))].slice(0, 32),
      }];
    })
    .sort((left, right) => (left.hasOpenFinding === right.hasOpenFinding ? 0 : left.hasOpenFinding ? -1 : 1)
      || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
      || (left.service ?? "").localeCompare(right.service ?? "")
      || left.signal.id.localeCompare(right.signal.id));

  return { cards, deploymentContexts, omittedRouteAliases, omittedAssociations };
}
