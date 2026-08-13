import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { analyzeFastApi, type FastApiRoute } from "../api/fastapi.js";
import { createSignal } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const REQUEST_OBJECT_ID = /\b(?:request|payload|body|data|params|query)\s*(?:\.\s*(?:[A-Za-z_]\w*_id|id|uuid)\b|\[\s*["'](?:[A-Za-z_]\w*_id|id|uuid)["']\s*\]|\.get\s*\(\s*["'](?:[A-Za-z_]\w*_id|id|uuid)["'])/i;
const SIGNATURE_OBJECT_ID = /^(?:async\s+)?def\s+\w+\s*\([\s\S]{0,1000}?\b(?:[A-Za-z_]\w*_id|id|uuid)\s*(?::|,|\))/m;
const OBJECT_ACCESS = /(?:\b(?:db|session)\s*\.\s*(?:get|delete|exec|execute|query|add|merge|commit)\s*\(|\b(?:CRUD\w*|\w*(?:repository|service|manager|dao|crud))\s*\.\s*\w*(?:get|find|detail|delete|remove|update|save|status|download|approve|reject)\w*\s*\(|\.\s*(?:where|filter|delete|update)\s*\()/i;
const AUTH_SESSION_ROUTE = /(?:^|\/)(?:login|logout|token|session\/current|me|profile)(?:\/|$)/i;

function objectIdFields(route: FastApiRoute): string[] {
  const fields = new Set<string>();
  const source = route.handlerSource;
  const patterns = [
    /\b(?:request|payload|body|data|params|query)\s*\.\s*([A-Za-z_]\w*_id|id|uuid)\b/gi,
    /\b(?:request|payload|body|data|params|query)\s*\[\s*["']([A-Za-z_]\w*_id|id|uuid)["']\s*\]/gi,
    /\b(?:request|payload|body|data|params|query)\s*\.get\s*\(\s*["']([A-Za-z_]\w*_id|id|uuid)["']/gi,
  ];
  for (const pattern of patterns) for (const match of source.matchAll(pattern)) if (match[1]) fields.add(match[1]);
  for (const match of route.path.matchAll(/\{([A-Za-z_]\w*)\}/g)) {
    if (match[1] && /(?:_id|^id$|uuid$)/i.test(match[1])) fields.add(match[1]);
  }
  return [...fields].sort();
}

function hasObjectOperation(route: FastApiRoute): boolean {
  if (AUTH_SESSION_ROUTE.test(route.path)) return false;
  const source = route.handlerSource;
  const receivesObjectId = REQUEST_OBJECT_ID.test(source)
    || SIGNATURE_OBJECT_ID.test(source)
    || /\{[^}]*\b(?:id|uuid)\b[^}]*\}/i.test(route.path);
  return receivesObjectId && OBJECT_ACCESS.test(source);
}

function isAuthenticated(route: FastApiRoute): boolean {
  return route.locallyProtected || (route.middlewareProtected && !route.whitelist);
}

function bolaSignal(route: FastApiRoute): Signal {
  return createSignal({
    engine: "aisec-python",
    ruleId: "fastapi.authorization.object-without-ownership-check",
    title: "FastAPI object operation has no visible ownership or role check",
    description: `${route.method} ${route.path} accepts an object identifier and performs a data lookup or mutation, but the handler and its router dependencies contain no recognized owner, tenant, permission, or administrator check. Authentication alone does not prove that the caller may access this object.`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: [route.location],
    cwe: ["CWE-639", "CWE-862"],
    owasp: ["A01:2021", "API1:2023"],
    tags: ["fastapi", "api", "authorization", "bola", "idor", "ownership"],
    remediation: "Bind the requested object to the authenticated subject, tenant, or an explicit privileged role in the database query or a centralized access-check helper. Verify with two low-privilege accounts that cross-account identifiers receive 403 or 404.",
    metadata: {
      route: `${route.method} ${route.path}`,
      handler: route.handlerName,
      objectIdFields: objectIdFields(route),
      ownerIdentityFields: route.responseOwnerFields,
    },
  });
}

export async function runPythonApiAuthorization(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const analysis = analyzeFastApi(context.inventory.files);
  if (!analysis.detected) {
    return {
      signals: [],
      coverage: {
        domain: "fastapi-object-authorization",
        engine: "aisec-python",
        status: "not_run",
        required: false,
        reason: "No FastAPI project detected",
        durationMs: Date.now() - started,
      },
    };
  }

  const signals: Signal[] = [];
  let truncated = false;
  for (const route of analysis.routes) {
    if (!isAuthenticated(route) || route.ownershipProtected || !hasObjectOperation(route)) continue;
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) {
      truncated = true;
      break;
    }
    signals.push(bolaSignal(route));
  }
  const reasons = [
    analysis.unresolvedIncludes > 0 ? `${analysis.unresolvedIncludes} include_router edge(s) could not be resolved` : undefined,
    "Object authorization is inferred from local source patterns; ORM wrappers and external policy engines may require manual review",
    truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
  ].filter((value): value is string => Boolean(value));
  return {
    signals,
    coverage: {
      domain: "fastapi-object-authorization",
      engine: "aisec-python",
      status: "partial",
      required: true,
      reason: reasons.join("; "),
      durationMs: Date.now() - started,
    },
  };
}
