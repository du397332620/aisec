import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { analyzeFastApi, pythonCodeMask, type FastApiRoute } from "../api/fastapi.js";
import { createSignal } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const PRIVILEGED_PATH = /(?:^|\/)(?:(?:admin|administration|internal|manage|management|permissions?|roles?)(?:\/|$)|(?:admin|administration|internal)[-_](?:config|settings?|tools?|api|console|panel)(?:\/|$)|(?:role|permission)[-_](?:management|admin)(?:\/|$))/i;
const PUBLIC_AUTH_ACTION = /(?:^|\/)(?:login|log-in|sign-in|register|sign-up|signup|logout|token|session\/current|me|profile|health|healthz|ready|readiness|live|liveness|docs|redoc|openapi\.json)\/?$/i;
const PRIVILEGED_HANDLER = /(?:assign|grant|revoke|change|update|set|delete|remove).*(?:role|permission)|(?:role|permission).*(?:assign|grant|revoke|change|update|set|delete|remove)|(?:list|get|find).*(?:all|non_admin).*(?:users?|accounts?)/i;
const PRIVILEGED_CALL = /\b(?:assign_role|grant_permission|revoke_permission|update_user_role|get_all_users|list_all_users|get_all_non_admin_users)\s*\(/i;

function isAuthenticated(route: FastApiRoute): boolean {
  return route.locallyProtected || (route.middlewareProtected && !route.whitelist);
}

function isPrivilegedOperation(route: FastApiRoute): boolean {
  if (PUBLIC_AUTH_ACTION.test(route.path)) return false;
  return PRIVILEGED_PATH.test(route.path)
    || PRIVILEGED_HANDLER.test(route.handlerName)
    || PRIVILEGED_CALL.test(pythonCodeMask(route.handlerSource));
}

function privilegedAuthorizationSignal(route: FastApiRoute): Signal {
  return createSignal({
    engine: "aisec-python",
    ruleId: "fastapi.authorization.privileged-operation-without-role-check",
    title: "FastAPI privileged operation has no visible role or permission check",
    description: `${route.method} ${route.path} is authenticated and exposes administrator, role, permission, internal-management, or all-user-management semantics, but no recognized local role, permission, policy, or administrator enforcement is visible.`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: [route.location],
    cwe: ["CWE-862", "CWE-863"],
    owasp: ["A01:2021", "API5:2023"],
    tags: ["fastapi", "python", "api", "authorization", "role", "permission"],
    remediation: "Enforce the required role or permission through a server-side route/router dependency or a centralized policy guard, then verify that an authenticated low-privilege account is denied before business logic executes.",
    metadata: { route: `${route.method} ${route.path}`, handler: route.handlerName },
  });
}

export async function runPythonApiPrivilegedAuthorization(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const analysis = analyzeFastApi(context.inventory.files);
  if (!analysis.detected) {
    return {
      signals: [],
      coverage: {
        domain: "fastapi-privileged-authorization",
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
    if (!isAuthenticated(route) || route.privilegeProtected || !isPrivilegedOperation(route)) continue;
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) {
      truncated = true;
      break;
    }
    signals.push(privilegedAuthorizationSignal(route));
  }
  const reasons = [
    analysis.unresolvedIncludes > 0 ? `${analysis.unresolvedIncludes} include_router edge(s) could not be resolved` : undefined,
    "Privileged operations and role/permission enforcement are inferred from bounded local source patterns; imported or dynamic dependencies, complex policy control flow, and external authorization engines require manual review",
    truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
  ].filter((value): value is string => Boolean(value));
  return {
    signals,
    coverage: {
      domain: "fastapi-privileged-authorization",
      engine: "aisec-python",
      status: "partial",
      required: true,
      reason: reasons.join("; "),
      durationMs: Date.now() - started,
    },
  };
}
