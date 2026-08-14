import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { analyzeNodeApi, type NodeApiRoute } from "../api/node.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import { createSignal } from "../core/utils.js";

const EXPLICIT_PUBLIC_PATH = /(?:^|\/)(?:login|log-in|register|sign-up|signup|health|healthz|ready|readiness|live|liveness|favicon\.ico|docs|openapi(?:\.json)?|swagger)\/?$/i;
const EXPLICIT_LOGIN_PATH = /(?:^|\/)(?:login|log-in|sign-in)\/?$/i;
const SENSITIVE_PATH = /(?:^|\/)(?:admin|internal|manage|users?|permissions?|roles?|projects?|documents?|reports?|chapters?|templates?|knowledge|signatures?|chat|generate|review|uploads?|downloads?|tokens?|sessions?|billing|payments?)(?:\/|$)/i;
const PRIVILEGED_PATH = /(?:^|\/)(?:admin|internal|manage|management|permissions?|roles?)(?:\/|$)/i;
const AUTH_SESSION_ROUTE = /(?:^|\/)(?:login|logout|token|session\/current|me|profile)(?:\/|$)/i;
const RULES = {
  expressAuth: { ruleId: "express.auth.sensitive-route-without-guard" },
  expressObjectAuthorization: { ruleId: "express.authorization.object-without-ownership-check" },
  expressPrivilegedAuthorization: { ruleId: "express.authorization.privileged-operation-without-role-check" },
  nestAuth: { ruleId: "nestjs.auth.sensitive-route-without-guard" },
  nestObjectAuthorization: { ruleId: "nestjs.authorization.object-without-ownership-check" },
  nestPrivilegedAuthorization: { ruleId: "nestjs.authorization.privileged-operation-without-role-check" },
} as const;

function isSensitiveRoute(route: NodeApiRoute, routes: NodeApiRoute[]): boolean {
  if (PRIVILEGED_PATH.test(route.path) || PRIVILEGED_PATH.test(route.declaredPath)) {
    return !EXPLICIT_LOGIN_PATH.test(route.path);
  }
  if (explicitPublicAuthEntry(route, routes)) return false;
  if (EXPLICIT_PUBLIC_PATH.test(route.path)) return false;
  if (["POST", "PUT", "PATCH", "DELETE", "ALL"].includes(route.method)) return true;
  return SENSITIVE_PATH.test(route.path);
}

function explicitPublicAuthEntry(route: NodeApiRoute, routes: NodeApiRoute[]): boolean {
  if (PRIVILEGED_PATH.test(route.path) || PRIVILEGED_PATH.test(route.declaredPath)) return false;
  const path = route.declaredPath;
  const semantics = `${route.handlerName}\n${route.handlerSource}`;
  if (route.method === "POST" && /^\/users?\/?$/i.test(path)) {
    if (/(?:sign\s*up|signup|register)/i.test(semantics)) return true;
    const hasAuthenticationSibling = routes.some((candidate) => candidate.framework === route.framework
      && /(?:^|\/)(?:login|log-in|sign-in|auth\/anonymous)\/?$/i.test(candidate.declaredPath));
    if (hasAuthenticationSibling && /createUser/i.test(semantics)) return true;
  }
  if (/^\/auth\/anonymous\/?$/i.test(path)
    && /(?:accessTokenLogin|anonymousLogin|validateAnonymousLogin)/i.test(semantics)) return true;
  if (/^\/auth\/webauthn\/(?:generate-authentication-options|verify-authentication)\/?$/i.test(path)
    && /(?:generateAuthenticationOptions|verifyAuthentication)/i.test(semantics)) return true;
  return false;
}

function frameworkId(route: NodeApiRoute): "express" | "nestjs" {
  return route.framework === "Express" ? "express" : "nestjs";
}

function unguardedSignal(route: NodeApiRoute): Signal {
  const framework = frameworkId(route);
  const ruleId = route.framework === "Express" ? RULES.expressAuth.ruleId : RULES.nestAuth.ruleId;
  return createSignal({
    engine: "aisec-typescript",
    ruleId,
    title: `${route.framework} sensitive route has no visible authentication guard`,
    description: `${route.method} ${route.path} has no recognized route, router, controller, application, or handler authentication guard. An upstream gateway or framework extension may still protect it.`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: [route.location],
    cwe: ["CWE-306", "CWE-862"],
    owasp: ["A01:2021", "A07:2021"],
    tags: [framework, "nodejs", "api", "auth", "authorization"],
    remediation: "Require a server-verified identity at the application, controller/router, or route boundary, and verify unauthenticated requests receive 401 or 403 in the deployed environment.",
    metadata: { route: `${route.method} ${route.path}`, handler: route.handlerName, framework: route.framework },
  });
}

function bolaSignal(route: NodeApiRoute): Signal {
  const framework = frameworkId(route);
  const ruleId = route.framework === "Express"
    ? RULES.expressObjectAuthorization.ruleId
    : RULES.nestObjectAuthorization.ruleId;
  return createSignal({
    engine: "aisec-typescript",
    ruleId,
    title: `${route.framework} object operation has no visible ownership or role check`,
    description: `${route.method} ${route.path} is authenticated, accepts an object identifier, and performs a lookup or mutation, but no recognized owner, tenant, permission, policy, role, or administrator constraint is visible. Authentication alone does not prove that the caller may access this object.`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: [route.location],
    cwe: ["CWE-639", "CWE-862"],
    owasp: ["A01:2021", "API1:2023"],
    tags: [framework, "nodejs", "api", "authorization", "bola", "idor", "ownership"],
    remediation: "Bind the requested object to the authenticated subject or tenant in the database query, or call a centralized policy/ownership guard. Verify with two low-privilege accounts that cross-account identifiers receive 403 or 404.",
    metadata: {
      route: `${route.method} ${route.path}`,
      handler: route.handlerName,
      framework: route.framework,
      objectIdFields: route.objectIdFields,
      ownerIdentityFields: route.responseOwnerFields,
    },
  });
}

function privilegedAuthorizationSignal(route: NodeApiRoute): Signal {
  const framework = frameworkId(route);
  const ruleId = route.framework === "Express"
    ? RULES.expressPrivilegedAuthorization.ruleId
    : RULES.nestPrivilegedAuthorization.ruleId;
  return createSignal({
    engine: "aisec-typescript",
    ruleId,
    title: `${route.framework} privileged operation has no visible role or permission check`,
    description: `${route.method} ${route.path} is authenticated and exposes administrator, role, permission, or all-user management semantics, but no recognized role, permission, policy, ability, or administrator constraint is visible.`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: [route.location],
    cwe: ["CWE-862", "CWE-863"],
    owasp: ["A01:2021", "API5:2023"],
    tags: [framework, "nodejs", "api", "authorization", "role", "permission"],
    remediation: "Enforce the required role or permission at the route boundary or in a centralized policy guard, then verify that an authenticated low-privilege account receives 403 or 404.",
    metadata: { route: `${route.method} ${route.path}`, handler: route.handlerName, framework: route.framework },
  });
}

export async function runNodeApiSecurity(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const analysis = analyzeNodeApi(context.inventory.files);
  if (!analysis.detectedExpress && !analysis.detectedNest) {
    return {
      signals: [],
      coverage: {
        domain: "node-api-security",
        engine: "aisec-typescript",
        status: "not_run",
        required: false,
        reason: "No Express or NestJS project detected",
        durationMs: Date.now() - started,
      },
    };
  }

  const signals: Signal[] = [];
  let truncated = false;
  const add = (signal: Signal): void => {
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) truncated = true;
    else signals.push(signal);
  };
  for (const route of analysis.routes) {
    if (truncated) break;
    if (isSensitiveRoute(route, analysis.routes) && !route.authenticationProtected) add(unguardedSignal(route));
    if (truncated) break;
    if (route.authenticationProtected && !route.ownershipProtected && !route.roleProtected && route.objectOperation
      && !AUTH_SESSION_ROUTE.test(route.path)) add(bolaSignal(route));
    if (truncated) break;
    if (route.authenticationProtected && route.privilegedOperation && !route.roleProtected) {
      add(privilegedAuthorizationSignal(route));
    }
  }

  const detected = [analysis.detectedExpress ? "Express" : undefined, analysis.detectedNest ? "NestJS" : undefined].filter(Boolean).join(" and ");
  const reasons = [
    `${detected} route and authorization coverage is bounded static inference; package aliases, dynamic registrations outside the supported local-constant forEach form, framework extensions, factory-provided dependencies, local call chains beyond the four-edge traversal limit, complex ORM wrappers, and external policy engines may require manual review`,
    analysis.filesWithParseErrors > 0 ? `${analysis.filesWithParseErrors} JavaScript/TypeScript source file(s) had parser diagnostics` : undefined,
    analysis.unresolvedHandlers > 0 ? `${analysis.unresolvedHandlers} Express handler reference(s) could not be resolved locally or through a relative module import` : undefined,
    analysis.unresolvedMounts > 0 ? `${analysis.unresolvedMounts} Express router mount(s) could not be resolved locally or through a relative module import` : undefined,
    analysis.unresolvedRegistrations > 0 ? `${analysis.unresolvedRegistrations} Express route registration site(s) could not be statically expanded` : undefined,
    analysis.routes.length === 0 ? `${detected} was detected but no supported routes were resolved` : undefined,
    truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
  ].filter((value): value is string => Boolean(value));
  return {
    signals,
    coverage: {
      domain: "node-api-security",
      engine: "aisec-typescript",
      status: "partial",
      required: true,
      reason: reasons.join("; "),
      durationMs: Date.now() - started,
    },
  };
}
