import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Signal } from "../schema.js";
import { analyzeFastApi, type FastApiRoute } from "../api/fastapi.js";
import {
  createFastApiObjectCapabilityAnalyzer,
  type FastApiObjectCapabilityMutationEvidence,
} from "../api/fastapi-capability.js";
import { createSignal } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";
import { FASTAPI_OBJECT_CAPABILITY_EVIDENCE_VERSION } from "../schema.js";

const EXPLICIT_PUBLIC_PATH = /(?:^|\/)(?:login|log-in|register|sign-up|signup|health|healthz|ready|readiness|live|liveness|favicon\.ico|docs|redoc|openapi\.json)\/?$/i;
const EXPLICIT_PUBLIC_AUTH_POST = /(?:^|\/)(?:login\/access-token|password-recovery(?:\/[^/]+)?|reset-password|token(?:\/oauth2|\/2fa\/(?:totp|fido2\/(?:begin|complete)))?|users?\/(?:reset[_-]password|verify)(?:\/finalize)?)\/?$/i;
const SENSITIVE_PATH = /(?:^|\/)(?:admin|internal|manage|users?|permissions?|roles?|projects?|documents?|reports?|chapters?|templates?|knowledge|signatures?|chat|generate|review|uploads?|downloads?|tokens?|access-token|password-recovery|reset-password|sessions?|billing|payments?)(?:\/|$)/i;

function isSensitiveRoute(route: FastApiRoute): boolean {
  if (EXPLICIT_PUBLIC_PATH.test(route.path)) return false;
  if (route.method === "POST" && EXPLICIT_PUBLIC_AUTH_POST.test(route.path)) return false;
  if (["POST", "PUT", "PATCH", "DELETE"].includes(route.method)) return true;
  return SENSITIVE_PATH.test(route.path);
}

function whitelistedSignal(route: FastApiRoute): Signal {
  const whitelist = route.whitelist!;
  return createSignal({
    engine: "aisec-python",
    ruleId: "fastapi.auth.whitelisted-sensitive-route",
    title: "FastAPI sensitive route bypasses authentication through a global whitelist",
    description: `${route.method} ${route.path} matches the global ${whitelist.kind} whitelist ${whitelist.value}, while the route and router contain no recognized authentication dependency or explicit guard.`,
    severity: "high",
    evidenceLevel: "static_confirmed",
    confidence: "high",
    locations: [route.location, whitelist.location],
    cwe: ["CWE-306", "CWE-862"],
    owasp: ["A01:2021", "A07:2021"],
    tags: ["fastapi", "api", "auth", "authorization", "whitelist"],
    remediation: "Remove sensitive paths and broad prefixes from the authentication whitelist, and enforce a server-verified identity or role dependency at the route or router boundary.",
    metadata: {
      route: `${route.method} ${route.path}`,
      handler: route.handlerName,
      whitelistKind: whitelist.kind,
      whitelistValue: whitelist.value,
    },
  });
}

function unguardedSignal(
  route: FastApiRoute,
  capability?: FastApiObjectCapabilityMutationEvidence,
): Signal {
  const authenticationGapReason = route.optionalAuthentication
    ? "optional_or_disabled_guard"
    : "no_visible_guard";
  const authenticationDescription = route.optionalAuthentication
    ? `${route.method} ${route.path} uses a recognized authentication dependency configured as optional or disabled, so unauthenticated execution remains possible unless handler or service logic rejects it.`
    : `${route.method} ${route.path} is attached to a FastAPI application with no recognized authentication middleware, router dependency, route dependency, or explicit identity check. An upstream gateway may still protect it.`;
  const capabilityDescription = capability
    ? " Bounded static evidence also shows a path-supplied object identifier reaching a sensitive mutation; its generator, lifecycle and one-time-state fields are review evidence only, not authorization or exploitability proof."
    : "";
  return createSignal({
    engine: "aisec-python",
    ruleId: "fastapi.auth.sensitive-route-without-guard",
    title: "FastAPI sensitive route has no visible authentication guard",
    description: `${authenticationDescription}${capabilityDescription}`,
    severity: "high",
    evidenceLevel: "inferred",
    confidence: "medium",
    locations: capability?.locations ?? [route.location],
    cwe: ["CWE-306", "CWE-862"],
    owasp: ["A01:2021", "A07:2021"],
    tags: ["fastapi", "api", "auth", "authorization"],
    remediation: capability
      ? "Require a server-verified identity and explicit object authorization before the mutation. Separately review identifier generation, disclosure, expiry, replay/atomicity and abuse controls; generator evidence alone is not an access-control boundary."
      : "Require a server-verified user or service identity at the application, router, or route boundary, and verify unauthenticated requests receive 401 or 403 in the deployed environment.",
    metadata: {
      route: `${route.method} ${route.path}`,
      handler: route.handlerName,
      authenticationGapReason,
      ...(capability ? {
        objectCapabilityMutation: true,
        capabilityEvidenceVersion: FASTAPI_OBJECT_CAPABILITY_EVIDENCE_VERSION,
        capabilityIdentifierFields: capability.identifierFields,
        capabilityIdentifierSource: capability.identifierSource,
        capabilityEntropyEvidence: capability.entropyEvidence,
        capabilityLifecycleEvidence: capability.lifecycleEvidence,
        capabilityOneTimeEvidence: capability.oneTimeEvidence,
        capabilityMutationImpact: capability.mutationImpact,
        capabilityAnalysisDepth: capability.analysisDepth,
      } : {}),
    },
  });
}

export async function runPythonApiAuth(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const analysis = analyzeFastApi(context.inventory.files);
  if (!analysis.detected) {
    return {
      signals: [],
      coverage: {
        domain: "fastapi-authentication",
        engine: "aisec-python",
        status: "not_run",
        required: false,
        reason: "No FastAPI project detected",
        durationMs: Date.now() - started,
      },
    };
  }

  const signals: Signal[] = [];
  const capabilityEvidence = createFastApiObjectCapabilityAnalyzer(context.inventory.files);
  let truncated = false;
  for (const route of analysis.routes.filter(isSensitiveRoute)) {
    let signal: Signal | undefined;
    if (route.whitelist && !route.locallyProtected) signal = whitelistedSignal(route);
    else if (!route.middlewareProtected && !route.locallyProtected) {
      signal = unguardedSignal(route, capabilityEvidence(route));
    }
    if (!signal) continue;
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) {
      truncated = true;
      break;
    }
    signals.push(signal);
  }

  const reasons = [
    analysis.routes.length === 0 ? "FastAPI was detected but no reachable decorated routes were resolved" : undefined,
    analysis.unresolvedIncludes > 0 ? `${analysis.unresolvedIncludes} include_router edge(s) could not be resolved` : undefined,
    truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
  ].filter((value): value is string => Boolean(value));
  return {
    signals,
    coverage: {
      domain: "fastapi-authentication",
      engine: "aisec-python",
      status: reasons.length > 0 ? "partial" : "complete",
      required: true,
      reason: reasons.join("; ") || undefined,
      durationMs: Date.now() - started,
    },
  };
}
