export const BOLA_MUTATING_PATH_MARKERS = new Set([
  "create", "update", "delete", "remove", "save", "upload", "generate", "approve", "reject",
  "cancel", "submit", "publish", "archive", "restore", "assign", "grant", "revoke", "reset",
  "change", "logout", "register", "import", "execute", "run", "start", "stop", "retry", "edit",
  "modify", "insert", "enable", "disable", "activate", "deactivate", "attach", "detach",
]);

export const BOLA_READ_PATH_MARKERS = new Set([
  "detail", "get", "list", "info", "search", "query", "read", "view", "preview", "status",
  "history", "stats", "statistics", "download", "export", "find", "lookup", "check",
]);

export function bolaMarkerTokens(value: string): string[] {
  return value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function firstBolaMutatingMarker(tokens: string[]): string | undefined {
  return [...BOLA_MUTATING_PATH_MARKERS].find((marker) => tokens.includes(marker));
}

export function hasBolaReadMarker(tokens: string[]): boolean {
  return [...BOLA_READ_PATH_MARKERS].some((marker) => tokens.includes(marker));
}

export type BolaStaticRouteClassification = "read_candidate" | "mutation_excluded" | "manual_review";

export function classifyBolaStaticRoute(method: string, path: string): {
  classification: BolaStaticRouteClassification;
  reason: string;
} {
  const normalizedMethod = method.toUpperCase();
  const tokens = bolaMarkerTokens(path);
  const mutationMarker = firstBolaMutatingMarker(tokens);
  if (mutationMarker) {
    return {
      classification: "mutation_excluded",
      reason: `route path contains the state-changing marker ${mutationMarker}`,
    };
  }
  if (!["GET", "POST"].includes(normalizedMethod)) {
    return {
      classification: "mutation_excluded",
      reason: `${normalizedMethod} is not permitted by the read-only BOLA verifier`,
    };
  }
  if (normalizedMethod === "GET" || hasBolaReadMarker(tokens)) {
    return {
      classification: "read_candidate",
      reason: `${normalizedMethod} route has read-only-compatible path semantics; fixture details still require review`,
    };
  }
  return {
    classification: "manual_review",
    reason: "POST route lacks an explicit read/query marker and cannot be passed to verify-bola automatically",
  };
}
