import type {
  BolaDraftCandidate,
  BolaDraftPlan,
  ScanReport,
  Signal,
  SourceLocation,
} from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { loadReport } from "../core/store.js";
import { stableId } from "../core/utils.js";
import { validateBolaDraftPlan } from "../core/schema-validation.js";
import { classifyBolaStaticRoute } from "./bola-policy.js";

const ROUTE = /^([A-Z]+)\s+(\/\S+)$/;

function sourceLocation(signal: Signal): SourceLocation {
  return signal.locations[0] ?? { path: "unknown" };
}

function routeFromSignal(signal: Signal): { method: string; path: string } | undefined {
  const value = signal.metadata?.route;
  if (typeof value !== "string") return undefined;
  const match = ROUTE.exec(value.trim());
  if (!match?.[1] || !match[2]) return undefined;
  return { method: match[1], path: match[2] };
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((item): item is string => typeof item === "string" && /^[A-Za-z_]\w*$/.test(item)))].sort();
}

function candidateSlug(path: string): string {
  const slug = path.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48);
  return slug || "object-read";
}

function requestBodyTemplate(method: string, objectIdFields: string[]): Record<string, string> | undefined {
  if (method !== "POST") return undefined;
  return Object.fromEntries(objectIdFields.map((field) => [field, `<SET_PRECREATED_OWNER_${field.toUpperCase()}>`]));
}

function ownerIdentityFieldCandidates(signal: Signal, objectIdFields: string[]): string[] {
  const candidates = stringArray(signal.metadata?.ownerIdentityFields);
  const requestFields = new Set(objectIdFields.map((field) => field.toLowerCase()));
  return candidates.filter((field) => !requestFields.has(field.toLowerCase()));
}

function candidateFromSignal(signal: Signal): BolaDraftCandidate | undefined {
  const route = routeFromSignal(signal);
  if (!route) return undefined;
  const classification = classifyBolaStaticRoute(route.method, route.path);
  const objectIdFields = stringArray(signal.metadata?.objectIdFields);
  const ownerFields = classification.classification === "read_candidate"
    ? ownerIdentityFieldCandidates(signal, objectIdFields)
    : [];
  const suggestedEvidenceMode = ownerFields.length > 0 ? "ownerIdentity" : "testDataLabel";
  const evidenceSuggestionReason = suggestedEvidenceMode === "ownerIdentity"
    ? `Static response evidence contains possible server-derived ownership field(s): ${ownerFields.join(", ")}. Confirm the field and response envelope before use.`
    : "No distinct response ownership field was identified with sufficient confidence; use an exact synthetic test-data marker unless manual review establishes ownerIdentity evidence.";
  const handler = typeof signal.metadata?.handler === "string" ? signal.metadata.handler : "unknown";
  const source = sourceLocation(signal);
  const id = stableId("bola_candidate", signal.fingerprint, route.method, route.path);
  return {
    id,
    classification: classification.classification,
    reason: classification.reason,
    method: route.method,
    path: route.path,
    handler,
    objectIdFields,
    suggestedEvidenceMode,
    ownerIdentityFieldCandidates: ownerFields,
    evidenceSuggestionReason,
    source: {
      signalId: signal.id,
      ruleId: signal.ruleId,
      fingerprint: signal.fingerprint,
      evidenceLevel: signal.evidenceLevel,
      location: source,
    },
    ...(classification.classification === "read_candidate" ? {
      requestTemplate: {
        method: route.method as "GET" | "POST",
        path: route.path,
        ...(requestBodyTemplate(route.method, objectIdFields) === undefined
          ? {}
          : { body: requestBodyTemplate(route.method, objectIdFields) }),
      },
      expectedTemplate: suggestedEvidenceMode === "ownerIdentity"
        ? {
            match: "ownerIdentity",
            statusCodes: [200],
            jsonPath: "<REVIEW_JSON_PATH_TO_SERVER_DERIVED_OWNER_FIELD>",
          }
        : {
            statusCodes: [200],
            jsonPath: "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>",
            value: `aisec-draft-${candidateSlug(route.path)}`,
          },
    } : {}),
  };
}

function isBolaSignal(signal: Signal): boolean {
  return signal.tags.includes("bola") || signal.tags.includes("idor");
}

export function createBolaDraftPlan(report: ScanReport): BolaDraftPlan {
  const openSignalIds = new Set(report.findings
    .filter((finding) => finding.status === "open")
    .flatMap((finding) => finding.signalIds));
  const candidates = report.signals
    .filter((signal) => openSignalIds.has(signal.id) && isBolaSignal(signal))
    .map(candidateFromSignal)
    .filter((candidate): candidate is BolaDraftCandidate => Boolean(candidate))
    .filter((candidate, index, all) => all.findIndex((item) => item.method === candidate.method && item.path === candidate.path) === index)
    .sort((left, right) => left.classification.localeCompare(right.classification)
      || left.path.localeCompare(right.path)
      || left.method.localeCompare(right.method));
  const summary = {
    total: candidates.length,
    readCandidates: candidates.filter((candidate) => candidate.classification === "read_candidate").length,
    mutationExcluded: candidates.filter((candidate) => candidate.classification === "mutation_excluded").length,
    manualReview: candidates.filter((candidate) => candidate.classification === "manual_review").length,
  };
  return validateBolaDraftPlan({
    schemaVersion: SCHEMA_VERSION,
    draftId: stableId("bola_draft", report.scanId, ...candidates.map((candidate) => candidate.id)),
    scanId: report.scanId,
    projectId: report.profile.projectId,
    generatedAt: new Date().toISOString(),
    status: "review_required",
    summary,
    candidates,
    prerequisites: [
      "Use only an explicitly authorized local, test, or staging target; production is refused.",
      "Select no more than nine read_candidate entries per authorization manifest.",
      "Create two distinct low-privilege test accounts and a dedicated synthetic object owned by the owner account.",
      "Replace every request placeholder with the exact pre-created object identifier; never enumerate identifiers.",
      "Choose the evidence mode after reviewing the response: use a primitive synthetic aisec-* marker, or accept suggested ownerIdentity only when the field is server-derived from the stored object and matches the login identity.",
      "For ownerIdentity suggestions, replace the JSON-path placeholder after confirming the exact response envelope; never use a request-supplied or caller-echoed field.",
      "Review the completed authorization manifest before running verify-bola --confirm.",
    ],
    nextCommand: "aisec verify-bola --authorization <reviewed-manifest.yml> --confirm",
    disclaimer: "This is a static review worksheet, not an executable authorization manifest. It performs no network requests and does not prove a vulnerability.",
  });
}

export async function draftBola(reference: string): Promise<BolaDraftPlan> {
  return createBolaDraftPlan(await loadReport(reference));
}
