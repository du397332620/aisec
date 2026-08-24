import type {
  BolaDraftCandidate,
  BolaDraftPlan,
  InterfaceVerificationCandidate,
  InterfaceVerificationSource,
  ScanReport,
  Signal,
  SourceLocation,
} from "../schema.js";
import { BOLA_DRAFT_SCHEMA_VERSION, SCHEMA_VERSION } from "../schema.js";
import { loadReport } from "../core/store.js";
import { stableId } from "../core/utils.js";
import { validateBolaDraftPlan } from "../core/schema-validation.js";
import { classifyBolaStaticRoute } from "./bola-policy.js";
import { createInterfaceVerificationQueue } from "./interface-verification-queue.js";

const ROUTE = /^([A-Z]+)\s+(\/\S+)$/;
const INTERFACE_CANDIDATE_ID = /^interface_candidate_[0-9a-f]{16}$/u;
const MAX_SELECTED_CANDIDATES = 9;

interface CandidateOverride {
  route: { method: string; path: string };
  handler: string;
  objectIdFields: string[];
  location: SourceLocation;
}

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

function candidateFromSignal(signal: Signal, override?: CandidateOverride): BolaDraftCandidate | undefined {
  const route = override?.route ?? routeFromSignal(signal);
  if (!route) return undefined;
  const classification = classifyBolaStaticRoute(route.method, route.path);
  const objectIdFields = override ? [...override.objectIdFields] : stringArray(signal.metadata?.objectIdFields);
  const ownerFields = classification.classification === "read_candidate"
    ? ownerIdentityFieldCandidates(signal, objectIdFields)
    : [];
  const suggestedEvidenceMode = ownerFields.length > 0 ? "ownerIdentity" : "testDataLabel";
  const evidenceSuggestionReason = suggestedEvidenceMode === "ownerIdentity"
    ? `Static response evidence contains possible server-derived ownership field(s): ${ownerFields.join(", ")}. Confirm the field and response envelope before use.`
    : "No distinct response ownership field was identified with sufficient confidence; use an exact synthetic test-data marker unless manual review establishes ownerIdentity evidence.";
  const handler = override?.handler ?? (typeof signal.metadata?.handler === "string" ? signal.metadata.handler : "unknown");
  const source = override?.location ?? sourceLocation(signal);
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
    .map((signal) => candidateFromSignal(signal))
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

function validateSelectedIds(candidateIds: readonly string[]): string[] {
  if (!Array.isArray(candidateIds) || candidateIds.length < 1 || candidateIds.length > MAX_SELECTED_CANDIDATES) {
    throw new Error("Selected BOLA draft requires one to nine candidate IDs");
  }
  const result: string[] = [];
  const seen = new Set<string>();
  for (const candidateId of candidateIds) {
    if (typeof candidateId !== "string" || !INTERFACE_CANDIDATE_ID.test(candidateId)) {
      throw new Error(`Selected BOLA draft candidate ID is invalid: ${String(candidateId)}`);
    }
    if (seen.has(candidateId)) throw new Error(`Selected BOLA draft contains a duplicate interface candidate ID: ${candidateId}`);
    seen.add(candidateId);
    result.push(candidateId);
  }
  return result;
}

function exactSelectedSource(candidate: InterfaceVerificationCandidate): InterfaceVerificationSource {
  if (candidate.sourceCount !== 1 || candidate.sources.length !== 1 || candidate.omittedSources !== 0) {
    throw new Error(`Selected interface candidate ${candidate.id} must have exactly one complete source`);
  }
  const source = candidate.sources[0]!;
  if (source.omittedOpenFindingIds !== 0) {
    throw new Error(`Selected interface candidate ${candidate.id} omits open finding IDs`);
  }
  return source;
}

function matchingSignal(report: ScanReport, source: InterfaceVerificationSource): Signal {
  const matches = report.signals.filter((signal) => signal.id === source.signalId);
  if (matches.length !== 1) {
    throw new Error(`Selected interface source ${source.signalId} does not resolve to exactly one scan signal`);
  }
  const signal = matches[0]!;
  if (signal.ruleId !== source.ruleId
    || signal.fingerprint !== source.fingerprint
    || signal.evidenceLevel !== source.evidenceLevel) {
    throw new Error(`Selected interface source ${source.signalId} does not match canonical scan evidence`);
  }
  return signal;
}

function selectedCandidate(
  report: ScanReport,
  candidate: InterfaceVerificationCandidate,
): BolaDraftCandidate {
  const source = exactSelectedSource(candidate);
  const signal = matchingSignal(report, source);
  const draftCandidate = candidateFromSignal(signal, {
    route: { method: candidate.method, path: candidate.path },
    handler: source.handler,
    objectIdFields: candidate.objectIdFields,
    location: { ...source.location },
  });
  if (!draftCandidate || draftCandidate.classification !== "read_candidate") {
    throw new Error(`Selected interface candidate ${candidate.id} is not a BOLA read candidate`);
  }
  return draftCandidate;
}

export function createSelectedBolaDraftPlan(
  report: ScanReport,
  candidateIds: readonly string[],
): BolaDraftPlan {
  const requestedIds = validateSelectedIds(candidateIds);
  const requested = new Set(requestedIds);
  const queue = createInterfaceVerificationQueue(report);
  const selected = queue.candidates.filter((candidate) => requested.has(candidate.id));
  if (selected.length !== requestedIds.length) {
    const visible = new Set(selected.map((candidate) => candidate.id));
    const missing = requestedIds.find((candidateId) => !visible.has(candidateId));
    throw new Error(`Selected interface candidate is not an emitted eligible candidate in this scan: ${missing ?? "unknown"}`);
  }

  const candidates = selected.map((candidate) => selectedCandidate(report, candidate));
  const routeIdentities = new Set(candidates.map((candidate) => `${candidate.method}\u0000${candidate.path}`));
  if (routeIdentities.size !== candidates.length) {
    throw new Error("Selected interface candidates contain a duplicate exact route");
  }
  const bindings = selected.map((candidate, index) => ({
    interfaceCandidateId: candidate.id,
    bolaCandidateId: candidates[index]!.id,
    signalId: candidates[index]!.source.signalId,
    route: candidate.route,
  }));
  const selectedIds = selected.map((candidate) => candidate.id);

  return validateBolaDraftPlan({
    schemaVersion: BOLA_DRAFT_SCHEMA_VERSION,
    draftId: stableId(
      "bola_draft",
      report.scanId,
      queue.queueId,
      ...selectedIds,
      ...candidates.map((candidate) => candidate.id),
    ),
    scanId: report.scanId,
    projectId: report.profile.projectId,
    generatedAt: new Date().toISOString(),
    status: "review_required",
    summary: {
      total: candidates.length,
      readCandidates: candidates.length,
      mutationExcluded: 0,
      manualReview: 0,
    },
    candidates,
    selection: {
      mode: "interface_queue",
      queueId: queue.queueId,
      queueCoverage: queue.coverage,
      queueCoverageScope: queue.coverageScope,
      candidateIds: selectedIds,
      bindings,
    },
    prerequisites: [
      "Selection is bound to a queue regenerated from this same scan report; review the recorded queue coverage and exact route bindings.",
      "Use only an explicitly authorized local, test, or staging target; production is refused.",
      "Select no more than nine read_candidate entries per authorization manifest.",
      "Create two distinct low-privilege test accounts and a dedicated synthetic object owned by the owner account.",
      "Replace every request placeholder with the exact pre-created object identifier; never enumerate identifiers.",
      "Choose the evidence mode after reviewing the response: use a primitive synthetic aisec-* marker, or accept suggested ownerIdentity only when the field is server-derived from the stored object and matches the login identity.",
      "For ownerIdentity suggestions, replace the JSON-path placeholder after confirming the exact response envelope; never use a request-supplied or caller-echoed field.",
      "Review the completed authorization manifest before running verify-bola --confirm.",
    ],
    nextCommand: "aisec verify-bola --authorization <reviewed-manifest.yml> --confirm",
    disclaimer: "This is a selected static review worksheet, not an executable authorization manifest. It performs no network requests and does not prove a vulnerability.",
  });
}

export async function draftBola(reference: string, candidateIds?: readonly string[]): Promise<BolaDraftPlan> {
  const report = await loadReport(reference);
  return candidateIds === undefined
    ? createBolaDraftPlan(report)
    : createSelectedBolaDraftPlan(report, candidateIds);
}
