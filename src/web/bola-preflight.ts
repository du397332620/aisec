import type {
  BolaAuthorizationCheck,
  BolaAuthorizationManifest,
  BolaAuthorizationTemplate,
  BolaAuthorizationTemplateCase,
  BolaDraftCandidate,
  BolaDraftEvidenceMode,
  BolaDraftPlan,
} from "../schema.js";
import {
  BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION,
  BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION,
  SCHEMA_VERSION,
} from "../schema.js";
import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateBolaAuthorizationCheck,
  validateBolaAuthorizationTemplate,
  validateBolaDraftPlan,
} from "../core/schema-validation.js";
import { sha256, stableId } from "../core/utils.js";
import {
  MAX_AUTHORIZATION_DOCUMENT_BYTES,
  loadBolaAuthorization,
  validateBolaAuthorization,
} from "./authorization.js";

export const MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES = MAX_AUTHORIZATION_DOCUMENT_BYTES;

const TEMPLATE_REVIEW_CHECKLIST = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Create two distinct low-privilege accounts and pre-created synthetic owner fixtures; never enumerate identifiers.",
  "Replace every target, login, fixture, route/body and response-evidence placeholder after reviewing each binding.",
  "Confirm every case is read-only and ownerIdentity evidence is server-derived rather than request-echoed.",
  "Copy only the completed manifest object to a separate file and run check-bola before any active verification.",
] as const;

const CHECK_REVIEW_REQUIREMENTS = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Provide two distinct low-privilege accounts through the declared environment variable names.",
  "Confirm every object identifier references only a pre-created synthetic owner fixture; never enumerate identifiers.",
  "Confirm every case is read-only and its response evidence is server-derived rather than request-echoed.",
  "Run verify-bola with --confirm only after this manual review.",
] as const;

function caseId(candidate: BolaDraftCandidate): string {
  return `case_${candidate.id.slice(-16)}`;
}

function evidenceMode(candidate: BolaDraftCandidate): BolaDraftEvidenceMode {
  return candidate.expectedTemplate?.match === "ownerIdentity" ? "ownerIdentity" : "testDataLabel";
}

function templateCase(candidate: BolaDraftCandidate, index: number): BolaAuthorizationTemplateCase {
  const request = candidate.requestTemplate;
  const expected = candidate.expectedTemplate;
  if (candidate.classification !== "read_candidate" || !request || !expected) {
    throw new Error(`Selected BOLA candidate ${candidate.id} is missing a read request template`);
  }
  if (candidate.objectIdFields.length === 0) {
    throw new Error(`Selected BOLA candidate ${candidate.id} has no object identifier field`);
  }
  const testDataLabel = `<SET_TEST_DATA_LABEL_${String(index + 1).padStart(2, "0")}>`;
  const mode = evidenceMode(candidate);
  return {
    id: caseId(candidate),
    method: request.method,
    path: request.path,
    readOnly: true,
    testDataLabel,
    ownerAccount: "owner",
    otherAccount: "other",
    ...(request.body === undefined ? {} : { body: { ...request.body } }),
    expected: mode === "ownerIdentity"
      ? {
          match: "ownerIdentity",
          statusCodes: [200],
          jsonPath: "<REVIEW_JSON_PATH_TO_SERVER_DERIVED_OWNER_FIELD>",
        }
      : {
          match: "testDataLabel",
          statusCodes: [200],
          jsonPath: "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>",
          value: testDataLabel,
        },
  };
}

function templateStableId(template: Omit<BolaAuthorizationTemplate, "templateId">): string {
  return stableId(
    "bola_template",
    template.draftId,
    template.scanId,
    template.projectId,
    template.selection.queueId,
    template.selection.queueCoverage,
    template.selection.queueCoverageScope,
    ...template.selection.candidateIds,
    ...template.bindings.flatMap((binding) => [
      binding.bolaCandidateId,
      binding.signalId,
      binding.route,
      binding.objectIdFields.join(","),
      binding.evidenceMode,
    ]),
  );
}

export function createBolaAuthorizationTemplate(value: unknown): BolaAuthorizationTemplate {
  const draft = validateBolaDraftPlan(value);
  if (draft.schemaVersion !== "1.1.0" || !draft.selection) {
    throw new Error("prepare-bola requires a selected BolaDraftPlan 1.1.0");
  }
  const cases = draft.candidates.map(templateCase);
  const bindings = draft.candidates.map((candidate, index) => {
    const source = draft.selection!.bindings[index]!;
    return {
      caseId: caseId(candidate),
      interfaceCandidateId: source.interfaceCandidateId,
      bolaCandidateId: candidate.id,
      signalId: source.signalId,
      route: source.route,
      objectIdFields: [...candidate.objectIdFields],
      evidenceMode: evidenceMode(candidate),
      reviewRequirements: {
        concretePrecreatedObjectId: true as const,
        readOnlySemantics: true as const,
        responseEvidence: true as const,
      },
    };
  });
  const withoutId: Omit<BolaAuthorizationTemplate, "templateId"> = {
    schemaVersion: BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION,
    draftId: draft.draftId,
    scanId: draft.scanId,
    projectId: draft.projectId,
    generatedAt: new Date().toISOString(),
    status: "placeholders_required",
    networkRequests: 0,
    selection: {
      mode: "interface_queue",
      queueId: draft.selection.queueId,
      queueCoverage: draft.selection.queueCoverage,
      queueCoverageScope: draft.selection.queueCoverageScope,
      candidateIds: [...draft.selection.candidateIds],
    },
    manifest: {
      schemaVersion: SCHEMA_VERSION,
      targetBaseUrl: "<SET_AUTHORIZED_BASE_URL>",
      environment: "<SET_LOCAL_TEST_OR_STAGING>",
      ownedBy: "<SET_AUTHORIZATION_OWNER>",
      allowedHosts: ["<SET_EXACT_AUTHORIZED_HOST>"],
      dataPrefix: "<SET_AISEC_DATA_PREFIX>",
      maxRequests: 2 + cases.length * 2,
      accounts: [
        { label: "owner", usernameEnv: "AISEC_BOLA_OWNER_USERNAME", passwordEnv: "AISEC_BOLA_OWNER_PASSWORD" },
        { label: "other", usernameEnv: "AISEC_BOLA_OTHER_USERNAME", passwordEnv: "AISEC_BOLA_OTHER_PASSWORD" },
      ],
      login: {
        path: "<SET_LOGIN_PATH>",
        usernameField: "<SET_LOGIN_USERNAME_FIELD>",
        passwordField: "<SET_LOGIN_PASSWORD_FIELD>",
        successStatusCodes: [200],
        tokenJsonPath: "<SET_LOGIN_TOKEN_JSON_PATH>",
        identityJsonPath: "<SET_LOGIN_IDENTITY_JSON_PATH>",
        tokenPrefix: "Bearer",
      },
      cases,
      acknowledgment: "<REVIEW_AND_SET_AUTHORIZATION_ACKNOWLEDGMENT>",
    },
    bindings,
    reviewChecklist: [...TEMPLATE_REVIEW_CHECKLIST],
    nextCommand: "aisec check-bola --authorization <completed-manifest.yml>",
    disclaimer: "This template contains unresolved instructions and is intentionally not executable. It performs no network requests and does not grant authorization or prove a vulnerability.",
  };
  return validateBolaAuthorizationTemplate({
    ...withoutId,
    templateId: templateStableId(withoutId),
  });
}

export async function loadSelectedBolaDraft(path: string): Promise<BolaDraftPlan> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
    "Selected BOLA draft",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("Selected BOLA draft must be valid JSON");
  }
  const draft = validateBolaDraftPlan(parsed);
  if (draft.schemaVersion !== "1.1.0" || !draft.selection) {
    throw new Error("prepare-bola requires a selected BolaDraftPlan 1.1.0");
  }
  return draft;
}

export async function prepareBola(path: string): Promise<BolaAuthorizationTemplate> {
  return createBolaAuthorizationTemplate(await loadSelectedBolaDraft(path));
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
    .join(",")}}`;
}

export function checkBolaAuthorization(value: unknown): BolaAuthorizationCheck {
  const manifest: BolaAuthorizationManifest = validateBolaAuthorization(value);
  const manifestDigestSha256 = sha256(canonicalJson(manifest));
  const cases = manifest.cases.length;
  const check: BolaAuthorizationCheck = {
    schemaVersion: BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION,
    checkId: stableId("bola_check", manifestDigestSha256),
    checkedAt: new Date().toISOString(),
    status: "valid_review_required",
    manifestDigestSha256,
    environment: manifest.environment,
    summary: {
      cases,
      requiredRequests: 2 + cases * 2,
      maxRequests: manifest.maxRequests,
      getCases: manifest.cases.filter((item) => item.method === "GET").length,
      postCases: manifest.cases.filter((item) => item.method === "POST").length,
      testDataLabelCases: manifest.cases.filter((item) => item.expected.match !== "ownerIdentity").length,
      ownerIdentityCases: manifest.cases.filter((item) => item.expected.match === "ownerIdentity").length,
    },
    caseIds: manifest.cases.map((item) => item.id),
    networkRequests: 0,
    environmentValuesRead: 0,
    dnsLookups: 0,
    reviewRequired: [...CHECK_REVIEW_REQUIREMENTS],
    nextCommand: "aisec verify-bola --authorization <same-reviewed-manifest.yml> --confirm",
    disclaimer: "This offline check validates manifest structure and declared safety constraints only. It performs no environment-value reads, DNS lookups or network requests and does not prove authorization, reachability, protection or vulnerability.",
  };
  return validateBolaAuthorizationCheck(check);
}

export async function checkBola(path: string): Promise<BolaAuthorizationCheck> {
  return checkBolaAuthorization(await loadBolaAuthorization(path));
}
