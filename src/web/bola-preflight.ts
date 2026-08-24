import type {
  BolaAuthorizationCheck,
  BolaAuthorizationManifest,
  BolaAuthorizationTemplate,
  BolaAuthorizationTemplateBindingCheck,
  BolaAuthorizationTemplateCase,
  BolaDraftCandidate,
  BolaDraftEvidenceMode,
  BolaDraftPlan,
  BolaVerificationCase,
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
  "Keep this wrapper unchanged and run check-bola with both the completed manifest and this same template before any active verification.",
] as const;

const LEGACY_CHECK_REVIEW_REQUIREMENTS = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Provide two distinct low-privilege accounts through the declared environment variable names.",
  "Confirm every object identifier references only a pre-created synthetic owner fixture; never enumerate identifiers.",
  "Confirm every case is read-only and its response evidence is server-derived rather than request-echoed.",
  "Run verify-bola with --confirm only after this manual review.",
] as const;

const CHECK_REVIEW_REQUIREMENTS = [
  "Confirm the exact non-production target and written authorization with the named owner.",
  "Provide two distinct low-privilege accounts through the declared environment variable names.",
  "Confirm every object identifier references only a pre-created synthetic owner fixture; never enumerate identifiers.",
  "Confirm every case is read-only and its response evidence is server-derived rather than request-echoed.",
  "Run verify-bola with this manifest, unchanged template, saved check and --confirm only after this manual review.",
] as const;

const LEGACY_VERIFY_COMMAND = "aisec verify-bola --authorization <same-reviewed-manifest.yml> --confirm" as const;
const BOUND_VERIFY_COMMAND = "aisec verify-bola --authorization <same-reviewed-manifest.yml> --template <same-template.json> --check <this-check.json> --confirm" as const;

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
    nextCommand: "aisec check-bola --authorization <completed-manifest.yml> --template <same-template.json>",
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

export async function loadBolaAuthorizationTemplate(path: string): Promise<BolaAuthorizationTemplate> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
    "BOLA authorization template",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("BOLA authorization template must be valid JSON");
  }
  return validateBolaAuthorizationTemplate(parsed);
}

export async function loadBolaAuthorizationCheck(path: string): Promise<BolaAuthorizationCheck> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
    "BOLA authorization check",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("BOLA authorization check must be valid JSON");
  }
  return validateBolaAuthorizationCheck(parsed);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`)
    .join(",")}}`;
}

const ROUTE_PLACEHOLDER = /^(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|:([A-Za-z_][A-Za-z0-9_]*)|\[([A-Za-z_][A-Za-z0-9_]*)\]|\*([A-Za-z_][A-Za-z0-9_]*))$/u;
const POSSIBLE_ROUTE_PLACEHOLDER = /^(?:\{|:|\[|\*)/u;

function routePlaceholderName(value: string): string | undefined {
  const match = ROUTE_PLACEHOLDER.exec(value);
  return match?.slice(1).find((item): item is string => item !== undefined);
}

function concreteRouteValue(value: string, index: number): string {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    throw new Error(`BOLA template binding route contains invalid percent encoding at case index ${index}`);
  }
  if (!decoded || decoded === "." || decoded === ".." || decoded.length > 512
    || decoded.includes("/") || decoded.includes("\\") || /[\u0000-\u001f\u007f]/u.test(decoded)
    || POSSIBLE_ROUTE_PLACEHOLDER.test(decoded)) {
    throw new Error(`BOLA template binding route has an invalid concrete object identifier at case index ${index}`);
  }
  return decoded;
}

function recordRouteValue(
  values: Map<string, string>,
  name: string,
  value: string,
  index: number,
): void {
  const previous = values.get(name);
  if (previous !== undefined && previous !== value) {
    throw new Error(`BOLA template binding repeats an object identifier with different values at case index ${index}`);
  }
  values.set(name, value);
}

function splitRoute(value: string, index: number, source: "template" | "manifest"): {
  pathname: string;
  query: Array<[string, string]>;
} {
  if (value.includes("#")) {
    throw new Error(`BOLA template binding ${source} route contains a fragment at case index ${index}`);
  }
  const separator = value.indexOf("?");
  const pathname = separator === -1 ? value : value.slice(0, separator);
  const queryText = separator === -1 ? "" : value.slice(separator + 1);
  return { pathname, query: [...new URLSearchParams(queryText).entries()] };
}

function matchRouteTemplate(templatePath: string, manifestPath: string, index: number): Map<string, string> {
  const template = splitRoute(templatePath, index, "template");
  const manifest = splitRoute(manifestPath, index, "manifest");
  const templateSegments = template.pathname.split("/");
  const manifestSegments = manifest.pathname.split("/");
  if (templateSegments.length !== manifestSegments.length || template.query.length !== manifest.query.length) {
    throw new Error(`BOLA template binding route structure differs at case index ${index}`);
  }

  const values = new Map<string, string>();
  for (let part = 0; part < templateSegments.length; part += 1) {
    const expected = templateSegments[part]!;
    const actual = manifestSegments[part]!;
    const name = routePlaceholderName(expected);
    if (name) {
      recordRouteValue(values, name, concreteRouteValue(actual, index), index);
    } else if (POSSIBLE_ROUTE_PLACEHOLDER.test(expected)) {
      throw new Error(`BOLA template binding contains an unsupported route placeholder at case index ${index}`);
    } else if (expected !== actual) {
      throw new Error(`BOLA template binding static route differs at case index ${index}`);
    }
  }

  for (let part = 0; part < template.query.length; part += 1) {
    const [expectedKey, expectedValue] = template.query[part]!;
    const [actualKey, actualValue] = manifest.query[part]!;
    if (expectedKey !== actualKey || POSSIBLE_ROUTE_PLACEHOLDER.test(expectedKey)) {
      throw new Error(`BOLA template binding query structure differs at case index ${index}`);
    }
    const name = routePlaceholderName(expectedValue);
    if (name) {
      recordRouteValue(values, name, concreteRouteValue(actualValue, index), index);
    } else if (POSSIBLE_ROUTE_PLACEHOLDER.test(expectedValue)) {
      throw new Error(`BOLA template binding contains an unsupported query placeholder at case index ${index}`);
    } else if (expectedValue !== actualValue) {
      throw new Error(`BOLA template binding static query differs at case index ${index}`);
    }
  }
  return values;
}

function evidenceModeForCase(value: BolaVerificationCase): BolaDraftEvidenceMode {
  return value.expected.match === "ownerIdentity" ? "ownerIdentity" : "testDataLabel";
}

function concreteObjectId(value: unknown): value is string | number {
  return (typeof value === "string" && value.trim().length > 0)
    || (typeof value === "number" && Number.isFinite(value));
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((item, index) => item === right[index]);
}

function assertManifestTemplateBinding(
  manifest: BolaAuthorizationManifest,
  template: BolaAuthorizationTemplate,
): void {
  if (manifest.cases.length !== template.manifest.cases.length
    || manifest.maxRequests !== template.manifest.maxRequests) {
    throw new Error("BOLA template binding case count or request budget differs");
  }

  for (let index = 0; index < template.bindings.length; index += 1) {
    const expected = template.manifest.cases[index]!;
    const binding = template.bindings[index]!;
    const actual = manifest.cases[index]!;
    if (actual.id !== expected.id || binding.caseId !== expected.id) {
      throw new Error(`BOLA template binding case order or ID differs at case index ${index}`);
    }
    if (actual.method !== expected.method || actual.readOnly !== expected.readOnly) {
      throw new Error(`BOLA template binding method or read-only declaration differs at case index ${index}`);
    }
    if (actual.ownerAccount !== expected.ownerAccount || actual.otherAccount !== expected.otherAccount) {
      throw new Error(`BOLA template binding account roles differ at case index ${index}`);
    }
    if (evidenceModeForCase(actual) !== binding.evidenceMode) {
      throw new Error(`BOLA template binding evidence mode differs at case index ${index}`);
    }
    if (!sameStrings(actual.expected.statusCodes.map(String), expected.expected.statusCodes.map(String))) {
      throw new Error(`BOLA template binding response status codes differ at case index ${index}`);
    }

    const routeValues = matchRouteTemplate(expected.path, actual.path, index);
    const fields = [...binding.objectIdFields].sort();
    const routeFields = [...routeValues.keys()].sort();
    if (routeFields.some((field) => !fields.includes(field))) {
      throw new Error(`BOLA template binding route uses an undeclared object-ID field at case index ${index}`);
    }

    if (actual.method === "GET") {
      if (!sameStrings(routeFields, fields) || actual.body !== undefined) {
        throw new Error(`BOLA template binding GET object-ID fields differ at case index ${index}`);
      }
      continue;
    }

    const body = actual.body;
    const bodyFields = body ? Object.keys(body).sort() : [];
    if (!body || !sameStrings(bodyFields, fields)) {
      throw new Error(`BOLA template binding POST object-ID fields differ at case index ${index}`);
    }
    for (const field of fields) {
      const value = body[field];
      if (!concreteObjectId(value)) {
        throw new Error(`BOLA template binding POST object identifier is not concrete at case index ${index}`);
      }
      const routeValue = routeValues.get(field);
      if (routeValue !== undefined && routeValue !== String(value)) {
        throw new Error(`BOLA template binding route/body object identifiers differ at case index ${index}`);
      }
    }
  }
}

function templateBindingCheck(
  template: BolaAuthorizationTemplate,
  templateDigestSha256: string,
): BolaAuthorizationTemplateBindingCheck {
  return {
    status: "verified",
    templateId: template.templateId,
    templateDigestSha256,
    draftId: template.draftId,
    scanId: template.scanId,
    projectId: template.projectId,
    queueId: template.selection.queueId,
    queueCoverage: template.selection.queueCoverage,
    queueCoverageScope: template.selection.queueCoverageScope,
    matchedCases: template.bindings.length,
    exactCaseOrder: true,
    exactRequestBudget: true,
    exactMethods: true,
    exactAccountRoles: true,
    routeTemplatesMatched: true,
    exactObjectIdFields: true,
    concreteObjectIds: true,
    exactEvidenceModes: true,
    exactStatusCodes: true,
  };
}

export function checkBolaAuthorization(value: unknown, templateValue?: unknown): BolaAuthorizationCheck {
  const manifest: BolaAuthorizationManifest = validateBolaAuthorization(value);
  const template = templateValue === undefined ? undefined : validateBolaAuthorizationTemplate(templateValue);
  if (template) assertManifestTemplateBinding(manifest, template);
  const manifestDigestSha256 = sha256(canonicalJson(manifest));
  const templateDigestSha256 = template ? sha256(canonicalJson(template)) : undefined;
  const cases = manifest.cases.length;
  const check: BolaAuthorizationCheck = {
    schemaVersion: template ? BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION : SCHEMA_VERSION,
    checkId: template
      ? stableId(
          "bola_check",
          manifestDigestSha256,
          template.templateId,
          templateDigestSha256!,
          template.draftId,
          template.scanId,
          template.projectId,
          template.selection.queueId,
          template.selection.queueCoverage,
          template.selection.queueCoverageScope,
          String(template.bindings.length),
        )
      : stableId("bola_check", manifestDigestSha256),
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
    ...(template && templateDigestSha256
      ? { templateBinding: templateBindingCheck(template, templateDigestSha256) }
      : {}),
    networkRequests: 0,
    environmentValuesRead: 0,
    dnsLookups: 0,
    reviewRequired: [...(template ? CHECK_REVIEW_REQUIREMENTS : LEGACY_CHECK_REVIEW_REQUIREMENTS)],
    nextCommand: template ? BOUND_VERIFY_COMMAND : LEGACY_VERIFY_COMMAND,
    disclaimer: "This offline check validates manifest structure and declared safety constraints only. It performs no environment-value reads, DNS lookups or network requests and does not prove authorization, reachability, protection or vulnerability.",
  };
  return validateBolaAuthorizationCheck(check);
}

function verificationReceiptProjection(check: BolaAuthorizationCheck): unknown {
  return {
    checkId: check.checkId,
    manifestDigestSha256: check.manifestDigestSha256,
    environment: check.environment,
    summary: check.summary,
    caseIds: check.caseIds,
    templateBinding: check.templateBinding,
  };
}

export function assertBolaVerificationPreflight(
  manifestValue: unknown,
  templateValue: unknown,
  checkValue: unknown,
): BolaAuthorizationCheck {
  const receipt = validateBolaAuthorizationCheck(checkValue);
  if (receipt.schemaVersion === SCHEMA_VERSION || !receipt.templateBinding) {
    throw new Error("BOLA active verification requires a template-bound authorization check 1.1.0 or 1.2.0");
  }
  const expected = checkBolaAuthorization(manifestValue, templateValue);
  if (canonicalJson(verificationReceiptProjection(receipt))
    !== canonicalJson(verificationReceiptProjection(expected))) {
    throw new Error("BOLA verification preflight receipt does not match the supplied manifest and template");
  }
  return receipt;
}

export async function checkBola(path: string, templatePath?: string): Promise<BolaAuthorizationCheck> {
  if (templatePath === undefined) return checkBolaAuthorization(await loadBolaAuthorization(path));
  const [manifest, template] = await Promise.all([
    loadBolaAuthorization(path),
    loadBolaAuthorizationTemplate(templatePath),
  ]);
  return checkBolaAuthorization(manifest, template);
}
