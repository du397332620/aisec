import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import {
  INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER,
  INTERFACE_SECURITY_REVIEW_RATIONALE_PLACEHOLDER,
  type AuthorizationManifest,
  type BolaAuthorizationCheck,
  type BolaAuthorizationManifest,
  type BolaAuthorizationTemplate,
  type BolaDraftPlan,
  type BolaVerificationAudit,
  type BolaVerificationLineageAudit,
  type BolaVerificationLineageCheck,
  type BolaVerificationReport,
  type CiReport,
  type FixContract,
  type InterfaceSecurityAudit,
  type InterfaceSecurityAuditEntry,
  type InterfaceSecurityDisposition,
  type InterfaceSecurityReview,
  type InterfaceSecurityReviewStatus,
  type InterfaceVerificationQueue,
  type RuleCatalog,
  type RulePack,
  type RulePackPreview,
  type RulePackRecord,
  type ScanReport,
  type SecurityPolicy,
} from "../schema.js";
import { SEVERITY_RANK } from "./constants.js";
import { ROUTE_SECURITY_CATEGORY_ORDER, ROUTE_SECURITY_RULES, routeSecurityIssueKey } from "./route-security.js";
import { evaluateRouteSecurityBaselineGate } from "./route-security-gate.js";
import { safeRelativePath } from "../reporters/safety.js";
import { classifyBolaStaticRoute } from "../web/bola-policy.js";
import { canonicalJson, sha256, stableId } from "./utils.js";

type PublicSchemaName = "ScanReport" | "CiReport" | "FixContract" | "AuthorizationManifest" | "BolaAuthorizationManifest" | "BolaAuthorizationTemplate" | "BolaAuthorizationCheck" | "BolaDraftPlan" | "BolaVerificationReport" | "BolaVerificationAudit" | "BolaVerificationLineageAudit" | "BolaVerificationLineageCheck" | "InterfaceVerificationQueue" | "InterfaceSecurityAudit" | "InterfaceSecurityDisposition" | "InterfaceSecurityReview" | "RuleCatalog" | "RulePack" | "RulePackPreview" | "SecurityPolicy";

function loadSchema(filename: string): object {
  const path = fileURLToPath(new URL(`../../../schemas/${filename}`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as object;
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
const addFormats = addFormatsModule as unknown as (instance: Ajv2020) => Ajv2020;
addFormats(ajv);

const scanReportValidator = ajv.compile(loadSchema("scan-report.schema.json"));
const ciReportValidator = ajv.compile(loadSchema("ci-report.schema.json"));
const fixContractValidator = ajv.compile(loadSchema("fix-contract.schema.json"));
const authorizationManifestValidator = ajv.compile(loadSchema("authorization-manifest.schema.json"));
const bolaAuthorizationManifestValidator = ajv.compile(loadSchema("bola-authorization-manifest.schema.json"));
const bolaAuthorizationTemplateValidator = ajv.compile(loadSchema("bola-authorization-template.schema.json"));
const bolaAuthorizationCheckValidator = ajv.compile(loadSchema("bola-authorization-check.schema.json"));
const bolaDraftPlanValidator = ajv.compile(loadSchema("bola-draft.schema.json"));
const bolaVerificationReportValidator = ajv.compile(loadSchema("bola-verification-report.schema.json"));
const bolaVerificationAuditValidator = ajv.compile(loadSchema("bola-verification-audit.schema.json"));
const bolaVerificationLineageAuditValidator = ajv.compile(loadSchema("bola-verification-lineage-audit.schema.json"));
const bolaVerificationLineageCheckValidator = ajv.compile(loadSchema("bola-verification-lineage-check.schema.json"));
const interfaceVerificationQueueValidator = ajv.compile(loadSchema("interface-verification-queue.schema.json"));
const interfaceSecurityAuditValidator = ajv.compile(loadSchema("interface-security-audit.schema.json"));
const interfaceSecurityDispositionValidator = ajv.compile(loadSchema("interface-security-disposition.schema.json"));
const interfaceSecurityReviewValidator = ajv.compile(loadSchema("interface-security-review.schema.json"));
const ruleCatalogValidator = ajv.compile(loadSchema("rule-catalog.schema.json"));
const rulePackValidator = ajv.compile(loadSchema("rule-pack.schema.json"));
const rulePackPreviewValidator = ajv.compile(loadSchema("rule-pack-preview.schema.json"));
const securityPolicyValidator = ajv.compile(loadSchema("security-policy.schema.json"));
const ROUTE_ATTRIBUTION_RULES = new Set([
  "python.dataflow.sql-injection",
  "python.dataflow.ssrf",
  "python.dataflow.untrusted-file-path",
  "python.dataflow.client-url-with-server-secret",
]);
const ROUTE_ATTRIBUTION_REASONS = new Set([
  "commented_out_call",
  "ambiguous_or_dynamic_dispatch",
  "request_origin_not_proven",
  "no_proven_route_path",
]);

function describeError(error: ErrorObject): string {
  const path = error.instancePath || "/";
  if (error.keyword === "additionalProperties") {
    const property = String((error.params as { additionalProperty?: unknown }).additionalProperty ?? "unknown");
    return `${path} contains unsupported additional properties: ${JSON.stringify(property)}`;
  }
  return `${path} ${error.message ?? `failed ${error.keyword}`}`;
}

function assertSchema<T>(name: PublicSchemaName, validator: ValidateFunction, value: unknown, contractVersion = "1.0.0"): T {
  if (validator(value)) return value as T;
  const details = (validator.errors ?? []).slice(0, 8).map(describeError).join("; ");
  throw new Error(`${name} does not match schema ${contractVersion}: ${details || "validation failed"}`);
}

function validateRouteSecurityComparison(report: ScanReport): void {
  const comparison = report.comparison?.routeSecurity;
  if (!comparison) return;
  const entries = [
    ...comparison.new,
    ...comparison.remaining,
    ...comparison.resolved,
    ...comparison.notRechecked,
  ];
  const identities = new Set(entries.map(routeSecurityIssueKey));
  if (identities.size !== entries.length) throw new Error("ScanReport route-security comparison identities must be unique across states");
  if (comparison.complete && (comparison.notRechecked.length > 0
    || comparison.omittedRouteAliases > 0
    || comparison.omittedAssociations > 0)) {
    throw new Error("ScanReport complete route-security comparison cannot contain unchecked or omitted evidence");
  }
}

export function validateScanReport(value: unknown): ScanReport {
  const report = assertSchema<ScanReport>("ScanReport", scanReportValidator, value, "1.4.0");
  validateRouteSecurityComparison(report);
  for (const signal of report.signals) {
    if (signal.engine !== "aisec-python" || !ROUTE_ATTRIBUTION_RULES.has(signal.ruleId)) continue;
    const status = signal.metadata?.routeAttributionStatus;
    const reason = signal.metadata?.routeAttributionReason;
    if (status === undefined && reason === undefined) continue;
    if (status !== "attributed" && status !== "unattributed") {
      throw new Error(`ScanReport Python route attribution ${signal.id} has an unsupported status`);
    }
    if (status === "attributed") {
      if (reason !== undefined || typeof signal.metadata?.route !== "string"
        || !Array.isArray(signal.metadata?.routes)
        || !["direct_handler", "bounded_call_graph", "mixed"].includes(String(signal.metadata?.routeAttribution))
        || typeof signal.metadata?.routeCallDepth !== "number") {
        throw new Error(`ScanReport attributed Python signal ${signal.id} requires route evidence without a gap reason`);
      }
    } else if (typeof reason !== "string" || !ROUTE_ATTRIBUTION_REASONS.has(reason)
      || signal.metadata?.route !== undefined
      || signal.metadata?.routes !== undefined
      || signal.metadata?.handler !== undefined
      || signal.metadata?.routeAttribution !== undefined
      || signal.metadata?.routeCallDepth !== undefined) {
      throw new Error(`ScanReport unattributed Python signal ${signal.id} requires one supported reason without route claims`);
    }
  }
  if (report.policy?.source === "operator") {
    if (!report.policy.policyId || !report.policy.digestSha256 || !report.policy.expiresAt) {
      throw new Error("ScanReport operator policy record requires policyId, digestSha256 and expiresAt");
    }
    if (report.policy.relaxations.length > 0) throw new Error("ScanReport operator policy record cannot contain relaxations");
    if (report.profileName !== "predeploy") throw new Error("ScanReport operator policy record requires the predeploy profile");
    if (report.policy.suppressionCount > 0 && report.policy.suppressionApproval !== "explicit") {
      throw new Error("ScanReport operator policy suppressions require explicit approval evidence");
    }
    if (report.policy.suppressionCount === 0 && report.policy.suppressionApproval !== "not_applicable") {
      throw new Error("ScanReport operator policy without suppressions cannot claim suppression approval");
    }
    const engines = new Set(report.policy.requiredEngines);
    for (const engine of ["gitleaks", "opengrep", "trivy"] as const) {
      if (!engines.has(engine)) throw new Error(`ScanReport operator policy record must retain required engine: ${engine}`);
      if (!report.coverage.some((item) => item.engine === engine && item.required)) {
        throw new Error(`ScanReport operator policy record requires coverage from engine: ${engine}`);
      }
    }
    const requiredRules = new Set(report.policy.requiredRuleIds);
    for (const ruleId of report.policy.blockingRuleIds) {
      if (!requiredRules.has(ruleId)) throw new Error(`ScanReport blocking policy rule must also be required: ${ruleId}`);
    }
    const knownRules = catalogRuleIds();
    for (const ruleId of report.policy.requiredRuleIds) {
      if (!knownRules.has(ruleId)) throw new Error(`ScanReport operator policy references unknown shipped rule: ${ruleId}`);
    }
    const routeGate = evaluateRouteSecurityBaselineGate(
      report.signals,
      report.findings,
      report.comparison,
      report.policy.routeSecurityBaseline,
    );
    if (routeGate.blockingEntries.length > 0 && report.decision !== "block") {
      throw new Error("ScanReport route-security baseline blockers require a block decision");
    }
    if (routeGate.incompleteReason && !["block", "incomplete"].includes(report.decision)) {
      throw new Error("ScanReport incomplete route-security baseline evaluation must fail closed");
    }
  }
  if (report.policy?.source === "defaults") {
    if (report.policy.policyId || report.policy.digestSha256 || report.policy.expiresAt) throw new Error("ScanReport default policy record cannot claim operator policy identity");
    if (report.policy.requiredRuleIds.length > 0 || report.policy.blockingRuleIds.length > 0 || report.policy.suppressionCount > 0) {
      throw new Error("ScanReport default policy record cannot claim operator rules or suppressions");
    }
    if (report.policy.suppressionApproval !== "not_applicable") throw new Error("ScanReport default policy record cannot claim suppression approval");
    if (report.policy.routeSecurityBaseline) throw new Error("ScanReport default policy record cannot claim an operator route-security baseline gate");
    if (report.policy.gate.minimumSeverity !== "high" || report.policy.gate.includeInferred || report.policy.gate.requireNoSuppressions) {
      throw new Error("ScanReport default policy record must retain the built-in gate");
    }
    const engines = new Set(report.policy.requiredEngines);
    const hasAllEngines = engines.size === 3 && ["gitleaks", "opengrep", "trivy"].every((engine) => engines.has(engine as "gitleaks" | "opengrep" | "trivy"));
    const hasNoEngines = engines.size === 0;
    if (!hasAllEngines && !hasNoEngines) throw new Error("ScanReport default policy record must require all external engines or explicitly disable all of them");
    const sourceOnly = report.policy.relaxations.includes("source_only_profile");
    const externalDisabled = report.policy.relaxations.includes("external_engines_disabled");
    if (report.profileName === "native") {
      if (!sourceOnly || !externalDisabled || !hasNoEngines) throw new Error("ScanReport native profile must record both default policy relaxations");
    } else if (sourceOnly || externalDisabled !== hasNoEngines) {
      throw new Error("ScanReport predeploy profile has inconsistent default policy relaxations");
    }
    for (const engine of ["gitleaks", "opengrep", "trivy"] as const) {
      if (!report.coverage.some((item) => item.engine === engine && item.required === hasAllEngines)) {
        throw new Error(`ScanReport default policy record requires consistent coverage from engine: ${engine}`);
      }
    }
  }
  if (report.rulePacks) {
    validateRulePackRecords(report.rulePacks, "ScanReport");
    const expectedPacks = new Map(report.rulePacks.map((pack) => [pack.packId, pack]));
    const expectedDomains = new Set(report.rulePacks.map((pack) => `rule-pack:${pack.packId}`));
    for (const pack of report.rulePacks) {
      const matching = report.coverage.filter((item) => item.engine === "aisec-rule-pack" && item.domain === `rule-pack:${pack.packId}`);
      if (matching.length !== 1 || matching[0]?.required !== true || matching[0]?.version !== pack.digestSha256) {
        throw new Error(`ScanReport rule pack ${pack.packId} requires exactly one required coverage record`);
      }
    }
    for (const coverage of report.coverage.filter((item) => item.engine === "aisec-rule-pack")) {
      if (!expectedDomains.has(coverage.domain)) throw new Error(`ScanReport contains rule-pack coverage without a matching record: ${coverage.domain}`);
    }
    for (const signal of report.signals.filter((item) => item.engine === "aisec-rule-pack")) {
      const packId = signal.metadata?.rulePackId;
      const digest = signal.metadata?.rulePackDigestSha256;
      const pack = typeof packId === "string" ? expectedPacks.get(packId) : undefined;
      if (!pack || typeof digest !== "string" || digest !== pack.digestSha256) {
        throw new Error(`ScanReport custom signal ${signal.id} does not match a declared rule-pack ID and digest`);
      }
      if (!signal.ruleId.startsWith(`custom.${packId}.`)) {
        throw new Error(`ScanReport custom signal ${signal.id} rule ID does not match rule pack ${packId}`);
      }
      if (signal.evidenceLevel === "verified") throw new Error(`ScanReport custom signal ${signal.id} cannot claim verified evidence`);
      const rulePackMatch = signal.metadata?.rulePackMatch;
      if (rulePackMatch !== undefined && rulePackMatch !== "present" && rulePackMatch !== "absent") {
        throw new Error(`ScanReport custom signal ${signal.id} has an unsupported rule-pack match mode`);
      }
      if (rulePackMatch === "absent") {
        if (signal.evidenceLevel !== "inferred") {
          throw new Error(`ScanReport absent custom signal ${signal.id} must use inferred evidence`);
        }
        const pathOnly = signal.locations.length === 1 && signal.locations.every((location) => (
          location.line === undefined
          && location.column === undefined
          && location.endLine === undefined
          && location.snippet === undefined
        ));
        if (!pathOnly) throw new Error(`ScanReport absent custom signal ${signal.id} must use one path-only location`);
      }
    }
  } else if (report.coverage.some((item) => item.engine === "aisec-rule-pack") || report.signals.some((item) => item.engine === "aisec-rule-pack")) {
    throw new Error("Legacy ScanReport cannot claim rule-pack coverage or signals without versioned rule-pack records");
  }
  return report;
}

function validateRulePackRecords(records: RulePackRecord[], contract: "ScanReport" | "CiReport"): void {
  const ids = new Set<string>();
  for (const record of records) {
    if (ids.has(record.packId)) throw new Error(`${contract} contains duplicate rule pack: ${record.packId}`);
    ids.add(record.packId);
  }
}

function ciTextIsSingleLine(value: string): boolean {
  return value.trim() === value && !/[\u0000-\u001f\u007f]/u.test(value);
}

function ciPathIsSafe(path: string): boolean {
  if (!ciTextIsSingleLine(path) || path.length > 1024) return false;
  const normalized = path.replaceAll("\\", "/");
  if (normalized.startsWith("/") || normalized.startsWith("//") || /^[A-Za-z]:\//u.test(normalized) || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized)) return false;
  return normalized.split("/").every((part) => part !== ".." && !/%(?:2e|2f|5c)/iu.test(part));
}

export function validateCiReport(value: unknown): CiReport {
  const report = assertSchema<CiReport>("CiReport", ciReportValidator, value, "1.4.0");
  if (report.rulePacks) validateRulePackRecords(report.rulePacks, "CiReport");
  if (report.routeAttribution) {
    const attribution = report.routeAttribution;
    if (attribution.eligibleSignals !== attribution.attributedSignals + attribution.unattributedSignals) {
      throw new Error("CiReport route-attribution totals are inconsistent");
    }
    const reasons = new Set(attribution.reasons.map((item) => item.reason));
    if (reasons.size !== attribution.reasons.length) throw new Error("CiReport route-attribution reasons must be unique");
    const explainedSignals = attribution.reasons.reduce((total, item) => total + item.signals, 0);
    if (explainedSignals !== attribution.unattributedSignals) {
      throw new Error("CiReport route-attribution reason counts are inconsistent");
    }
    if ((attribution.unattributedSignals === 0) !== (attribution.unattributedFindings === 0)) {
      throw new Error("CiReport route-attribution finding count is inconsistent");
    }
  }
  const routeComparison = report.comparison?.routeSecurity;
  if (routeComparison) {
    const total = routeComparison.new + routeComparison.remaining + routeComparison.resolved + routeComparison.notRechecked;
    if (routeComparison.entries.length + routeComparison.omittedEntries !== total) {
      throw new Error("CiReport route-security comparison entry totals are inconsistent");
    }
    const stateCounts = new Map<string, number>();
    const identities = new Set<string>();
    for (const entry of routeComparison.entries) {
      stateCounts.set(entry.state, (stateCounts.get(entry.state) ?? 0) + 1);
      const identity = routeSecurityIssueKey(entry);
      if (identities.has(identity)) throw new Error("CiReport route-security comparison identities must be unique across states");
      identities.add(identity);
    }
    const expected = {
      new: routeComparison.new,
      remaining: routeComparison.remaining,
      resolved: routeComparison.resolved,
      not_rechecked: routeComparison.notRechecked,
    };
    for (const [state, count] of Object.entries(expected)) {
      if ((stateCounts.get(state) ?? 0) > count) throw new Error("CiReport route-security comparison state counts are inconsistent");
    }
    if (!routeComparison.recorded && (routeComparison.complete || total > 0
      || routeComparison.omittedRouteAliases > 0
      || routeComparison.omittedAssociations > 0)) {
      throw new Error("CiReport unrecorded route-security comparison cannot claim evidence");
    }
    if (routeComparison.complete && (routeComparison.notRechecked > 0
      || routeComparison.omittedRouteAliases > 0
      || routeComparison.omittedAssociations > 0)) {
      throw new Error("CiReport complete route-security comparison cannot contain unchecked or omitted evidence");
    }
  }
  const expectedExitCode = report.decision === "block" ? 1 : report.decision === "incomplete" ? 2 : 0;
  if (report.recommendedExitCode !== expectedExitCode) throw new Error(`CiReport decision ${report.decision} requires recommendedExitCode ${expectedExitCode}`);
  const open = report.counts.critical + report.counts.high + report.counts.medium + report.counts.low + report.counts.info;
  if (report.counts.open !== open) throw new Error("CiReport counts.open must equal the severity-count total");
  if (report.requiredCoverage.total !== report.requiredCoverage.complete + report.requiredCoverage.gaps.length) {
    throw new Error("CiReport required coverage totals are inconsistent");
  }
  const routeGateIncomplete = Boolean(report.policy.routeSecurityBaseline
    && (!routeComparison?.recorded
      || (report.policy.routeSecurityBaseline.requireComplete && routeComparison.recorded && !routeComparison.complete)));
  if (report.decision === "incomplete" && report.requiredCoverage.gaps.length === 0 && !routeGateIncomplete) {
    throw new Error("CiReport incomplete decision requires a required coverage gap or incomplete route-security baseline evaluation");
  }
  if (report.requiredCoverage.gaps.length > 0 && !["block", "incomplete"].includes(report.decision)) {
    throw new Error(`CiReport decision ${report.decision} cannot claim complete acceptance with required coverage gaps`);
  }
  if (routeGateIncomplete && !["block", "incomplete"].includes(report.decision)) {
    throw new Error(`CiReport decision ${report.decision} cannot claim complete acceptance with an incomplete route-security baseline evaluation`);
  }
  const plainText = [report.disclaimer, ...report.decisionReasons];
  for (const gap of report.requiredCoverage.gaps) plainText.push(gap.domain, gap.engine, ...(gap.reason ? [gap.reason] : []));
  for (const annotation of report.annotations) plainText.push(annotation.title, annotation.message);
  if (report.policy.policyId) plainText.push(report.policy.policyId);
  if (plainText.some((item) => !ciTextIsSingleLine(item))) throw new Error("CiReport text must be trimmed single-line content without control characters");

  const decisionAnnotations = report.annotations.filter((item) => item.kind === "decision");
  if (decisionAnnotations.length !== 1) throw new Error("CiReport must contain exactly one decision annotation");
  const expectedDecisionLevel = report.decision === "block" || report.decision === "incomplete" ? "error" : report.decision === "review" ? "warning" : "notice";
  if (decisionAnnotations[0]?.level !== expectedDecisionLevel) throw new Error(`CiReport decision annotation must use level ${expectedDecisionLevel}`);
  const coverageAnnotations = report.annotations.filter((item) => item.kind === "coverage");
  const expectedCoverageAnnotations = Math.min(report.requiredCoverage.gaps.length, 20);
  if (coverageAnnotations.length !== expectedCoverageAnnotations || coverageAnnotations.some((item) => item.level !== "error")) {
    throw new Error("CiReport coverage annotations must represent the first 20 required coverage gaps as errors");
  }
  if (report.omitted.coverageAnnotations !== Math.max(0, report.requiredCoverage.gaps.length - 20)) {
    throw new Error("CiReport omitted coverage annotation count is inconsistent");
  }
  const findingAnnotations = report.annotations.filter((item) => item.kind === "finding");
  if (findingAnnotations.length > 50) throw new Error("CiReport cannot contain more than 50 finding annotations");
  if (report.omitted.findingAnnotations > 0 && findingAnnotations.length !== 50) {
    throw new Error("CiReport omitted findings require a full 50-finding annotation window");
  }
  const findingFingerprints = new Set<string>();
  for (const annotation of report.annotations) {
    if (annotation.path && !ciPathIsSafe(annotation.path)) throw new Error(`CiReport annotation path is not a safe relative path: ${annotation.path}`);
    if (annotation.endLine !== undefined && annotation.startLine !== undefined && annotation.endLine < annotation.startLine) throw new Error("CiReport annotation endLine cannot precede startLine");
    if (annotation.endColumn !== undefined && annotation.startColumn !== undefined && annotation.endLine === annotation.startLine && annotation.endColumn < annotation.startColumn) {
      throw new Error("CiReport annotation endColumn cannot precede startColumn on the same line");
    }
    if (annotation.kind !== "finding" && (annotation.path || annotation.startLine || annotation.startColumn || annotation.endLine || annotation.endColumn || annotation.findingId || annotation.fingerprint || annotation.severity || annotation.evidenceLevel || annotation.findingStatus || annotation.blocksRelease !== undefined || annotation.baselineState)) {
      throw new Error("CiReport non-finding annotations cannot claim source-location or finding fields");
    }
    if (annotation.kind === "finding") {
      if (findingFingerprints.has(annotation.fingerprint!)) throw new Error(`CiReport contains duplicate finding annotation: ${annotation.fingerprint}`);
      findingFingerprints.add(annotation.fingerprint!);
      if (!report.comparison && annotation.baselineState) throw new Error("CiReport annotation cannot claim baseline state without a comparison");
      if ((annotation.level === "error") !== annotation.blocksRelease) throw new Error("CiReport finding error level must match blocksRelease");
      if (annotation.findingStatus === "suppressed" && !annotation.blocksRelease) throw new Error("CiReport suppressed findings are annotatable only when they block release");
    }
  }

  if (report.decision === "block" && !findingAnnotations.some((item) => item.blocksRelease)) {
    throw new Error("CiReport block decision requires a release-blocking finding annotation");
  }
  if (report.comparison) {
    const annotatedNew = findingAnnotations.filter((item) => item.baselineState === "new").length;
    const annotatedUnchanged = findingAnnotations.filter((item) => item.baselineState === "unchanged").length;
    if (annotatedNew > report.comparison.new || annotatedUnchanged > report.comparison.remaining) {
      throw new Error("CiReport annotated baseline states exceed the comparison counts");
    }
  }

  const policy = report.policy;
  if (policy.source === "not_recorded") {
    if (policy.targetConfiguration !== "not_recorded" || policy.policyId || policy.digestSha256 || policy.expiresAt || policy.gate || policy.routeSecurityBaseline || policy.requiredEngines.length > 0 || policy.suppressionCount !== 0 || policy.suppressionApproval !== "not_recorded" || policy.relaxations.length > 0) {
      throw new Error("CiReport legacy policy summary cannot claim recorded policy evidence");
    }
  } else {
    if (policy.targetConfiguration === "not_recorded" || !policy.gate) throw new Error("CiReport recorded policy summary requires target disposition and gate evidence");
    if (policy.source === "operator") {
      if (!policy.policyId || !policy.digestSha256 || !policy.expiresAt) throw new Error("CiReport operator policy summary requires identity, digest and expiry");
      if (report.profileName !== "predeploy") throw new Error("CiReport operator policy summary requires the predeploy profile");
      if (policy.relaxations.length > 0 || policy.requiredEngines.length !== 3) throw new Error("CiReport operator policy summary must retain all engines without relaxations");
      if (policy.suppressionCount > 0 ? policy.suppressionApproval !== "explicit" : policy.suppressionApproval !== "not_applicable") throw new Error("CiReport operator suppression approval is inconsistent");
    } else {
      if (policy.policyId || policy.digestSha256 || policy.expiresAt || policy.suppressionCount !== 0 || policy.suppressionApproval !== "not_applicable") {
        throw new Error("CiReport default policy summary cannot claim operator identity or suppressions");
      }
      if (policy.gate.minimumSeverity !== "high" || policy.gate.includeInferred || policy.gate.requireNoSuppressions) throw new Error("CiReport default policy summary must retain the built-in gate");
      if (policy.routeSecurityBaseline) throw new Error("CiReport default policy summary cannot claim an operator route-security baseline gate");
      const engines = new Set(policy.requiredEngines);
      const hasAllEngines = engines.size === 3 && ["gitleaks", "opengrep", "trivy"].every((engine) => engines.has(engine as "gitleaks" | "opengrep" | "trivy"));
      const hasNoEngines = engines.size === 0;
      if (!hasAllEngines && !hasNoEngines) throw new Error("CiReport default policy summary must require all external engines or disable all of them");
      const sourceOnly = policy.relaxations.includes("source_only_profile");
      const externalDisabled = policy.relaxations.includes("external_engines_disabled");
      if (report.profileName === "native") {
        if (!sourceOnly || !externalDisabled || !hasNoEngines) throw new Error("CiReport native profile must record both default policy relaxations");
      } else if (sourceOnly || externalDisabled !== hasNoEngines) {
        throw new Error("CiReport predeploy profile has inconsistent default policy relaxations");
      }
    }
  }
  return report;
}

export function validateFixContract(value: unknown): FixContract {
  return assertSchema<FixContract>("FixContract", fixContractValidator, value);
}

export function validateAuthorizationManifestSchema(value: unknown): AuthorizationManifest {
  return assertSchema<AuthorizationManifest>("AuthorizationManifest", authorizationManifestValidator, value);
}

export function validateBolaAuthorizationManifestSchema(value: unknown): BolaAuthorizationManifest {
  return assertSchema<BolaAuthorizationManifest>("BolaAuthorizationManifest", bolaAuthorizationManifestValidator, value);
}

function expectedTemplateId(template: BolaAuthorizationTemplate): string {
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

export function validateBolaAuthorizationTemplate(value: unknown): BolaAuthorizationTemplate {
  const template = assertSchema<BolaAuthorizationTemplate>(
    "BolaAuthorizationTemplate",
    bolaAuthorizationTemplateValidator,
    value,
    "1.1.0",
  );
  const total = template.manifest.cases.length;
  if (total < 1 || total > 9
    || template.selection.candidateIds.length !== total
    || template.bindings.length !== total
    || template.manifest.maxRequests !== 2 + total * 2) {
    throw new Error("BolaAuthorizationTemplate case, binding and request totals are inconsistent");
  }

  const caseIds = new Set<string>();
  const interfaceIds = new Set<string>();
  const bolaIds = new Set<string>();
  const routes = new Set<string>();
  for (let index = 0; index < total; index += 1) {
    const item = template.manifest.cases[index]!;
    const binding = template.bindings[index]!;
    const interfaceCandidateId = template.selection.candidateIds[index]!;
    const expectedCaseId = `case_${binding.bolaCandidateId.slice(-16)}`;
    if (item.id !== expectedCaseId || binding.caseId !== item.id) {
      throw new Error(`BolaAuthorizationTemplate case binding is inconsistent at index ${index}`);
    }
    if (binding.interfaceCandidateId !== interfaceCandidateId) {
      throw new Error(`BolaAuthorizationTemplate interface selection order is inconsistent at index ${index}`);
    }
    const route = `${item.method} ${item.path}`;
    if (binding.route !== route) {
      throw new Error(`BolaAuthorizationTemplate binding route is inconsistent at index ${index}`);
    }
    if (item.testDataLabel !== `<SET_TEST_DATA_LABEL_${String(index + 1).padStart(2, "0")}>`) {
      throw new Error(`BolaAuthorizationTemplate test-data placeholder is inconsistent at index ${index}`);
    }
    if (item.expected.match !== binding.evidenceMode) {
      throw new Error(`BolaAuthorizationTemplate evidence binding is inconsistent at index ${index}`);
    }
    if (item.expected.match === "testDataLabel" && item.expected.value !== item.testDataLabel) {
      throw new Error(`BolaAuthorizationTemplate evidence value is inconsistent at index ${index}`);
    }
    if (item.method === "POST") {
      const expectedBody = Object.fromEntries(binding.objectIdFields.map((field) => [
        field,
        `<SET_PRECREATED_OWNER_${field.toUpperCase()}>`,
      ]));
      if (!item.body
        || Object.keys(item.body).length !== Object.keys(expectedBody).length
        || Object.entries(expectedBody).some(([field, placeholder]) => item.body?.[field] !== placeholder)) {
        throw new Error(`BolaAuthorizationTemplate request body is inconsistent at index ${index}`);
      }
    } else if (item.body !== undefined) {
      throw new Error(`BolaAuthorizationTemplate GET request contains a body at index ${index}`);
    }
    if (caseIds.has(item.id)
      || interfaceIds.has(binding.interfaceCandidateId)
      || bolaIds.has(binding.bolaCandidateId)
      || routes.has(binding.route)) {
      throw new Error("BolaAuthorizationTemplate bindings contain duplicate identities");
    }
    caseIds.add(item.id);
    interfaceIds.add(binding.interfaceCandidateId);
    bolaIds.add(binding.bolaCandidateId);
    routes.add(binding.route);
  }
  if (template.templateId !== expectedTemplateId(template)) {
    throw new Error("BolaAuthorizationTemplate stable template ID is inconsistent");
  }
  return template;
}

export function validateBolaAuthorizationCheck(value: unknown): BolaAuthorizationCheck {
  const check = assertSchema<BolaAuthorizationCheck>(
    "BolaAuthorizationCheck",
    bolaAuthorizationCheckValidator,
    value,
    "1.2.0",
  );
  const summary = check.summary;
  if (check.caseIds.length !== summary.cases
    || summary.requiredRequests !== 2 + summary.cases * 2
    || summary.maxRequests < summary.requiredRequests
    || summary.getCases + summary.postCases !== summary.cases
    || summary.testDataLabelCases + summary.ownerIdentityCases !== summary.cases) {
    throw new Error("BolaAuthorizationCheck summary totals are inconsistent");
  }
  if (check.templateBinding && check.templateBinding.matchedCases !== summary.cases) {
    throw new Error("BolaAuthorizationCheck template binding totals are inconsistent");
  }
  const expectedCheckId = check.templateBinding
    ? stableId(
        "bola_check",
        check.manifestDigestSha256,
        check.templateBinding.templateId,
        check.templateBinding.templateDigestSha256,
        check.templateBinding.draftId,
        check.templateBinding.scanId,
        check.templateBinding.projectId,
        check.templateBinding.queueId,
        check.templateBinding.queueCoverage,
        check.templateBinding.queueCoverageScope,
        String(check.templateBinding.matchedCases),
      )
    : stableId("bola_check", check.manifestDigestSha256);
  if (check.checkId !== expectedCheckId) {
    throw new Error("BolaAuthorizationCheck stable check ID is inconsistent");
  }
  return check;
}

export function validateBolaVerificationReport(value: unknown): BolaVerificationReport {
  const report = assertSchema<BolaVerificationReport>(
    "BolaVerificationReport",
    bolaVerificationReportValidator,
    value,
    "1.1.0",
  );
  if (Date.parse(report.completedAt) < Date.parse(report.startedAt)) {
    throw new Error("BolaVerificationReport completedAt precedes startedAt");
  }

  const caseIds = new Set<string>();
  const casesById = new Map<string, BolaVerificationReport["cases"][number]>();
  for (const item of report.cases) {
    if (caseIds.has(item.caseId)) throw new Error("BolaVerificationReport case IDs must be unique");
    if (item.ownerAccount === item.otherAccount
      || !report.accounts.includes(item.ownerAccount)
      || !report.accounts.includes(item.otherAccount)) {
      throw new Error(`BolaVerificationReport case ${item.caseId} account roles are inconsistent`);
    }
    caseIds.add(item.caseId);
    casesById.set(item.caseId, item);
  }

  const incomplete = report.cases.some((item) => item.status === "inconclusive" || item.status === "not_run");
  const expectedCoverage = incomplete ? "partial" : "complete";
  if (report.coverage[0]?.status !== expectedCoverage) {
    throw new Error("BolaVerificationReport coverage is inconsistent with case outcomes");
  }
  const expectedRequestCount = 2 + report.cases.length + report.cases.filter((item) => (
    item.otherStatus !== undefined
    || item.reason === "cross-account request failed before a response could be safely evaluated"
  )).length;
  if (report.requestCount !== expectedRequestCount) {
    throw new Error("BolaVerificationReport request count is inconsistent with case execution");
  }
  if (report.cases.some((item) => (
    (item.status === "vulnerable" || item.status === "protected")
    && (item.ownerStatus === undefined || item.otherStatus === undefined)
  ))) {
    throw new Error("BolaVerificationReport conclusive cases require both response status codes");
  }

  const signaledCases = new Set<string>();
  for (const signal of report.signals) {
    const metadata = signal.metadata;
    const caseId = typeof metadata?.caseId === "string" ? metadata.caseId : "";
    const item = casesById.get(caseId);
    if (!item || item.status !== "vulnerable" || signaledCases.has(caseId)) {
      throw new Error("BolaVerificationReport signals must map one-to-one to vulnerable cases");
    }
    if (metadata?.method !== item.method
      || metadata?.ownerAccount !== item.ownerAccount
      || metadata?.otherAccount !== item.otherAccount
      || metadata?.testDataLabel !== item.testDataLabel
      || signal.locations[0]?.path !== new URL(item.path, report.target).toString()) {
      throw new Error(`BolaVerificationReport signal provenance is inconsistent for case ${caseId}`);
    }
    signaledCases.add(caseId);
  }
  if (report.cases.some((item) => item.status === "vulnerable" && !signaledCases.has(item.caseId))) {
    throw new Error("BolaVerificationReport every vulnerable case requires one verified signal");
  }

  const provenance = report.provenance;
  if (!provenance) return report;
  const summary = provenance.authorization.summary;
  const orderedCaseIds = report.cases.map((item) => item.caseId);
  if (summary.cases !== report.cases.length
    || summary.requiredRequests !== 2 + summary.cases * 2
    || summary.maxRequests < summary.requiredRequests
    || summary.getCases !== report.cases.filter((item) => item.method === "GET").length
    || summary.postCases !== report.cases.filter((item) => item.method === "POST").length
    || summary.getCases + summary.postCases !== summary.cases
    || summary.testDataLabelCases + summary.ownerIdentityCases !== summary.cases
    || provenance.template.matchedCases !== summary.cases
    || report.requestCount > summary.maxRequests
    || provenance.authorization.caseIds.length !== orderedCaseIds.length
    || provenance.authorization.caseIds.some((caseId, index) => caseId !== orderedCaseIds[index])) {
    throw new Error("BolaVerificationReport authorization provenance is inconsistent with results");
  }
  const expectedCheckId = stableId(
    "bola_check",
    provenance.manifest.digestSha256,
    provenance.template.templateId,
    provenance.template.templateDigestSha256,
    provenance.template.draftId,
    provenance.template.scanId,
    provenance.template.projectId,
    provenance.template.queueId,
    provenance.template.queueCoverage,
    provenance.template.queueCoverageScope,
    String(provenance.template.matchedCases),
  );
  if (provenance.receipt.checkId !== expectedCheckId) {
    throw new Error("BolaVerificationReport receipt identity is inconsistent");
  }
  return report;
}

export function validateBolaVerificationAudit(value: unknown): BolaVerificationAudit {
  const audit = assertSchema<BolaVerificationAudit>(
    "BolaVerificationAudit",
    bolaVerificationAuditValidator,
    value,
  );
  const summary = audit.report.summary;
  if (summary.vulnerable + summary.protected + summary.inconclusive + summary.notRun !== summary.cases) {
    throw new Error("BolaVerificationAudit result summary totals are inconsistent");
  }
  if (summary.verifiedSignals !== summary.vulnerable) {
    throw new Error("BolaVerificationAudit verified signal total is inconsistent");
  }
  if (audit.report.requiredRequests !== 2 + summary.cases * 2
    || audit.report.authorizedMaxRequests < audit.report.requiredRequests
    || audit.report.requestCount < 2 + summary.cases + summary.vulnerable + summary.protected
    || audit.report.requestCount > audit.report.requiredRequests
    || audit.report.requestCount > audit.report.authorizedMaxRequests) {
    throw new Error("BolaVerificationAudit request budget is inconsistent");
  }
  const expectedCoverage = summary.inconclusive > 0 || summary.notRun > 0 ? "partial" : "complete";
  if (audit.report.coverageStatus !== expectedCoverage) {
    throw new Error("BolaVerificationAudit coverage is inconsistent with result summary");
  }
  const expectedAuditId = stableId(
    "bola_audit",
    audit.report.verificationId,
    audit.report.digestSha256,
    audit.receipt.schemaVersion,
    audit.receipt.checkId,
    audit.receipt.checkedAt,
    audit.manifest.digestSha256,
    audit.template.schemaVersion,
    audit.template.templateId,
    audit.template.digestSha256,
  );
  if (audit.auditId !== expectedAuditId) {
    throw new Error("BolaVerificationAudit stable audit ID is inconsistent");
  }
  return audit;
}

export function validateBolaVerificationLineageAudit(
  value: unknown,
): BolaVerificationLineageAudit {
  const audit = assertSchema<BolaVerificationLineageAudit>(
    "BolaVerificationLineageAudit",
    bolaVerificationLineageAuditValidator,
    value,
  );
  if (audit.queue.reviewedRoutes !== audit.queue.eligibleRoutes + audit.queue.excludedRoutes) {
    throw new Error("BolaVerificationLineageAudit route totals are inconsistent");
  }
  if (audit.queue.selectedCandidates !== audit.draft.selectedCandidates
    || audit.queue.selectedCandidates > audit.queue.eligibleRoutes) {
    throw new Error("BolaVerificationLineageAudit selected candidate total is inconsistent");
  }
  const expectedLineageAuditId = stableId(
    "bola_lineage_audit",
    audit.scan.schemaVersion,
    audit.scan.scanId,
    audit.scan.projectId,
    audit.scan.digestSha256,
    audit.queue.schemaVersion,
    audit.queue.queueId,
    audit.queue.coverageStatus,
    audit.queue.coverageScope,
    String(audit.queue.reviewedRoutes),
    String(audit.queue.eligibleRoutes),
    String(audit.queue.excludedRoutes),
    String(audit.queue.selectedCandidates),
    audit.draft.schemaVersion,
    audit.draft.draftId,
    audit.draft.generatedAt,
    audit.draft.digestSha256,
    audit.template.schemaVersion,
    audit.template.templateId,
    audit.template.digestSha256,
    audit.verificationAudit.schemaVersion,
    audit.verificationAudit.auditId,
    audit.verificationAudit.verificationId,
    audit.verificationAudit.reportDigestSha256,
  );
  if (audit.lineageAuditId !== expectedLineageAuditId) {
    throw new Error("BolaVerificationLineageAudit stable lineage audit ID is inconsistent");
  }
  return audit;
}

export function validateBolaVerificationLineageCheck(
  value: unknown,
): BolaVerificationLineageCheck {
  const check = assertSchema<BolaVerificationLineageCheck>(
    "BolaVerificationLineageCheck",
    bolaVerificationLineageCheckValidator,
    value,
  );
  const expectedLineageCheckId = stableId(
    "bola_lineage_check",
    check.receipt.schemaVersion,
    check.receipt.lineageAuditId,
    check.receipt.auditedAt,
    check.receipt.digestSha256,
  );
  if (check.lineageCheckId !== expectedLineageCheckId) {
    throw new Error("BolaVerificationLineageCheck stable lineage check ID is inconsistent");
  }
  return check;
}

export function validateBolaDraftPlan(value: unknown): BolaDraftPlan {
  const plan = assertSchema<BolaDraftPlan>("BolaDraftPlan", bolaDraftPlanValidator, value, "1.1.0");
  if (plan.schemaVersion === "1.0.0") return plan;

  const selection = plan.selection!;
  const total = plan.candidates.length;
  if (total < 1 || total > 9
    || plan.summary.total !== total
    || plan.summary.readCandidates !== total
    || plan.summary.mutationExcluded !== 0
    || plan.summary.manualReview !== 0
    || selection.candidateIds.length !== total
    || selection.bindings.length !== total) {
    throw new Error("BolaDraftPlan selected summary totals are inconsistent");
  }

  const interfaceIds = new Set<string>();
  const bolaIds = new Set<string>();
  const routes = new Set<string>();
  for (let index = 0; index < total; index += 1) {
    const candidate = plan.candidates[index]!;
    const binding = selection.bindings[index]!;
    const interfaceCandidateId = selection.candidateIds[index]!;
    if (candidate.classification !== "read_candidate") {
      throw new Error(`BolaDraftPlan selected candidate ${candidate.id} is not a read candidate`);
    }
    if (binding.interfaceCandidateId !== interfaceCandidateId) {
      throw new Error(`BolaDraftPlan selected binding order is inconsistent at index ${index}`);
    }
    if (binding.bolaCandidateId !== candidate.id) {
      throw new Error(`BolaDraftPlan selected binding candidate is inconsistent at index ${index}`);
    }
    if (binding.signalId !== candidate.source.signalId) {
      throw new Error(`BolaDraftPlan selected binding signal is inconsistent at index ${index}`);
    }
    const route = `${candidate.method} ${candidate.path}`;
    if (binding.route !== route) {
      throw new Error(`BolaDraftPlan selected binding route is inconsistent at index ${index}`);
    }
    if (candidate.requestTemplate?.method !== candidate.method
      || candidate.requestTemplate.path !== candidate.path) {
      throw new Error(`BolaDraftPlan selected request template is inconsistent for ${candidate.id}`);
    }
    if (safeRelativePath(candidate.source.location.path) !== candidate.source.location.path) {
      throw new Error(`BolaDraftPlan selected candidate ${candidate.id} contains an unsafe or non-normalized source path`);
    }
    const expectedCandidateId = stableId(
      "bola_candidate",
      candidate.source.fingerprint,
      candidate.method,
      candidate.path,
    );
    if (candidate.id !== expectedCandidateId) {
      throw new Error(`BolaDraftPlan selected candidate ${candidate.id} stable ID is inconsistent`);
    }
    if (interfaceIds.has(interfaceCandidateId)
      || bolaIds.has(candidate.id)
      || routes.has(route)) {
      throw new Error("BolaDraftPlan selected bindings contain duplicate identities");
    }
    interfaceIds.add(interfaceCandidateId);
    bolaIds.add(candidate.id);
    routes.add(route);
  }

  const expectedDraftId = stableId(
    "bola_draft",
    plan.scanId,
    selection.queueId,
    ...selection.candidateIds,
    ...plan.candidates.map((candidate) => candidate.id),
  );
  if (plan.draftId !== expectedDraftId) {
    throw new Error("BolaDraftPlan selected stable draft ID is inconsistent");
  }
  return plan;
}

const INTERFACE_EXCLUSION_REASON_ORDER = [
  "no_open_finding",
  "no_open_object_authorization_finding",
  "unsupported_verification_category",
  "mutation_semantics",
  "ambiguous_read_semantics",
  "unproven_route_source",
  "missing_object_identifier",
] as const;

export function validateInterfaceVerificationQueue(value: unknown): InterfaceVerificationQueue {
  const queue = assertSchema<InterfaceVerificationQueue>(
    "InterfaceVerificationQueue",
    interfaceVerificationQueueValidator,
    value,
  );
  const summary = queue.summary;
  if (summary.reviewedRoutes !== summary.eligibleRoutes + summary.excludedRoutes) {
    throw new Error("InterfaceVerificationQueue route totals are inconsistent");
  }
  if (summary.emittedCandidates !== queue.candidates.length
    || summary.eligibleRoutes !== summary.emittedCandidates + summary.omittedCandidates
    || summary.emittedExclusions !== queue.exclusions.length
    || summary.excludedRoutes !== summary.emittedExclusions + summary.omittedExclusions) {
    throw new Error("InterfaceVerificationQueue emitted and omitted route totals are inconsistent");
  }
  const shouldBePartial = summary.omittedCandidates > 0
    || summary.omittedExclusions > 0
    || summary.omittedSourceRecords > 0
    || summary.omittedFindingIds > 0
    || summary.sourceOmissions.routeAliases > 0
    || summary.sourceOmissions.associations > 0;
  if ((queue.coverage === "partial") !== shouldBePartial) {
    throw new Error("InterfaceVerificationQueue coverage is inconsistent with recorded omissions");
  }

  const visibleOmittedSourceRecords = queue.candidates.reduce((total, candidate) => total + candidate.omittedSources, 0)
    + queue.exclusions.reduce((total, exclusion) => total + exclusion.omittedSignals, 0);
  const visibleOmittedFindingIds = queue.candidates.reduce((total, candidate) => (
    total + candidate.sources.reduce((sourceTotal, source) => sourceTotal + source.omittedOpenFindingIds, 0)
  ), 0) + queue.exclusions.reduce((total, exclusion) => total + exclusion.omittedOpenFindings, 0);
  const routeDetailsAreComplete = summary.omittedCandidates === 0 && summary.omittedExclusions === 0;
  if (summary.omittedSourceRecords < visibleOmittedSourceRecords
    || summary.omittedFindingIds < visibleOmittedFindingIds
    || (routeDetailsAreComplete && (summary.omittedSourceRecords !== visibleOmittedSourceRecords
      || summary.omittedFindingIds !== visibleOmittedFindingIds))) {
    throw new Error("InterfaceVerificationQueue evidence omission totals are inconsistent");
  }

  const routeIdentities = new Set<string>();
  for (const candidate of queue.candidates) {
    const identity = `${candidate.framework}\u0000${candidate.route}`;
    if (routeIdentities.has(identity)) throw new Error("InterfaceVerificationQueue contains a duplicate route identity");
    routeIdentities.add(identity);
    if (candidate.route !== `${candidate.method} ${candidate.path}`) {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} route fields are inconsistent`);
    }
    const classification = classifyBolaStaticRoute(candidate.method, candidate.path);
    if (classification.classification !== "read_candidate") {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} is not BOLA read compatible`);
    }
    const expectedPolicy = candidate.method === "GET" ? "safe_get" : "reviewed_read_post";
    if (candidate.methodPolicy !== expectedPolicy) {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} method policy is inconsistent`);
    }
    const expectedReviews = candidate.method === "POST"
      ? ["confirm_route_and_fixture_match", "confirm_response_evidence", "confirm_post_read_only"]
      : ["confirm_route_and_fixture_match", "confirm_response_evidence"];
    if (candidate.requiredReviews.length !== expectedReviews.length
      || candidate.requiredReviews.some((review, index) => review !== expectedReviews[index])) {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} required reviews are inconsistent`);
    }
    if (!candidate.categories.includes("object_authorization")) {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} lacks object-authorization evidence`);
    }
    if (candidate.sourceCount !== candidate.sources.length + candidate.omittedSources) {
      throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} source totals are inconsistent`);
    }
    const sourceIds = new Set<string>();
    const candidateObjectIds = new Set(candidate.objectIdFields);
    for (const source of candidate.sources) {
      if (sourceIds.has(source.signalId)) {
        throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} contains duplicate source signals`);
      }
      sourceIds.add(source.signalId);
      if (safeRelativePath(source.location.path) !== source.location.path) {
        throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} contains an unsafe or non-normalized source path`);
      }
      const presentation = ROUTE_SECURITY_RULES[source.ruleId];
      if (presentation?.category !== "object_authorization" || presentation.framework !== candidate.framework) {
        throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} source is not trusted object-authorization evidence`);
      }
      if (source.objectIdFields.some((field) => !candidateObjectIds.has(field))) {
        throw new Error(`InterfaceVerificationQueue candidate ${candidate.id} source object identifiers are inconsistent`);
      }
    }
  }

  const visibleReasonCounts = new Map<string, number>();
  for (const exclusion of queue.exclusions) {
    const identity = `${exclusion.framework}\u0000${exclusion.route}`;
    if (routeIdentities.has(identity)) throw new Error("InterfaceVerificationQueue contains a duplicate route identity");
    routeIdentities.add(identity);
    if (exclusion.route !== `${exclusion.method} ${exclusion.path}`) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} route fields are inconsistent`);
    }
    if (exclusion.signalCount !== exclusion.signalIds.length + exclusion.omittedSignals
      || exclusion.openFindingCount !== exclusion.openFindingIds.length + exclusion.omittedOpenFindings) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} evidence totals are inconsistent`);
    }
    const classification = classifyBolaStaticRoute(exclusion.method, exclusion.path).classification;
    if ((classification === "mutation_excluded") !== exclusion.reasons.includes("mutation_semantics")
      || (classification === "manual_review") !== exclusion.reasons.includes("ambiguous_read_semantics")) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} read classification is inconsistent`);
    }
    if ((exclusion.openFindingCount === 0) !== exclusion.reasons.includes("no_open_finding")) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} open-finding reason is inconsistent`);
    }
    if ((exclusion.categories.includes("object_authorization")) === exclusion.reasons.includes("unsupported_verification_category")) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} verification category reason is inconsistent`);
    }
    const orderedReasons = INTERFACE_EXCLUSION_REASON_ORDER.filter((reason) => exclusion.reasons.includes(reason));
    if (orderedReasons.length !== exclusion.reasons.length
      || orderedReasons.some((reason, index) => reason !== exclusion.reasons[index])) {
      throw new Error(`InterfaceVerificationQueue exclusion ${exclusion.id} reasons are not deterministic`);
    }
    for (const reason of exclusion.reasons) visibleReasonCounts.set(reason, (visibleReasonCounts.get(reason) ?? 0) + 1);
  }

  const summaryReasons = new Set<string>();
  let previousReasonIndex = -1;
  let reasonAssignments = 0;
  for (const entry of summary.exclusionReasons) {
    if (summaryReasons.has(entry.reason)) throw new Error("InterfaceVerificationQueue contains duplicate exclusion reason totals");
    summaryReasons.add(entry.reason);
    const reasonIndex = INTERFACE_EXCLUSION_REASON_ORDER.indexOf(entry.reason);
    if (reasonIndex <= previousReasonIndex) throw new Error("InterfaceVerificationQueue exclusion reason totals are not deterministic");
    previousReasonIndex = reasonIndex;
    const visible = visibleReasonCounts.get(entry.reason) ?? 0;
    if (entry.routes < visible || entry.routes > summary.excludedRoutes
      || (summary.omittedExclusions === 0 && entry.routes !== visible)) {
      throw new Error(`InterfaceVerificationQueue exclusion reason count is inconsistent for ${entry.reason}`);
    }
    reasonAssignments += entry.routes;
  }
  if ([...visibleReasonCounts.keys()].some((reason) => !summaryReasons.has(reason))) {
    throw new Error("InterfaceVerificationQueue is missing a visible exclusion reason total");
  }
  if ((summary.excludedRoutes === 0) !== (summary.exclusionReasons.length === 0)
    || reasonAssignments < summary.excludedRoutes) {
    throw new Error("InterfaceVerificationQueue exclusion reason coverage is inconsistent");
  }
  return queue;
}

const INTERFACE_AUDIT_ATTRIBUTION_REASON_ORDER = [
  "commented_out_call",
  "ambiguous_or_dynamic_dispatch",
  "request_origin_not_proven",
  "no_proven_route_path",
  "not_recorded",
] as const;

function compareInterfaceAuditEntries(
  left: InterfaceSecurityAuditEntry,
  right: InterfaceSecurityAuditEntry,
): number {
  return (left.findingStatus === right.findingStatus ? 0 : left.findingStatus === "open" ? -1 : 1)
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.framework.localeCompare(right.framework)
    || left.route.localeCompare(right.route)
    || ROUTE_SECURITY_CATEGORY_ORDER.indexOf(left.category) - ROUTE_SECURITY_CATEGORY_ORDER.indexOf(right.category);
}

function assertSortedUniqueStrings(values: readonly string[], label: string): void {
  for (let index = 0; index < values.length; index += 1) {
    if (index > 0 && values[index - 1]!.localeCompare(values[index]!) >= 0) {
      throw new Error(`InterfaceSecurityAudit ${label} must be sorted and unique`);
    }
  }
}

export function validateInterfaceSecurityAudit(value: unknown): InterfaceSecurityAudit {
  const audit = assertSchema<InterfaceSecurityAudit>(
    "InterfaceSecurityAudit",
    interfaceSecurityAuditValidator,
    value,
  );
  const summary = audit.summary;
  const expectedAuditId = stableId(
    "interface_audit",
    audit.scan.schemaVersion,
    audit.scan.scanId,
    audit.scan.projectId,
    audit.scan.digestSha256,
  );
  if (audit.auditId !== expectedAuditId) {
    throw new Error("InterfaceSecurityAudit stable audit ID is inconsistent");
  }
  if (summary.routeCategoryEntries !== summary.openEntries + summary.suppressedOnlyEntries
    || summary.routeCategoryEntries !== summary.emittedEntries + summary.omittedEntries
    || summary.emittedEntries !== audit.entries.length
    || (summary.routeCategoryEntries === 0) !== (summary.reviewedRoutes === 0)
    || summary.reviewedRoutes > summary.routeCategoryEntries
    || summary.routeCategoryEntries > summary.reviewedRoutes * ROUTE_SECURITY_CATEGORY_ORDER.length) {
    throw new Error("InterfaceSecurityAudit entry totals are inconsistent");
  }
  if (summary.attribution.eligibleSignals
      !== summary.attribution.attributedSignals + summary.attribution.unattributedSignals
    || (summary.attribution.unattributedSignals === 0)
      !== (summary.attribution.unattributedFindings === 0)) {
    throw new Error("InterfaceSecurityAudit attribution totals are inconsistent");
  }
  if (summary.deploymentContexts.open > summary.deploymentContexts.observed) {
    throw new Error("InterfaceSecurityAudit deployment-context totals are inconsistent");
  }

  const attributionReasons = new Set<string>();
  let previousAttributionReason = -1;
  let attributedReasonSignals = 0;
  for (const entry of summary.attribution.reasons) {
    const reasonIndex = INTERFACE_AUDIT_ATTRIBUTION_REASON_ORDER.indexOf(entry.reason);
    if (reasonIndex <= previousAttributionReason || attributionReasons.has(entry.reason)) {
      throw new Error("InterfaceSecurityAudit attribution reasons are not deterministic");
    }
    previousAttributionReason = reasonIndex;
    attributionReasons.add(entry.reason);
    attributedReasonSignals += entry.signals;
  }
  if (attributedReasonSignals !== summary.attribution.unattributedSignals
    || (summary.attribution.unattributedSignals === 0) !== (summary.attribution.reasons.length === 0)) {
    throw new Error("InterfaceSecurityAudit attribution reason totals are inconsistent");
  }

  const routeCategoryIdentities = new Set<string>();
  const visibleRoutes = new Set<string>();
  const visibleCategoryCounts = new Map<string, { entries: number; openEntries: number }>();
  let visibleOpenEntries = 0;
  let visibleOmittedSourceRecords = 0;
  let visibleOmittedFindingIdReferences = 0;
  let visibleUnlocatedSourceRecords = 0;
  for (let entryIndex = 0; entryIndex < audit.entries.length; entryIndex += 1) {
    const entry = audit.entries[entryIndex]!;
    const identity = `${entry.framework}\u0000${entry.route}\u0000${entry.category}`;
    if (routeCategoryIdentities.has(identity)) {
      throw new Error("InterfaceSecurityAudit contains a duplicate route-category identity");
    }
    routeCategoryIdentities.add(identity);
    visibleRoutes.add(`${entry.framework}\u0000${entry.route}`);
    if (entryIndex > 0 && compareInterfaceAuditEntries(audit.entries[entryIndex - 1]!, entry) > 0) {
      throw new Error("InterfaceSecurityAudit entries are not deterministic");
    }
    if (entry.route !== `${entry.method} ${entry.path}`) {
      throw new Error(`InterfaceSecurityAudit entry ${entry.id} route fields are inconsistent`);
    }
    const expectedEntryId = stableId(
      "interface_audit_entry",
      audit.scan.scanId,
      entry.framework,
      entry.route,
      entry.category,
    );
    if (entry.id !== expectedEntryId) {
      throw new Error(`InterfaceSecurityAudit entry ${entry.id} stable entry ID is inconsistent`);
    }
    if (entry.sourceCount !== entry.sources.length + entry.omittedSources) {
      throw new Error(`InterfaceSecurityAudit entry ${entry.id} source totals are inconsistent`);
    }
    visibleOmittedSourceRecords += entry.omittedSources;
    if (entry.findingStatus === "open") visibleOpenEntries += 1;
    const categoryCount = visibleCategoryCounts.get(entry.category) ?? { entries: 0, openEntries: 0 };
    categoryCount.entries += 1;
    if (entry.findingStatus === "open") categoryCount.openEntries += 1;
    visibleCategoryCounts.set(entry.category, categoryCount);

    const sourceIds = new Set<string>();
    let visibleOpenFindingReferences = 0;
    for (let sourceIndex = 0; sourceIndex < entry.sources.length; sourceIndex += 1) {
      const source = entry.sources[sourceIndex]!;
      if (sourceIds.has(source.signalId)) {
        throw new Error(`InterfaceSecurityAudit entry ${entry.id} contains duplicate source signals`);
      }
      sourceIds.add(source.signalId);
      if (sourceIndex > 0) {
        const previous = entry.sources[sourceIndex - 1]!;
        if (previous.ruleId.localeCompare(source.ruleId) > 0
          || (previous.ruleId === source.ruleId && previous.signalId.localeCompare(source.signalId) >= 0)) {
          throw new Error(`InterfaceSecurityAudit entry ${entry.id} sources are not deterministic`);
        }
      }
      const presentation = ROUTE_SECURITY_RULES[source.ruleId];
      if (presentation?.category !== entry.category || presentation.framework !== entry.framework) {
        throw new Error(`InterfaceSecurityAudit entry ${entry.id} source category or framework is inconsistent`);
      }
      if (source.location) {
        if (safeRelativePath(source.location.path) !== source.location.path) {
          throw new Error(`InterfaceSecurityAudit entry ${entry.id} contains an unsafe or non-normalized source path`);
        }
      } else {
        visibleUnlocatedSourceRecords += 1;
      }
      assertSortedUniqueStrings(source.openFindingIds, `${entry.id} open finding IDs`);
      assertSortedUniqueStrings(source.suppressedFindingIds, `${entry.id} suppressed finding IDs`);
      const openSet = new Set(source.openFindingIds);
      if (source.suppressedFindingIds.some((findingId) => openSet.has(findingId))) {
        throw new Error(`InterfaceSecurityAudit entry ${entry.id} contains contradictory finding status references`);
      }
      const openReferences = source.openFindingIds.length + source.omittedOpenFindingIds;
      const suppressedReferences = source.suppressedFindingIds.length + source.omittedSuppressedFindingIds;
      if (openReferences + suppressedReferences === 0) {
        throw new Error(`InterfaceSecurityAudit entry ${entry.id} source lacks finding evidence`);
      }
      visibleOpenFindingReferences += openReferences;
      visibleOmittedFindingIdReferences += source.omittedOpenFindingIds + source.omittedSuppressedFindingIds;
    }
    if ((entry.findingStatus === "suppressed_only" && visibleOpenFindingReferences > 0)
      || (entry.findingStatus === "open" && visibleOpenFindingReferences === 0 && entry.omittedSources === 0)) {
      throw new Error(`InterfaceSecurityAudit entry ${entry.id} finding status is inconsistent`);
    }
  }

  if (visibleOpenEntries > summary.openEntries
    || (summary.omittedEntries === 0 && visibleOpenEntries !== summary.openEntries)) {
    throw new Error("InterfaceSecurityAudit visible open-entry total is inconsistent");
  }
  if (visibleRoutes.size > summary.reviewedRoutes
    || (summary.omittedEntries === 0 && visibleRoutes.size !== summary.reviewedRoutes)) {
    throw new Error("InterfaceSecurityAudit reviewed route total is inconsistent");
  }
  if (summary.omittedSourceRecords < visibleOmittedSourceRecords
    || (summary.omittedEntries === 0 && summary.omittedSourceRecords !== visibleOmittedSourceRecords)) {
    throw new Error("InterfaceSecurityAudit omitted source totals are inconsistent");
  }
  if (summary.omittedFindingIdReferences < visibleOmittedFindingIdReferences
    || (summary.omittedEntries === 0 && summary.omittedSourceRecords === 0
      && summary.omittedFindingIdReferences !== visibleOmittedFindingIdReferences)) {
    throw new Error("InterfaceSecurityAudit omitted finding reference totals are inconsistent");
  }
  if (summary.unlocatedSourceRecords < visibleUnlocatedSourceRecords
    || (summary.omittedEntries === 0 && summary.omittedSourceRecords === 0
      && summary.unlocatedSourceRecords !== visibleUnlocatedSourceRecords)) {
    throw new Error("InterfaceSecurityAudit unlocated source totals are inconsistent");
  }

  const summaryCategories = new Set<string>();
  let previousCategory = -1;
  let totalCategoryEntries = 0;
  let totalCategoryOpenEntries = 0;
  for (const category of summary.categories) {
    const categoryIndex = ROUTE_SECURITY_CATEGORY_ORDER.indexOf(category.category);
    if (categoryIndex <= previousCategory || summaryCategories.has(category.category)) {
      throw new Error("InterfaceSecurityAudit category summaries are not deterministic");
    }
    previousCategory = categoryIndex;
    summaryCategories.add(category.category);
    if (category.openEntries > category.entries) {
      throw new Error(`InterfaceSecurityAudit category totals are inconsistent for ${category.category}`);
    }
    const visible = visibleCategoryCounts.get(category.category) ?? { entries: 0, openEntries: 0 };
    if (category.entries < visible.entries || category.openEntries < visible.openEntries
      || (summary.omittedEntries === 0
        && (category.entries !== visible.entries || category.openEntries !== visible.openEntries))) {
      throw new Error(`InterfaceSecurityAudit category totals are inconsistent for ${category.category}`);
    }
    totalCategoryEntries += category.entries;
    totalCategoryOpenEntries += category.openEntries;
  }
  if ([...visibleCategoryCounts.keys()].some((category) => !summaryCategories.has(category))
    || totalCategoryEntries !== summary.routeCategoryEntries
    || totalCategoryOpenEntries !== summary.openEntries
    || (summary.routeCategoryEntries === 0) !== (summary.categories.length === 0)) {
    throw new Error("InterfaceSecurityAudit category summary totals are inconsistent");
  }

  const shouldBePartial = summary.omittedEntries > 0
    || summary.omittedSourceRecords > 0
    || summary.omittedFindingIdReferences > 0
    || summary.unlocatedSourceRecords > 0
    || summary.sourceOmissions.routeAliases > 0
    || summary.sourceOmissions.associations > 0
    || summary.attribution.unattributedSignals > 0;
  if ((audit.coverage === "partial") !== shouldBePartial) {
    throw new Error("InterfaceSecurityAudit coverage is inconsistent with recorded evidence gaps");
  }
  return audit;
}

function interfaceReviewTime(value: string): number {
  const parsed = new Date(value).getTime();
  if (!Number.isFinite(parsed)) {
    throw new Error(`Interface security review timestamp is not supported: ${value}`);
  }
  return parsed;
}

function assertInterfaceReviewText(value: string, label: string): void {
  if (value !== value.trim()) {
    throw new Error(`InterfaceSecurityDisposition ${label} must not have leading or trailing whitespace`);
  }
}

export function validateInterfaceSecurityDisposition(
  value: unknown,
): InterfaceSecurityDisposition {
  const disposition = assertSchema<InterfaceSecurityDisposition>(
    "InterfaceSecurityDisposition",
    interfaceSecurityDispositionValidator,
    value,
  );
  assertInterfaceReviewText(disposition.reviewedBy, "review owner");
  const hasOwner = disposition.reviewedBy !== INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER;
  if (hasOwner !== (disposition.reviewedAt !== undefined)) {
    throw new Error("InterfaceSecurityDisposition review owner and reviewedAt must be completed together");
  }
  if (disposition.reviewedAt
    && interfaceReviewTime(disposition.reviewedAt) < interfaceReviewTime(disposition.preparedAt)) {
    throw new Error("InterfaceSecurityDisposition reviewedAt must not precede preparedAt");
  }

  const entryIds = new Set<string>();
  for (const entry of disposition.entries) {
    if (entryIds.has(entry.entryId)) {
      throw new Error(`InterfaceSecurityDisposition contains duplicate entry ID: ${entry.entryId}`);
    }
    entryIds.add(entry.entryId);
    assertInterfaceReviewText(entry.rationale, `${entry.entryId} rationale`);
    const decided = entry.decision !== "unreviewed";
    if (decided && (!hasOwner || !disposition.reviewedAt)) {
      throw new Error("InterfaceSecurityDisposition decided entries require a review owner and reviewedAt");
    }
    if (decided && entry.rationale === INTERFACE_SECURITY_REVIEW_RATIONALE_PLACEHOLDER) {
      throw new Error(`InterfaceSecurityDisposition ${entry.entryId} must replace the template rationale`);
    }
    const expiring = entry.decision === "false_positive" || entry.decision === "accepted_risk";
    if (expiring && !entry.expiresAt) {
      throw new Error(`InterfaceSecurityDisposition ${entry.entryId} ${entry.decision} requires expiresAt`);
    }
    if (!expiring && entry.expiresAt) {
      throw new Error(`InterfaceSecurityDisposition ${entry.entryId} ${entry.decision} forbids expiresAt`);
    }
    if (entry.expiresAt && disposition.reviewedAt
      && interfaceReviewTime(entry.expiresAt) <= interfaceReviewTime(disposition.reviewedAt)) {
      throw new Error(`InterfaceSecurityDisposition ${entry.entryId} expiresAt must be after reviewedAt`);
    }
  }
  return disposition;
}

function expectedInterfaceReviewStatus(
  review: Pick<InterfaceSecurityReview, "audit" | "disposition" | "summary">,
): InterfaceSecurityReviewStatus {
  const reviewerComplete = review.disposition.reviewedBy !== INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER
    && review.disposition.reviewedAt !== undefined;
  if (review.audit.coverage === "partial"
    || review.summary.unreviewed > 0
    || review.summary.expiredDecisions > 0
    || !reviewerComplete) {
    return "incomplete";
  }
  if (review.summary.fixRequired > 0
    || review.summary.authorizedVerificationRequired > 0) {
    return "action_required";
  }
  return "recorded";
}

export function validateInterfaceSecurityReview(value: unknown): InterfaceSecurityReview {
  const review = assertSchema<InterfaceSecurityReview>(
    "InterfaceSecurityReview",
    interfaceSecurityReviewValidator,
    value,
  );
  const reconstructedDisposition = validateInterfaceSecurityDisposition({
    schemaVersion: review.disposition.schemaVersion,
    audit: {
      schemaVersion: review.audit.schemaVersion,
      auditId: review.audit.auditId,
      digestSha256: review.audit.digestSha256,
    },
    preparedAt: review.disposition.preparedAt,
    reviewedBy: review.disposition.reviewedBy,
    ...(review.disposition.reviewedAt === undefined
      ? {}
      : { reviewedAt: review.disposition.reviewedAt }),
    entries: review.entries,
  });
  const expectedDispositionDigest = sha256(canonicalJson(reconstructedDisposition));
  if (review.disposition.digestSha256 !== expectedDispositionDigest) {
    throw new Error("InterfaceSecurityReview disposition digest is inconsistent with receipt fields");
  }
  if (interfaceReviewTime(review.checkedAt) < interfaceReviewTime(review.disposition.preparedAt)) {
    throw new Error("InterfaceSecurityReview checkedAt must not precede disposition preparedAt");
  }
  if (review.disposition.reviewedAt
    && interfaceReviewTime(review.disposition.reviewedAt) > interfaceReviewTime(review.checkedAt)) {
    throw new Error("InterfaceSecurityReview disposition reviewedAt is in the future relative to checkedAt");
  }
  if (review.audit.coverage === "complete"
    && (review.audit.omittedEntries > 0 || review.audit.unattributedSignals > 0)) {
    throw new Error("InterfaceSecurityReview complete audit cannot claim recorded output or attribution omissions");
  }

  const expectedSummary: InterfaceSecurityReview["summary"] = {
    total: review.entries.length,
    unreviewed: 0,
    fixRequired: 0,
    falsePositive: 0,
    acceptedRisk: 0,
    authorizedVerificationRequired: 0,
    expiredDecisions: 0,
  };
  for (const entry of review.entries) {
    if (entry.decision === "unreviewed") expectedSummary.unreviewed += 1;
    else if (entry.decision === "fix_required") expectedSummary.fixRequired += 1;
    else if (entry.decision === "false_positive") expectedSummary.falsePositive += 1;
    else if (entry.decision === "accepted_risk") expectedSummary.acceptedRisk += 1;
    else expectedSummary.authorizedVerificationRequired += 1;
    if (entry.expiresAt
      && interfaceReviewTime(entry.expiresAt) <= interfaceReviewTime(review.checkedAt)) {
      expectedSummary.expiredDecisions += 1;
    }
  }
  if (review.audit.emittedEntries !== review.entries.length
    || canonicalJson(review.summary) !== canonicalJson(expectedSummary)) {
    throw new Error("InterfaceSecurityReview summary totals are inconsistent");
  }
  const expectedStatus = expectedInterfaceReviewStatus(review);
  if (review.status !== expectedStatus) {
    throw new Error("InterfaceSecurityReview status is inconsistent with coverage and disposition state");
  }
  const expectedReviewId = stableId(
    "interface_security_review",
    review.schemaVersion,
    review.audit.schemaVersion,
    review.audit.auditId,
    review.audit.digestSha256,
    review.disposition.schemaVersion,
    review.disposition.digestSha256,
    review.checkedAt,
  );
  if (review.reviewId !== expectedReviewId) {
    throw new Error("InterfaceSecurityReview stable review ID is inconsistent");
  }
  return review;
}

export function validateRuleCatalog(value: unknown): RuleCatalog {
  const catalog = assertSchema<RuleCatalog>("RuleCatalog", ruleCatalogValidator, value);
  const profiles = new Set<string>();
  for (const profile of catalog.applicabilityProfiles) {
    if (profiles.has(profile.id)) throw new Error(`RuleCatalog contains duplicate applicability profile: ${profile.id}`);
    profiles.add(profile.id);
  }
  const rules = new Set<string>();
  for (const rule of catalog.rules) {
    if (rules.has(rule.ruleId)) throw new Error(`RuleCatalog contains duplicate rule: ${rule.ruleId}`);
    rules.add(rule.ruleId);
    for (const profile of rule.applicability) {
      if (!profiles.has(profile)) throw new Error(`RuleCatalog rule ${rule.ruleId} references unknown applicability profile: ${profile}`);
    }
  }
  return catalog;
}

function assertSafeRulePackSelector(value: string, label: string, prefix: boolean): void {
  if (value !== value.trim() || /[\\\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`RulePack ${label} must be trimmed text without backslashes or control characters`);
  }
  if (value.startsWith("/") || value.startsWith("//") || /^[A-Za-z]:/u.test(value) || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(value)) {
    throw new Error(`RulePack ${label} must be a safe relative path selector`);
  }
  if (prefix !== value.endsWith("/")) {
    throw new Error(`RulePack ${label} ${prefix ? "must" : "must not"} end with /`);
  }
  const path = prefix ? value.slice(0, -1) : value;
  if (!path || path.includes("//") || path.split("/").some((part) => !part || part === "." || part === ".." || /%(?:2e|2f|5c)/iu.test(part))) {
    throw new Error(`RulePack ${label} contains an unsafe or ambiguous path segment`);
  }
}

export function validateRulePack(value: unknown): RulePack {
  const pack = assertSchema<RulePack>("RulePack", rulePackValidator, value, "1.1.0");
  const assertSafeText = (text: string, label: string): void => {
    if (text !== text.trim() || /[\u0000-\u001f\u007f]/u.test(text)) throw new Error(`RulePack ${label} must be trimmed single-line text without control characters`);
  };
  assertSafeText(pack.description, `${pack.packId} description`);
  const ruleIds = new Set<string>();
  for (const rule of pack.rules) {
    const expectedPrefix = `custom.${pack.packId}.`;
    if (!rule.ruleId.startsWith(expectedPrefix)) {
      throw new Error(`RulePack rule ${rule.ruleId} must start with ${expectedPrefix}`);
    }
    if (ruleIds.has(rule.ruleId)) throw new Error(`RulePack contains duplicate rule: ${rule.ruleId}`);
    ruleIds.add(rule.ruleId);
    assertSafeText(rule.title, `${rule.ruleId} title`);
    assertSafeText(rule.description, `${rule.ruleId} description`);
    assertSafeText(rule.remediation, `${rule.ruleId} remediation`);
    if (rule.match.emitWhen === "absent" && rule.evidenceLevel !== "inferred") {
      throw new Error(`RulePack absent rule ${rule.ruleId} must use inferred evidence`);
    }
    for (const selector of rule.files.pathPrefixes ?? []) assertSafeRulePackSelector(selector, `${rule.ruleId} pathPrefixes`, true);
    for (const selector of rule.files.excludePathPrefixes ?? []) assertSafeRulePackSelector(selector, `${rule.ruleId} excludePathPrefixes`, true);
    for (const selector of rule.files.pathSuffixes ?? []) assertSafeRulePackSelector(selector, `${rule.ruleId} pathSuffixes`, false);
    const caseSensitive = rule.match.caseSensitive ?? true;
    const normalize = (literal: string): string => caseSensitive ? literal : literal.toLowerCase();
    const excludes = new Set((rule.match.excludes ?? []).map(normalize));
    for (const literal of [...rule.match.containsAny, ...(rule.match.containsAll ?? [])]) {
      if (!literal.trim()) throw new Error(`RulePack rule ${rule.ruleId} contains a whitespace-only literal`);
      if (excludes.has(normalize(literal))) throw new Error(`RulePack rule ${rule.ruleId} both requires and excludes the same literal`);
    }
    const literalBytes = [...rule.match.containsAny, ...(rule.match.containsAll ?? []), ...(rule.match.excludes ?? [])]
      .reduce((total, literal) => total + Buffer.byteLength(literal, "utf8"), 0);
    if (literalBytes > 16 * 1024) throw new Error(`RulePack rule ${rule.ruleId} literals exceed 16 KiB`);
  }
  return pack;
}

export function validateRulePackPreview(value: unknown): RulePackPreview {
  const preview = assertSchema<RulePackPreview>("RulePackPreview", rulePackPreviewValidator, value);
  const inventoryShouldBePartial = preview.inventory.reasons.length > 0;
  if ((preview.inventory.status === "partial") !== inventoryShouldBePartial) {
    throw new Error("RulePackPreview inventory status must agree with its reasons");
  }
  const packIds = new Set<string>();
  const ruleIds = new Set<string>();
  for (const pack of preview.rulePacks) {
    if (packIds.has(pack.packId)) throw new Error(`RulePackPreview contains duplicate rule pack: ${pack.packId}`);
    packIds.add(pack.packId);
    if (pack.ruleCount !== pack.rules.length) throw new Error(`RulePackPreview rule count does not match pack ${pack.packId}`);
    for (const rule of pack.rules) {
      if (!rule.ruleId.startsWith(`custom.${pack.packId}.`)) {
        throw new Error(`RulePackPreview rule ID does not match pack ${pack.packId}: ${rule.ruleId}`);
      }
      if (ruleIds.has(rule.ruleId)) throw new Error(`RulePackPreview contains duplicate rule: ${rule.ruleId}`);
      ruleIds.add(rule.ruleId);
      if (rule.evaluatedFileCount > preview.inventory.fileCount || rule.selectedFileCount > rule.evaluatedFileCount) {
        throw new Error(`RulePackPreview rule ${rule.ruleId} contains impossible file counts`);
      }
      if (rule.selectedFiles.length + rule.omittedSelectedFileCount !== rule.selectedFileCount) {
        throw new Error(`RulePackPreview rule ${rule.ruleId} selected-file counts are inconsistent`);
      }
      if (rule.selectedFiles.some((path) => safeRelativePath(path) !== path)) {
        throw new Error(`RulePackPreview rule ${rule.ruleId} contains an unsafe or non-normalized selected path`);
      }
      if ((rule.status === "partial") !== (rule.reasons.length > 0)) {
        throw new Error(`RulePackPreview rule ${rule.ruleId} status must agree with its reasons`);
      }
      if (rule.emitWhen === "absent" && rule.selectedFileCount === 0 && rule.status !== "partial") {
        throw new Error(`RulePackPreview absent rule ${rule.ruleId} cannot be complete with no selected files`);
      }
    }
    const packShouldBePartial = preview.inventory.status === "partial" || pack.rules.some((rule) => rule.status === "partial");
    if ((pack.status === "partial") !== packShouldBePartial || (pack.status === "partial") !== (pack.reasons.length > 0)) {
      throw new Error(`RulePackPreview pack ${pack.packId} status is inconsistent`);
    }
  }
  const previewShouldBePartial = preview.inventory.status === "partial" || preview.rulePacks.some((pack) => pack.status === "partial");
  if ((preview.status === "partial") !== previewShouldBePartial || (preview.status === "partial") !== (preview.reasons.length > 0)) {
    throw new Error("RulePackPreview status is inconsistent");
  }
  return preview;
}

let bundledRuleIds: Set<string> | undefined;

function catalogRuleIds(): Set<string> {
  if (!bundledRuleIds) {
    const path = fileURLToPath(new URL("../../../rules/catalog.json", import.meta.url));
    const catalog = validateRuleCatalog(JSON.parse(readFileSync(path, "utf8")) as unknown);
    bundledRuleIds = new Set(catalog.rules.map((rule) => rule.ruleId));
  }
  return bundledRuleIds;
}

export function validateSecurityPolicy(value: unknown): SecurityPolicy {
  const policy = assertSchema<SecurityPolicy>("SecurityPolicy", securityPolicyValidator, value, "1.1.0");
  const requiredEngines = new Set(policy.requiredEngines);
  for (const engine of ["gitleaks", "opengrep", "trivy"] as const) {
    if (!requiredEngines.has(engine)) throw new Error(`SecurityPolicy must retain required engine: ${engine}`);
  }
  const knownRules = catalogRuleIds();
  for (const ruleId of [...policy.rules.required, ...policy.rules.block]) {
    if (!knownRules.has(ruleId)) throw new Error(`SecurityPolicy references unknown shipped rule: ${ruleId}`);
  }
  const requiredRules = new Set(policy.rules.required);
  for (const ruleId of policy.rules.block) {
    if (!requiredRules.has(ruleId)) throw new Error(`SecurityPolicy blocking rule must also be required: ${ruleId}`);
  }
  const suppressionFingerprints = new Set<string>();
  for (const suppression of policy.suppressions) {
    const fingerprint = suppression.fingerprint.toLowerCase();
    if (suppressionFingerprints.has(fingerprint)) throw new Error(`SecurityPolicy contains duplicate suppression fingerprint: ${fingerprint}`);
    suppressionFingerprints.add(fingerprint);
    if (!suppression.reason.trim()) throw new Error(`SecurityPolicy suppression ${fingerprint} must contain a non-whitespace reason`);
  }
  return policy;
}
