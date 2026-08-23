import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { AuthorizationManifest, BolaAuthorizationManifest, BolaDraftPlan, CiReport, FixContract, RuleCatalog, RulePack, RulePackPreview, RulePackRecord, ScanReport, SecurityPolicy } from "../schema.js";
import { routeSecurityIssueKey } from "./route-security.js";
import { safeRelativePath } from "../reporters/safety.js";

type PublicSchemaName = "ScanReport" | "CiReport" | "FixContract" | "AuthorizationManifest" | "BolaAuthorizationManifest" | "BolaDraftPlan" | "RuleCatalog" | "RulePack" | "RulePackPreview" | "SecurityPolicy";

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
const bolaDraftPlanValidator = ajv.compile(loadSchema("bola-draft.schema.json"));
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
  const report = assertSchema<ScanReport>("ScanReport", scanReportValidator, value, "1.3.0");
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
  }
  if (report.policy?.source === "defaults") {
    if (report.policy.policyId || report.policy.digestSha256 || report.policy.expiresAt) throw new Error("ScanReport default policy record cannot claim operator policy identity");
    if (report.policy.requiredRuleIds.length > 0 || report.policy.blockingRuleIds.length > 0 || report.policy.suppressionCount > 0) {
      throw new Error("ScanReport default policy record cannot claim operator rules or suppressions");
    }
    if (report.policy.suppressionApproval !== "not_applicable") throw new Error("ScanReport default policy record cannot claim suppression approval");
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
  const report = assertSchema<CiReport>("CiReport", ciReportValidator, value, "1.3.0");
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
  if (report.decision === "incomplete" && report.requiredCoverage.gaps.length === 0) {
    throw new Error("CiReport incomplete decision requires a required coverage gap");
  }
  if (report.requiredCoverage.gaps.length > 0 && !["block", "incomplete"].includes(report.decision)) {
    throw new Error(`CiReport decision ${report.decision} cannot claim complete acceptance with required coverage gaps`);
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
    if (policy.targetConfiguration !== "not_recorded" || policy.policyId || policy.digestSha256 || policy.expiresAt || policy.gate || policy.requiredEngines.length > 0 || policy.suppressionCount !== 0 || policy.suppressionApproval !== "not_recorded" || policy.relaxations.length > 0) {
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

export function validateBolaDraftPlan(value: unknown): BolaDraftPlan {
  return assertSchema<BolaDraftPlan>("BolaDraftPlan", bolaDraftPlanValidator, value);
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
  const policy = assertSchema<SecurityPolicy>("SecurityPolicy", securityPolicyValidator, value);
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
