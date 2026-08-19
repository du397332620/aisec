import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { AuthorizationManifest, BolaAuthorizationManifest, BolaDraftPlan, FixContract, RuleCatalog, ScanReport, SecurityPolicy } from "../schema.js";

type PublicSchemaName = "ScanReport" | "FixContract" | "AuthorizationManifest" | "BolaAuthorizationManifest" | "BolaDraftPlan" | "RuleCatalog" | "SecurityPolicy";

function loadSchema(filename: string): object {
  const path = fileURLToPath(new URL(`../../../schemas/${filename}`, import.meta.url));
  return JSON.parse(readFileSync(path, "utf8")) as object;
}

const ajv = new Ajv2020({ allErrors: true, strict: true });
const addFormats = addFormatsModule as unknown as (instance: Ajv2020) => Ajv2020;
addFormats(ajv);

const scanReportValidator = ajv.compile(loadSchema("scan-report.schema.json"));
const fixContractValidator = ajv.compile(loadSchema("fix-contract.schema.json"));
const authorizationManifestValidator = ajv.compile(loadSchema("authorization-manifest.schema.json"));
const bolaAuthorizationManifestValidator = ajv.compile(loadSchema("bola-authorization-manifest.schema.json"));
const bolaDraftPlanValidator = ajv.compile(loadSchema("bola-draft.schema.json"));
const ruleCatalogValidator = ajv.compile(loadSchema("rule-catalog.schema.json"));
const securityPolicyValidator = ajv.compile(loadSchema("security-policy.schema.json"));

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

export function validateScanReport(value: unknown): ScanReport {
  const report = assertSchema<ScanReport>("ScanReport", scanReportValidator, value, "1.1.0");
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
