import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Ajv2020, type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { AuthorizationManifest, BolaAuthorizationManifest, BolaDraftPlan, FixContract, RuleCatalog, ScanReport } from "../schema.js";

type PublicSchemaName = "ScanReport" | "FixContract" | "AuthorizationManifest" | "BolaAuthorizationManifest" | "BolaDraftPlan" | "RuleCatalog";

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

function describeError(error: ErrorObject): string {
  const path = error.instancePath || "/";
  if (error.keyword === "additionalProperties") {
    const property = String((error.params as { additionalProperty?: unknown }).additionalProperty ?? "unknown");
    return `${path} contains unsupported additional properties: ${JSON.stringify(property)}`;
  }
  return `${path} ${error.message ?? `failed ${error.keyword}`}`;
}

function assertSchema<T>(name: PublicSchemaName, validator: ValidateFunction, value: unknown): T {
  if (validator(value)) return value as T;
  const details = (validator.errors ?? []).slice(0, 8).map(describeError).join("; ");
  throw new Error(`${name} does not match schema 1.0.0: ${details || "validation failed"}`);
}

export function validateScanReport(value: unknown): ScanReport {
  return assertSchema<ScanReport>("ScanReport", scanReportValidator, value);
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
