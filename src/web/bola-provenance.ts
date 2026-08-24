import type {
  BolaAuthorizationCheck,
  BolaAuthorizationManifest,
  BolaAuthorizationTemplate,
  BolaVerificationProvenance,
  BolaVerificationReport,
} from "../schema.js";
import { BOLA_VERIFICATION_REPORT_SCHEMA_VERSION } from "../schema.js";
import { canonicalJson } from "../core/utils.js";

export function createBolaVerificationProvenance(
  manifest: BolaAuthorizationManifest,
  template: BolaAuthorizationTemplate,
  check: BolaAuthorizationCheck,
): BolaVerificationProvenance {
  const binding = check.templateBinding;
  if (!binding) throw new Error("BOLA verification report provenance requires a template-bound authorization check");
  return {
    status: "preflight_verified",
    receipt: {
      schemaVersion: check.schemaVersion as BolaVerificationProvenance["receipt"]["schemaVersion"],
      checkId: check.checkId,
      checkedAt: check.checkedAt,
    },
    manifest: {
      schemaVersion: manifest.schemaVersion,
      digestSha256: check.manifestDigestSha256,
      environment: check.environment,
    },
    template: {
      schemaVersion: template.schemaVersion,
      ...binding,
    },
    authorization: {
      summary: { ...check.summary },
      caseIds: [...check.caseIds],
    },
  };
}

export function assertBolaVerificationReportSourceBinding(
  manifest: BolaAuthorizationManifest,
  template: BolaAuthorizationTemplate,
  check: BolaAuthorizationCheck,
  report: BolaVerificationReport,
): void {
  if (report.schemaVersion !== BOLA_VERIFICATION_REPORT_SCHEMA_VERSION || !report.provenance) {
    throw new Error("BOLA offline audit requires a provenance-bound BolaVerificationReport 1.1.0");
  }
  const expectedProvenance = createBolaVerificationProvenance(manifest, template, check);
  if (canonicalJson(report.provenance) !== canonicalJson(expectedProvenance)) {
    throw new Error("BOLA verification report provenance does not match the supplied manifest, template and check");
  }

  const accountLabels = manifest.accounts.map((account) => account.label);
  if (report.target !== manifest.targetBaseUrl
    || report.accounts.length !== accountLabels.length
    || report.accounts.some((account, index) => account !== accountLabels[index])
    || report.cases.length !== manifest.cases.length) {
    throw new Error("BOLA verification report source fields do not match the supplied manifest");
  }

  for (let index = 0; index < manifest.cases.length; index += 1) {
    const expected = manifest.cases[index]!;
    const actual = report.cases[index]!;
    if (actual.caseId !== expected.id
      || actual.method !== expected.method
      || actual.path !== expected.path
      || actual.testDataLabel !== expected.testDataLabel
      || actual.ownerAccount !== expected.ownerAccount
      || actual.otherAccount !== expected.otherAccount) {
      throw new Error(`BOLA verification report source fields differ at case index ${index}`);
    }
  }
}
