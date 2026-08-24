import type {
  BolaVerificationAudit,
  BolaVerificationReport,
} from "../schema.js";
import {
  BOLA_VERIFICATION_AUDIT_SCHEMA_VERSION,
} from "../schema.js";
import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateBolaAuthorizationCheck,
  validateBolaAuthorizationTemplate,
  validateBolaVerificationAudit,
  validateBolaVerificationReport,
} from "../core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import { loadBolaAuthorization, validateBolaAuthorization } from "./authorization.js";
import {
  MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
  assertBolaVerificationPreflight,
  loadBolaAuthorizationCheck,
  loadBolaAuthorizationTemplate,
} from "./bola-preflight.js";
import { assertBolaVerificationReportSourceBinding } from "./bola-provenance.js";

export const MAX_BOLA_AUDIT_DOCUMENT_BYTES = MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES;

export interface AuditBolaOptions {
  templatePath: string;
  checkPath: string;
  reportPath: string;
}

export async function loadBolaVerificationReport(path: string): Promise<BolaVerificationReport> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_AUDIT_DOCUMENT_BYTES,
    "BOLA verification report",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("BOLA verification report must be valid JSON");
  }
  return validateBolaVerificationReport(parsed);
}

export function auditBolaVerification(
  manifestValue: unknown,
  templateValue: unknown,
  checkValue: unknown,
  reportValue: unknown,
): BolaVerificationAudit {
  const manifest = validateBolaAuthorization(manifestValue);
  const template = validateBolaAuthorizationTemplate(templateValue);
  const check = validateBolaAuthorizationCheck(checkValue);
  const report = validateBolaVerificationReport(reportValue);
  const receipt = assertBolaVerificationPreflight(manifest, template, check);
  assertBolaVerificationReportSourceBinding(manifest, template, receipt, report);
  const binding = receipt.templateBinding;
  if (!binding) throw new Error("BOLA offline audit requires a template-bound authorization check");

  const reportDigestSha256 = sha256(canonicalJson(report));
  const summary = {
    cases: report.cases.length,
    vulnerable: report.cases.filter((item) => item.status === "vulnerable").length,
    protected: report.cases.filter((item) => item.status === "protected").length,
    inconclusive: report.cases.filter((item) => item.status === "inconclusive").length,
    notRun: report.cases.filter((item) => item.status === "not_run").length,
    verifiedSignals: report.signals.length,
  };
  const receiptSchemaVersion = receipt.schemaVersion as BolaVerificationAudit["receipt"]["schemaVersion"];
  const auditId = stableId(
    "bola_audit",
    report.verificationId,
    reportDigestSha256,
    receiptSchemaVersion,
    receipt.checkId,
    receipt.checkedAt,
    receipt.manifestDigestSha256,
    template.schemaVersion,
    binding.templateId,
    binding.templateDigestSha256,
  );
  return validateBolaVerificationAudit({
    schemaVersion: BOLA_VERIFICATION_AUDIT_SCHEMA_VERSION,
    auditId,
    auditedAt: new Date().toISOString(),
    status: "artifacts_verified",
    report: {
      schemaVersion: report.schemaVersion,
      verificationId: report.verificationId,
      digestSha256: reportDigestSha256,
      requestCount: report.requestCount,
      requiredRequests: receipt.summary.requiredRequests,
      authorizedMaxRequests: receipt.summary.maxRequests,
      coverageStatus: report.coverage[0]!.status as "complete" | "partial",
      summary,
    },
    receipt: {
      schemaVersion: receiptSchemaVersion,
      checkId: receipt.checkId,
      checkedAt: receipt.checkedAt,
    },
    manifest: {
      schemaVersion: manifest.schemaVersion,
      digestSha256: receipt.manifestDigestSha256,
    },
    template: {
      schemaVersion: template.schemaVersion,
      templateId: binding.templateId,
      digestSha256: binding.templateDigestSha256,
    },
    binding: {
      preflightReceipt: true,
      reportProvenance: true,
      reportSourceFields: true,
      exactCaseOrder: true,
      exactRequestBudget: true,
      resultSemantics: true,
    },
    io: {
      environmentValuesRead: 0,
      dnsLookups: 0,
      requesterCalls: 0,
      networkRequests: 0,
    },
    limitations: [
      "This audit proves local structural and digest consistency only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
      "This audit does not replay requests or prove that the recorded network observations occurred or still describe the service.",
      "A protected listed case is not proof that the route or system is secure beyond the exact recorded verification scope.",
    ],
  });
}

export async function auditBola(
  authorizationPath: string,
  options: AuditBolaOptions,
): Promise<BolaVerificationAudit> {
  const [manifest, template, check, report] = await Promise.all([
    loadBolaAuthorization(authorizationPath),
    loadBolaAuthorizationTemplate(options.templatePath),
    loadBolaAuthorizationCheck(options.checkPath),
    loadBolaVerificationReport(options.reportPath),
  ]);
  return auditBolaVerification(manifest, template, check, report);
}
