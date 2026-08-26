import type {
  BolaAuthorizationTemplate,
  BolaVerificationLineageAudit,
  ScanReport,
} from "../schema.js";
import {
  BOLA_VERIFICATION_LINEAGE_AUDIT_SCHEMA_VERSION,
} from "../schema.js";
import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateBolaAuthorizationCheck,
  validateBolaAuthorizationTemplate,
  validateBolaDraftPlan,
  validateBolaVerificationLineageAudit,
  validateBolaVerificationReport,
  validateScanReport,
} from "../core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import { loadBolaAuthorization, validateBolaAuthorization } from "./authorization.js";
import { auditBolaVerification, loadBolaVerificationReport } from "./bola-audit.js";
import { createSelectedBolaDraftPlan } from "./bola-draft.js";
import {
  createBolaAuthorizationTemplate,
  loadBolaAuthorizationCheck,
  loadBolaAuthorizationTemplate,
  loadSelectedBolaDraft,
} from "./bola-preflight.js";
import { createInterfaceVerificationQueue } from "./interface-verification-queue.js";

export const MAX_BOLA_LINEAGE_SCAN_REPORT_BYTES = 64 * 1024 * 1024;

export interface AuditBolaLineageOptions {
  scanReportPath: string;
  draftPath: string;
  authorizationPath: string;
  templatePath: string;
  checkPath: string;
  reportPath: string;
}

export async function loadBolaLineageScanReport(path: string): Promise<ScanReport> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_LINEAGE_SCAN_REPORT_BYTES,
    "BOLA lineage scan report",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("BOLA lineage scan report must be valid JSON");
  }
  return validateScanReport(parsed);
}

function assertSelectedDraftMatchesScan(
  scan: ScanReport,
  draftValue: unknown,
): ReturnType<typeof validateBolaDraftPlan> {
  const draft = validateBolaDraftPlan(draftValue);
  if (draft.schemaVersion !== "1.1.0" || !draft.selection) {
    throw new Error("BOLA lineage audit requires a selected BolaDraftPlan 1.1.0");
  }
  const regenerated = createSelectedBolaDraftPlan(scan, draft.selection.candidateIds);
  const comparableRegenerated = { ...regenerated, generatedAt: draft.generatedAt };
  if (canonicalJson(comparableRegenerated) !== canonicalJson(draft)) {
    throw new Error("BOLA lineage selected draft does not match the regenerated scan selection");
  }
  return draft;
}

function templateSourceFields(template: BolaAuthorizationTemplate): object {
  return {
    templateId: template.templateId,
    draftId: template.draftId,
    scanId: template.scanId,
    projectId: template.projectId,
    selection: template.selection,
    manifest: template.manifest,
    bindings: template.bindings,
  };
}

function assertTemplateMatchesDraft(
  draft: ReturnType<typeof validateBolaDraftPlan>,
  template: BolaAuthorizationTemplate,
): void {
  const regenerated = createBolaAuthorizationTemplate(draft);
  if (canonicalJson(templateSourceFields(regenerated))
    !== canonicalJson(templateSourceFields(template))) {
    throw new Error("BOLA lineage authorization template does not match the selected draft");
  }
}

export function auditBolaVerificationLineage(
  scanValue: unknown,
  draftValue: unknown,
  manifestValue: unknown,
  templateValue: unknown,
  checkValue: unknown,
  reportValue: unknown,
): BolaVerificationLineageAudit {
  const scan = validateScanReport(scanValue);
  const manifest = validateBolaAuthorization(manifestValue);
  const template = validateBolaAuthorizationTemplate(templateValue);
  const check = validateBolaAuthorizationCheck(checkValue);
  const report = validateBolaVerificationReport(reportValue);
  const draft = assertSelectedDraftMatchesScan(scan, draftValue);
  assertTemplateMatchesDraft(draft, template);

  const queue = createInterfaceVerificationQueue(scan);
  const verificationAudit = auditBolaVerification(
    manifest,
    template,
    check,
    report,
  );
  const scanDigestSha256 = sha256(canonicalJson(scan));
  const draftDigestSha256 = sha256(canonicalJson(draft));
  const selectedCandidates = draft.candidates.length;
  const lineageAuditId = stableId(
    "bola_lineage_audit",
    scan.schemaVersion,
    scan.scanId,
    scan.profile.projectId,
    scanDigestSha256,
    queue.schemaVersion,
    queue.queueId,
    queue.coverage,
    queue.coverageScope,
    String(queue.summary.reviewedRoutes),
    String(queue.summary.eligibleRoutes),
    String(queue.summary.excludedRoutes),
    String(selectedCandidates),
    draft.schemaVersion,
    draft.draftId,
    draft.generatedAt,
    draftDigestSha256,
    template.schemaVersion,
    template.templateId,
    verificationAudit.template.digestSha256,
    verificationAudit.schemaVersion,
    verificationAudit.auditId,
    verificationAudit.report.verificationId,
    verificationAudit.report.digestSha256,
  );

  return validateBolaVerificationLineageAudit({
    schemaVersion: BOLA_VERIFICATION_LINEAGE_AUDIT_SCHEMA_VERSION,
    lineageAuditId,
    auditedAt: new Date().toISOString(),
    status: "lineage_verified",
    scan: {
      schemaVersion: scan.schemaVersion,
      scanId: scan.scanId,
      projectId: scan.profile.projectId,
      digestSha256: scanDigestSha256,
    },
    queue: {
      schemaVersion: queue.schemaVersion,
      queueId: queue.queueId,
      coverageStatus: queue.coverage,
      coverageScope: queue.coverageScope,
      reviewedRoutes: queue.summary.reviewedRoutes,
      eligibleRoutes: queue.summary.eligibleRoutes,
      excludedRoutes: queue.summary.excludedRoutes,
      selectedCandidates,
    },
    draft: {
      schemaVersion: draft.schemaVersion,
      draftId: draft.draftId,
      generatedAt: draft.generatedAt,
      digestSha256: draftDigestSha256,
      selectedCandidates,
    },
    template: {
      schemaVersion: template.schemaVersion,
      templateId: template.templateId,
      digestSha256: verificationAudit.template.digestSha256,
    },
    verificationAudit: {
      schemaVersion: verificationAudit.schemaVersion,
      auditId: verificationAudit.auditId,
      verificationId: verificationAudit.report.verificationId,
      reportDigestSha256: verificationAudit.report.digestSha256,
    },
    binding: {
      scanReport: true,
      regeneratedQueue: true,
      selectedDraft: true,
      draftTemplate: true,
      retainedArtifacts: true,
      exactCandidateOrder: true,
      exactSourceEvidence: true,
    },
    io: {
      environmentValuesRead: 0,
      dnsLookups: 0,
      requesterCalls: 0,
      networkRequests: 0,
    },
    limitations: [
      "This lineage audit proves consistency among the exact retained files only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
      "This lineage audit does not execute target code, replay requests or prove that the recorded scan and network observations occurred.",
      "Static selection and protected listed cases do not prove that a route or system is secure or exploitable beyond the exact recorded scope.",
    ],
  });
}

export async function auditBolaLineage(
  options: AuditBolaLineageOptions,
): Promise<BolaVerificationLineageAudit> {
  const [scan, draft, manifest, template, check, report] = await Promise.all([
    loadBolaLineageScanReport(options.scanReportPath),
    loadSelectedBolaDraft(options.draftPath),
    loadBolaAuthorization(options.authorizationPath),
    loadBolaAuthorizationTemplate(options.templatePath),
    loadBolaAuthorizationCheck(options.checkPath),
    loadBolaVerificationReport(options.reportPath),
  ]);
  return auditBolaVerificationLineage(
    scan,
    draft,
    manifest,
    template,
    check,
    report,
  );
}
