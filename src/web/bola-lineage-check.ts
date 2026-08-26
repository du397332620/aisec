import type {
  BolaVerificationLineageAudit,
  BolaVerificationLineageCheck,
} from "../schema.js";
import {
  BOLA_VERIFICATION_LINEAGE_CHECK_SCHEMA_VERSION,
} from "../schema.js";
import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateBolaVerificationLineageAudit,
  validateBolaVerificationLineageCheck,
} from "../core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import { loadBolaAuthorization } from "./authorization.js";
import { loadBolaVerificationReport } from "./bola-audit.js";
import {
  auditBolaVerificationLineage,
  loadBolaLineageScanReport,
} from "./bola-lineage-audit.js";
import {
  MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES,
  loadBolaAuthorizationCheck,
  loadBolaAuthorizationTemplate,
  loadSelectedBolaDraft,
} from "./bola-preflight.js";

export const MAX_BOLA_LINEAGE_RECEIPT_BYTES = MAX_BOLA_PREFLIGHT_DOCUMENT_BYTES;

export interface CheckBolaLineageOptions {
  scanReportPath: string;
  draftPath: string;
  authorizationPath: string;
  templatePath: string;
  checkPath: string;
  reportPath: string;
  lineageAuditPath: string;
}

export async function loadBolaVerificationLineageAudit(
  path: string,
): Promise<BolaVerificationLineageAudit> {
  const text = await readBoundedUtf8File(
    path,
    MAX_BOLA_LINEAGE_RECEIPT_BYTES,
    "BOLA verification lineage audit",
  );
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error("BOLA verification lineage audit must be valid JSON");
  }
  return validateBolaVerificationLineageAudit(parsed);
}

function stableLineageFields(audit: BolaVerificationLineageAudit): object {
  const { auditedAt: _regeneratedTimestamp, ...stableFields } = audit;
  return stableFields;
}

export function checkBolaVerificationLineageReceipt(
  scanValue: unknown,
  draftValue: unknown,
  manifestValue: unknown,
  templateValue: unknown,
  checkValue: unknown,
  reportValue: unknown,
  lineageAuditValue: unknown,
): BolaVerificationLineageCheck {
  const savedAudit = validateBolaVerificationLineageAudit(lineageAuditValue);
  const recomputedAudit = auditBolaVerificationLineage(
    scanValue,
    draftValue,
    manifestValue,
    templateValue,
    checkValue,
    reportValue,
  );
  if (canonicalJson(stableLineageFields(savedAudit))
    !== canonicalJson(stableLineageFields(recomputedAudit))) {
    throw new Error("saved BOLA lineage audit stable fields do not match the recomputed retained artifacts");
  }

  const receiptDigestSha256 = sha256(canonicalJson(savedAudit));
  const lineageCheckId = stableId(
    "bola_lineage_check",
    savedAudit.schemaVersion,
    savedAudit.lineageAuditId,
    savedAudit.auditedAt,
    receiptDigestSha256,
  );
  return validateBolaVerificationLineageCheck({
    schemaVersion: BOLA_VERIFICATION_LINEAGE_CHECK_SCHEMA_VERSION,
    lineageCheckId,
    checkedAt: new Date().toISOString(),
    status: "saved_lineage_verified",
    receipt: {
      schemaVersion: savedAudit.schemaVersion,
      lineageAuditId: savedAudit.lineageAuditId,
      auditedAt: savedAudit.auditedAt,
      digestSha256: receiptDigestSha256,
    },
    binding: {
      savedReceipt: true,
      recomputedLineage: true,
      exactStableFields: true,
      retainedArtifacts: true,
      exactReceiptDigest: true,
    },
    io: {
      environmentValuesRead: 0,
      dnsLookups: 0,
      requesterCalls: 0,
      networkRequests: 0,
    },
    limitations: [
      "The saved lineage audit timestamp is recorded and digest-bound but excluded from recomputation because each lineage audit records its own execution time.",
      "This check proves consistency among the saved receipt and exact retained files only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
      "This check does not execute target code, replay requests or prove that the recorded scan and network observations occurred.",
    ],
  });
}

export async function checkBolaLineage(
  options: CheckBolaLineageOptions,
): Promise<BolaVerificationLineageCheck> {
  const [scan, draft, manifest, template, check, report, lineageAudit] = await Promise.all([
    loadBolaLineageScanReport(options.scanReportPath),
    loadSelectedBolaDraft(options.draftPath),
    loadBolaAuthorization(options.authorizationPath),
    loadBolaAuthorizationTemplate(options.templatePath),
    loadBolaAuthorizationCheck(options.checkPath),
    loadBolaVerificationReport(options.reportPath),
    loadBolaVerificationLineageAudit(options.lineageAuditPath),
  ]);
  return checkBolaVerificationLineageReceipt(
    scan,
    draft,
    manifest,
    template,
    check,
    report,
    lineageAudit,
  );
}
