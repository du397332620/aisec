import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateInterfaceSecurityAudit,
  validateInterfaceSecurityDisposition,
  validateInterfaceSecurityReview,
  validateInterfaceSecurityReviewCheck,
} from "../core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import {
  INTERFACE_SECURITY_REVIEW_CHECK_SCHEMA_VERSION,
  type InterfaceSecurityAudit,
  type InterfaceSecurityDisposition,
  type InterfaceSecurityReview,
  type InterfaceSecurityReviewCheck,
} from "../schema.js";
import {
  checkInterfaceSecurityReview,
  loadInterfaceSecurityAudit,
  loadInterfaceSecurityDisposition,
} from "./interface-security-review.js";

export const MAX_INTERFACE_SECURITY_REVIEW_BYTES = 2 * 1024 * 1024;

export const INTERFACE_SECURITY_REVIEW_CHECK_LIMITATIONS = [
  "This check proves exact local file consistency and current local expiry evaluation only; SHA-256 digests and stable IDs are not signatures and do not authenticate reviewer identity, origin or time.",
  "The saved receipt remains unchanged; its current evaluation can differ only when retained expiry timestamps cross the current local clock, which is not a trusted timestamp authority.",
  "This check does not prove scan evidence, reachability, deployed behavior, exploitability, the absence of vulnerabilities or that any route or project is safe.",
  "The check executes no target code, reads no credential values, resolves no DNS and sends no network requests.",
] as const;

export const INTERFACE_SECURITY_REVIEW_CHECK_DISCLAIMER = "Saved review verified means only that the retained review matches the exact retained audit and disposition. The current evaluation is not a security pass, release waiver, active test result or assurance that any route or project is safe.";

async function loadReviewJson(path: string): Promise<unknown> {
  const text = await readBoundedUtf8File(
    path,
    MAX_INTERFACE_SECURITY_REVIEW_BYTES,
    "Interface security review",
  );
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error("Interface security review must be valid JSON");
  }
}

export async function loadInterfaceSecurityReview(
  path: string,
): Promise<InterfaceSecurityReview> {
  return validateInterfaceSecurityReview(await loadReviewJson(path));
}

function expectedSavedAudit(
  audit: InterfaceSecurityAudit,
): InterfaceSecurityReview["audit"] {
  return {
    schemaVersion: audit.schemaVersion,
    auditId: audit.auditId,
    digestSha256: sha256(canonicalJson(audit)),
    coverage: audit.coverage,
    emittedEntries: audit.summary.emittedEntries,
    omittedEntries: audit.summary.omittedEntries,
    unattributedSignals: audit.summary.attribution.unattributedSignals,
  };
}

function expectedSavedDisposition(
  disposition: InterfaceSecurityDisposition,
): InterfaceSecurityReview["disposition"] {
  return {
    schemaVersion: disposition.schemaVersion,
    digestSha256: sha256(canonicalJson(disposition)),
    preparedAt: disposition.preparedAt,
    reviewedBy: disposition.reviewedBy,
    ...(disposition.reviewedAt === undefined
      ? {}
      : { reviewedAt: disposition.reviewedAt }),
  };
}

function assertSavedReviewMatchesRetainedFiles(
  audit: InterfaceSecurityAudit,
  disposition: InterfaceSecurityDisposition,
  review: InterfaceSecurityReview,
): void {
  if (canonicalJson(review.audit) !== canonicalJson(expectedSavedAudit(audit))) {
    throw new Error("Saved InterfaceSecurityReview audit fields do not match the retained audit");
  }
  const retainedDisposition = expectedSavedDisposition(disposition);
  const savedDispositionMetadata = {
    schemaVersion: review.disposition.schemaVersion,
    preparedAt: review.disposition.preparedAt,
    reviewedBy: review.disposition.reviewedBy,
    ...(review.disposition.reviewedAt === undefined
      ? {}
      : { reviewedAt: review.disposition.reviewedAt }),
  };
  const retainedDispositionMetadata = {
    schemaVersion: retainedDisposition.schemaVersion,
    preparedAt: retainedDisposition.preparedAt,
    reviewedBy: retainedDisposition.reviewedBy,
    ...(retainedDisposition.reviewedAt === undefined
      ? {}
      : { reviewedAt: retainedDisposition.reviewedAt }),
  };
  if (canonicalJson(savedDispositionMetadata)
    !== canonicalJson(retainedDispositionMetadata)) {
    throw new Error("Saved InterfaceSecurityReview disposition fields do not match the retained disposition");
  }
  if (canonicalJson(review.entries) !== canonicalJson(disposition.entries)) {
    throw new Error("Saved InterfaceSecurityReview entries do not match the exact retained disposition order");
  }
  if (review.disposition.digestSha256 !== retainedDisposition.digestSha256) {
    throw new Error("Saved InterfaceSecurityReview disposition digest does not match the exact retained disposition");
  }
}

export function checkSavedInterfaceSecurityReview(
  auditValue: unknown,
  dispositionValue: unknown,
  reviewValue: unknown,
): InterfaceSecurityReviewCheck {
  const audit = validateInterfaceSecurityAudit(auditValue);
  const disposition = validateInterfaceSecurityDisposition(dispositionValue);
  const savedReview = validateInterfaceSecurityReview(reviewValue);
  assertSavedReviewMatchesRetainedFiles(audit, disposition, savedReview);

  const localCheckStartedAt = new Date().toISOString();
  if (new Date(savedReview.checkedAt).getTime()
    > new Date(localCheckStartedAt).getTime()) {
    throw new Error("Saved InterfaceSecurityReview checkedAt is in the future relative to the current local check");
  }

  const current = checkInterfaceSecurityReview(audit, disposition);
  const savedReviewDigest = sha256(canonicalJson(savedReview));
  const changedSinceSaved = savedReview.status !== current.status
    || savedReview.summary.expiredDecisions !== current.summary.expiredDecisions;
  const schemaVersion = savedReview.schemaVersion === "1.0.0"
    ? "1.0.0"
    : INTERFACE_SECURITY_REVIEW_CHECK_SCHEMA_VERSION;
  const receiptCheckId = stableId(
    "interface_security_review_check",
    schemaVersion,
    savedReview.schemaVersion,
    savedReview.reviewId,
    savedReview.checkedAt,
    savedReviewDigest,
    savedReview.status,
    String(savedReview.summary.expiredDecisions),
    current.status,
    String(current.summary.expiredDecisions),
    String(changedSinceSaved),
    current.checkedAt,
  );
  return validateInterfaceSecurityReviewCheck({
    schemaVersion,
    receiptCheckId,
    checkedAt: current.checkedAt,
    status: "saved_review_verified",
    savedReview: {
      schemaVersion: savedReview.schemaVersion,
      reviewId: savedReview.reviewId,
      checkedAt: savedReview.checkedAt,
      digestSha256: savedReviewDigest,
      status: savedReview.status,
      expiredDecisions: savedReview.summary.expiredDecisions,
    },
    currentEvaluation: {
      status: current.status,
      expiredDecisions: current.summary.expiredDecisions,
      changedSinceSaved,
    },
    binding: {
      savedReceipt: true,
      exactAudit: true,
      exactDisposition: true,
      exactEntryOrder: true,
      exactSavedFields: true,
      exactReceiptDigest: true,
      currentExpiryReevaluated: true,
    },
    networkRequests: 0,
    dnsLookups: 0,
    credentialEnvironmentReads: 0,
    targetCodeExecutions: 0,
    limitations: [...INTERFACE_SECURITY_REVIEW_CHECK_LIMITATIONS],
    disclaimer: INTERFACE_SECURITY_REVIEW_CHECK_DISCLAIMER,
  });
}

export interface CheckInterfaceReviewReceiptOptions {
  auditPath: string;
  dispositionPath: string;
  reviewPath: string;
}

export async function checkInterfaceReviewReceipt(
  options: CheckInterfaceReviewReceiptOptions,
): Promise<InterfaceSecurityReviewCheck> {
  const [audit, disposition, review] = await Promise.all([
    loadInterfaceSecurityAudit(options.auditPath),
    loadInterfaceSecurityDisposition(options.dispositionPath),
    loadInterfaceSecurityReview(options.reviewPath),
  ]);
  return checkSavedInterfaceSecurityReview(audit, disposition, review);
}
