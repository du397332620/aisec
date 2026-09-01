import { readBoundedUtf8File } from "../core/bounded-file.js";
import {
  validateInterfaceSecurityAudit,
  validateInterfaceSecurityDisposition,
  validateInterfaceSecurityReview,
} from "../core/schema-validation.js";
import { canonicalJson, sha256, stableId } from "../core/utils.js";
import {
  FASTAPI_AUTHENTICATION_GAP_REASONS,
  INTERFACE_SECURITY_DISPOSITION_SCHEMA_VERSION,
  INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER,
  INTERFACE_SECURITY_REVIEW_RATIONALE_PLACEHOLDER,
  INTERFACE_SECURITY_REVIEW_SCHEMA_VERSION,
  type InterfaceSecurityAudit,
  type InterfaceSecurityAuditEntry,
  type InterfaceSecurityDisposition,
  type InterfaceSecurityDispositionEntry,
  type InterfaceSecurityReview,
  type InterfaceSecurityReviewStatus,
} from "../schema.js";

export const MAX_INTERFACE_SECURITY_AUDIT_BYTES = 16 * 1024 * 1024;
export const MAX_INTERFACE_SECURITY_DISPOSITION_BYTES = 1024 * 1024;

export const INTERFACE_SECURITY_REVIEW_LIMITATIONS = [
  "This receipt proves consistency between one exact local audit and one exact local disposition only; SHA-256 digests and stable IDs are not signatures and do not authenticate reviewer identity, origin or time.",
  "A disposition never changes, suppresses or overrides the source scan findings, scan decision or interface audit coverage.",
  "Static review cannot prove reachability, deployed behavior, exploitability or the absence of interface-security flaws; authorized verification remains a separate workflow.",
  "The receipt contains route and human-review context and must be inspected before sharing.",
] as const;

export const INTERFACE_SECURITY_REVIEW_DISCLAIMER = "Recorded means only that every emitted entry in a complete static audit has a current operator disposition. It is not a security pass, vulnerability clearance, active test result or assurance that any route or project is safe.";

function authenticationGapReasons(
  entry: InterfaceSecurityAuditEntry,
): InterfaceSecurityDispositionEntry["authenticationGapReasons"] {
  const reasons = [...new Set(entry.sources.flatMap((source) => (
    source.authenticationGapReason ? [source.authenticationGapReason] : []
  )))];
  reasons.sort((left, right) => (
    FASTAPI_AUTHENTICATION_GAP_REASONS.indexOf(left)
    - FASTAPI_AUTHENTICATION_GAP_REASONS.indexOf(right)
  ));
  return reasons.length > 0 ? reasons : undefined;
}

function dispositionEntry(
  entry: InterfaceSecurityAuditEntry,
  schemaVersion: InterfaceSecurityDisposition["schemaVersion"],
): InterfaceSecurityDispositionEntry {
  const gapReasons = schemaVersion === "1.1.0"
    ? authenticationGapReasons(entry)
    : undefined;
  return {
    entryId: entry.id,
    framework: entry.framework,
    route: entry.route,
    category: entry.category,
    severity: entry.severity,
    findingStatus: entry.findingStatus,
    ...(gapReasons ? { authenticationGapReasons: gapReasons } : {}),
    decision: "unreviewed",
    rationale: INTERFACE_SECURITY_REVIEW_RATIONALE_PLACEHOLDER,
  };
}

export function createInterfaceSecurityDisposition(
  auditValue: unknown,
): InterfaceSecurityDisposition {
  const audit = validateInterfaceSecurityAudit(auditValue);
  const schemaVersion = audit.schemaVersion === "1.0.0"
    ? "1.0.0"
    : INTERFACE_SECURITY_DISPOSITION_SCHEMA_VERSION;
  return validateInterfaceSecurityDisposition({
    schemaVersion,
    audit: {
      schemaVersion: audit.schemaVersion,
      auditId: audit.auditId,
      digestSha256: sha256(canonicalJson(audit)),
    },
    preparedAt: new Date().toISOString(),
    reviewedBy: INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER,
    entries: audit.entries.map((entry) => dispositionEntry(entry, schemaVersion)),
  });
}

async function loadJson(
  path: string,
  maxBytes: number,
  label: string,
): Promise<unknown> {
  const text = await readBoundedUtf8File(path, maxBytes, label);
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new Error(`${label} must be valid JSON`);
  }
}

export async function loadInterfaceSecurityAudit(
  path: string,
): Promise<InterfaceSecurityAudit> {
  return validateInterfaceSecurityAudit(await loadJson(
    path,
    MAX_INTERFACE_SECURITY_AUDIT_BYTES,
    "Interface security audit",
  ));
}

export async function loadInterfaceSecurityDisposition(
  path: string,
): Promise<InterfaceSecurityDisposition> {
  return validateInterfaceSecurityDisposition(await loadJson(
    path,
    MAX_INTERFACE_SECURITY_DISPOSITION_BYTES,
    "Interface security disposition",
  ));
}

export async function prepareInterfaceReview(
  auditPath: string,
): Promise<InterfaceSecurityDisposition> {
  return createInterfaceSecurityDisposition(await loadInterfaceSecurityAudit(auditPath));
}

function assertDispositionMatchesAudit(
  audit: InterfaceSecurityAudit,
  disposition: InterfaceSecurityDisposition,
): void {
  if (disposition.audit.schemaVersion !== audit.schemaVersion
    || disposition.audit.auditId !== audit.auditId) {
    throw new Error("Interface security disposition audit binding does not match the supplied audit");
  }
  const exactAuditDigest = sha256(canonicalJson(audit));
  if (disposition.audit.digestSha256 !== exactAuditDigest) {
    throw new Error("Interface security disposition does not match the exact audit digest");
  }
  if (disposition.entries.length !== audit.entries.length
    || disposition.entries.some((entry, index) => entry.entryId !== audit.entries[index]?.id)) {
    throw new Error("Interface security disposition does not match the exact ordered entry set");
  }
  for (let index = 0; index < audit.entries.length; index += 1) {
    const source = audit.entries[index]!;
    const reviewed = disposition.entries[index]!;
    if (reviewed.framework !== source.framework
      || reviewed.route !== source.route
      || reviewed.category !== source.category
      || reviewed.severity !== source.severity
      || reviewed.findingStatus !== source.findingStatus
      || canonicalJson(reviewed.authenticationGapReasons ?? [])
        !== canonicalJson(authenticationGapReasons(source) ?? [])) {
      throw new Error(`Interface security disposition entry context does not match audit entry ${source.id}`);
    }
  }
}

function dispositionSummary(
  disposition: InterfaceSecurityDisposition,
  checkedAt: string,
): InterfaceSecurityReview["summary"] {
  const summary: InterfaceSecurityReview["summary"] = {
    total: disposition.entries.length,
    unreviewed: 0,
    fixRequired: 0,
    falsePositive: 0,
    acceptedRisk: 0,
    authorizedVerificationRequired: 0,
    expiredDecisions: 0,
  };
  const checkedTime = new Date(checkedAt).getTime();
  for (const entry of disposition.entries) {
    if (entry.decision === "unreviewed") summary.unreviewed += 1;
    else if (entry.decision === "fix_required") summary.fixRequired += 1;
    else if (entry.decision === "false_positive") summary.falsePositive += 1;
    else if (entry.decision === "accepted_risk") summary.acceptedRisk += 1;
    else summary.authorizedVerificationRequired += 1;
    if (entry.expiresAt && new Date(entry.expiresAt).getTime() <= checkedTime) {
      summary.expiredDecisions += 1;
    }
  }
  return summary;
}

function reviewStatus(
  audit: InterfaceSecurityAudit,
  disposition: InterfaceSecurityDisposition,
  summary: InterfaceSecurityReview["summary"],
): InterfaceSecurityReviewStatus {
  const reviewerComplete = disposition.reviewedBy !== INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER
    && disposition.reviewedAt !== undefined;
  if (audit.coverage === "partial"
    || summary.unreviewed > 0
    || summary.expiredDecisions > 0
    || !reviewerComplete) {
    return "incomplete";
  }
  return summary.fixRequired > 0 || summary.authorizedVerificationRequired > 0
    ? "action_required"
    : "recorded";
}

export function checkInterfaceSecurityReview(
  auditValue: unknown,
  dispositionValue: unknown,
): InterfaceSecurityReview {
  const audit = validateInterfaceSecurityAudit(auditValue);
  const disposition = validateInterfaceSecurityDisposition(dispositionValue);
  assertDispositionMatchesAudit(audit, disposition);
  const checkedAt = new Date().toISOString();
  const auditDigestSha256 = sha256(canonicalJson(audit));
  const dispositionDigestSha256 = sha256(canonicalJson(disposition));
  const summary = dispositionSummary(disposition, checkedAt);
  const status = reviewStatus(audit, disposition, summary);
  const schemaVersion = disposition.schemaVersion === "1.0.0"
    ? "1.0.0"
    : INTERFACE_SECURITY_REVIEW_SCHEMA_VERSION;
  const reviewId = stableId(
    "interface_security_review",
    schemaVersion,
    audit.schemaVersion,
    audit.auditId,
    auditDigestSha256,
    disposition.schemaVersion,
    dispositionDigestSha256,
    checkedAt,
  );
  return validateInterfaceSecurityReview({
    schemaVersion,
    reviewId,
    checkedAt,
    status,
    audit: {
      schemaVersion: audit.schemaVersion,
      auditId: audit.auditId,
      digestSha256: auditDigestSha256,
      coverage: audit.coverage,
      emittedEntries: audit.summary.emittedEntries,
      omittedEntries: audit.summary.omittedEntries,
      unattributedSignals: audit.summary.attribution.unattributedSignals,
    },
    disposition: {
      schemaVersion: disposition.schemaVersion,
      digestSha256: dispositionDigestSha256,
      preparedAt: disposition.preparedAt,
      reviewedBy: disposition.reviewedBy,
      ...(disposition.reviewedAt === undefined
        ? {}
        : { reviewedAt: disposition.reviewedAt }),
    },
    summary,
    entries: disposition.entries.map((entry) => ({ ...entry })),
    assertions: {
      auditBindingVerified: true,
      exactEntrySetVerified: true,
      originalFindingsUnchanged: true,
      originalDecisionUnchanged: true,
    },
    networkRequests: 0,
    dnsLookups: 0,
    credentialEnvironmentReads: 0,
    targetCodeExecutions: 0,
    limitations: [...INTERFACE_SECURITY_REVIEW_LIMITATIONS],
    disclaimer: INTERFACE_SECURITY_REVIEW_DISCLAIMER,
  });
}

export interface CheckInterfaceReviewOptions {
  auditPath: string;
  dispositionPath: string;
}

export async function checkInterfaceReview(
  options: CheckInterfaceReviewOptions,
): Promise<InterfaceSecurityReview> {
  const [audit, disposition] = await Promise.all([
    loadInterfaceSecurityAudit(options.auditPath),
    loadInterfaceSecurityDisposition(options.dispositionPath),
  ]);
  return checkInterfaceSecurityReview(audit, disposition);
}
