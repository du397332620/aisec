export const SCHEMA_VERSION = "1.0.0" as const;
export const SCAN_REPORT_SCHEMA_VERSION = "1.4.0" as const;
export const CI_REPORT_SCHEMA_VERSION = "1.4.0" as const;
export const RULE_PACK_PREVIEW_SCHEMA_VERSION = "1.0.0" as const;
export const INTERFACE_VERIFICATION_QUEUE_SCHEMA_VERSION = "1.0.0" as const;
export const INTERFACE_SECURITY_AUDIT_SCHEMA_VERSION = "1.0.0" as const;
export const INTERFACE_SECURITY_DISPOSITION_SCHEMA_VERSION = "1.0.0" as const;
export const INTERFACE_SECURITY_REVIEW_SCHEMA_VERSION = "1.0.0" as const;
export const INTERFACE_SECURITY_REVIEW_OWNER_PLACEHOLDER = "<SET_REVIEW_OWNER>" as const;
export const INTERFACE_SECURITY_REVIEW_RATIONALE_PLACEHOLDER = "Review the linked static evidence before changing this disposition." as const;
export const BOLA_DRAFT_SCHEMA_VERSION = "1.1.0" as const;
export const BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION = "1.1.0" as const;
export const BOLA_AUTHORIZATION_CHECK_LEGACY_BOUND_SCHEMA_VERSION = "1.1.0" as const;
export const BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION = "1.2.0" as const;
export const BOLA_VERIFICATION_REPORT_SCHEMA_VERSION = "1.1.0" as const;
export const BOLA_VERIFICATION_AUDIT_SCHEMA_VERSION = "1.0.0" as const;
export const BOLA_VERIFICATION_LINEAGE_AUDIT_SCHEMA_VERSION = "1.0.0" as const;
export const BOLA_VERIFICATION_LINEAGE_CHECK_SCHEMA_VERSION = "1.0.0" as const;

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EvidenceLevel = "verified" | "static_confirmed" | "inferred";
export type CoverageStatus = "complete" | "partial" | "not_run" | "failed";
export type Decision = "block" | "incomplete" | "review" | "no_blockers_found";
export type SecurityPolicyEngine = "gitleaks" | "opengrep" | "trivy";
export type PolicyMinimumSeverity = "high" | "medium" | "low" | "info";
export type PolicyRelaxation = "source_only_profile" | "external_engines_disabled";

export interface PolicySuppression {
  fingerprint: string;
  reason: string;
  expires: string;
}

export interface SecurityPolicyGate {
  minimumSeverity: PolicyMinimumSeverity;
  includeInferred: boolean;
  requireNoSuppressions: boolean;
}

export interface RouteSecurityBaselineGate {
  minimumSeverity: PolicyMinimumSeverity;
  includeInferred: boolean;
  requireComplete: boolean;
}

export interface SecurityPolicy {
  schemaVersion: "1.0.0" | "1.1.0";
  policyId: string;
  expiresAt: string;
  profile: "predeploy";
  requiredEngines: SecurityPolicyEngine[];
  gate: SecurityPolicyGate;
  routeSecurityBaseline?: RouteSecurityBaselineGate;
  rules: {
    required: string[];
    block: string[];
  };
  suppressions: PolicySuppression[];
}

export interface ScanPolicyRecord {
  source: "defaults" | "operator";
  targetConfiguration: "absent" | "ignored";
  policyId?: string;
  digestSha256?: string;
  expiresAt?: string;
  gate: SecurityPolicyGate;
  routeSecurityBaseline?: RouteSecurityBaselineGate;
  requiredEngines: SecurityPolicyEngine[];
  requiredRuleIds: string[];
  blockingRuleIds: string[];
  suppressionCount: number;
  suppressionApproval: "not_applicable" | "explicit";
  relaxations: PolicyRelaxation[];
}

export type RuleCatalogSource = "native" | "bundled_opengrep";
export type RuleApplicabilityBasis = "syntax" | "configuration" | "artifact" | "engine";

export interface RuleApplicabilityTechnology {
  name: string;
  versionRange: string;
  basis: RuleApplicabilityBasis;
}

export interface RuleApplicabilityProfile {
  id: string;
  languages: string[];
  technologies: RuleApplicabilityTechnology[];
  versionStatement: string;
}

export interface RuleCatalogEntry {
  ruleId: string;
  source: RuleCatalogSource;
  category: "secrets" | "dataflow" | "application" | "api-security" | "baas" | "mobile-source" | "mobile-artifact" | "sast-general";
  summary: string;
  cwe: string[];
  defaultEvidenceLevel: EvidenceLevel;
  applicability: string[];
  falsePositiveModes: string[];
  reviewGuidance: string;
}

export interface RuleCatalog {
  schemaVersion: "1.0.0";
  description: string;
  applicabilityProfiles: RuleApplicabilityProfile[];
  rules: RuleCatalogEntry[];
}

export interface RulePackFileSelector {
  extensions: string[];
  pathPrefixes?: string[];
  pathSuffixes?: string[];
  excludePathPrefixes?: string[];
}

export interface RulePackMatch {
  containsAny: string[];
  containsAll?: string[];
  excludes?: string[];
  caseSensitive?: boolean;
  emitWhen?: "present" | "absent";
}

export interface RulePackRule {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  evidenceLevel: "static_confirmed" | "inferred";
  confidence: "high" | "medium" | "low";
  cwe: string[];
  tags: string[];
  remediation: string;
  files: RulePackFileSelector;
  match: RulePackMatch;
}

export interface RulePack {
  schemaVersion: "1.0.0" | "1.1.0";
  packId: string;
  description: string;
  rules: RulePackRule[];
}

export interface RulePackRecord {
  packId: string;
  digestSha256: string;
  ruleCount: number;
}

export type RulePackPreviewStatus = "complete" | "partial";

export interface RulePackRulePreview {
  ruleId: string;
  title: string;
  emitWhen: "present" | "absent";
  status: RulePackPreviewStatus;
  evaluatedFileCount: number;
  selectedFileCount: number;
  selectedFiles: string[];
  omittedSelectedFileCount: number;
  reasons: string[];
}

export interface RulePackPreviewRecord extends RulePackRecord {
  status: RulePackPreviewStatus;
  rules: RulePackRulePreview[];
  reasons: string[];
}

export interface RulePackPreviewInventory {
  status: RulePackPreviewStatus;
  fileCount: number;
  totalBytes: number;
  skippedFiles: number;
  skippedReasons: Record<string, number>;
  reasons: string[];
}

export interface RulePackPreview {
  schemaVersion: typeof RULE_PACK_PREVIEW_SCHEMA_VERSION;
  toolVersion: string;
  target: string;
  status: RulePackPreviewStatus;
  inventory: RulePackPreviewInventory;
  rulePacks: RulePackPreviewRecord[];
  reasons: string[];
  disclaimer: string;
}

export interface SourceLocation {
  path: string;
  line?: number;
  column?: number;
  endLine?: number;
  snippet?: string;
}

export interface ProjectProfile {
  root: string;
  projectId: string;
  detectedAt: string;
  languages: string[];
  frameworks: string[];
  packageManagers: string[];
  baas: string[];
  mobilePlatforms: string[];
  llmProviders: string[];
  manifests: string[];
  artifacts: Array<{ path: string; type: "apk" | "ipa" }>;
  routes: string[];
  fileCount: number;
  skippedFiles: number;
}

export type AssetKind =
  | "project"
  | "client"
  | "server"
  | "api_route"
  | "database"
  | "auth"
  | "mobile_app"
  | "artifact"
  | "ci"
  | "llm";

export interface AssetNode {
  id: string;
  kind: AssetKind;
  label: string;
  metadata?: Record<string, string | number | boolean>;
}

export interface AssetEdge {
  from: string;
  to: string;
  relation: string;
  evidence?: SourceLocation[];
}

export interface AssetGraph {
  nodes: AssetNode[];
  edges: AssetEdge[];
}

export interface Signal {
  id: string;
  fingerprint: string;
  engine: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  evidenceLevel: EvidenceLevel;
  confidence: "high" | "medium" | "low";
  locations: SourceLocation[];
  cwe?: string[];
  owasp?: string[];
  tags: string[];
  remediation?: string;
  metadata?: Record<string, string | number | boolean | string[]>;
}

export interface AttackPathStep {
  assetId: string;
  action: string;
  signalIds: string[];
}

export interface AttackPath {
  id: string;
  fingerprint: string;
  title: string;
  summary: string;
  severity: Severity;
  evidenceLevel: EvidenceLevel;
  signalIds: string[];
  steps: AttackPathStep[];
  remediation: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  title: string;
  severity: Severity;
  evidenceLevel: EvidenceLevel;
  status: "open" | "suppressed";
  signalIds: string[];
  attackPathId?: string;
  suppression?: { reason: string; expires: string };
}

export interface CoverageRecord {
  domain: string;
  engine: string;
  status: CoverageStatus;
  required: boolean;
  version?: string;
  reason?: string;
  durationMs?: number;
}

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  attackPaths: number;
  suppressed: number;
}

export type RouteSecurityCategory =
  | "authentication"
  | "object_authorization"
  | "privileged_authorization"
  | "sql_injection"
  | "ssrf"
  | "untrusted_file_path"
  | "credential_forwarding"
  | "exception_disclosure";

export type RouteSecurityFramework = "FastAPI" | "Express" | "NestJS";

export interface RouteSecurityComparisonEntry {
  framework: RouteSecurityFramework;
  route: string;
  category: RouteSecurityCategory;
  severity: Severity;
}

export interface RouteSecurityComparison {
  complete: boolean;
  omittedRouteAliases: number;
  omittedAssociations: number;
  new: RouteSecurityComparisonEntry[];
  remaining: RouteSecurityComparisonEntry[];
  resolved: RouteSecurityComparisonEntry[];
  notRechecked: RouteSecurityComparisonEntry[];
}

export type InterfaceVerificationMethodPolicy = "safe_get" | "reviewed_read_post";
export type InterfaceVerificationRequiredReview =
  | "confirm_route_and_fixture_match"
  | "confirm_response_evidence"
  | "confirm_post_read_only";
export type InterfaceVerificationExclusionReason =
  | "no_open_finding"
  | "no_open_object_authorization_finding"
  | "unsupported_verification_category"
  | "mutation_semantics"
  | "ambiguous_read_semantics"
  | "unproven_route_source"
  | "missing_object_identifier";

export interface InterfaceVerificationSource {
  signalId: string;
  ruleId: string;
  fingerprint: string;
  evidenceLevel: EvidenceLevel;
  handler: string;
  objectIdFields: string[];
  openFindingIds: string[];
  omittedOpenFindingIds: number;
  location: {
    path: string;
    line?: number;
    column?: number;
  };
}

export interface InterfaceVerificationCandidate {
  id: string;
  framework: RouteSecurityFramework;
  route: string;
  method: "GET" | "POST";
  path: string;
  severity: Severity;
  categories: RouteSecurityCategory[];
  verification: "two_account_object_read";
  methodPolicy: InterfaceVerificationMethodPolicy;
  eligibility: [
    "open_object_authorization_finding",
    "exact_route_provenance",
    "bola_read_compatible",
    "recorded_object_identifier",
  ];
  objectIdFields: string[];
  sourceCount: number;
  sources: InterfaceVerificationSource[];
  omittedSources: number;
  requiredReviews: InterfaceVerificationRequiredReview[];
}

export interface InterfaceVerificationExclusion {
  id: string;
  framework: RouteSecurityFramework;
  route: string;
  method: string;
  path: string;
  severity: Severity;
  categories: RouteSecurityCategory[];
  reasons: InterfaceVerificationExclusionReason[];
  signalCount: number;
  signalIds: string[];
  omittedSignals: number;
  openFindingCount: number;
  openFindingIds: string[];
  omittedOpenFindings: number;
}

export interface InterfaceVerificationQueue {
  schemaVersion: typeof INTERFACE_VERIFICATION_QUEUE_SCHEMA_VERSION;
  queueId: string;
  scanId: string;
  projectId: string;
  generatedAt: string;
  status: "review_required";
  coverage: "complete" | "partial";
  coverageScope: "observed_route_cards_only";
  networkRequests: 0;
  summary: {
    reviewedRoutes: number;
    eligibleRoutes: number;
    excludedRoutes: number;
    emittedCandidates: number;
    omittedCandidates: number;
    emittedExclusions: number;
    omittedExclusions: number;
    omittedSourceRecords: number;
    omittedFindingIds: number;
    sourceOmissions: {
      routeAliases: number;
      associations: number;
    };
    exclusionReasons: Array<{
      reason: InterfaceVerificationExclusionReason;
      routes: number;
    }>;
  };
  candidates: InterfaceVerificationCandidate[];
  exclusions: InterfaceVerificationExclusion[];
  prerequisites: [
    "authorized_non_production_target",
    "two_distinct_low_privilege_accounts",
    "precreated_synthetic_owner_object",
    "exact_object_id_no_enumeration",
    "review_response_evidence",
    "manual_manifest_review_and_confirm",
  ];
  limitations: string[];
  nextCommand: "aisec draft-bola --scan <same-scan-id-or-report.json> --output bola-draft.json";
  disclaimer: string;
}

export type InterfaceSecurityFindingStatus = "open" | "suppressed_only";

export interface InterfaceSecurityAuditSource {
  signalId: string;
  ruleId: string;
  fingerprint: string;
  evidenceLevel: EvidenceLevel;
  handler?: string;
  location?: {
    path: string;
    line?: number;
    column?: number;
  };
  openFindingIds: string[];
  omittedOpenFindingIds: number;
  suppressedFindingIds: string[];
  omittedSuppressedFindingIds: number;
}

export interface InterfaceSecurityAuditEntry {
  id: string;
  framework: RouteSecurityFramework;
  route: string;
  method: string;
  path: string;
  category: RouteSecurityCategory;
  severity: Severity;
  findingStatus: InterfaceSecurityFindingStatus;
  sourceCount: number;
  sources: InterfaceSecurityAuditSource[];
  omittedSources: number;
}

export interface InterfaceSecurityAudit {
  schemaVersion: typeof INTERFACE_SECURITY_AUDIT_SCHEMA_VERSION;
  auditId: string;
  generatedAt: string;
  status: "review_required";
  scan: {
    schemaVersion: ScanReport["schemaVersion"];
    scanId: string;
    projectId: string;
    digestSha256: string;
  };
  coverage: "complete" | "partial";
  coverageScope: "observed_attributed_routes_only";
  networkRequests: 0;
  dnsLookups: 0;
  credentialEnvironmentReads: 0;
  targetCodeExecutions: 0;
  summary: {
    reviewedRoutes: number;
    routeCategoryEntries: number;
    openEntries: number;
    suppressedOnlyEntries: number;
    emittedEntries: number;
    omittedEntries: number;
    omittedSourceRecords: number;
    omittedFindingIdReferences: number;
    unlocatedSourceRecords: number;
    sourceOmissions: {
      routeAliases: number;
      associations: number;
    };
    categories: Array<{
      category: RouteSecurityCategory;
      entries: number;
      openEntries: number;
    }>;
    attribution: {
      eligibleSignals: number;
      attributedSignals: number;
      unattributedSignals: number;
      unattributedFindings: number;
      reasons: Array<{
        reason: RouteAttributionGapReason;
        signals: number;
      }>;
    };
    deploymentContexts: {
      observed: number;
      open: number;
    };
  };
  entries: InterfaceSecurityAuditEntry[];
  limitations: string[];
  disclaimer: string;
}

export type InterfaceSecurityDispositionDecision =
  | "unreviewed"
  | "fix_required"
  | "false_positive"
  | "accepted_risk"
  | "authorized_verification_required";

export interface InterfaceSecurityDispositionEntry {
  entryId: string;
  framework: RouteSecurityFramework;
  route: string;
  category: RouteSecurityCategory;
  severity: Severity;
  findingStatus: InterfaceSecurityFindingStatus;
  decision: InterfaceSecurityDispositionDecision;
  rationale: string;
  expiresAt?: string;
}

export interface InterfaceSecurityDisposition {
  schemaVersion: typeof INTERFACE_SECURITY_DISPOSITION_SCHEMA_VERSION;
  audit: {
    schemaVersion: InterfaceSecurityAudit["schemaVersion"];
    auditId: string;
    digestSha256: string;
  };
  preparedAt: string;
  reviewedBy: string;
  reviewedAt?: string;
  entries: InterfaceSecurityDispositionEntry[];
}

export type InterfaceSecurityReviewStatus =
  | "incomplete"
  | "action_required"
  | "recorded";

export interface InterfaceSecurityReview {
  schemaVersion: typeof INTERFACE_SECURITY_REVIEW_SCHEMA_VERSION;
  reviewId: string;
  checkedAt: string;
  status: InterfaceSecurityReviewStatus;
  audit: {
    schemaVersion: InterfaceSecurityAudit["schemaVersion"];
    auditId: string;
    digestSha256: string;
    coverage: InterfaceSecurityAudit["coverage"];
    emittedEntries: number;
    omittedEntries: number;
    unattributedSignals: number;
  };
  disposition: {
    schemaVersion: InterfaceSecurityDisposition["schemaVersion"];
    digestSha256: string;
    preparedAt: string;
    reviewedBy: string;
    reviewedAt?: string;
  };
  summary: {
    total: number;
    unreviewed: number;
    fixRequired: number;
    falsePositive: number;
    acceptedRisk: number;
    authorizedVerificationRequired: number;
    expiredDecisions: number;
  };
  entries: InterfaceSecurityDispositionEntry[];
  assertions: {
    auditBindingVerified: true;
    exactEntrySetVerified: true;
    originalFindingsUnchanged: true;
    originalDecisionUnchanged: true;
  };
  networkRequests: 0;
  dnsLookups: 0;
  credentialEnvironmentReads: 0;
  targetCodeExecutions: 0;
  limitations: string[];
  disclaimer: string;
}

export interface ScanComparison {
  baselineScanId: string;
  new: string[];
  remaining: string[];
  resolved: string[];
  notRechecked: string[];
  routeSecurity?: RouteSecurityComparison;
}

export interface ScanReport {
  schemaVersion: "1.0.0" | "1.1.0" | "1.2.0" | "1.3.0" | typeof SCAN_REPORT_SCHEMA_VERSION;
  toolVersion: string;
  scanId: string;
  startedAt: string;
  completedAt: string;
  target: string;
  profileName: "predeploy" | "native";
  profile: ProjectProfile;
  assetGraph: AssetGraph;
  coverage: CoverageRecord[];
  signals: Signal[];
  attackPaths: AttackPath[];
  findings: Finding[];
  decision: Decision;
  decisionReasons: string[];
  summary: ScanSummary;
  policy?: ScanPolicyRecord;
  rulePacks?: RulePackRecord[];
  comparison?: ScanComparison;
  disclaimer: string;
}

export type CiAnnotationLevel = "error" | "warning" | "notice";
export type CiAnnotationKind = "decision" | "coverage" | "finding";
export type CiBaselineState = "new" | "unchanged";
export type RouteAttributionGapReason =
  | "commented_out_call"
  | "ambiguous_or_dynamic_dispatch"
  | "request_origin_not_proven"
  | "no_proven_route_path"
  | "not_recorded";

export interface CiCoverageGap {
  domain: string;
  engine: string;
  status: Exclude<CoverageStatus, "complete">;
  reason?: string;
}

export interface CiPolicySummary {
  source: "defaults" | "operator" | "not_recorded";
  targetConfiguration: "absent" | "ignored" | "not_recorded";
  policyId?: string;
  digestSha256?: string;
  expiresAt?: string;
  gate?: SecurityPolicyGate;
  routeSecurityBaseline?: RouteSecurityBaselineGate;
  requiredEngines: SecurityPolicyEngine[];
  suppressionCount: number;
  suppressionApproval: "not_applicable" | "explicit" | "not_recorded";
  relaxations: PolicyRelaxation[];
}

export interface CiAnnotation {
  kind: CiAnnotationKind;
  level: CiAnnotationLevel;
  title: string;
  message: string;
  path?: string;
  startLine?: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  findingId?: string;
  fingerprint?: string;
  severity?: Severity;
  evidenceLevel?: EvidenceLevel;
  findingStatus?: Finding["status"];
  blocksRelease?: boolean;
  baselineState?: CiBaselineState;
}

export interface CiRouteAttributionReasonSummary {
  reason: RouteAttributionGapReason;
  signals: number;
}

export interface CiRouteAttributionSummary {
  eligibleSignals: number;
  attributedSignals: number;
  unattributedSignals: number;
  unattributedFindings: number;
  reasons: CiRouteAttributionReasonSummary[];
}

export type CiRouteSecurityComparisonState = "new" | "remaining" | "resolved" | "not_rechecked";

export interface CiRouteSecurityComparisonEntry extends RouteSecurityComparisonEntry {
  state: CiRouteSecurityComparisonState;
}

export interface CiRouteSecurityComparisonSummary {
  recorded: boolean;
  complete: boolean;
  new: number;
  remaining: number;
  resolved: number;
  notRechecked: number;
  omittedRouteAliases: number;
  omittedAssociations: number;
  entries: CiRouteSecurityComparisonEntry[];
  omittedEntries: number;
}

export interface CiReport {
  schemaVersion: "1.0.0" | "1.1.0" | "1.2.0" | "1.3.0" | typeof CI_REPORT_SCHEMA_VERSION;
  toolVersion: string;
  scanId: string;
  profileName: ScanReport["profileName"];
  decision: Decision;
  recommendedExitCode: 0 | 1 | 2;
  decisionReasons: string[];
  counts: ScanSummary & { open: number };
  requiredCoverage: {
    total: number;
    complete: number;
    gaps: CiCoverageGap[];
  };
  policy: CiPolicySummary;
  rulePacks?: RulePackRecord[];
  routeAttribution?: CiRouteAttributionSummary;
  comparison?: {
    baselineScanId: string;
    new: number;
    remaining: number;
    resolved: number;
    notRechecked: number;
    routeSecurity?: CiRouteSecurityComparisonSummary;
  };
  annotations: CiAnnotation[];
  omitted: {
    coverageAnnotations: number;
    findingAnnotations: number;
  };
  disclaimer: string;
}

export interface FixContract {
  schemaVersion: typeof SCHEMA_VERSION;
  contractId: string;
  scanId: string;
  findingFingerprint: string;
  title: string;
  evidence: Array<{
    ruleId: string;
    level: EvidenceLevel;
    locations: SourceLocation[];
    description: string;
  }>;
  objective: string;
  constraints: string[];
  requiredTests: string[];
  rescan: { command: string; closeWhen: string[] };
  agentPrompt: string;
}

export interface AuthorizationManifest {
  schemaVersion: typeof SCHEMA_VERSION;
  targetBaseUrl: string;
  environment: "local" | "test" | "staging";
  ownedBy: string;
  allowedHosts: string[];
  dataPrefix: string;
  maxRequests: number;
  accounts?: Array<{ label: string; usernameEnv: string; passwordEnv: string }>;
  acknowledgment: "I am authorized to test this target";
}

export interface WebVerificationReport {
  schemaVersion: typeof SCHEMA_VERSION;
  verificationId: string;
  target: string;
  startedAt: string;
  completedAt: string;
  requestCount: number;
  coverage: CoverageRecord[];
  signals: Signal[];
  limitations: string[];
}

export interface BolaTestAccount {
  label: string;
  usernameEnv: string;
  passwordEnv: string;
}

export interface BolaLoginConfiguration {
  path: string;
  usernameField: string;
  passwordField: string;
  successStatusCodes: number[];
  tokenJsonPath: string;
  identityJsonPath: string;
  tokenPrefix: "Bearer";
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

export interface BolaVerificationCase {
  id: string;
  method: "GET" | "POST";
  path: string;
  readOnly: true;
  testDataLabel: string;
  ownerAccount: string;
  otherAccount: string;
  body?: { [key: string]: JsonValue };
  expected: {
    match?: "testDataLabel";
    statusCodes: number[];
    jsonPath: string;
    value: string;
  } | {
    match: "ownerIdentity";
    statusCodes: number[];
    jsonPath: string;
  };
}

export interface BolaAuthorizationManifest {
  schemaVersion: typeof SCHEMA_VERSION;
  targetBaseUrl: string;
  environment: "local" | "test" | "staging";
  ownedBy: string;
  allowedHosts: string[];
  dataPrefix: string;
  maxRequests: number;
  accounts: [BolaTestAccount, BolaTestAccount];
  login: BolaLoginConfiguration;
  cases: BolaVerificationCase[];
  acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data";
}

export interface BolaCaseResult {
  caseId: string;
  method: "GET" | "POST";
  path: string;
  testDataLabel: string;
  ownerAccount: string;
  otherAccount: string;
  status: "vulnerable" | "protected" | "inconclusive" | "not_run";
  ownerStatus?: number;
  otherStatus?: number;
  reason: string;
}

export interface BolaVerificationProvenance {
  status: "preflight_verified";
  receipt: {
    schemaVersion:
      | typeof BOLA_AUTHORIZATION_CHECK_LEGACY_BOUND_SCHEMA_VERSION
      | typeof BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION;
    checkId: string;
    checkedAt: string;
  };
  manifest: {
    schemaVersion: typeof SCHEMA_VERSION;
    digestSha256: string;
    environment: "local" | "test" | "staging";
  };
  template: BolaAuthorizationTemplateBindingCheck & {
    schemaVersion:
      | typeof SCHEMA_VERSION
      | typeof BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION;
  };
  authorization: {
    summary: BolaAuthorizationCheck["summary"];
    caseIds: string[];
  };
}

export interface BolaVerificationReport {
  schemaVersion:
    | typeof SCHEMA_VERSION
    | typeof BOLA_VERIFICATION_REPORT_SCHEMA_VERSION;
  verificationId: string;
  target: string;
  startedAt: string;
  completedAt: string;
  requestCount: number;
  accounts: string[];
  coverage: CoverageRecord[];
  signals: Signal[];
  cases: BolaCaseResult[];
  limitations: string[];
  provenance?: BolaVerificationProvenance;
}

export interface BolaVerificationAudit {
  schemaVersion: typeof BOLA_VERIFICATION_AUDIT_SCHEMA_VERSION;
  auditId: string;
  auditedAt: string;
  status: "artifacts_verified";
  report: {
    schemaVersion: typeof BOLA_VERIFICATION_REPORT_SCHEMA_VERSION;
    verificationId: string;
    digestSha256: string;
    requestCount: number;
    requiredRequests: number;
    authorizedMaxRequests: number;
    coverageStatus: "complete" | "partial";
    summary: {
      cases: number;
      vulnerable: number;
      protected: number;
      inconclusive: number;
      notRun: number;
      verifiedSignals: number;
    };
  };
  receipt: {
    schemaVersion:
      | typeof BOLA_AUTHORIZATION_CHECK_LEGACY_BOUND_SCHEMA_VERSION
      | typeof BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION;
    checkId: string;
    checkedAt: string;
  };
  manifest: {
    schemaVersion: typeof SCHEMA_VERSION;
    digestSha256: string;
  };
  template: {
    schemaVersion:
      | typeof SCHEMA_VERSION
      | typeof BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION;
    templateId: string;
    digestSha256: string;
  };
  binding: {
    preflightReceipt: true;
    reportProvenance: true;
    reportSourceFields: true;
    exactCaseOrder: true;
    exactRequestBudget: true;
    resultSemantics: true;
  };
  io: {
    environmentValuesRead: 0;
    dnsLookups: 0;
    requesterCalls: 0;
    networkRequests: 0;
  };
  limitations: [
    "This audit proves local structural and digest consistency only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
    "This audit does not replay requests or prove that the recorded network observations occurred or still describe the service.",
    "A protected listed case is not proof that the route or system is secure beyond the exact recorded verification scope.",
  ];
}

export interface BolaVerificationLineageAudit {
  schemaVersion: typeof BOLA_VERIFICATION_LINEAGE_AUDIT_SCHEMA_VERSION;
  lineageAuditId: string;
  auditedAt: string;
  status: "lineage_verified";
  scan: {
    schemaVersion: ScanReport["schemaVersion"];
    scanId: string;
    projectId: string;
    digestSha256: string;
  };
  queue: {
    schemaVersion: typeof INTERFACE_VERIFICATION_QUEUE_SCHEMA_VERSION;
    queueId: string;
    coverageStatus: "complete" | "partial";
    coverageScope: "observed_route_cards_only";
    reviewedRoutes: number;
    eligibleRoutes: number;
    excludedRoutes: number;
    selectedCandidates: number;
  };
  draft: {
    schemaVersion: typeof BOLA_DRAFT_SCHEMA_VERSION;
    draftId: string;
    generatedAt: string;
    digestSha256: string;
    selectedCandidates: number;
  };
  template: {
    schemaVersion:
      | typeof SCHEMA_VERSION
      | typeof BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION;
    templateId: string;
    digestSha256: string;
  };
  verificationAudit: {
    schemaVersion: typeof BOLA_VERIFICATION_AUDIT_SCHEMA_VERSION;
    auditId: string;
    verificationId: string;
    reportDigestSha256: string;
  };
  binding: {
    scanReport: true;
    regeneratedQueue: true;
    selectedDraft: true;
    draftTemplate: true;
    retainedArtifacts: true;
    exactCandidateOrder: true;
    exactSourceEvidence: true;
  };
  io: {
    environmentValuesRead: 0;
    dnsLookups: 0;
    requesterCalls: 0;
    networkRequests: 0;
  };
  limitations: [
    "This lineage audit proves consistency among the exact retained files only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
    "This lineage audit does not execute target code, replay requests or prove that the recorded scan and network observations occurred.",
    "Static selection and protected listed cases do not prove that a route or system is secure or exploitable beyond the exact recorded scope.",
  ];
}

export interface BolaVerificationLineageCheck {
  schemaVersion: typeof BOLA_VERIFICATION_LINEAGE_CHECK_SCHEMA_VERSION;
  lineageCheckId: string;
  checkedAt: string;
  status: "saved_lineage_verified";
  receipt: {
    schemaVersion: typeof BOLA_VERIFICATION_LINEAGE_AUDIT_SCHEMA_VERSION;
    lineageAuditId: string;
    auditedAt: string;
    digestSha256: string;
  };
  binding: {
    savedReceipt: true;
    recomputedLineage: true;
    exactStableFields: true;
    retainedArtifacts: true;
    exactReceiptDigest: true;
  };
  io: {
    environmentValuesRead: 0;
    dnsLookups: 0;
    requesterCalls: 0;
    networkRequests: 0;
  };
  limitations: [
    "The saved lineage audit timestamp is recorded and digest-bound but excluded from recomputation because each lineage audit records its own execution time.",
    "This check proves consistency among the saved receipt and exact retained files only; stable IDs and digests are not signatures and do not authenticate author, origin or freshness.",
    "This check does not execute target code, replay requests or prove that the recorded scan and network observations occurred.",
  ];
}

export type BolaDraftClassification = "read_candidate" | "mutation_excluded" | "manual_review";
export type BolaDraftEvidenceMode = "testDataLabel" | "ownerIdentity";

export interface BolaDraftCandidate {
  id: string;
  classification: BolaDraftClassification;
  reason: string;
  method: string;
  path: string;
  handler: string;
  objectIdFields: string[];
  suggestedEvidenceMode?: BolaDraftEvidenceMode;
  ownerIdentityFieldCandidates?: string[];
  evidenceSuggestionReason?: string;
  source: {
    signalId: string;
    ruleId: string;
    fingerprint: string;
    evidenceLevel: EvidenceLevel;
    location: SourceLocation;
  };
  requestTemplate?: {
    method: "GET" | "POST";
    path: string;
    body?: Record<string, string>;
  };
  expectedTemplate?: {
    match?: "testDataLabel";
    statusCodes: [200];
    jsonPath: "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>";
    value: string;
  } | {
    match: "ownerIdentity";
    statusCodes: [200];
    jsonPath: "<REVIEW_JSON_PATH_TO_SERVER_DERIVED_OWNER_FIELD>";
  };
}

export interface BolaDraftPlan {
  schemaVersion: typeof SCHEMA_VERSION | typeof BOLA_DRAFT_SCHEMA_VERSION;
  draftId: string;
  scanId: string;
  projectId: string;
  generatedAt: string;
  status: "review_required";
  summary: {
    total: number;
    readCandidates: number;
    mutationExcluded: number;
    manualReview: number;
  };
  candidates: BolaDraftCandidate[];
  selection?: {
    mode: "interface_queue";
    queueId: string;
    queueCoverage: "complete" | "partial";
    queueCoverageScope: "observed_route_cards_only";
    candidateIds: string[];
    bindings: Array<{
      interfaceCandidateId: string;
      bolaCandidateId: string;
      signalId: string;
      route: string;
    }>;
  };
  prerequisites: string[];
  nextCommand: "aisec verify-bola --authorization <reviewed-manifest.yml> --confirm";
  disclaimer: string;
}

export interface BolaAuthorizationTemplateCase {
  id: string;
  method: "GET" | "POST";
  path: string;
  readOnly: true;
  testDataLabel: string;
  ownerAccount: "owner";
  otherAccount: "other";
  body?: Record<string, string>;
  expected: {
    match: "testDataLabel";
    statusCodes: [200];
    jsonPath: "<SET_JSON_PATH_TO_SYNTHETIC_MARKER>";
    value: string;
  } | {
    match: "ownerIdentity";
    statusCodes: [200];
    jsonPath: "<REVIEW_JSON_PATH_TO_SERVER_DERIVED_OWNER_FIELD>";
  };
}

export interface BolaAuthorizationTemplate {
  schemaVersion: typeof SCHEMA_VERSION | typeof BOLA_AUTHORIZATION_TEMPLATE_SCHEMA_VERSION;
  templateId: string;
  draftId: string;
  scanId: string;
  projectId: string;
  generatedAt: string;
  status: "placeholders_required";
  networkRequests: 0;
  selection: {
    mode: "interface_queue";
    queueId: string;
    queueCoverage: "complete" | "partial";
    queueCoverageScope: "observed_route_cards_only";
    candidateIds: string[];
  };
  manifest: {
    schemaVersion: typeof SCHEMA_VERSION;
    targetBaseUrl: "<SET_AUTHORIZED_BASE_URL>";
    environment: "<SET_LOCAL_TEST_OR_STAGING>";
    ownedBy: "<SET_AUTHORIZATION_OWNER>";
    allowedHosts: ["<SET_EXACT_AUTHORIZED_HOST>"];
    dataPrefix: "<SET_AISEC_DATA_PREFIX>";
    maxRequests: number;
    accounts: [
      { label: "owner"; usernameEnv: "AISEC_BOLA_OWNER_USERNAME"; passwordEnv: "AISEC_BOLA_OWNER_PASSWORD" },
      { label: "other"; usernameEnv: "AISEC_BOLA_OTHER_USERNAME"; passwordEnv: "AISEC_BOLA_OTHER_PASSWORD" },
    ];
    login: {
      path: "<SET_LOGIN_PATH>";
      usernameField: "<SET_LOGIN_USERNAME_FIELD>";
      passwordField: "<SET_LOGIN_PASSWORD_FIELD>";
      successStatusCodes: [200];
      tokenJsonPath: "<SET_LOGIN_TOKEN_JSON_PATH>";
      identityJsonPath: "<SET_LOGIN_IDENTITY_JSON_PATH>";
      tokenPrefix: "Bearer";
    };
    cases: BolaAuthorizationTemplateCase[];
    acknowledgment: "<REVIEW_AND_SET_AUTHORIZATION_ACKNOWLEDGMENT>";
  };
  bindings: Array<{
    caseId: string;
    interfaceCandidateId: string;
    bolaCandidateId: string;
    signalId: string;
    route: string;
    objectIdFields: string[];
    evidenceMode: BolaDraftEvidenceMode;
    reviewRequirements: {
      concretePrecreatedObjectId: true;
      readOnlySemantics: true;
      responseEvidence: true;
    };
  }>;
  reviewChecklist: string[];
  nextCommand:
    | "aisec check-bola --authorization <completed-manifest.yml>"
    | "aisec check-bola --authorization <completed-manifest.yml> --template <same-template.json>";
  disclaimer: string;
}

export interface BolaAuthorizationTemplateBindingCheck {
  status: "verified";
  templateId: string;
  templateDigestSha256: string;
  draftId: string;
  scanId: string;
  projectId: string;
  queueId: string;
  queueCoverage: "complete" | "partial";
  queueCoverageScope: "observed_route_cards_only";
  matchedCases: number;
  exactCaseOrder: true;
  exactRequestBudget: true;
  exactMethods: true;
  exactAccountRoles: true;
  routeTemplatesMatched: true;
  exactObjectIdFields: true;
  concreteObjectIds: true;
  exactEvidenceModes: true;
  exactStatusCodes: true;
}

export interface BolaAuthorizationCheck {
  schemaVersion:
    | typeof SCHEMA_VERSION
    | typeof BOLA_AUTHORIZATION_CHECK_LEGACY_BOUND_SCHEMA_VERSION
    | typeof BOLA_AUTHORIZATION_CHECK_SCHEMA_VERSION;
  checkId: string;
  checkedAt: string;
  status: "valid_review_required";
  manifestDigestSha256: string;
  environment: "local" | "test" | "staging";
  summary: {
    cases: number;
    requiredRequests: number;
    maxRequests: number;
    getCases: number;
    postCases: number;
    testDataLabelCases: number;
    ownerIdentityCases: number;
  };
  caseIds: string[];
  templateBinding?: BolaAuthorizationTemplateBindingCheck;
  networkRequests: 0;
  environmentValuesRead: 0;
  dnsLookups: 0;
  reviewRequired: string[];
  nextCommand:
    | "aisec verify-bola --authorization <same-reviewed-manifest.yml> --confirm"
    | "aisec verify-bola --authorization <same-reviewed-manifest.yml> --template <same-template.json> --check <this-check.json> --confirm";
  disclaimer: string;
}

export interface ScanOptions {
  profile: "predeploy" | "native";
  artifacts: string[];
  nativeOnly: boolean;
  includeGitHistory: boolean;
  maxFiles: number;
  maxFileBytes: number;
  maxTotalBytes: number;
  timeoutMs: number;
  persist: boolean;
  policyPath?: string;
  confirmPolicySuppressions: boolean;
  rulePackPaths: string[];
}
