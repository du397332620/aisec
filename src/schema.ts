export const SCHEMA_VERSION = "1.0.0" as const;

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EvidenceLevel = "verified" | "static_confirmed" | "inferred";
export type CoverageStatus = "complete" | "partial" | "not_run" | "failed";
export type Decision = "block" | "incomplete" | "review" | "no_blockers_found";

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

export interface ScanComparison {
  baselineScanId: string;
  new: string[];
  remaining: string[];
  resolved: string[];
  notRechecked: string[];
}

export interface ScanReport {
  schemaVersion: typeof SCHEMA_VERSION;
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
  comparison?: ScanComparison;
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
    statusCodes: number[];
    jsonPath: string;
    value: string;
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

export interface BolaVerificationReport {
  schemaVersion: typeof SCHEMA_VERSION;
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
}
