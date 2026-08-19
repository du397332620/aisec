import type { FixContract, ScanReport } from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { newId } from "./utils.js";
import { validateFixContract, validateScanReport } from "./schema-validation.js";

export function createFixContract(report: ScanReport, findingReference: string): FixContract {
  validateScanReport(report);
  const finding = report.findings.find((item) => item.id === findingReference || item.fingerprint === findingReference);
  if (!finding) throw new Error(`Finding not found in ${report.scanId}: ${findingReference}`);
  const signals = finding.signalIds.map((id) => report.signals.find((signal) => signal.id === id)).filter((signal) => signal !== undefined);
  const attackPath = finding.attackPathId ? report.attackPaths.find((item) => item.id === finding.attackPathId) : undefined;
  const remediation = attackPath?.remediation
    ?? (signals.map((signal) => signal.remediation).filter(Boolean).join(" ") || "Remove the unsafe behavior while preserving intended functionality.");
  const locations = signals.flatMap((signal) => signal.locations.map((location) => `${location.path}${location.line ? `:${location.line}` : ""}`));
  const requiredTests = [
    "Add a regression test that fails against the vulnerable behavior and passes after the fix.",
    finding.title.toLowerCase().includes("auth") || signals.some((signal) => signal.tags.includes("authorization"))
      ? "Test unauthenticated, wrong-user/wrong-tenant, and authorized access separately."
      : "Test malicious input and the expected legitimate path.",
    "Run the existing project test suite without weakening or deleting assertions.",
  ];
  const policyArgument = report.policy?.source === "operator" ? ` --policy ${JSON.stringify("<same-trusted-policy.yml>")}` : "";
  const suppressionConfirmation = report.policy?.source === "operator" && report.policy.suppressionCount > 0 ? " --confirm-policy-suppressions" : "";
  const rescanCommand = `aisec rescan --baseline ${report.scanId}${policyArgument}${suppressionConfirmation} ${JSON.stringify(report.target)}`;
  const constraints = [
    "Do not expose, print, rotate, or fabricate secret values in source code.",
    "Do not disable authentication, authorization, validation, TLS, security headers, or tests to make the finding disappear.",
    "Preserve the documented product behavior and public API unless the insecure behavior is itself the API.",
    "Do not add blanket or target-owned suppressions. If a false positive is proven, record a narrow suppression with a reason and expiry in the operator-owned policy.",
    "The fix must not introduce new high or critical findings.",
  ];
  return validateFixContract({
    schemaVersion: SCHEMA_VERSION,
    contractId: newId("fix"),
    scanId: report.scanId,
    findingFingerprint: finding.fingerprint,
    title: finding.title,
    evidence: signals.map((signal) => ({ ruleId: signal.ruleId, level: signal.evidenceLevel, locations: signal.locations, description: signal.description })),
    objective: remediation,
    constraints,
    requiredTests,
    rescan: {
      command: rescanCommand,
      closeWhen: [
        "The finding fingerprint is listed as resolved, not notRechecked.",
        "No new high or critical findings are introduced.",
        "All required and existing tests pass.",
      ],
    },
    agentPrompt: [
      `Fix security finding: ${finding.title}`,
      `Evidence locations: ${locations.join(", ") || "see attached evidence"}.`,
      `Objective: ${remediation}`,
      "Constraints:",
      ...constraints.map((constraint) => `- ${constraint}`),
      "Acceptance tests:",
      ...requiredTests.map((test) => `- ${test}`),
      `After the change run: ${rescanCommand}`,
    ].join("\n"),
  });
}
