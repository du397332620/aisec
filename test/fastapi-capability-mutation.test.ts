import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { scanProject } from "../src/core/scan.js";
import { validateScanReport } from "../src/core/schema-validation.js";
import { createInterfaceSecurityAudit } from "../src/web/interface-security-audit.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures", "corpus", "fastapi-capability-mutation");
const ruleId = "fastapi.auth.sensitive-route-without-guard";

const capabilityMetadataKeys = [
  "authenticationGapReason",
  "capabilityAnalysisDepth",
  "capabilityEntropyEvidence",
  "capabilityEvidenceVersion",
  "capabilityIdentifierFields",
  "capabilityIdentifierSource",
  "capabilityLifecycleEvidence",
  "capabilityMutationImpact",
  "capabilityOneTimeEvidence",
  "handler",
  "objectCapabilityMutation",
  "route",
].sort();

test("FastAPI auth findings retain bounded object-capability mutation evidence", async () => {
  const { report } = await scanProject(join(fixtures, "positive"), { nativeOnly: true, persist: false });
  assert.doesNotThrow(() => validateScanReport(report));
  const signals = report.signals.filter((signal) => signal.ruleId === ruleId);
  assert.equal(signals.length, 7);
  const byRoute = new Map(signals.map((signal) => [String(signal.metadata?.route), signal]));
  const expected = {
    "PATCH /objects/{object_id}/set": ["object_id", "not_proven", "not_proven", "not_proven", "generic_sensitive_state", "handler_only"],
    "PATCH /payments/{payment_id}/address": ["payment_id", "ulid_generator_observed", "state_guard_observed", "write_once_guard_observed", "payment_address", "one_local_method"],
    "PATCH /profiles/{profile_id}": ["profile_id", "ulid_generator_observed", "not_proven", "write_once_guard_observed", "personal_data", "handler_only"],
    "POST /refunds/{refund_id}/submit": ["refund_id", "ulid_generator_observed", "not_proven", "atomic_state_guard_observed", "payout_destination", "one_local_method"],
    "DELETE /sessions/{session_id}": ["session_id", "uuid4_generator_observed", "not_proven", "not_proven", "destructive_operation", "handler_only"],
    "POST /tokens/{token_id}/rotate": ["token_id", "secrets_generator_observed", "expiration_guard_observed", "not_proven", "credential_state", "one_local_method"],
    "PATCH /workflows/{workflow_id}/approve": ["workflow_id", "typed_uuid_only", "not_proven", "not_proven", "workflow_state", "handler_only"],
  } as const;

  for (const [route, values] of Object.entries(expected)) {
    const signal = byRoute.get(route);
    assert.ok(signal, route);
    assert.deepEqual(Object.keys(signal.metadata ?? {}).sort(), capabilityMetadataKeys);
    assert.equal(signal.severity, "high");
    assert.equal(signal.evidenceLevel, "inferred");
    assert.equal(signal.metadata?.objectCapabilityMutation, true);
    assert.equal(signal.metadata?.capabilityEvidenceVersion, "1.0.0");
    assert.deepEqual(signal.metadata?.capabilityIdentifierFields, [values[0]]);
    assert.equal(signal.metadata?.capabilityIdentifierSource, "path_parameter");
    assert.equal(signal.metadata?.capabilityEntropyEvidence, values[1]);
    assert.equal(signal.metadata?.capabilityLifecycleEvidence, values[2]);
    assert.equal(signal.metadata?.capabilityOneTimeEvidence, values[3]);
    assert.equal(signal.metadata?.capabilityMutationImpact, values[4]);
    assert.equal(signal.metadata?.capabilityAnalysisDepth, values[5]);
    assert.ok(signal.locations.length >= 1 && signal.locations.length <= 4);
    assert.match(signal.description, /review evidence only, not authorization or exploitability proof/u);
  }

  const { report: baselineReport } = await scanProject(join(fixtures, "fingerprint-baseline"), {
    nativeOnly: true,
    persist: false,
  });
  const baseline = baselineReport.signals.find((signal) => signal.ruleId === ruleId);
  assert.ok(baseline);
  assert.equal(baseline.metadata?.objectCapabilityMutation, undefined);
  assert.equal(
    byRoute.get("PATCH /profiles/{profile_id}")?.fingerprint,
    baseline.fingerprint,
    "capability evidence must not change the existing authentication finding fingerprint",
  );

  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /state does not allow changes|address already set|already submitted/iu);
  assert.doesNotMatch(serialized, /external_id|token_urlsafe\(32\)/iu);
  assert.doesNotMatch(serialized, /"(?:requestBody|targetUrl|credentialValue)"/u);
});

test("capability metadata fails closed on create, comparison, overflow, body-only, read, decoy and protected near misses", async () => {
  const { report } = await scanProject(join(fixtures, "near-miss"), { nativeOnly: true, persist: false });
  const signals = report.signals.filter((signal) => signal.ruleId === ruleId);
  assert.deepEqual(signals.map((signal) => signal.metadata?.route), [
    "PATCH /bulk/{a_id}/{b_id}/{c_id}/{d_id}/{e_id}",
    "PATCH /comparisons/{comparison_id}",
    "PATCH /documents",
    "PATCH /documents/{document_id}",
    "POST /orders/{order_id}",
    "PATCH /records/{record_id}",
    "GET /reports/{report_id}",
  ]);
  assert.ok(signals.every((signal) => (
    signal.metadata?.objectCapabilityMutation === undefined
    && !Object.keys(signal.metadata ?? {}).some((key) => key.startsWith("capability"))
  )));
  assert.ok(!signals.some((signal) => signal.metadata?.route === "PATCH /secure/{record_id}"));
});

test("interface audit does not copy capability metadata before a strict artifact version exists", async () => {
  const { report } = await scanProject(join(fixtures, "positive"), { nativeOnly: true, persist: false });
  const audit = createInterfaceSecurityAudit(report);
  assert.doesNotMatch(JSON.stringify(audit), /objectCapabilityMutation|capability[A-Z]/u);
  assert.ok(audit.entries.some((entry) => (
    entry.framework === "FastAPI" && entry.category === "authentication"
  )));
});
