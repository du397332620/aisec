import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import { serializeReport } from "../src/reporters/index.js";
import { engineStatus } from "../src/engines/manager.js";
import { trivyDatabaseStatus } from "../src/engines/trivy-db.js";
import { materializeFixture, SYNTHETIC_EXTERNAL_STRIPE_LIVE_KEY } from "./helpers/materialize-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

test("verified real engines reject target-controlled suppressions and normalize findings", async () => {
  const statuses = await engineStatus();
  for (const name of ["gitleaks", "opengrep", "trivy"] as const) {
    const status = statuses.find((item) => item.name === name);
    assert.ok(status?.command, `${name} must be installed for the real-engine integration suite`);
    assert.equal(status.compatible, true, status.error ?? `${name} must be a verified version`);
  }
  assert.equal((await trivyDatabaseStatus()).state, "ready", "run `aisec engines prepare trivy` before the real-engine integration suite");

  const fixture = await materializeFixture(join(fixtures, "external-vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_EXTERNAL_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_EXTERNAL_STRIPE_LIVE_KEY,
  }]);
  try {
    const ignoredVirtualEnvironment = join(fixture.path, ".venv", "lib", "python3.13", "site-packages");
    await mkdir(ignoredVirtualEnvironment, { recursive: true });
    await writeFile(join(ignoredVirtualEnvironment, "ignored.py"), "import pickle\npickle.loads(untrusted_payload)\n");
    const { report } = await scanProject(fixture.path, { persist: false });
    const coverage = new Map(report.coverage.map((item) => [item.engine, item]));
    for (const name of ["gitleaks", "opengrep", "trivy"] as const) assert.equal(coverage.get(name)?.status, "complete");

    const byEngine = new Map(report.signals.map((signal) => [`${signal.engine}:${signal.ruleId}`, signal]));
    assert.ok([...byEngine.keys()].some((key) => key.startsWith("gitleaks:")), "gitleaks:allow and target config must not hide the fixture secret");
    const opengrepRules = new Set(report.signals.filter((signal) => signal.engine === "opengrep").map((signal) => signal.ruleId));
    assert.deepEqual(opengrepRules, new Set([
      "aisec.generic.weak-hash",
      "aisec.javascript.dynamic-code-execution",
      "aisec.python.unsafe-pickle-load",
    ]), ".semgrepignore and nosemgrep must not hide any shipped Opengrep rule");
    assert.ok(report.signals.filter((signal) => signal.engine === "opengrep")
      .every((signal) => !signal.locations.some((location) => location.path.startsWith(".venv/"))),
    "AIsec-owned inventory exclusions must keep third-party virtual environments out of Opengrep");
    assert.ok([...byEngine.keys()].some((key) => key.startsWith("trivy:CVE-")), "target trivy.yaml, .trivyignore and trivy-secret.yaml must not hide a known vulnerable dependency");
    const vulnerableDependency = report.signals.find((signal) => signal.engine === "trivy" && signal.metadata?.package === "lodash");
    assert.ok(vulnerableDependency, "the fixed vulnerable npm package must remain visible");
    assert.equal(vulnerableDependency.metadata?.dependencyRelationship, "direct");
    assert.equal(vulnerableDependency.metadata?.dependencyClass, "lang-pkgs");
    assert.equal(vulnerableDependency.metadata?.dependencyEcosystem, "npm");
    assert.equal(vulnerableDependency.metadata?.fixAvailable, true);
    assert.ok(Number.isSafeInteger(vulnerableDependency.metadata?.packageLocationLine));
    assert.equal(report.decision, "block");
    assert.doesNotMatch(serializeReport(report, "json"), new RegExp(SYNTHETIC_EXTERNAL_STRIPE_LIVE_KEY));
  } finally {
    await fixture.cleanup();
  }
});

test("verified real engines stay clean while bounded native coverage keeps the decision incomplete", async () => {
  const { report } = await scanProject(join(fixtures, "external-safe"), { persist: false });
  for (const name of ["gitleaks", "opengrep", "trivy"] as const) {
    assert.equal(report.coverage.find((item) => item.engine === name)?.status, "complete");
    assert.equal(report.signals.filter((signal) => signal.engine === name).length, 0);
  }
  assert.equal(report.coverage.find((item) => item.domain === "python-dataflow")?.status, "partial");
  assert.equal(report.decision, "incomplete");
});
