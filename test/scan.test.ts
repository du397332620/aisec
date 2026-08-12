import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import { createFixContract } from "../src/core/contracts.js";
import { compareReports } from "../src/core/compare.js";
import { validateAuthorization } from "../src/web/authorization.js";
import { verifyWeb } from "../src/web/verify.js";
import { serializeReport } from "../src/reporters/index.js";
import { engineStatus, installManagedEngine, resolveEngineCommand } from "../src/engines/manager.js";
import { sha256 } from "../src/core/utils.js";
import { engineCompatibility, parseEngineVersion } from "../src/engines/compatibility.js";
import { trivyDatabaseStatus } from "../src/engines/trivy-db.js";
import { materializeFixture, SYNTHETIC_STRIPE_LIVE_KEY } from "./helpers/materialize-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

async function materializeVulnerableFixture() {
  return materializeFixture(join(fixtures, "vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_STRIPE_LIVE_KEY,
  }]);
}

test("vulnerable full-stack fixture produces evidence-backed attack paths and redacts secrets", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    assert.equal(report.decision, "block");
    assert.ok(report.attackPaths.some((path) => path.title.includes("BaaS")));
    assert.ok(report.attackPaths.some((path) => path.title.includes("Prompt-controlled")));
    assert.ok(report.signals.some((signal) => signal.ruleId === "dataflow.sql-injection"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "react-native.sensitive-async-storage"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "supabase.table-without-rls"));
    const json = serializeReport(report, "json");
    assert.doesNotMatch(json, new RegExp(SYNTHETIC_STRIPE_LIVE_KEY));
    assert.match(json, /sk_…890/);
  } finally {
    await fixture.cleanup();
  }
});

test("safe near-miss fixture is not blocked in native-only mode", async () => {
  const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
  assert.equal(report.decision, "no_blockers_found");
  assert.equal(report.findings.filter((finding) => finding.status === "open").length, 0);
  assert.equal(report.coverage.find((item) => item.domain === "baas-authorization")?.status, "complete");
});

test("an inferred attack path does not hide a stronger component finding", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-injection-"));
  try {
    await writeFile(join(temporary, "package.json"), '{"dependencies":{"next":"15.0.0"}}');
    await import("node:fs/promises").then(({ mkdir }) => mkdir(join(temporary, "app", "api", "admin"), { recursive: true }));
    await writeFile(join(temporary, "app", "api", "admin", "route.ts"), 'export async function POST(req: any) { const id = req.body.id; return db.query(`select * from users where id = ${id}`); }\n');
    const { report } = await scanProject(temporary, { nativeOnly: true, persist: false });
    assert.ok(report.attackPaths.some((path) => path.evidenceLevel === "inferred"));
    assert.ok(report.findings.some((finding) => finding.evidenceLevel === "static_confirmed" && finding.title.includes("database query")));
    assert.equal(report.decision, "block");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("missing optional engines make a normal predeploy scan incomplete, not clean", async () => {
  const oldPath = process.env.PATH;
  process.env.PATH = "";
  try {
    const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: false, persist: false });
    assert.equal(report.decision, "incomplete");
    assert.ok(report.coverage.some((item) => item.required && item.status === "not_run"));
  } finally {
    process.env.PATH = oldPath;
  }
});

test("fix contracts retain evidence, constraints and a baseline rescan", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const contract = createFixContract(report, report.findings[0]!.id);
    assert.equal(contract.scanId, report.scanId);
    assert.ok(contract.evidence.length > 0);
    assert.ok(contract.constraints.some((constraint) => constraint.includes("new high or critical")));
    assert.match(contract.rescan.command, new RegExp(report.scanId));
  } finally {
    await fixture.cleanup();
  }
});

test("baseline comparison distinguishes resolved from not rechecked", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report: baseline } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const { report: current } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
    const comparison = compareReports(current, baseline);
    assert.ok(comparison.resolved.length > 0);
    assert.equal(comparison.remaining.length, 0);
  } finally {
    await fixture.cleanup();
  }
});

test("partial coverage cannot close a baseline finding as resolved", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report: baseline } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const { report: current } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
    const typescriptFinding = baseline.findings.find((finding) => finding.signalIds.some((id) => baseline.signals.find((signal) => signal.id === id)?.engine === "aisec-typescript"));
    assert.ok(typescriptFinding);
    const dataflowCoverage = current.coverage.find((item) => item.domain === "js-ts-dataflow");
    assert.ok(dataflowCoverage);
    dataflowCoverage.status = "partial";
    const comparison = compareReports(current, baseline);
    assert.ok(comparison.notRechecked.includes(typescriptFinding.fingerprint));
    assert.ok(!comparison.resolved.includes(typescriptFinding.fingerprint));
  } finally {
    await fixture.cleanup();
  }
});

test("authorization manifests reject production, host drift and excessive requests", () => {
  const valid = {
    schemaVersion: "1.0.0",
    targetBaseUrl: "https://staging.example.test",
    environment: "staging",
    ownedBy: "Example team",
    allowedHosts: ["staging.example.test"],
    dataPrefix: "aisec-fixture",
    maxRequests: 20,
    acknowledgment: "I am authorized to test this target",
  };
  assert.equal(validateAuthorization(valid).environment, "staging");
  assert.throws(() => validateAuthorization({ ...valid, environment: "production" }));
  assert.throws(() => validateAuthorization({ ...valid, allowedHosts: ["other.example.test"] }));
  assert.throws(() => validateAuthorization({ ...valid, maxRequests: 1000 }));
  assert.throws(() => validateAuthorization({ ...valid, targetBaseUrl: "https://127.0.0.1", allowedHosts: ["127.0.0.1"] }));
  assert.throws(() => validateAuthorization({ ...valid, targetBaseUrl: "https://metadata.google.internal", allowedHosts: ["metadata.google.internal"] }));
});

test("expired suppressions do not hide findings", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-fixture-"));
  try {
    await writeFile(join(temporary, "index.ts"), `const key = "${SYNTHETIC_STRIPE_LIVE_KEY}";\n`);
    const initial = await scanProject(temporary, { nativeOnly: true, persist: false });
    const finding = initial.report.findings[0]!;
    await writeFile(join(temporary, ".aisec.yml"), `version: 1\nsuppressions:\n  - fingerprint: ${finding.fingerprint}\n    reason: confirmed synthetic fixture\n    expires: 2000-01-01\n`);
    const rescanned = await scanProject(temporary, { nativeOnly: true, persist: false });
    assert.equal(rescanned.report.findings[0]?.status, "open");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Flutter source rules detect insecure storage, unrestricted WebView and disabled TLS validation", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-flutter-"));
  try {
    await mkdir(join(temporary, "lib"), { recursive: true });
    await writeFile(join(temporary, "pubspec.yaml"), "name: aisec_fixture\ndependencies:\n  flutter:\n    sdk: flutter\n");
    await writeFile(join(temporary, "lib", "main.dart"), `
      prefs.setString('refreshToken', token);
      final controller = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);
      client.badCertificateCallback = (cert, host, port) => true;
    `);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const rules = new Set(report.signals.map((signal) => signal.ruleId));
    assert.ok(rules.has("flutter.sensitive-shared-preferences"));
    assert.ok(rules.has("flutter.webview-unrestricted-javascript"));
    assert.ok(rules.has("flutter.accept-all-certificates"));
    assert.equal(report.decision, "block");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("framework-public privileged variables are detected at both definition and client reference", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-client-secret-"));
  try {
    await writeFile(join(temporary, ".env"), "NEXT_PUBLIC_ADMIN_SECRET=fixture-value-only\n");
    await writeFile(join(temporary, "client.ts"), "export const key = process.env.NEXT_PUBLIC_ADMIN_SECRET;\n");
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const rules = new Set(report.signals.map((signal) => signal.ruleId));
    assert.ok(rules.has("secret.client-public-privileged-variable"));
    assert.ok(rules.has("secret.client-public-privileged-reference"));
    assert.doesNotMatch(serializeReport(report, "json"), /fixture-value-only/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("project inventory skips symlinks and makes incomplete coverage explicit", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-symlink-"));
  const outside = await mkdtemp(join(tmpdir(), "aisec-outside-"));
  try {
    const outsideKey = ["sk", "live", "outsidefixture123456789"].join("_");
    await writeFile(join(outside, "secret.ts"), `const key = "${outsideKey}";\n`);
    await symlink(join(outside, "secret.ts"), join(temporary, "linked.ts"));
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.equal(report.signals.length, 0);
    const inventory = report.coverage.find((item) => item.domain === "project-inventory");
    assert.equal(inventory?.status, "partial");
    assert.match(inventory?.reason ?? "", /symbolic_link/);
    assert.equal(report.decision, "incomplete");
  } finally {
    await rm(temporary, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("managed engines are digest-pinned and tampering becomes invalid status", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engines-"));
  const oldDataDir = process.env.AISEC_DATA_DIR;
  process.env.AISEC_DATA_DIR = join(temporary, "data");
  const source = join(temporary, "gitleaks-fixture");
  try {
    await writeFile(source, "#!/bin/sh\nprintf 'fixture-engine 1.0\\n'\n");
    await chmod(source, 0o700);
    const digest = sha256(await readFile(source));
    await installManagedEngine("gitleaks", source, digest);
    assert.ok((await resolveEngineCommand("gitleaks"))?.endsWith("/engines/gitleaks"));
    await writeFile(join(temporary, "data", "engines", "gitleaks"), "#!/bin/sh\nprintf 'tampered\\n'\n");
    await chmod(join(temporary, "data", "engines", "gitleaks"), 0o700);
    await assert.rejects(() => resolveEngineCommand("gitleaks"), /integrity check/);
    assert.equal((await engineStatus()).find((item) => item.name === "gitleaks")?.source, "invalid");
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR;
    else process.env.AISEC_DATA_DIR = oldDataDir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("external engine version parsing permits only the verified Beta matrix", () => {
  assert.equal(parseEngineVersion("gitleaks", "gitleaks version 8.30.1"), "8.30.1");
  assert.equal(parseEngineVersion("opengrep", "1.26.0"), "1.26.0");
  assert.equal(parseEngineVersion("trivy", "Version: 0.73.0"), "0.73.0");
  assert.equal(engineCompatibility("gitleaks", "8.30.1").supported, true);
  assert.equal(engineCompatibility("opengrep", "1.25.0").supported, false);
  assert.match(engineCompatibility("trivy", "unknown").reason ?? "", /could not be determined/);
});

test("unverified external engine versions fail closed", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engine-failures-"));
  const project = join(temporary, "project");
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldGitleaks = process.env.AISEC_GITLEAKS_PATH;
  const oldOpengrep = process.env.AISEC_OPENGREP_PATH;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"engine-failure-fixture","private":true}');
    const scripts = {
      gitleaks: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'gitleaks version 8.29.0\\n'; exit 0; fi\nexit 0\n",
      opengrep: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.25.0\\n'; exit 0; fi\nexit 0\n",
      trivy: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Version: 0.72.0\\n'; exit 0; fi\nprintf '{\"Results\":[]}'\nexit 0\n",
    };
    for (const [name, script] of Object.entries(scripts)) {
      const path = join(temporary, name);
      await writeFile(path, script);
      await chmod(path, 0o700);
      process.env[`AISEC_${name.toUpperCase()}_PATH`] = path;
    }
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const { report } = await scanProject(project, { persist: false, timeoutMs: 5_000 });
    const external = report.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine));
    assert.ok(external.every((item) => item.status === "failed"));
    assert.equal(report.decision, "incomplete");
    assert.ok(external.every((item) => /not verified/.test(item.reason ?? "")));
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldGitleaks === undefined) delete process.env.AISEC_GITLEAKS_PATH; else process.env.AISEC_GITLEAKS_PATH = oldGitleaks;
    if (oldOpengrep === undefined) delete process.env.AISEC_OPENGREP_PATH; else process.env.AISEC_OPENGREP_PATH = oldOpengrep;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("every external adapter fails closed on process failure, malformed output and timeout", async (t) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engine-faults-"));
  const project = join(temporary, "project");
  const oldPath = process.env.PATH;
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldGitleaks = process.env.AISEC_GITLEAKS_PATH;
  const oldOpengrep = process.env.AISEC_OPENGREP_PATH;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"engine-fault-fixture","private":true}');
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const database = join(process.env.AISEC_DATA_DIR, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString(), DownloadedAt: new Date().toISOString(), NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    process.env.PATH = "";
    const versions = {
      gitleaks: "gitleaks version 8.30.1",
      opengrep: "1.26.0",
      trivy: "Version: 0.73.0",
    } as const;
    for (const mode of ["failure", "malformed", "timeout"] as const) {
      await t.test(mode, async () => {
        for (const name of ["gitleaks", "opengrep", "trivy"] as const) {
          const command = join(temporary, `${name}-${mode}`);
          let behavior = "printf 'engine failed\\n' >&2\nexit 2";
          if (mode === "timeout") behavior = "while :; do :; done";
          if (mode === "malformed" && name === "gitleaks") {
            behavior = "report=''\nwhile [ \"$#\" -gt 0 ]; do\n  if [ \"$1\" = \"--report-path\" ]; then shift; report=\"$1\"; break; fi\n  shift\ndone\nprintf 'not-json' > \"$report\"\nexit 0";
          } else if (mode === "malformed" && name === "trivy") {
            behavior = "printf '{\"SchemaVersion\":2,\"Results\":\"not-an-array\"}\\n'\nexit 0";
          } else if (mode === "malformed") {
            behavior = "printf '{\"results\":[{\"path\":42}],\"errors\":[]}\\n'\nexit 0";
          }
          await writeFile(command, `#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '${versions[name]}'; exit 0; fi\n${behavior}\n`);
          await chmod(command, 0o700);
          process.env[`AISEC_${name.toUpperCase()}_PATH`] = command;
        }
        const { report } = await scanProject(project, { persist: false, timeoutMs: 100 });
        const external = report.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine));
        assert.equal(external.length, 3);
        assert.ok(external.every((item) => item.status === "failed"));
        assert.ok(external.every((item) => mode === "failure"
          ? /engine failed/.test(item.reason ?? "")
          : mode === "malformed"
            ? /invalid JSON|unexpected JSON schema/.test(item.reason ?? "")
            : /timed out/.test(item.reason ?? "")));
        assert.equal(report.decision, "incomplete");
      });
    }
  } finally {
    if (oldPath === undefined) delete process.env.PATH; else process.env.PATH = oldPath;
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldGitleaks === undefined) delete process.env.AISEC_GITLEAKS_PATH; else process.env.AISEC_GITLEAKS_PATH = oldGitleaks;
    if (oldOpengrep === undefined) delete process.env.AISEC_OPENGREP_PATH; else process.env.AISEC_OPENGREP_PATH = oldOpengrep;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Trivy accepts its schema-v2 empty report with Results omitted", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-trivy-empty-"));
  const project = join(temporary, "project");
  const command = join(temporary, "trivy");
  const oldPath = process.env.PATH;
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"trivy-empty-fixture","private":true}');
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const database = join(process.env.AISEC_DATA_DIR, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    await writeFile(command, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Version: 0.73.0\\n'; exit 0; fi\nprintf '{\"SchemaVersion\":2,\"Trivy\":{\"Version\":\"0.73.0\"}}\\n'\n");
    await chmod(command, 0o700);
    process.env.PATH = "";
    process.env.AISEC_TRIVY_PATH = command;
    const { report } = await scanProject(project, { persist: false });
    const coverage = report.coverage.find((item) => item.engine === "trivy");
    assert.equal(coverage?.status, "complete");
    assert.equal(report.signals.filter((signal) => signal.engine === "trivy").length, 0);
  } finally {
    if (oldPath === undefined) delete process.env.PATH; else process.env.PATH = oldPath;
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Trivy database readiness distinguishes missing, stale and ready caches", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-trivy-db-"));
  const oldDataDir = process.env.AISEC_DATA_DIR;
  process.env.AISEC_DATA_DIR = temporary;
  try {
    assert.equal((await trivyDatabaseStatus()).state, "missing");
    const database = join(temporary, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    assert.equal((await trivyDatabaseStatus()).state, "invalid");
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: "2026-01-01T00:00:00Z", DownloadedAt: "2026-01-01T00:00:00Z", NextUpdate: "2026-01-02T00:00:00Z" }));
    assert.equal((await trivyDatabaseStatus()).state, "stale");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString(), DownloadedAt: new Date().toISOString(), NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    assert.equal((await trivyDatabaseStatus()).state, "ready");
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("authorized local passive verification is bounded and refuses redirect origin drift", async (t) => {
  let mode: "headers" | "redirect" = "headers";
  const server = createServer((_request, response) => {
    if (mode === "redirect") {
      response.writeHead(302, { location: "http://127.0.0.1:9/escaped" });
      response.end();
      return;
    }
    response.writeHead(200, { "set-cookie": "session=fixture; SameSite=Lax" });
    response.end("ok");
  });
  let listening = false;
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    listening = true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "EPERM") {
      t.skip("the execution sandbox forbids local loopback listeners");
      return;
    }
    throw error;
  }
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const temporary = await mkdtemp(join(tmpdir(), "aisec-web-"));
  const manifest = join(temporary, "authorization.yml");
  await writeFile(manifest, `schemaVersion: 1.0.0\ntargetBaseUrl: http://127.0.0.1:${address.port}/\nenvironment: local\nownedBy: AIsec tests\nallowedHosts:\n  - 127.0.0.1\ndataPrefix: aisec-fixture\nmaxRequests: 6\nacknowledgment: I am authorized to test this target\n`);
  try {
    await assert.rejects(() => verifyWeb(manifest, false), /requires --confirm/);
    const report = await verifyWeb(manifest, true);
    assert.equal(report.requestCount, 1);
    assert.ok(report.signals.some((signal) => signal.ruleId === "web.session-cookie-flags"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "web.missing-csp"));
    mode = "redirect";
    await assert.rejects(() => verifyWeb(manifest, true), /changed the explicitly authorized origin/);
  } finally {
    if (listening) {
      server.close();
      await once(server, "close");
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact paths require a real ZIP container before any scanner is invoked", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-"));
  try {
    const artifact = join(temporary, "fake.apk");
    await writeFile(artifact, "this is not an apk");
    await assert.rejects(() => scanProject(temporary, { artifacts: [artifact], nativeOnly: true, persist: false }), /valid ZIP container signature/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
