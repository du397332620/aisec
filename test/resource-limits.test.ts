import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../src/core/constants.js";
import { executableExists, parsePositiveInt } from "../src/core/utils.js";
import { runProcess } from "../src/engines/process.js";
import { writeStoredZip } from "./helpers/write-stored-zip.js";

test("scan options enforce non-bypassable resource ceilings", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-option-limits-"));
  try {
    await assert.rejects(() => scanProject(temporary, { persist: false, maxFiles: 100_001 }), /maxFiles cannot exceed 100000/);
    await assert.rejects(() => scanProject(temporary, { persist: false, maxFileBytes: 16 * 1024 * 1024 + 1 }), /maxFileBytes cannot exceed/);
    await assert.rejects(() => scanProject(temporary, { persist: false, maxTotalBytes: 512 * 1024 * 1024 + 1 }), /maxTotalBytes cannot exceed/);
    await assert.rejects(() => scanProject(temporary, { persist: false, timeoutMs: 30 * 60_000 + 1 }), /timeoutMs cannot exceed/);
    await assert.rejects(() => scanProject(temporary, { persist: false, artifacts: Array.from({ length: 11 }, (_, index) => `${index}.apk`) }), /artifacts cannot exceed 10/);
    assert.throws(() => parsePositiveInt("12oops", 1), /positive integer/);
    assert.throws(() => parsePositiveInt("9007199254740992", 1), /positive integer/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("inventory byte and entry ceilings produce explicit incomplete coverage", async () => {
  const byteFixture = await mkdtemp(join(tmpdir(), "aisec-byte-limit-"));
  const binaryFixture = await mkdtemp(join(tmpdir(), "aisec-binary-byte-limit-"));
  const entryFixture = await mkdtemp(join(tmpdir(), "aisec-entry-limit-"));
  try {
    await writeFile(join(byteFixture, "oversized.md"), "x".repeat(256));
    const byteResult = await scanProject(byteFixture, { profile: "native", nativeOnly: true, persist: false, maxTotalBytes: 128 });
    assert.equal(byteResult.report.profile.fileCount, 0);
    assert.equal(byteResult.report.decision, "incomplete");
    assert.match(byteResult.report.coverage.find((item) => item.domain === "project-inventory")?.reason ?? "", /total_bytes_limit/);

    await writeFile(join(binaryFixture, "001.ts"), Buffer.concat([Buffer.from([0]), Buffer.alloc(99, "a")]));
    await writeFile(join(binaryFixture, "002.ts"), "b".repeat(100));
    const binaryResult = await scanProject(binaryFixture, { profile: "native", nativeOnly: true, persist: false, maxTotalBytes: 150 });
    const binaryReason = binaryResult.report.coverage.find((item) => item.domain === "project-inventory")?.reason ?? "";
    assert.equal(binaryResult.report.profile.fileCount, 0);
    assert.match(binaryReason, /binary_file/);
    assert.match(binaryReason, /total_bytes_limit/);

    await Promise.all(Array.from({ length: 101 }, (_, index) => writeFile(join(entryFixture, `${String(index).padStart(3, "0")}.ignored`), "")));
    const entryResult = await scanProject(entryFixture, { profile: "native", nativeOnly: true, persist: false, maxFiles: 20 });
    assert.equal(entryResult.report.profile.fileCount, 0);
    assert.equal(entryResult.report.decision, "incomplete");
    assert.match(entryResult.report.coverage.find((item) => item.domain === "project-inventory")?.reason ?? "", /entry_limit/);
  } finally {
    await rm(byteFixture, { recursive: true, force: true });
    await rm(binaryFixture, { recursive: true, force: true });
    await rm(entryFixture, { recursive: true, force: true });
  }
});

test("finding floods are capped and make detector coverage partial", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-finding-limit-"));
  try {
    const lines = Array.from({ length: MAX_SIGNALS_PER_DETECTOR + 1 }, (_, index) => `NEXT_PUBLIC_ADMIN_SECRET_${index}=fixture-value-${index}`);
    await writeFile(join(temporary, ".env"), `${lines.join("\n")}\n`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const coverage = report.coverage.find((item) => item.domain === "secrets");
    assert.equal(report.signals.filter((signal) => signal.engine === "aisec-native").length, MAX_SIGNALS_PER_DETECTOR);
    assert.equal(coverage?.status, "partial");
    assert.match(coverage?.reason ?? "", /signal safety limit/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("child stdout and stderr share one output budget", async () => {
  const limit = 4_096;
  const result = await runProcess(process.execPath, ["-e", "process.stdout.write('a'.repeat(4096)); process.stderr.write('b'.repeat(4096)); setTimeout(() => {}, 1000)"], { timeoutMs: 5_000, maxOutputBytes: limit });
  assert.equal(result.truncated, true);
  assert.ok(Buffer.byteLength(result.stdout) + Buffer.byteLength(result.stderr) <= limit);
});

test("unsafe and oversized archive resources fail coverage closed", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-archive-limits-"));
  try {
    const unsafe = join(temporary, "unsafe.apk");
    await writeStoredZip(unsafe, { "../escape.txt": "never extract", "assets/config.json": "{}" });
    const unsafeResult = await scanProject(temporary, { profile: "predeploy", nativeOnly: true, artifacts: [unsafe], persist: false });
    const unsafeCoverage = unsafeResult.report.coverage.find((item) => item.domain === "mobile-artifact-static");
    assert.equal(unsafeCoverage?.status, "partial");
    assert.match(unsafeCoverage?.reason ?? "", /unsafe paths/);
    assert.equal(unsafeResult.report.decision, "incomplete");

    const oversized = join(temporary, "oversized.ipa");
    await writeStoredZip(oversized, { "Payload/Fixture.app/assets/config.json": "a".repeat(600 * 1024) });
    const oversizedResult = await scanProject(temporary, { profile: "predeploy", nativeOnly: true, artifacts: [oversized], persist: false });
    const oversizedCoverage = oversizedResult.report.coverage.find((item) => item.domain === "mobile-artifact-static");
    assert.equal(oversizedCoverage?.status, "partial");
    assert.match(oversizedCoverage?.reason ?? "", /safety limit/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
