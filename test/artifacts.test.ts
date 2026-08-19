import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import { executableExists } from "../src/core/utils.js";
import { writeStoredZip } from "./helpers/write-stored-zip.js";

function utf16Be(value: string): Buffer {
  const littleEndian = Buffer.from(value, "utf16le");
  for (let index = 0; index < littleEndian.length; index += 2) {
    const first = littleEndian[index]!;
    littleEndian[index] = littleEndian[index + 1]!;
    littleEndian[index + 1] = first;
  }
  return littleEndian;
}

test("artifact scanning recovers bounded ASCII and UTF-16 evidence from binary package members", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-binary-"));
  const secret = ["sk", "live", "binaryfixture123456789"].join("_");
  try {
    const apk = join(temporary, "binary.apk");
    const ipa = join(temporary, "binary.ipa");
    await writeStoredZip(apk, {
      "AndroidManifest.xml": Buffer.from([0x03, 0x00, 0x08, 0x00]),
      "classes.dex": Buffer.concat([
        Buffer.from([0x64, 0x65, 0x78, 0x0a, 0x00, 0xff]),
        Buffer.from(secret, "ascii"),
        Buffer.from([0x00, 0xff, 0x00]),
        Buffer.from("http://api.mobile-fixture.test/v1", "ascii"),
      ]),
    });
    await writeStoredZip(ipa, {
      "Payload/Fixture.app/Info.plist": Buffer.concat([
        Buffer.from([0xff, 0x00, 0xfe, 0x00]),
        utf16Be("<key>NSAllowsArbitraryLoads</key><true/>"),
      ]),
    });

    const { report } = await scanProject(temporary, {
      profile: "predeploy",
      nativeOnly: true,
      artifacts: [apk, ipa],
      persist: false,
    });
    const rules = new Set(report.signals.filter((signal) => signal.engine === "aisec-artifact").map((signal) => signal.ruleId));
    assert.ok(rules.has("artifact.embedded-secret"));
    assert.ok(rules.has("artifact.cleartext-endpoint"));
    assert.ok(rules.has("artifact.ios-ats-disabled"));
    assert.equal(report.coverage.find((item) => item.domain === "mobile-artifact-static")?.status, "complete");
    assert.doesNotMatch(JSON.stringify(report), new RegExp(secret));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact scanning keeps documentation, reserved endpoints and non-secret client values as near misses", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-near-miss-"));
  try {
    const apk = join(temporary, "near-miss.apk");
    const ipa = join(temporary, "near-miss.ipa");
    await writeStoredZip(apk, {
      "classes.dex": Buffer.concat([
        Buffer.from("pk_live_publishablefixture123456 http://example.com/v1", "ascii"),
        Buffer.from([0x00]),
        Buffer.from("http://www.apache.org/licenses/LICENSE-2.0 http://ns.adobe.com/xap/1.0/", "ascii"),
      ]),
    });
    await writeStoredZip(ipa, {
      "Payload/Fixture.app/Info.plist": "<key>NSAllowsArbitraryLoads</key><false/><key>NSAllowsArbitraryLoadsInWebContent</key><true/>",
    });

    const { report } = await scanProject(temporary, {
      profile: "predeploy",
      nativeOnly: true,
      artifacts: [apk, ipa],
      persist: false,
    });
    assert.deepEqual(report.signals.filter((signal) => signal.engine === "aisec-artifact"), []);
    assert.equal(report.coverage.find((item) => item.domain === "mobile-artifact-static")?.status, "complete");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact scanning decodes binary plist booleans and fails partial on malformed semantic data", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-bplist-"));
  try {
    const valid = join(temporary, "valid.ipa");
    const malformed = join(temporary, "malformed.ipa");
    const binaryPlist = Buffer.from("YnBsaXN0MDDSAQIDBl8QFk5TQXBwVHJhbnNwb3J0U2VjdXJpdHlYRW5kcG9pbnTRBAVfEBZOU0FsbG93c0FyYml0cmFyeUxvYWRzCV8QH2h0dHA6Ly9hcGkuYmluYXJ5LXBsaXN0LnRlc3QvdjEIDSYvMktMAAAAAAAAAQEAAAAAAAAABwAAAAAAAAAAAAAAAAAAAG4=", "base64");
    await writeStoredZip(valid, { "Payload/Fixture.app/Info.plist": binaryPlist });
    await writeStoredZip(malformed, { "Payload/Fixture.app/Info.plist": Buffer.concat([Buffer.from("bplist00"), Buffer.alloc(32)]) });

    const validResult = await scanProject(temporary, {
      profile: "predeploy",
      nativeOnly: true,
      artifacts: [valid],
      persist: false,
    });
    const rules = new Set(validResult.report.signals.filter((signal) => signal.engine === "aisec-artifact").map((signal) => signal.ruleId));
    assert.ok(rules.has("artifact.cleartext-endpoint"));
    assert.ok(rules.has("artifact.ios-ats-disabled"));
    assert.equal(validResult.report.coverage.find((item) => item.domain === "mobile-artifact-static")?.status, "complete");

    const malformedResult = await scanProject(temporary, {
      profile: "predeploy",
      nativeOnly: true,
      artifacts: [malformed],
      persist: false,
    });
    const malformedCoverage = malformedResult.report.coverage.find((item) => item.domain === "mobile-artifact-static");
    assert.equal(malformedCoverage?.status, "partial");
    assert.match(malformedCoverage?.reason ?? "", /binary plist semantic decoding failed/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact scanning prioritizes the application Info.plist ahead of framework metadata", async (t) => {
  if (!(await executableExists("unzip"))) {
    t.skip("unzip is not installed");
    return;
  }
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-priority-"));
  try {
    const ipa = join(temporary, "priority.ipa");
    const entries: Record<string, string> = {};
    for (let index = 0; index < 30; index += 1) {
      entries[`Payload/Fixture.app/assets/config-${index}.json`] = "{}";
    }
    entries["Payload/Fixture.app/Info.plist"] = "<key>NSAllowsArbitraryLoads</key><true/>";
    await writeStoredZip(ipa, entries);

    const { report } = await scanProject(temporary, {
      profile: "predeploy",
      nativeOnly: true,
      artifacts: [ipa],
      persist: false,
    });
    assert.ok(report.signals.some((signal) => signal.ruleId === "artifact.ios-ats-disabled"));
    const coverage = report.coverage.find((item) => item.domain === "mobile-artifact-static");
    assert.equal(coverage?.status, "partial");
    assert.match(coverage?.reason ?? "", /only 25 of 31 supported archive entries/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
