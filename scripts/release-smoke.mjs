import assert from "node:assert/strict";
import { appendFile, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildRelease, verifyRelease } from "./release-lib.mjs";

const temporary = await mkdtemp(join(tmpdir(), "aisec-release-smoke-"));
try {
  const originalRefType = process.env.GITHUB_REF_TYPE;
  const originalRefName = process.env.GITHUB_REF_NAME;
  process.env.GITHUB_REF_TYPE = "tag";
  process.env.GITHUB_REF_NAME = "v9.9.9";
  await assert.rejects(() => buildRelease(join(temporary, "wrong-tag"), { allowDirty: true }), /must exactly match package version/);
  if (originalRefType === undefined) delete process.env.GITHUB_REF_TYPE; else process.env.GITHUB_REF_TYPE = originalRefType;
  if (originalRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = originalRefName;

  const first = join(temporary, "first");
  const second = join(temporary, "second");
  await buildRelease(first, { allowDirty: true });
  await assert.rejects(() => buildRelease(first, { allowDirty: true }), /output already exists/);
  await buildRelease(second, { allowDirty: true });
  await verifyRelease(first, { allowDirty: true });
  await verifyRelease(second, { allowDirty: true });
  const files = (await readdir(first)).sort();
  assert.deepEqual(files, (await readdir(second)).sort());
  for (const filename of files) assert.deepEqual(await readFile(join(first, filename)), await readFile(join(second, filename)), `${filename} must be reproducible in the same build environment`);
  const manifest = JSON.parse(await readFile(join(first, "release-manifest.json"), "utf8"));
  const tarball = manifest.artifacts.find((artifact) => artifact.mediaType === "application/gzip")?.path;
  assert.ok(tarball);
  await appendFile(join(first, tarball), "tampered");
  await assert.rejects(() => verifyRelease(first, { allowDirty: true }), /size mismatch|digest mismatch/);
  await writeFile(join(second, "undeclared.txt"), "unexpected release content\n");
  await assert.rejects(() => verifyRelease(second, { allowDirty: true }), /unexpected file/);
  process.stdout.write(`Release smoke reproduced and verified ${files.length} files on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
