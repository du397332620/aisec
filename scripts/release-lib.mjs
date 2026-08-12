import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, NO_UPDATE_NOTIFIER: "1", ...options.env },
    maxBuffer: 20 * 1024 * 1024,
    timeout: options.timeout ?? 120_000,
  });
  if (result.error) throw new Error(`${command} ${args.join(" ")} failed: ${result.error.message}`, { cause: result.error });
  if (result.status !== 0) {
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim().slice(-8_000);
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}\n${output}`);
  }
  return result.stdout;
}

async function sha256(path) {
  return createHash("sha256").update(await readFile(path)).digest("hex");
}

function safeFilename(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.match(value, /^[A-Za-z0-9][A-Za-z0-9._-]*$/, `${label} must be a plain filename`);
  return value;
}

function packageNameFromLockPath(path, item) {
  if (typeof item.name === "string" && item.name) return item.name;
  const marker = `node_modules${sep}`;
  const normalized = path.replaceAll("/", sep);
  const offset = normalized.lastIndexOf(marker);
  return offset === -1 ? undefined : normalized.slice(offset + marker.length).replaceAll(sep, "/");
}

function deterministicUuid(value) {
  const bytes = createHash("sha256").update(value).digest().subarray(0, 16);
  // RFC 9562 UUIDv8: deterministic, locally defined SHA-256 name mapping.
  bytes[6] = (bytes[6] & 0x0f) | 0x80;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function expectedSbomSerial(metadata, source) {
  const repository = typeof metadata.repository === "string" ? metadata.repository : metadata.repository?.url;
  return `urn:uuid:${deterministicUuid(`${repository}\n${metadata.name}\n${metadata.version}\n${source.commit}`)}`;
}

function normalizeSbom(sbom, metadata, source) {
  sbom.serialNumber = expectedSbomSerial(metadata, source);
  if (sbom.metadata && typeof sbom.metadata === "object") delete sbom.metadata.timestamp;
  if (Array.isArray(sbom.components)) sbom.components.sort((left, right) => String(left["bom-ref"]).localeCompare(String(right["bom-ref"]), "en"));
  if (Array.isArray(sbom.dependencies)) {
    for (const dependency of sbom.dependencies) if (Array.isArray(dependency.dependsOn)) dependency.dependsOn.sort();
    sbom.dependencies.sort((left, right) => String(left.ref).localeCompare(String(right.ref), "en"));
  }
  return sbom;
}

async function packageMetadata() {
  return JSON.parse(await readFile(join(repositoryRoot, "package.json"), "utf8"));
}

async function sourceState(allowDirty) {
  const commit = run("git", ["rev-parse", "HEAD"]).trim();
  assert.match(commit, /^[0-9a-f]{40}$/, "release source must have a Git commit");
  const status = run("git", ["status", "--porcelain=v1", "--untracked-files=normal"]).trim();
  const dirty = status.length > 0;
  if (dirty && !allowDirty) throw new Error(`Release builds require a clean Git worktree:\n${status}`);
  return { commit, dirty };
}

function validateReleaseRef(version) {
  if (process.env.GITHUB_REF_TYPE !== "tag") return;
  const expected = `v${version}`;
  if (process.env.GITHUB_REF_NAME !== expected) throw new Error(`Release tag ${process.env.GITHUB_REF_NAME} must exactly match package version ${expected}`);
}

export async function buildRelease(outputPath, options = {}) {
  const outputDirectory = isAbsolute(outputPath) ? resolve(outputPath) : resolve(repositoryRoot, outputPath);
  const metadata = await packageMetadata();
  validateReleaseRef(metadata.version);
  const source = await sourceState(Boolean(options.allowDirty));
  try {
    await access(outputDirectory, constants.F_OK);
    throw new Error(`Release output already exists: ${outputDirectory}`);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Release output already exists:")) throw error;
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  await mkdir(outputDirectory, { mode: 0o755 });

  const packed = JSON.parse(run(npmCommand, ["pack", "--json", "--ignore-scripts", "--pack-destination", outputDirectory]));
  assert.equal(packed.length, 1, "npm pack must produce exactly one tarball");
  assert.equal(packed[0].name, metadata.name);
  assert.equal(packed[0].version, metadata.version);
  const tarballName = safeFilename(packed[0].filename, "tarball filename");
  assert.match(tarballName, /\.tgz$/);

  const sbom = normalizeSbom(JSON.parse(run(npmCommand, [
    "sbom",
    "--sbom-format=cyclonedx",
    "--sbom-type=application",
    "--omit=dev",
    "--package-lock-only",
  ])), metadata, source);
  const sbomName = safeFilename(tarballName.replace(/\.tgz$/, ".cdx.json"), "SBOM filename");
  await writeFile(join(outputDirectory, sbomName), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o644 });

  const repository = typeof metadata.repository === "string" ? metadata.repository : metadata.repository?.url;
  const npmVersion = run(npmCommand, ["--version"]).trim();
  const artifacts = [];
  for (const [path, mediaType] of [[tarballName, "application/gzip"], [sbomName, "application/vnd.cyclonedx+json"]]) {
    const details = await stat(join(outputDirectory, path));
    artifacts.push({ path, mediaType, size: details.size, sha256: await sha256(join(outputDirectory, path)) });
  }
  const manifest = {
    schemaVersion: 1,
    package: { name: metadata.name, version: metadata.version, node: metadata.engines?.node },
    source: {
      repository,
      commit: source.commit,
      ref: process.env.GITHUB_REF ?? null,
      dirty: source.dirty,
    },
    build: { node: process.version, npm: npmVersion, platform: process.platform, arch: process.arch },
    artifacts,
  };
  const manifestName = "release-manifest.json";
  await writeFile(join(outputDirectory, manifestName), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o644 });

  const checksumNames = [...artifacts.map((item) => item.path), manifestName].sort();
  const checksums = [];
  for (const name of checksumNames) checksums.push(`${await sha256(join(outputDirectory, name))}  ${name}`);
  await writeFile(join(outputDirectory, "SHA256SUMS"), `${checksums.join("\n")}\n`, { mode: 0o644 });
  await verifyRelease(outputDirectory, { allowDirty: Boolean(options.allowDirty) });
  return { outputDirectory, manifest };
}

export async function verifyRelease(outputPath, options = {}) {
  const outputDirectory = isAbsolute(outputPath) ? resolve(outputPath) : resolve(repositoryRoot, outputPath);
  const metadata = await packageMetadata();
  validateReleaseRef(metadata.version);
  const lock = JSON.parse(await readFile(join(repositoryRoot, "package-lock.json"), "utf8"));
  const manifest = JSON.parse(await readFile(join(outputDirectory, "release-manifest.json"), "utf8"));
  const currentSource = await sourceState(Boolean(options.allowDirty));
  const expectedRepository = typeof metadata.repository === "string" ? metadata.repository : metadata.repository?.url;
  assert.equal(manifest.schemaVersion, 1);
  assert.deepEqual(manifest.package, { name: metadata.name, version: metadata.version, node: metadata.engines.node });
  assert.equal(manifest.source.repository, expectedRepository);
  assert.equal(manifest.source.commit, currentSource.commit, "release source commit does not match this checkout");
  if (process.env.GITHUB_REF !== undefined) {
    assert.equal(manifest.source.ref, process.env.GITHUB_REF, "release source ref does not match this environment");
  } else if (manifest.source.ref !== null) {
    assert.equal(typeof manifest.source.ref, "string", "release source ref must be a string or null");
    run("git", ["check-ref-format", manifest.source.ref]);
  }
  assert.equal(manifest.source.dirty, currentSource.dirty, "release source dirty state does not match this checkout");
  if (manifest.source.dirty && !options.allowDirty) throw new Error("Release manifest records a dirty source worktree");
  assert.equal(typeof manifest.build?.node, "string");
  assert.equal(typeof manifest.build?.npm, "string");
  assert.equal(typeof manifest.build?.platform, "string");
  assert.equal(typeof manifest.build?.arch, "string");
  assert.ok(Array.isArray(manifest.artifacts) && manifest.artifacts.length === 2, "release manifest must describe the tarball and SBOM");

  const checksumNames = [];
  let tarball;
  let sbomPath;
  for (const artifact of manifest.artifacts) {
    const name = safeFilename(artifact.path, "artifact path");
    const path = join(outputDirectory, name);
    const details = await stat(path);
    assert.equal(details.isFile(), true);
    assert.equal(details.size, artifact.size, `${name} size mismatch`);
    assert.equal(await sha256(path), artifact.sha256, `${name} digest mismatch`);
    checksumNames.push(name);
    if (artifact.mediaType === "application/gzip") tarball = path;
    if (artifact.mediaType === "application/vnd.cyclonedx+json") sbomPath = path;
  }
  assert.equal(new Set(checksumNames).size, checksumNames.length, "release manifest contains duplicate artifact paths");
  assert.ok(tarball?.endsWith(".tgz"), "release must contain one npm tarball");
  assert.ok(sbomPath?.endsWith(".cdx.json"), "release must contain one CycloneDX SBOM");

  const sbom = JSON.parse(await readFile(sbomPath, "utf8"));
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.5");
  assert.equal(sbom.serialNumber, expectedSbomSerial(metadata, currentSource), "SBOM serial number must be deterministic for this source commit");
  assert.equal(sbom.metadata?.timestamp, undefined, "normalized SBOM must not contain a volatile timestamp");
  assert.equal(sbom.metadata?.component?.version, metadata.version);
  assert.equal(sbom.metadata?.component?.purl, `pkg:npm/${metadata.name.replace(/^@/, "%40")}@${metadata.version}`);

  const expectedComponents = new Set();
  for (const [path, item] of Object.entries(lock.packages ?? {})) {
    if (!path || item.dev === true) continue;
    const name = packageNameFromLockPath(path, item);
    if (name && item.version) expectedComponents.add(`${name}@${item.version}`);
  }
  const actualComponents = new Set((sbom.components ?? []).map((item) => item["bom-ref"]));
  assert.deepEqual([...actualComponents].sort(), [...expectedComponents].sort(), "SBOM must exactly match locked production dependencies");

  checksumNames.push("release-manifest.json");
  const expectedChecksums = [];
  for (const name of checksumNames.sort()) expectedChecksums.push(`${await sha256(join(outputDirectory, name))}  ${name}`);
  assert.equal(await readFile(join(outputDirectory, "SHA256SUMS"), "utf8"), `${expectedChecksums.join("\n")}\n`);
  const files = (await readdir(outputDirectory)).sort();
  assert.deepEqual(files, ["SHA256SUMS", ...checksumNames].sort(), "release output contains an unexpected file");
  return manifest;
}
