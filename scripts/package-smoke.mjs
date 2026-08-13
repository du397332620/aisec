import assert from "node:assert/strict";
import { constants } from "node:fs";
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const packageMetadata = JSON.parse(await readFile(join(repositoryRoot, "package.json"), "utf8"));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repositoryRoot,
    encoding: "utf8",
    env: { ...process.env, ...options.env },
    maxBuffer: 10 * 1024 * 1024,
    timeout: options.timeout ?? 60_000,
  });
  if (result.error) throw new Error(`${command} ${args.join(" ")} failed: ${result.error.message}`, { cause: result.error });
  const expectedStatus = options.expectedStatus ?? 0;
  if (result.status !== expectedStatus) {
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim().slice(-4_000);
    const reason = result.signal ? `terminated by ${result.signal}` : `exited ${result.status}`;
    throw new Error(`${command} ${args.join(" ")} ${reason}; expected ${expectedStatus}\n${output}`);
  }
  return result.stdout;
}

function parseReport(output, label) {
  try {
    return JSON.parse(output);
  } catch {
    throw new Error(`${label} did not return a JSON report: ${output.slice(0, 1_000)}`);
  }
}

const temporary = await mkdtemp(join(tmpdir(), "aisec-package-smoke-"));
try {
  const tarballs = join(temporary, "tarballs");
  const consumer = join(temporary, "consumer");
  await mkdir(tarballs);
  await mkdir(consumer);
  await writeFile(join(consumer, "package.json"), '{"name":"aisec-package-smoke","private":true}\n');

  process.stdout.write("Packing AIsec and installing it into an empty project...\n");
  const packed = JSON.parse(run(npmCommand, ["pack", "--ignore-scripts", "--json", "--pack-destination", tarballs]));
  assert.equal(packed.length, 1, "npm pack must create exactly one tarball");
  assert.equal(packed[0].name, packageMetadata.name);
  assert.equal(packed[0].version, packageMetadata.version);
  assert.match(packed[0].filename, /^[A-Za-z0-9._-]+\.tgz$/);
  const tarball = join(tarballs, packed[0].filename);
  await access(tarball, constants.R_OK);

  run(npmCommand, [
    "install",
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--registry=https://registry.npmjs.org",
    tarball,
  ], { cwd: consumer, timeout: 180_000 });

  const packageRoot = join(consumer, "node_modules", ...packageMetadata.name.split("/"));
  const executable = join(consumer, "node_modules", ".bin", process.platform === "win32" ? "aisec.cmd" : "aisec");
  await access(executable, process.platform === "win32" ? constants.R_OK : constants.X_OK);
  const scanEnvironment = { AISEC_DATA_DIR: join(temporary, "data") };

  assert.equal(run(executable, ["--version"], { cwd: consumer, env: scanEnvironment }).trim(), packageMetadata.version);

  process.stdout.write("Running the installed CLI against safe and vulnerable fixtures...\n");
  const safe = parseReport(run(executable, [
    "scan",
    join(packageRoot, "test", "fixtures", "safe"),
    "--native-only",
    "--no-persist",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment }), "safe fixture");
  assert.equal(safe.decision, "no_blockers_found");

  const vulnerable = parseReport(run(executable, [
    "scan",
    join(packageRoot, "test", "fixtures", "vulnerable"),
    "--native-only",
    "--no-persist",
    "--format",
    "json",
  ], { cwd: consumer, env: scanEnvironment, expectedStatus: 1 }), "vulnerable fixture");
  assert.equal(vulnerable.decision, "block");

  process.stdout.write("Running the public corpus from inside the installed package...\n");
  const benchmarkOutput = run(process.execPath, [join(packageRoot, "dist", "src", "benchmark.js")], {
    cwd: consumer,
    env: scanEnvironment,
  });
  assert.ok(benchmarkOutput.trim(), "the installed benchmark entry point must produce a result");
  const benchmark = JSON.parse(benchmarkOutput);
  assert.deepEqual(benchmark.catalog, { totalRules: 43, rulesWithPositive: 43, rulesWithNearMiss: 43 });
  assert.equal(benchmark.totals.truePositive, 44);
  assert.equal(benchmark.totals.falsePositive, 0);
  assert.equal(benchmark.totals.falseNegative, 0);
  assert.equal(benchmark.totals.evidenceMismatches, 0);

  process.stdout.write(`Package smoke passed on ${process.platform}/${process.arch} with ${process.version}.\n`);
} finally {
  await rm(temporary, { recursive: true, force: true });
}
