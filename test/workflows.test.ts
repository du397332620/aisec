import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import YAML from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(here, "..", "..");

interface WorkflowStep {
  uses?: string;
  run?: string;
  with?: Record<string, unknown>;
}

interface WorkflowJob {
  if?: string;
  permissions?: Record<string, string>;
  strategy?: { matrix?: { os?: string[]; node?: number[] } };
  steps?: WorkflowStep[];
}

interface Workflow {
  on?: unknown;
  permissions?: Record<string, string>;
  jobs?: Record<string, WorkflowJob>;
}

async function loadWorkflow(filename: string): Promise<Workflow> {
  return YAML.parse(await readFile(join(repositoryRoot, ".github", "workflows", filename), "utf8")) as Workflow;
}

test("all third-party workflow actions are pinned to immutable commits", async () => {
  for (const filename of ["ci.yml", "release.yml"]) {
    const workflow = await loadWorkflow(filename);
    for (const [jobName, job] of Object.entries(workflow.jobs ?? {})) {
      for (const step of job.steps ?? []) {
        if (step.uses) assert.match(step.uses, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/, `${filename}:${jobName} must pin ${step.uses}`);
      }
    }
  }
});

test("CI and release workflows retain the supported matrix and least-privilege release boundary", async () => {
  const ci = await loadWorkflow("ci.yml");
  assert.deepEqual(ci.permissions, { contents: "read" });
  assert.deepEqual(ci.jobs?.test?.strategy?.matrix, { os: ["ubuntu-24.04", "macos-15"], node: [22, 24] });
  assert.ok(ci.jobs?.test?.steps?.some((step) => step.run === "npm ci --ignore-scripts --registry=https://registry.npmjs.org"));
  assert.ok(ci.jobs?.test?.steps?.some((step) => step.run === "npm run test:release"));
  assert.ok(ci.jobs?.test?.steps?.some((step) => step.run === "npm run benchmark:resources"));
  assert.ok(ci.jobs?.test?.steps?.some((step) => step.run === "npm run test:docs"));

  const release = await loadWorkflow("release.yml");
  assert.deepEqual(release.permissions, { contents: "read" });
  assert.deepEqual(release.jobs?.build?.permissions, {
    contents: "read",
    "id-token": "write",
    attestations: "write",
    "artifact-metadata": "write",
  });
  const releaseNode = release.jobs?.build?.steps?.find((step) => step.uses?.startsWith("actions/setup-node@"));
  assert.equal(releaseNode?.with?.["node-version"], "24.19.0");
  assert.ok(release.jobs?.build?.steps?.some((step) => step.run === "npm ci --ignore-scripts --registry=https://registry.npmjs.org"));
  assert.ok(release.jobs?.build?.steps?.some((step) => step.run?.includes("npm run benchmark:resources")));
  assert.ok(release.jobs?.build?.steps?.some((step) => step.run?.includes("npm run test:docs")));
  assert.deepEqual(release.jobs?.publish?.permissions, { contents: "write" });
  assert.equal(release.jobs?.publish?.if, "github.ref_type == 'tag'");
  assert.ok(release.jobs?.publish?.steps?.some((step) => step.run?.includes("gh release create") && step.run.includes("--verify-tag")));
  assert.ok(!Object.values(release.jobs ?? {}).flatMap((job) => job.steps ?? []).some((step) => step.run?.includes("npm publish")));
});
