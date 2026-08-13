import { open, stat } from "node:fs/promises";
import { basename, extname, resolve } from "node:path";
import type { AssetGraph, AssetNode, ProjectProfile } from "../schema.js";
import type { FileInventory, ProjectFile } from "./files.js";
import { sha256, stableId, unique } from "./utils.js";
import { analyzeFastApi } from "../api/fastapi.js";
import { analyzeNodeApi } from "../api/node.js";

type PackageJson = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
};

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  ".js": "JavaScript", ".jsx": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
  ".ts": "TypeScript", ".tsx": "TypeScript", ".mts": "TypeScript", ".cts": "TypeScript",
  ".dart": "Dart", ".java": "Java", ".kt": "Kotlin", ".kts": "Kotlin",
  ".swift": "Swift", ".m": "Objective-C", ".mm": "Objective-C++", ".py": "Python",
  ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".cs": "C#", ".rs": "Rust",
};

function packages(files: ProjectFile[]): Set<string> {
  const result = new Set<string>();
  for (const file of files.filter((candidate) => basename(candidate.relativePath) === "package.json")) {
    try {
      const parsed = JSON.parse(file.content) as PackageJson;
      for (const name of Object.keys({ ...parsed.dependencies, ...parsed.devDependencies })) result.add(name);
    } catch {
      // Invalid manifests are handled by dedicated checks; inspection remains best effort.
    }
  }
  return result;
}

function inferRoutes(files: ProjectFile[]): string[] {
  const routes: string[] = [];
  for (const file of files) {
    let match = file.relativePath.match(/(?:^|\/)app\/(api\/.*?)\/route\.(?:js|jsx|ts|tsx)$/);
    if (match?.[1]) routes.push(`/${match[1].replace(/\[(?:\.\.\.)?([^\]]+)\]/g, ":$1")}`);
    match = file.relativePath.match(/(?:^|\/)pages\/(api\/.*?)\.(?:js|jsx|ts|tsx)$/);
    if (match?.[1]) routes.push(`/${match[1].replace(/\[(?:\.\.\.)?([^\]]+)\]/g, ":$1")}`);
  }
  return unique(routes).sort();
}

function inferFrameworks(dependencies: Set<string>, files: ProjectFile[]): string[] {
  const frameworks: string[] = [];
  const mapping: Array<[string, string]> = [
    ["next", "Next.js"], ["react", "React"], ["express", "Express"],
    ["@nestjs/core", "NestJS"], ["react-native", "React Native"],
    ["expo", "Expo"], ["firebase", "Firebase"], ["@supabase/supabase-js", "Supabase"],
  ];
  for (const [dependency, framework] of mapping) if (dependencies.has(dependency)) frameworks.push(framework);
  if (files.some((file) => basename(file.relativePath) === "pubspec.yaml")) frameworks.push("Flutter");
  return unique(frameworks);
}

export async function inspectProject(
  root: string,
  inventory: FileInventory,
  artifacts: string[],
): Promise<ProjectProfile> {
  const dependencies = packages(inventory.files);
  const fastApi = analyzeFastApi(inventory.files);
  const nodeApi = analyzeNodeApi(inventory.files);
  const languages = unique(inventory.files
    .map((file) => LANGUAGE_BY_EXTENSION[extname(file.relativePath).toLowerCase()])
    .filter((value): value is string => Boolean(value))).sort();

  const manifests = inventory.files
    .filter((file) => /(?:package(?:-lock)?\.json|pnpm-lock\.yaml|yarn\.lock|pubspec\.(?:yaml|lock)|Podfile(?:\.lock)?|AndroidManifest\.xml|Info\.plist|firebase\.json|go\.mod|Cargo\.toml|pyproject\.toml|requirements\.txt)$/.test(file.relativePath))
    .map((file) => file.relativePath);
  const packageManagers: string[] = [];
  if (manifests.some((path) => path.endsWith("pnpm-lock.yaml"))) packageManagers.push("pnpm");
  else if (manifests.some((path) => path.endsWith("yarn.lock"))) packageManagers.push("yarn");
  else if (manifests.some((path) => path.endsWith("package.json"))) packageManagers.push("npm");
  if (manifests.some((path) => path.endsWith("pubspec.yaml"))) packageManagers.push("pub");
  if (manifests.some((path) => /Podfile/.test(path))) packageManagers.push("cocoapods");

  const baas: string[] = [];
  if (dependencies.has("@supabase/supabase-js") || inventory.files.some((f) => /supabase\/(?:migrations|config\.toml)/.test(f.relativePath))) baas.push("Supabase");
  if (dependencies.has("firebase") || manifests.some((path) => path.endsWith("firebase.json")) || inventory.files.some((f) => /firestore\.rules$/.test(f.relativePath))) baas.push("Firebase");

  const mobilePlatforms: string[] = [];
  if (manifests.some((path) => /AndroidManifest\.xml$/.test(path))) mobilePlatforms.push("Android");
  if (manifests.some((path) => /Info\.plist$/.test(path)) || manifests.some((path) => /Podfile/.test(path))) mobilePlatforms.push("iOS");
  if (manifests.some((path) => path.endsWith("pubspec.yaml"))) mobilePlatforms.push("Flutter");
  if (dependencies.has("react-native")) mobilePlatforms.push("React Native");

  const providerMapping: Array<[string, string]> = [
    ["openai", "OpenAI"], ["@anthropic-ai/sdk", "Anthropic"], ["@google/generative-ai", "Google AI"],
    ["langchain", "LangChain"], ["@langchain/core", "LangChain"], ["ai", "Vercel AI SDK"],
    ["@modelcontextprotocol/sdk", "MCP"],
  ];
  const llmProviders = unique(providerMapping.filter(([name]) => dependencies.has(name)).map(([, provider]) => provider));

  const normalizedArtifacts: ProjectProfile["artifacts"] = [];
  for (const artifact of artifacts) {
    const absolute = resolve(artifact);
    const info = await stat(absolute);
    if (!info.isFile()) throw new Error(`Artifact is not a regular file: ${artifact}`);
    if (info.size === 0 || info.size > 2 * 1024 * 1024 * 1024) throw new Error(`Artifact must be between 1 byte and 2 GiB: ${artifact}`);
    const extension = extname(absolute).toLowerCase();
    if (extension !== ".apk" && extension !== ".ipa") throw new Error(`Unsupported artifact type: ${artifact}`);
    const handle = await open(absolute, "r");
    try {
      const signature = Buffer.alloc(4);
      const { bytesRead } = await handle.read(signature, 0, signature.length, 0);
      const validZip = bytesRead === 4 && signature[0] === 0x50 && signature[1] === 0x4b
        && ((signature[2] === 0x03 && signature[3] === 0x04)
          || (signature[2] === 0x05 && signature[3] === 0x06)
          || (signature[2] === 0x07 && signature[3] === 0x08));
      if (!validZip) throw new Error(`Artifact does not have a valid ZIP container signature: ${artifact}`);
    } finally {
      await handle.close();
    }
    normalizedArtifacts.push({ path: absolute, type: extension.slice(1) as "apk" | "ipa" });
  }

  return {
    root,
    projectId: `project_${sha256(root).slice(0, 16)}`,
    detectedAt: new Date().toISOString(),
    languages,
    frameworks: unique([
      ...inferFrameworks(dependencies, inventory.files),
      ...(fastApi.detected ? ["FastAPI"] : []),
      ...(nodeApi.detectedExpress ? ["Express"] : []),
      ...(nodeApi.detectedNest ? ["NestJS"] : []),
    ]),
    packageManagers,
    baas,
    mobilePlatforms: unique(mobilePlatforms),
    llmProviders,
    manifests: manifests.sort(),
    artifacts: normalizedArtifacts,
    routes: unique([
      ...inferRoutes(inventory.files),
      ...fastApi.routes.map((route) => `${route.method} ${route.path}`),
      ...nodeApi.routes.map((route) => `${route.method} ${route.path}`),
    ]).sort(),
    fileCount: inventory.files.length,
    skippedFiles: inventory.skippedFiles,
  };
}

function node(kind: AssetNode["kind"], label: string): AssetNode {
  return { id: stableId("asset", kind, label), kind, label };
}

export function buildAssetGraph(profile: ProjectProfile): AssetGraph {
  const project = node("project", basename(profile.root));
  const nodes: AssetNode[] = [project];
  const edges: AssetGraph["edges"] = [];
  const add = (asset: AssetNode, relation: string): void => {
    if (!nodes.some((existing) => existing.id === asset.id)) nodes.push(asset);
    edges.push({ from: project.id, to: asset.id, relation });
  };

  if (profile.frameworks.some((name) => ["React", "Next.js"].includes(name))) add(node("client", "Web client"), "contains");
  if (profile.frameworks.some((name) => ["Next.js", "Express", "NestJS", "FastAPI"].includes(name))) add(node("server", "Application server"), "contains");
  for (const route of profile.routes) add(node("api_route", route), "exposes");
  for (const baas of profile.baas) {
    const database = node("database", baas);
    add(database, "uses");
    const auth = node("auth", `${baas} Auth`);
    add(auth, "uses");
    edges.push({ from: auth.id, to: database.id, relation: "authorizes" });
  }
  if (profile.mobilePlatforms.length > 0) add(node("mobile_app", profile.mobilePlatforms.join(" + ")), "ships");
  for (const artifact of profile.artifacts) add(node("artifact", artifact.path), "builds");
  if (profile.llmProviders.length > 0) add(node("llm", profile.llmProviders.join(" + ")), "calls");
  return { nodes, edges };
}
