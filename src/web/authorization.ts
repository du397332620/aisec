import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import YAML from "yaml";
import type { AuthorizationManifest, BolaAuthorizationManifest } from "../schema.js";
import { validateAuthorizationManifestSchema, validateBolaAuthorizationManifestSchema } from "../core/schema-validation.js";
import { BOLA_MUTATING_PATH_MARKERS, BOLA_READ_PATH_MARKERS, bolaMarkerTokens } from "./bola-policy.js";

function isPrivateIpv4(host: string): boolean {
  const parts = host.split(".").map(Number);
  if (parts.length !== 4 || parts.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) return false;
  return parts[0] === 10
    || parts[0] === 127
    || (parts[0] === 172 && (parts[1] ?? 0) >= 16 && (parts[1] ?? 0) <= 31)
    || (parts[0] === 192 && parts[1] === 168);
}

function normalizedHostname(url: URL): string {
  return url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
}

interface TargetAuthorization {
  targetBaseUrl: string;
  environment: "local" | "test" | "staging";
  allowedHosts: string[];
}

function validateTarget<T extends TargetAuthorization>(manifest: T): T {
  const url = new URL(manifest.targetBaseUrl);
  const hostname = normalizedHostname(url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP(S) targets are supported");
  const allowedHosts = [...new Set(manifest.allowedHosts.map((host) => host.toLowerCase()))];
  if (!allowedHosts.includes(hostname)) throw new Error("target host must appear exactly in allowedHosts");
  const forbiddenHosts = new Set(["169.254.169.254", "100.100.100.200", "168.63.129.16", "metadata.google.internal"]);
  if (forbiddenHosts.has(hostname) || hostname.endsWith(".internal") || hostname.endsWith(".local") || hostname.endsWith(".localhost")) throw new Error("Cloud metadata and internal-only hostnames are never valid verification targets");
  if (manifest.environment === "local" && !(hostname === "localhost" || isPrivateIpv4(hostname) || hostname === "::1")) throw new Error("local manifests may target only localhost, loopback or a private IPv4 address");
  if (manifest.environment !== "local" && url.protocol !== "https:") throw new Error("test and staging targets must use HTTPS");
  if (manifest.environment !== "local" && (isPrivateIpv4(hostname) || hostname === "::1")) throw new Error("test and staging manifests cannot target private or loopback IP literals");
  if (url.username || url.password) throw new Error("Credentials must not be embedded in targetBaseUrl");
  if (url.hash) throw new Error("targetBaseUrl must not contain a URL fragment");
  if (isIP(hostname) === 6 && hostname !== "::1") throw new Error("Non-loopback IPv6 literals are not accepted in the initial verifier");
  return { ...manifest, targetBaseUrl: url.toString(), allowedHosts };
}

export function validateAuthorization(value: unknown): AuthorizationManifest {
  return validateTarget(validateAuthorizationManifestSchema(value));
}

export async function loadAuthorization(path: string): Promise<AuthorizationManifest> {
  const text = await readFile(resolve(path), "utf8");
  const parsed = path.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
  return validateAuthorization(parsed);
}

function pathTokens(path: string, base: string): { decoded: string; tokens: string[] } {
  const url = new URL(path, base);
  if (url.origin !== new URL(base).origin) throw new Error(`Configured path escaped the authorized origin: ${path}`);
  if (url.username || url.password || url.hash) throw new Error(`Configured path contains credentials or a fragment: ${path}`);
  try {
    const decoded = decodeURIComponent(`${url.pathname}${url.search}`);
    if (decoded.includes("%")) throw new Error("nested percent encoding is not accepted");
    return { decoded, tokens: bolaMarkerTokens(decoded) };
  } catch {
    throw new Error(`Configured path contains invalid percent encoding: ${path}`);
  }
}

function containsJsonString(value: unknown, expected: string): boolean {
  if (typeof value === "string" && value.toLowerCase().includes(expected.toLowerCase())) return true;
  if (Array.isArray(value)) return value.some((item) => containsJsonString(item, expected));
  if (value && typeof value === "object") return Object.values(value).some((item) => containsJsonString(item, expected));
  return false;
}

function containsJsonProperty(value: unknown, expected: string): boolean {
  if (Array.isArray(value)) return value.some((item) => containsJsonProperty(item, expected));
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(([key, nested]) => key.toLowerCase() === expected.toLowerCase() || containsJsonProperty(nested, expected));
}

function mutatingBodyMarker(value: unknown): string | undefined {
  if (typeof value === "string") {
    const tokens = value.replace(/([a-z0-9])([A-Z])/g, "$1 $2").toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
    return [...BOLA_MUTATING_PATH_MARKERS].find((marker) => tokens.includes(marker));
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      const marker = mutatingBodyMarker(item);
      if (marker) return marker;
    }
  } else if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const marker = mutatingBodyMarker(key) ?? mutatingBodyMarker(nested);
      if (marker) return marker;
    }
  }
  return undefined;
}

export function validateBolaAuthorization(value: unknown): BolaAuthorizationManifest {
  const manifest = validateTarget(validateBolaAuthorizationManifestSchema(value));
  const labels = manifest.accounts.map((account) => account.label);
  if (new Set(labels).size !== 2) throw new Error("BOLA verification requires two distinct account labels");
  const credentialVariables = manifest.accounts.flatMap((account) => [account.usernameEnv, account.passwordEnv]);
  if (new Set(credentialVariables).size !== credentialVariables.length) throw new Error("Each BOLA credential must use a distinct environment variable");
  if (manifest.login.usernameField === manifest.login.passwordField) throw new Error("Login usernameField and passwordField must differ");
  if (manifest.login.tokenJsonPath === manifest.login.identityJsonPath) throw new Error("Login tokenJsonPath and identityJsonPath must differ");
  const loginTokens = pathTokens(manifest.login.path, manifest.targetBaseUrl).tokens;
  if (!["login", "signin", "session", "token"].some((marker) => loginTokens.includes(marker))) throw new Error("login.path must identify an authentication endpoint");
  const unsafeLoginMarker = [...BOLA_MUTATING_PATH_MARKERS].find((marker) => !["create", "start"].includes(marker) && loginTokens.includes(marker));
  if (unsafeLoginMarker) throw new Error(`login.path has an unrelated state-changing marker: ${unsafeLoginMarker}`);

  const requiredRequests = 2 + manifest.cases.length * 2;
  if (manifest.maxRequests < requiredRequests) throw new Error(`maxRequests must allow the fixed plan of ${requiredRequests} requests`);
  const caseIds = new Set<string>();
  for (const item of manifest.cases) {
    if (caseIds.has(item.id)) throw new Error(`BOLA case id must be unique: ${item.id}`);
    caseIds.add(item.id);
    if (!labels.includes(item.ownerAccount) || !labels.includes(item.otherAccount) || item.ownerAccount === item.otherAccount) {
      throw new Error(`BOLA case ${item.id} must reference two different declared accounts`);
    }
    if (!item.testDataLabel.startsWith(`${manifest.dataPrefix}-`) && !item.testDataLabel.startsWith(`${manifest.dataPrefix}_`)) {
      throw new Error(`BOLA case ${item.id} testDataLabel must begin with dataPrefix`);
    }
    if (item.expected.match !== "ownerIdentity" && item.expected.value !== item.testDataLabel) {
      throw new Error(`BOLA case ${item.id} expected.value must exactly equal testDataLabel`);
    }
    const parsedPath = pathTokens(item.path, manifest.targetBaseUrl);
    const mutatingMarker = [...BOLA_MUTATING_PATH_MARKERS].find((marker) => parsedPath.tokens.includes(marker));
    if (mutatingMarker) throw new Error(`BOLA case ${item.id} path has a state-changing marker: ${mutatingMarker}`);
    if (item.method === "POST" && ![...BOLA_READ_PATH_MARKERS].some((marker) => parsedPath.tokens.includes(marker))) {
      throw new Error(`BOLA case ${item.id} POST path must contain an explicit read/query marker`);
    }
    if (item.method === "POST" && item.body === undefined) throw new Error(`BOLA case ${item.id} POST requires a fixed body`);
    if (item.method === "GET" && item.body !== undefined) throw new Error(`BOLA case ${item.id} GET cannot contain a body`);
    const bodyMarker = mutatingBodyMarker(item.body);
    if (bodyMarker) throw new Error(`BOLA case ${item.id} body has a state-changing marker: ${bodyMarker}`);
    if (item.expected.match !== "ownerIdentity"
      && (parsedPath.decoded.toLowerCase().includes(item.expected.value.toLowerCase()) || containsJsonString(item.body, item.expected.value))) {
      throw new Error(`BOLA case ${item.id} response marker must not be supplied in the request`);
    }
    if (item.expected.match === "ownerIdentity") {
      const ownerField = item.expected.jsonPath.split(".").at(-1)!;
      const querySuppliesOwnerField = [...new URL(item.path, manifest.targetBaseUrl).searchParams.keys()]
        .some((key) => key.toLowerCase() === ownerField.toLowerCase());
      if (querySuppliesOwnerField || containsJsonProperty(item.body, ownerField)) {
        throw new Error(`BOLA case ${item.id} owner identity evidence field must not be supplied in the request`);
      }
    }
  }
  return manifest;
}

export async function loadBolaAuthorization(path: string): Promise<BolaAuthorizationManifest> {
  const text = await readFile(resolve(path), "utf8");
  const parsed = path.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
  return validateBolaAuthorization(parsed);
}

export function assertAllowedResponseUrl(manifest: TargetAuthorization, responseUrl: string): void {
  const url = new URL(responseUrl);
  const hostname = normalizedHostname(url);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Redirect produced a non-HTTP(S) URL or embedded credentials");
  if (!manifest.allowedHosts.includes(hostname)) throw new Error(`Redirect escaped the authorized host allowlist: ${hostname}`);
  if (url.origin !== new URL(manifest.targetBaseUrl).origin) throw new Error(`Redirect changed the explicitly authorized origin: ${url.origin}`);
}
