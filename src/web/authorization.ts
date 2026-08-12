import { readFile } from "node:fs/promises";
import { isIP } from "node:net";
import { resolve } from "node:path";
import YAML from "yaml";
import type { AuthorizationManifest } from "../schema.js";

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

export function validateAuthorization(value: unknown): AuthorizationManifest {
  if (!value || typeof value !== "object") throw new Error("Authorization manifest must be an object");
  const manifest = value as Partial<AuthorizationManifest>;
  if (manifest.schemaVersion !== "1.0.0") throw new Error("Authorization manifest schemaVersion must be 1.0.0");
  if (!manifest.targetBaseUrl) throw new Error("targetBaseUrl is required");
  const url = new URL(manifest.targetBaseUrl);
  const hostname = normalizedHostname(url);
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP(S) targets are supported");
  if (!manifest.environment || !["local", "test", "staging"].includes(manifest.environment)) throw new Error("environment must be local, test, or staging");
  if (!manifest.ownedBy?.trim()) throw new Error("ownedBy is required");
  if (manifest.acknowledgment !== "I am authorized to test this target") throw new Error("Exact authorization acknowledgment is required");
  if (!Array.isArray(manifest.allowedHosts) || manifest.allowedHosts.length < 1 || manifest.allowedHosts.length > 10
    || manifest.allowedHosts.some((host) => typeof host !== "string" || host !== host.trim() || host.includes(":") || !/^[A-Za-z0-9.-]+$/.test(host))) {
    throw new Error("allowedHosts must contain 1 through 10 hostnames without schemes, paths or ports");
  }
  const allowedHosts = [...new Set(manifest.allowedHosts.map((host) => host.toLowerCase()))];
  if (!allowedHosts.includes(hostname)) throw new Error("target host must appear exactly in allowedHosts");
  const forbiddenHosts = new Set(["169.254.169.254", "100.100.100.200", "168.63.129.16", "metadata.google.internal"]);
  if (forbiddenHosts.has(hostname) || hostname.endsWith(".internal") || hostname.endsWith(".local") || hostname.endsWith(".localhost")) throw new Error("Cloud metadata and internal-only hostnames are never valid verification targets");
  if (!manifest.dataPrefix || !/^aisec[-_][A-Za-z0-9_-]{3,40}$/.test(manifest.dataPrefix)) throw new Error("dataPrefix must begin with aisec- or aisec_ and contain only safe characters");
  if (!Number.isInteger(manifest.maxRequests) || (manifest.maxRequests ?? 0) < 1 || (manifest.maxRequests ?? 0) > 100) throw new Error("maxRequests must be an integer from 1 through 100");
  if (manifest.environment === "local" && !(hostname === "localhost" || isPrivateIpv4(hostname) || hostname === "::1")) throw new Error("local manifests may target only localhost, loopback or a private IPv4 address");
  if (manifest.environment !== "local" && url.protocol !== "https:") throw new Error("test and staging targets must use HTTPS");
  if (manifest.environment !== "local" && (isPrivateIpv4(hostname) || hostname === "::1")) throw new Error("test and staging manifests cannot target private or loopback IP literals");
  if (url.username || url.password) throw new Error("Credentials must not be embedded in targetBaseUrl");
  if (url.hash) throw new Error("targetBaseUrl must not contain a URL fragment");
  if (isIP(hostname) === 6 && hostname !== "::1") throw new Error("Non-loopback IPv6 literals are not accepted in the initial verifier");
  if (manifest.accounts !== undefined) {
    if (!Array.isArray(manifest.accounts) || manifest.accounts.length > 2 || manifest.accounts.some((account) => !account || typeof account !== "object"
      || typeof account.label !== "string" || !account.label.trim()
      || !/^[A-Z_][A-Z0-9_]*$/.test(account.usernameEnv)
      || !/^[A-Z_][A-Z0-9_]*$/.test(account.passwordEnv))) {
      throw new Error("accounts may contain at most two labels with uppercase username/password environment variable names");
    }
  }
  return { ...manifest, targetBaseUrl: url.toString(), allowedHosts } as AuthorizationManifest;
}

export async function loadAuthorization(path: string): Promise<AuthorizationManifest> {
  const text = await readFile(resolve(path), "utf8");
  const parsed = path.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
  return validateAuthorization(parsed);
}

export function assertAllowedResponseUrl(manifest: AuthorizationManifest, responseUrl: string): void {
  const url = new URL(responseUrl);
  const hostname = normalizedHostname(url);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Redirect produced a non-HTTP(S) URL or embedded credentials");
  if (!manifest.allowedHosts.includes(hostname)) throw new Error(`Redirect escaped the authorized host allowlist: ${hostname}`);
  if (url.origin !== new URL(manifest.targetBaseUrl).origin) throw new Error(`Redirect changed the explicitly authorized origin: ${url.origin}`);
}
