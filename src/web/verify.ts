import { lookup } from "node:dns/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP } from "node:net";
import type { LookupAddress } from "node:dns";
import type { Signal, WebVerificationReport } from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { createSignal, makeLocation, newId } from "../core/utils.js";
import { assertAllowedResponseUrl, loadAuthorization } from "./authorization.js";

interface PassiveResponse {
  url: string;
  status: number;
  headers: IncomingHttpHeaders;
}

const unsafeAddresses = new BlockList();
for (const [network, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8],
  ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
] as Array<[string, number]>) unsafeAddresses.addSubnet(network, prefix, "ipv4");
for (const [network, prefix] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8], ["2001:db8::", 32],
] as Array<[string, number]>) unsafeAddresses.addSubnet(network, prefix, "ipv6");

function headerSignal(target: string, ruleId: string, title: string, description: string, remediation: string): Signal {
  return createSignal({
    engine: "aisec-web-passive",
    ruleId,
    title,
    description,
    severity: "medium",
    evidenceLevel: "verified",
    confidence: "high",
    locations: [makeLocation(target, "", 0, target)],
    cwe: ["CWE-693"],
    tags: ["web", "headers", "passive"],
    remediation,
  });
}

function hostWithoutBrackets(url: URL): string { return url.hostname.replace(/^\[|\]$/g, ""); }

async function pinnedAddress(url: URL, local: boolean): Promise<LookupAddress> {
  const hostname = hostWithoutBrackets(url);
  const literalFamily = isIP(hostname);
  const addresses = literalFamily
    ? [{ address: hostname, family: literalFamily as 4 | 6 }]
    : await lookup(hostname, { all: true, verbatim: true });
  if (addresses.length === 0) throw new Error(`Authorized target did not resolve: ${hostname}`);
  if (!local) {
    const unsafe = addresses.find((item) => unsafeAddresses.check(item.address, item.family === 6 ? "ipv6" : "ipv4"));
    if (unsafe) throw new Error(`Authorized target resolved to a non-public address and was refused: ${unsafe.address}`);
  }
  // Pin the chosen address into the socket lookup callback. This prevents a
  // second DNS answer from changing the destination between validation and IO.
  return addresses[0]!;
}

async function passiveGet(target: string, local: boolean): Promise<PassiveResponse> {
  const url = new URL(target);
  const address = await pinnedAddress(url, local);
  const transport = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise((resolve, reject) => {
    let settled = false;
    const request = transport(url, {
      method: "GET",
      agent: false,
      maxHeaderSize: 64 * 1024,
      headers: { "user-agent": "AIsec/0.1 passive-authorized-verifier", accept: "text/html,application/json;q=0.8,*/*;q=0.1" },
      lookup: (_hostname, _options, callback) => callback(null, address.address, address.family),
    }, (response) => {
      settled = true;
      response.destroy();
      resolve({ url: target, status: response.statusCode ?? 0, headers: response.headers });
    });
    request.setTimeout(15_000, () => request.destroy(new Error("Authorized web request timed out")));
    request.once("error", (error) => { if (!settled) reject(error); });
    request.end();
  });
}

function firstHeader(headers: IncomingHttpHeaders, name: string): string | undefined {
  const value = headers[name];
  return Array.isArray(value) ? value[0] : value;
}

export async function verifyWeb(authorizationPath: string, confirmed: boolean): Promise<WebVerificationReport> {
  if (!confirmed) throw new Error("Web verification requires --confirm after reviewing the authorization manifest");
  const manifest = await loadAuthorization(authorizationPath);
  const startedAt = new Date().toISOString();
  let requestCount = 0;
  let currentUrl = manifest.targetBaseUrl;
  let response: PassiveResponse | undefined;
  while (requestCount < Math.min(manifest.maxRequests, 6)) {
    assertAllowedResponseUrl(manifest, currentUrl);
    response = await passiveGet(currentUrl, manifest.environment === "local");
    requestCount += 1;
    const location = firstHeader(response.headers, "location");
    if (![301, 302, 303, 307, 308].includes(response.status) || !location) break;
    const next = new URL(location, currentUrl);
    assertAllowedResponseUrl(manifest, next.toString());
    currentUrl = next.toString();
  }
  if (!response) throw new Error("No authorized web request could be sent");
  if ([301, 302, 303, 307, 308].includes(response.status)) throw new Error("Authorized redirect limit was exceeded");
  assertAllowedResponseUrl(manifest, response.url);
  const signals: Signal[] = [];
  const headers = response.headers;
  if (!headers["content-security-policy"]) signals.push(headerSignal(response.url, "web.missing-csp", "Content-Security-Policy header is absent", "The tested response does not define a CSP. This increases the impact of an XSS defect but does not itself prove XSS.", "Deploy a nonce- or hash-based CSP appropriate to the application and test it in report-only mode before enforcement."));
  if (!headers["x-content-type-options"]) signals.push(headerSignal(response.url, "web.missing-nosniff", "X-Content-Type-Options header is absent", "Browsers may MIME-sniff some responses.", "Set X-Content-Type-Options: nosniff on application responses."));
  if (new URL(response.url).protocol === "https:" && !headers["strict-transport-security"]) signals.push(headerSignal(response.url, "web.missing-hsts", "Strict-Transport-Security header is absent", "The HTTPS response does not instruct browsers to remain on HTTPS.", "Set HSTS after confirming every subdomain and endpoint supports HTTPS."));
  const cookies = headers["set-cookie"] ?? [];
  for (const cookie of cookies) {
    if (!/;\s*secure(?:;|$)/i.test(cookie) || !/;\s*httponly(?:;|$)/i.test(cookie)) {
      signals.push(createSignal({
        engine: "aisec-web-passive", ruleId: "web.session-cookie-flags", title: "A response cookie lacks Secure or HttpOnly", description: "A cookie set by the tested response lacks one or both baseline session protections.",
        severity: "high", evidenceLevel: "verified", confidence: "high", locations: [{ path: response.url, snippet: cookie.replace(/^([^=]+)=[^;]*/, "$1=[REDACTED]") }], cwe: ["CWE-614", "CWE-1004"], tags: ["web", "cookie", "session"],
        remediation: "Set Secure and HttpOnly on session cookies and select an explicit SameSite policy compatible with the authentication flow.",
      }));
    }
  }
  return {
    schemaVersion: SCHEMA_VERSION,
    verificationId: newId("verify"),
    target: manifest.targetBaseUrl,
    startedAt,
    completedAt: new Date().toISOString(),
    requestCount,
    coverage: [{ domain: "web-passive-baseline", engine: "aisec-web-passive", status: "complete", required: true }],
    signals,
    limitations: [
      "Only non-mutating GET requests were sent, including redirects on the exact authorized origin.",
      "Authentication, IDOR, injection, upload and state-changing behavior were not tested.",
      "A clean passive result is not evidence that the target is free of application vulnerabilities.",
    ],
  };
}
