import type { IncomingHttpHeaders } from "node:http";
import type { Signal, WebVerificationReport } from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { createSignal, makeLocation, newId } from "../core/utils.js";
import { assertAllowedResponseUrl, loadAuthorization } from "./authorization.js";
import { boundedHttpRequest } from "./http.js";

interface PassiveResponse {
  url: string;
  status: number;
  headers: IncomingHttpHeaders;
}

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

async function passiveGet(target: string, local: boolean): Promise<PassiveResponse> {
  const response = await boundedHttpRequest({ url: target, method: "GET", local, captureBody: false });
  return { url: response.url, status: response.status, headers: response.headers };
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
