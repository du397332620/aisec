import type {
  BolaAuthorizationManifest,
  BolaCaseResult,
  BolaVerificationCase,
  BolaVerificationReport,
  JsonValue,
  Signal,
} from "../schema.js";
import { SCHEMA_VERSION } from "../schema.js";
import { createSignal, newId } from "../core/utils.js";
import { assertAllowedResponseUrl, loadBolaAuthorization } from "./authorization.js";
import { boundedHttpRequest, type BoundedHttpRequest, type BoundedHttpResponse } from "./http.js";

export type BolaRequester = (input: BoundedHttpRequest) => Promise<BoundedHttpResponse>;
export type BolaEnvironment = Record<string, string | undefined>;

interface AuthenticatedAccount {
  label: string;
  token: string;
  identity: string;
}

function jsonAtPath(value: unknown, path: string): unknown {
  let current = value;
  for (const segment of path.split(".")) {
    if (current === null || typeof current !== "object" || Array.isArray(current) || !Object.hasOwn(current, segment)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

function parseJson(body: string): unknown {
  if (Buffer.byteLength(body) === 0) throw new Error("response body was empty");
  try {
    return JSON.parse(body) as unknown;
  } catch {
    throw new Error("response body was not valid JSON");
  }
}

function exactPrimitive(left: unknown, right: string): boolean {
  return typeof left === typeof right && left === right;
}

function caseRequest(
  manifest: BolaAuthorizationManifest,
  item: BolaVerificationCase,
  token: string,
): BoundedHttpRequest {
  const url = new URL(item.path, manifest.targetBaseUrl).toString();
  assertAllowedResponseUrl(manifest, url);
  const body = item.body === undefined ? undefined : JSON.stringify(item.body satisfies Record<string, JsonValue>);
  return {
    url,
    method: item.method,
    local: manifest.environment === "local",
    body,
    headers: {
      authorization: `${manifest.login.tokenPrefix} ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
  };
}

function verifiedBolaSignal(manifest: BolaAuthorizationManifest, item: BolaVerificationCase): Signal {
  const target = new URL(item.path, manifest.targetBaseUrl);
  return createSignal({
    engine: "aisec-bola-verifier",
    ruleId: "web.bola.cross-account-object-access",
    title: "A second account can read another account's object",
    description: `The owner baseline and the cross-account request both returned the configured marker for pre-created test data ${item.testDataLabel}. This verifies missing object-level authorization for this test case.`,
    severity: "high",
    evidenceLevel: "verified",
    confidence: "high",
    locations: [{
      path: target.toString(),
      snippet: `${item.method} ${target.pathname}: ${item.ownerAccount} and ${item.otherAccount} returned the configured test-object marker`,
    }],
    cwe: ["CWE-639"],
    owasp: ["A01:2021-Broken Access Control", "API1:2023-Broken Object Level Authorization"],
    tags: ["web", "api", "authorization", "bola", "idor", "active-authorized"],
    remediation: "Resolve the authenticated principal on the server and constrain every object lookup by both object identifier and owner/tenant authorization. Add a two-account regression test for this route.",
    metadata: {
      caseId: item.id,
      method: item.method,
      ownerAccount: item.ownerAccount,
      otherAccount: item.otherAccount,
      testDataLabel: item.testDataLabel,
    },
  });
}

async function authenticate(
  manifest: BolaAuthorizationManifest,
  environment: BolaEnvironment,
  requester: BolaRequester,
  account: BolaAuthorizationManifest["accounts"][number],
  countRequest: () => void,
): Promise<AuthenticatedAccount> {
  const username = environment[account.usernameEnv];
  const password = environment[account.passwordEnv];
  if (!username?.trim() || !password) throw new Error(`BOLA account ${account.label} requires non-empty ${account.usernameEnv} and ${account.passwordEnv}`);
  const url = new URL(manifest.login.path, manifest.targetBaseUrl).toString();
  assertAllowedResponseUrl(manifest, url);
  const body = JSON.stringify({
    [manifest.login.usernameField]: username,
    [manifest.login.passwordField]: password,
  });
  countRequest();
  const response = await requester({
    url,
    method: "POST",
    local: manifest.environment === "local",
    body,
    headers: { "content-type": "application/json" },
  });
  assertAllowedResponseUrl(manifest, response.url);
  if (!manifest.login.successStatusCodes.includes(response.status)) throw new Error(`Login for BOLA account ${account.label} returned HTTP ${response.status}`);
  const token = jsonAtPath(parseJson(response.body), manifest.login.tokenJsonPath);
  if (typeof token !== "string" || token.length === 0 || token.length > 16_384 || /[\s\x00-\x1f\x7f]/.test(token)) {
    throw new Error(`Login for BOLA account ${account.label} did not return a valid token at ${manifest.login.tokenJsonPath}`);
  }
  const identity = jsonAtPath(parseJson(response.body), manifest.login.identityJsonPath);
  if ((typeof identity !== "string" && typeof identity !== "number") || String(identity).length === 0 || String(identity).length > 500) {
    throw new Error(`Login for BOLA account ${account.label} did not return a stable identity at ${manifest.login.identityJsonPath}`);
  }
  return { label: account.label, token, identity: String(identity) };
}

function evaluateOwner(item: BolaVerificationCase, response: BoundedHttpResponse): { ok: true } | { ok: false; reason: string } {
  if (!item.expected.statusCodes.includes(response.status)) return { ok: false, reason: `owner baseline returned HTTP ${response.status}` };
  try {
    const marker = jsonAtPath(parseJson(response.body), item.expected.jsonPath);
    if (!exactPrimitive(marker, item.expected.value)) return { ok: false, reason: "owner baseline did not return the configured test-object marker" };
    return { ok: true };
  } catch (error) {
    return { ok: false, reason: `owner baseline ${error instanceof Error ? error.message : String(error)}` };
  }
}

function evaluateOther(item: BolaVerificationCase, response: BoundedHttpResponse): Pick<BolaCaseResult, "status" | "reason"> {
  let marker: unknown;
  try {
    marker = jsonAtPath(parseJson(response.body), item.expected.jsonPath);
    if (exactPrimitive(marker, item.expected.value)) {
      return { status: "vulnerable", reason: `cross-account response exposed the owner's configured test-object marker with HTTP ${response.status}` };
    }
  } catch {
    marker = undefined;
  }
  if ([401, 403, 404].includes(response.status)) return { status: "protected", reason: `cross-account request was denied with HTTP ${response.status}` };
  if (!item.expected.statusCodes.includes(response.status)) return { status: "inconclusive", reason: `cross-account request returned unexpected HTTP ${response.status}` };
  try {
    if (marker !== undefined && (typeof marker === "string" || typeof marker === "number" || typeof marker === "boolean")) {
      return { status: "protected", reason: "cross-account response returned a different object marker" };
    }
    return { status: "inconclusive", reason: "cross-account response did not expose a comparable object marker" };
  } catch (error) {
    return { status: "inconclusive", reason: `cross-account ${error instanceof Error ? error.message : String(error)}` };
  }
}

export async function executeBolaVerification(
  manifest: BolaAuthorizationManifest,
  environment: BolaEnvironment = process.env,
  requester: BolaRequester = boundedHttpRequest,
): Promise<BolaVerificationReport> {
  const startedAt = new Date().toISOString();
  let requestCount = 0;
  const countRequest = (): void => {
    requestCount += 1;
    if (requestCount > manifest.maxRequests) throw new Error("BOLA verification exceeded the authorized request budget");
  };
  const usernames = manifest.accounts.map((account) => environment[account.usernameEnv]);
  if (usernames.some((username) => !username)) throw new Error("Both BOLA test-account usernames must be provided through the declared environment variables");
  if (usernames[0]!.trim().toLowerCase() === usernames[1]!.trim().toLowerCase()) throw new Error("BOLA verification requires two distinct account usernames");

  const authenticated: AuthenticatedAccount[] = [];
  for (const account of manifest.accounts) authenticated.push(await authenticate(manifest, environment, requester, account, countRequest));
  if (authenticated[0]!.token === authenticated[1]!.token) throw new Error("BOLA login returned the same token for both accounts; account separation cannot be verified");
  if (authenticated[0]!.identity.trim().toLowerCase() === authenticated[1]!.identity.trim().toLowerCase()) throw new Error("BOLA login resolved both credentials to the same account identity");
  const tokens = new Map(authenticated.map((account) => [account.label, account.token]));
  const cases: BolaCaseResult[] = [];
  const signals: Signal[] = [];

  for (const item of manifest.cases) {
    const base: Omit<BolaCaseResult, "status" | "reason"> = {
      caseId: item.id,
      method: item.method,
      path: item.path,
      testDataLabel: item.testDataLabel,
      ownerAccount: item.ownerAccount,
      otherAccount: item.otherAccount,
    };
    const ownerToken = tokens.get(item.ownerAccount)!;
    const otherToken = tokens.get(item.otherAccount)!;
    let ownerResponse: BoundedHttpResponse;
    try {
      countRequest();
      ownerResponse = await requester(caseRequest(manifest, item, ownerToken));
      assertAllowedResponseUrl(manifest, ownerResponse.url);
    } catch (error) {
      cases.push({ ...base, status: "inconclusive", reason: `owner request failed: ${error instanceof Error ? error.message : String(error)}` });
      continue;
    }
    const owner = evaluateOwner(item, ownerResponse);
    if (!owner.ok) {
      cases.push({ ...base, status: "inconclusive", ownerStatus: ownerResponse.status, reason: owner.reason });
      continue;
    }
    let otherResponse: BoundedHttpResponse;
    try {
      countRequest();
      otherResponse = await requester(caseRequest(manifest, item, otherToken));
      assertAllowedResponseUrl(manifest, otherResponse.url);
    } catch (error) {
      cases.push({ ...base, status: "inconclusive", ownerStatus: ownerResponse.status, reason: `cross-account request failed: ${error instanceof Error ? error.message : String(error)}` });
      continue;
    }
    const outcome = evaluateOther(item, otherResponse);
    cases.push({ ...base, ...outcome, ownerStatus: ownerResponse.status, otherStatus: otherResponse.status });
    if (outcome.status === "vulnerable") signals.push(verifiedBolaSignal(manifest, item));
  }

  const incomplete = cases.some((item) => item.status === "inconclusive" || item.status === "not_run");
  return {
    schemaVersion: SCHEMA_VERSION,
    verificationId: newId("bola"),
    target: manifest.targetBaseUrl,
    startedAt,
    completedAt: new Date().toISOString(),
    requestCount,
    accounts: manifest.accounts.map((account) => account.label),
    coverage: [{
      domain: "active-bola-verification",
      engine: "aisec-bola-verifier",
      status: incomplete ? "partial" : "complete",
      required: true,
      reason: incomplete ? "At least one configured case lacked a valid owner baseline or a conclusive cross-account response" : undefined,
    }],
    signals,
    cases,
    limitations: [
      "Only the exact preconfigured login and object-read requests were sent; object identifiers were not enumerated or mutated.",
      "Each cross-account request was sent only after the owner account returned the configured pre-created test-object marker.",
      "This verifies only listed cases and does not establish that other routes, roles, tenants or object types enforce authorization.",
      "Credentials and bearer tokens are read from environment variables and are never included in the report.",
      "The verifier cannot independently prove that the declared accounts are low privilege; account role and fixture isolation remain the operator's responsibility.",
    ],
  };
}

export async function verifyBola(
  authorizationPath: string,
  confirmed: boolean,
  environment: BolaEnvironment = process.env,
): Promise<BolaVerificationReport> {
  if (!confirmed) throw new Error("BOLA verification requires --confirm after reviewing the authorization manifest and test data");
  const manifest = await loadBolaAuthorization(authorizationPath);
  return executeBolaVerification(manifest, environment);
}
