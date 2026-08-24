import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { BolaAuthorizationManifest } from "../src/schema.js";
import { validateBolaVerificationReport } from "../src/core/schema-validation.js";
import { validateBolaAuthorization } from "../src/web/authorization.js";
import { executeBolaVerification, verifyBola, type BolaRequester } from "../src/web/bola.js";

const manifestValue = {
  schemaVersion: "1.0.0",
  targetBaseUrl: "https://staging.example.test/",
  environment: "staging",
  ownedBy: "AIsec tests",
  allowedHosts: ["staging.example.test"],
  dataPrefix: "aisec-fixture",
  maxRequests: 4,
  accounts: [
    { label: "owner", usernameEnv: "AISEC_BOLA_OWNER_USERNAME", passwordEnv: "AISEC_BOLA_OWNER_PASSWORD" },
    { label: "other", usernameEnv: "AISEC_BOLA_OTHER_USERNAME", passwordEnv: "AISEC_BOLA_OTHER_PASSWORD" },
  ],
  login: {
    path: "/user/login",
    usernameField: "username",
    passwordField: "password",
    successStatusCodes: [200],
    tokenJsonPath: "data.access_token",
    identityJsonPath: "data.user_id",
    tokenPrefix: "Bearer",
  },
  cases: [{
    id: "project-detail",
    method: "POST",
    path: "/project/detail",
    readOnly: true,
    testDataLabel: "aisec-fixture-project-a",
    ownerAccount: "owner",
    otherAccount: "other",
    body: { project_id: 12345 },
    expected: { statusCodes: [200], jsonPath: "data.project_name", value: "aisec-fixture-project-a" },
  }],
  acknowledgment: "I am authorized to test this non-production target with two low-privilege accounts and pre-created test data",
} as const;

const ownerIdentityManifestValue = {
  ...manifestValue,
  cases: [{
    ...manifestValue.cases[0],
    id: "ai-session-get",
    path: "/knowledge/ai/session/get",
    testDataLabel: "aisec-fixture-session-a",
    body: { session_id: 777 },
    expected: { match: "ownerIdentity", statusCodes: [200], jsonPath: "data.user_id" },
  }],
} as const;

const credentials = {
  AISEC_BOLA_OWNER_USERNAME: "fixture_owner",
  AISEC_BOLA_OWNER_PASSWORD: "owner_password",
  AISEC_BOLA_OTHER_USERNAME: "fixture_other",
  AISEC_BOLA_OTHER_PASSWORD: "other_password",
};

function jsonResponse(url: string, status: number, body: unknown) {
  return { url, status, headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
}

function requesterFor(otherResponse: { status: number; body: unknown }): { requester: BolaRequester; seen: Array<{ url: string; body?: string; authorization?: string }> } {
  const seen: Array<{ url: string; body?: string; authorization?: string }> = [];
  const requester: BolaRequester = async (input) => {
    seen.push({ url: input.url, body: input.body, authorization: input.headers?.authorization });
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      return jsonResponse(input.url, 200, { data: {
        access_token: login.username === "fixture_owner" ? "owner-token" : "other-token",
        user_id: login.username === "fixture_owner" ? 101 : 202,
      } });
    }
    if (input.headers?.authorization === "Bearer owner-token") return jsonResponse(input.url, 200, { data: { id: 12345, project_name: "aisec-fixture-project-a", secret: "owner data" } });
    return jsonResponse(input.url, otherResponse.status, otherResponse.body);
  };
  return { requester, seen };
}

test("BOLA manifest rejects unsafe methods, mutation routes and ambiguous accounts", () => {
  assert.equal(validateBolaAuthorization(manifestValue).cases.length, 1);
  assert.equal(validateBolaAuthorization(ownerIdentityManifestValue).cases[0]?.expected.match, "ownerIdentity");
  assert.throws(() => validateBolaAuthorization({ ...manifestValue, environment: "production" }), /BolaAuthorizationManifest.*environment/);
  assert.throws(() => validateBolaAuthorization({ ...manifestValue, maxRequests: 3 }), /maxRequests must be >= 4/);
  assert.throws(() => validateBolaAuthorization({ ...manifestValue, accounts: [manifestValue.accounts[0], manifestValue.accounts[0]] }), /distinct account labels/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    accounts: [{ ...manifestValue.accounts[0], usernameEnv: "PATH" }, manifestValue.accounts[1]],
  }), /BolaAuthorizationManifest.*usernameEnv/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    login: { ...manifestValue.login, path: "/user/delete/login" },
  }), /login\.path has an unrelated state-changing marker: delete/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], method: "DELETE" }],
  }), /BolaAuthorizationManifest.*method/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], path: "/project/delete" }],
  }), /state-changing marker: delete/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], path: "/project/action" }],
  }), /explicit read\/query marker/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], path: "/budget/action" }],
  }), /explicit read\/query marker/, "the substring 'get' inside budget must not authorize a POST route");
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], testDataLabel: "aisec-other-project" }],
  }), /testDataLabel must begin with dataPrefix/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], expected: { ...manifestValue.cases[0].expected, value: "aisec-fixture-other-project" } }],
  }), /expected.value must exactly equal testDataLabel/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], body: { project_id: 12345, project_name: "aisec-fixture-project-a" } }],
  }), /response marker must not be supplied in the request/);
  assert.throws(() => validateBolaAuthorization({
    ...manifestValue,
    cases: [{ ...manifestValue.cases[0], body: { project_id: 12345, action: "delete" } }],
  }), /body has a state-changing marker: delete/);
  assert.throws(() => validateBolaAuthorization({
    ...ownerIdentityManifestValue,
    cases: [{
      ...ownerIdentityManifestValue.cases[0],
      expected: { ...ownerIdentityManifestValue.cases[0].expected, value: "aisec-fixture-session-a" },
    }],
  }), /BolaAuthorizationManifest.*expected/);
  assert.throws(() => validateBolaAuthorization({
    ...ownerIdentityManifestValue,
    cases: [{ ...ownerIdentityManifestValue.cases[0], body: { session_id: 777, user_id: 101 } }],
  }), /owner identity evidence field must not be supplied in the request/);
});

test("BOLA verifier reports verified cross-account object access without leaking credentials or tokens", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  const { requester, seen } = requesterFor({ status: 200, body: { data: { id: 12345, project_name: "aisec-fixture-project-a", secret: "owner data" } } });
  const report = await executeBolaVerification(manifest, credentials, requester);
  assert.equal(report.schemaVersion, "1.0.0");
  assert.ok(!report.provenance);
  assert.equal(validateBolaVerificationReport(report), report);
  assert.equal(report.requestCount, 4);
  assert.equal(report.coverage[0]?.status, "complete");
  assert.equal(report.cases[0]?.status, "vulnerable");
  assert.equal(report.signals[0]?.ruleId, "web.bola.cross-account-object-access");
  assert.equal(report.signals[0]?.evidenceLevel, "verified");
  assert.equal(seen[2]?.authorization, "Bearer owner-token");
  assert.equal(seen[3]?.authorization, "Bearer other-token");
  const serialized = JSON.stringify(report);
  for (const secret of [...Object.values(credentials), "owner-token", "other-token", "owner data"]) assert.ok(!serialized.includes(secret));
});

test("legacy BOLA reports are strict and cannot claim active preflight provenance", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  const report = await executeBolaVerification(manifest, credentials, requesterFor({
    status: 200,
    body: { data: { project_name: "aisec-fixture-project-a" } },
  }).requester);
  assert.equal(validateBolaVerificationReport(report), report);

  assert.throws(
    () => validateBolaVerificationReport({ ...report, schemaVersion: "1.1.0" }),
    /BolaVerificationReport.*provenance/u,
  );
  assert.throws(
    () => validateBolaVerificationReport({ ...report, provenance: { status: "preflight_verified" } }),
    /BolaVerificationReport.*provenance/u,
  );
  assert.throws(
    () => validateBolaVerificationReport({ ...report, responseBody: "must-not-be-recorded" }),
    /BolaVerificationReport.*additional properties/u,
  );

  const duplicateCase = structuredClone(report);
  duplicateCase.cases.push(structuredClone(duplicateCase.cases[0]!));
  assert.throws(() => validateBolaVerificationReport(duplicateCase), /case IDs must be unique/u);

  const missingSignal = structuredClone(report);
  missingSignal.signals = [];
  assert.throws(() => validateBolaVerificationReport(missingSignal), /every vulnerable case requires one verified signal/u);

  const mismatchedSignal = structuredClone(report);
  mismatchedSignal.signals[0]!.metadata!.caseId = "different-case";
  assert.throws(() => validateBolaVerificationReport(mismatchedSignal), /one-to-one to vulnerable cases/u);

  const forgedRequestCount = structuredClone(report);
  forgedRequestCount.requestCount -= 1;
  assert.throws(() => validateBolaVerificationReport(forgedRequestCount), /request count is inconsistent/u);
});

test("BOLA report reasons do not retain arbitrary requester error or response text", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  const sentinel = "RAW_RESPONSE_SECRET_7f9134";
  const requester: BolaRequester = async (input) => {
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      const owner = login.username === "fixture_owner";
      return jsonResponse(input.url, 200, { data: {
        access_token: owner ? "owner-token" : "other-token",
        user_id: owner ? 101 : 202,
      } });
    }
    if (input.headers?.authorization === "Bearer owner-token") {
      return jsonResponse(input.url, 200, { data: { project_name: "aisec-fixture-project-a" } });
    }
    throw new Error(`${sentinel}: ${JSON.stringify({ responseBody: "private customer data" })}`);
  };
  const report = await executeBolaVerification(manifest, credentials, requester);
  assert.equal(report.cases[0]?.status, "inconclusive");
  assert.equal(report.cases[0]?.reason, "cross-account request failed before a response could be safely evaluated");
  assert.doesNotMatch(JSON.stringify(report), new RegExp(`${sentinel}|private customer data`, "u"));
  assert.equal(validateBolaVerificationReport(report), report);
});

test("BOLA verifier can use a response owner field without storing account identities", async () => {
  const manifest = validateBolaAuthorization(ownerIdentityManifestValue);
  const seen: Array<{ authorization?: string }> = [];
  const requester: BolaRequester = async (input) => {
    seen.push({ authorization: input.headers?.authorization });
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      const owner = login.username === "fixture_owner";
      return jsonResponse(input.url, 200, { data: {
        access_token: owner ? "owner-token" : "other-token",
        user_id: owner ? "owner-private-identity" : "other-private-identity",
      } });
    }
    return jsonResponse(input.url, 200, { data: { id: 777, user_id: "owner-private-identity" } });
  };

  const report = await executeBolaVerification(manifest, credentials, requester);
  assert.equal(report.requestCount, 4);
  assert.equal(report.coverage[0]?.status, "complete");
  assert.equal(report.cases[0]?.status, "vulnerable");
  assert.equal(report.signals[0]?.ruleId, "web.bola.cross-account-object-access");
  assert.equal(report.signals[0]?.evidenceLevel, "verified");
  assert.deepEqual(seen.map((item) => item.authorization), [undefined, undefined, "Bearer owner-token", "Bearer other-token"]);
  const serialized = JSON.stringify(report);
  for (const secret of [
    ...Object.values(credentials),
    "owner-token",
    "other-token",
    "owner-private-identity",
    "other-private-identity",
  ]) assert.ok(!serialized.includes(secret));
});

test("owner identity evidence requires a valid owner baseline and recognizes explicit denial", async () => {
  const manifest = validateBolaAuthorization(ownerIdentityManifestValue);
  const requester = (ownerIdentity: string, otherStatus: number, otherIdentity?: string): BolaRequester => async (input) => {
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      const owner = login.username === "fixture_owner";
      return jsonResponse(input.url, 200, { data: {
        access_token: owner ? "owner-token" : "other-token",
        user_id: owner ? "owner-private-identity" : "other-private-identity",
      } });
    }
    if (input.headers?.authorization === "Bearer owner-token") {
      return jsonResponse(input.url, 200, { data: { id: 777, user_id: ownerIdentity } });
    }
    return jsonResponse(input.url, otherStatus, otherIdentity === undefined ? { detail: "forbidden" } : { data: { id: 777, user_id: otherIdentity } });
  };

  const invalidBaseline = await executeBolaVerification(manifest, credentials, requester("not-the-owner", 200, "owner-private-identity"));
  assert.equal(invalidBaseline.requestCount, 3, "the cross-account request is skipped when owner evidence does not match the authenticated owner");
  assert.equal(invalidBaseline.cases[0]?.status, "inconclusive");
  assert.equal(invalidBaseline.coverage[0]?.status, "partial");

  const denied = await executeBolaVerification(manifest, credentials, requester("owner-private-identity", 403));
  assert.equal(denied.requestCount, 4);
  assert.equal(denied.cases[0]?.status, "protected");
  assert.equal(denied.coverage[0]?.status, "complete");
  assert.equal(denied.signals.length, 0);

  const differentOwner = await executeBolaVerification(manifest, credentials, requester("owner-private-identity", 200, "other-private-identity"));
  assert.equal(differentOwner.cases[0]?.status, "protected");
  assert.equal(differentOwner.coverage[0]?.status, "complete");

  const wrongTypeRequester: BolaRequester = async (input) => {
    if (input.url.endsWith("/user/login")) return requester("owner-private-identity", 200, "ignored")(input);
    if (input.headers?.authorization === "Bearer owner-token") return jsonResponse(input.url, 200, { data: { user_id: "owner-private-identity" } });
    return jsonResponse(input.url, 200, { data: { user_id: false } });
  };
  const nonComparable = await executeBolaVerification(manifest, credentials, wrongTypeRequester);
  assert.equal(nonComparable.cases[0]?.status, "inconclusive");
  assert.equal(nonComparable.coverage[0]?.status, "partial");
});

test("BOLA verifier distinguishes explicit denial from inconclusive responses", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  const denied = await executeBolaVerification(manifest, credentials, requesterFor({ status: 403, body: { detail: "forbidden" } }).requester);
  assert.equal(denied.cases[0]?.status, "protected");
  assert.equal(denied.coverage[0]?.status, "complete");
  assert.equal(denied.signals.length, 0);

  const leakingDenial = await executeBolaVerification(manifest, credentials, requesterFor({
    status: 403,
    body: { data: { project_name: "aisec-fixture-project-a" }, detail: "forbidden" },
  }).requester);
  assert.equal(leakingDenial.cases[0]?.status, "vulnerable", "a denial status must not hide leaked owner data");
  assert.equal(leakingDenial.signals[0]?.ruleId, "web.bola.cross-account-object-access");

  const ambiguous = await executeBolaVerification(manifest, credentials, requesterFor({ status: 200, body: { code: 403, message: "forbidden" } }).requester);
  assert.equal(ambiguous.cases[0]?.status, "inconclusive");
  assert.equal(ambiguous.coverage[0]?.status, "partial");
  assert.equal(ambiguous.signals.length, 0);
});

test("BOLA verifier requires separate usernames and valid owner baselines", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  await assert.rejects(() => executeBolaVerification(manifest, { ...credentials, AISEC_BOLA_OTHER_USERNAME: "fixture_owner" }, requesterFor({ status: 403, body: {} }).requester), /two distinct account usernames/);
  await assert.rejects(() => executeBolaVerification(manifest, { ...credentials, AISEC_BOLA_OTHER_USERNAME: "   " }, requesterFor({ status: 403, body: {} }).requester), /usernames must be provided|requires non-empty/);

  const requester: BolaRequester = async (input) => {
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      return jsonResponse(input.url, 200, { data: { access_token: `${login.username}-token`, user_id: login.username === "fixture_owner" ? 101 : 202 } });
    }
    return jsonResponse(input.url, 404, { detail: "missing owner fixture" });
  };
  const report = await executeBolaVerification(manifest, credentials, requester);
  assert.equal(report.requestCount, 3, "cross-account request is skipped when the owner baseline fails");
  assert.equal(report.cases[0]?.status, "inconclusive");
  assert.equal(report.coverage[0]?.status, "partial");
});

test("BOLA verifier rejects two logins that resolve to the same account identity", async () => {
  const manifest = validateBolaAuthorization(manifestValue);
  const requester: BolaRequester = async (input) => {
    if (input.url.endsWith("/user/login")) {
      const login = JSON.parse(input.body ?? "{}") as { username?: string };
      return jsonResponse(input.url, 200, { data: { access_token: `${login.username}-token`, user_id: 101 } });
    }
    throw new Error("object request must not run");
  };
  await assert.rejects(() => executeBolaVerification(manifest, credentials, requester), /same account identity/);
});

test("authorized local BOLA verification performs exactly two logins and two read requests", async (context) => {
  const requests: Array<{ path: string; authorization?: string }> = [];
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      requests.push({ path: request.url ?? "", authorization: request.headers.authorization });
      response.setHeader("content-type", "application/json");
      if (request.url === "/user/login") {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { username: string };
        response.end(JSON.stringify({ data: { access_token: `${body.username}-token`, user_id: body.username === "fixture_owner" ? 101 : 202 } }));
        return;
      }
      if (request.headers.authorization === "Bearer fixture_owner-token") response.end(JSON.stringify({ data: { id: 12345, project_name: "aisec-fixture-project-a" } }));
      else {
        response.statusCode = 403;
        response.end(JSON.stringify({ detail: "forbidden" }));
      }
    });
  });
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "EPERM") {
      context.skip("the execution sandbox forbids local loopback listeners");
      return;
    }
    throw error;
  }
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const temporary = await mkdtemp(join(tmpdir(), "aisec-bola-"));
  const manifestPath = join(temporary, "authorization.yml");
  const localManifest: BolaAuthorizationManifest = {
    ...validateBolaAuthorization(manifestValue),
    targetBaseUrl: `http://127.0.0.1:${address.port}/`,
    environment: "local",
    allowedHosts: ["127.0.0.1"],
  };
  await writeFile(manifestPath, JSON.stringify(localManifest));
  try {
    await assert.rejects(() => verifyBola(manifestPath, {
      confirmed: false,
      templatePath: join(temporary, "missing-template.json"),
      checkPath: join(temporary, "missing-check.json"),
      environment: credentials,
    }), /requires --confirm/);
    const report = await executeBolaVerification(localManifest, credentials);
    assert.equal(report.requestCount, 4);
    assert.equal(report.cases[0]?.status, "protected");
    assert.deepEqual(requests.map((item) => item.path), ["/user/login", "/user/login", "/project/detail", "/project/detail"]);
  } finally {
    server.close();
    await once(server, "close");
    await rm(temporary, { recursive: true, force: true });
  }
});
