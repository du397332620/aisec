import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { scanProject } from "../src/core/scan.js";
import { createFixContract } from "../src/core/contracts.js";
import { compareReports } from "../src/core/compare.js";
import { validateAuthorization } from "../src/web/authorization.js";
import { verifyWeb } from "../src/web/verify.js";
import { serializeReport } from "../src/reporters/index.js";
import { engineStatus, installManagedEngine, resolveEngineCommand } from "../src/engines/manager.js";
import { sha256 } from "../src/core/utils.js";
import { engineCompatibility, parseEngineVersion } from "../src/engines/compatibility.js";
import { normalizeOpengrepRuleId } from "../src/engines/opengrep.js";
import { trivyDatabaseStatus } from "../src/engines/trivy-db.js";
import { materializeFixture, SYNTHETIC_STRIPE_LIVE_KEY } from "./helpers/materialize-fixture.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, "..", "..", "test", "fixtures");

async function materializeVulnerableFixture() {
  return materializeFixture(join(fixtures, "vulnerable"), [{
    relativePath: ".env.example",
    placeholder: "__AISEC_SYNTHETIC_STRIPE_LIVE_KEY__",
    value: SYNTHETIC_STRIPE_LIVE_KEY,
  }]);
}

test("vulnerable full-stack fixture produces evidence-backed attack paths and redacts secrets", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    assert.equal(report.decision, "block");
    assert.ok(report.attackPaths.some((path) => path.title.includes("BaaS")));
    assert.ok(report.attackPaths.some((path) => path.title.includes("Prompt-controlled")));
    assert.ok(report.signals.some((signal) => signal.ruleId === "dataflow.sql-injection"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "react-native.sensitive-async-storage"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "supabase.table-without-rls"));
    const json = serializeReport(report, "json");
    assert.doesNotMatch(json, new RegExp(SYNTHETIC_STRIPE_LIVE_KEY));
    assert.match(json, /sk_…890/);
  } finally {
    await fixture.cleanup();
  }
});

test("safe near-miss fixture is not blocked in native-only mode", async () => {
  const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
  assert.equal(report.decision, "no_blockers_found");
  assert.equal(report.findings.filter((finding) => finding.status === "open").length, 0);
  assert.equal(report.coverage.find((item) => item.domain === "baas-authorization")?.status, "complete");
});

test("FastAPI auth analysis detects a sensitive route bypassed by a prefix whitelist", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-auth", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(report.profile.frameworks.includes("FastAPI"));
  assert.ok(report.profile.routes.includes("POST /permission/operation/create"));
  const finding = report.signals.find((signal) => signal.ruleId === "fastapi.auth.whitelisted-sensitive-route");
  assert.ok(finding);
  assert.equal(finding.evidenceLevel, "static_confirmed");
  assert.equal(finding.metadata?.route, "POST /permission/operation/create");
});

test("FastAPI auth analysis accepts an explicit route-level dependency inside a whitelist", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-auth", "near-miss"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(report.profile.frameworks.includes("FastAPI"));
  assert.ok(!report.signals.some((signal) => signal.ruleId === "fastapi.auth.whitelisted-sensitive-route"));
});

test("FastAPI object authorization detects an authenticated ID operation without ownership binding", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const finding = report.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(finding);
  assert.equal(finding.evidenceLevel, "inferred");
  assert.equal(finding.metadata?.route, "POST /document/delete");
  assert.deepEqual(finding.metadata?.objectIdFields, ["report_id"]);
  assert.deepEqual(finding.metadata?.ownerIdentityFields, []);
});

test("FastAPI object authorization records explicit response owner fields for BOLA planning", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "positive-read"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const finding = report.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
  assert.ok(finding);
  assert.equal(finding.metadata?.route, "POST /document/detail");
  assert.deepEqual(finding.metadata?.ownerIdentityFields, ["user_id"]);
});

test("FastAPI object authorization resolves owner fields from a response model", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-fastapi-response-owner-"));
  try {
    await writeFile(join(temporary, "main.py"), `
from fastapi import Depends, FastAPI
from pydantic import BaseModel

def get_current_user():
    return {"id": 7}

class DocumentResponse(BaseModel):
    id: int
    tenant_id: int

app = FastAPI(dependencies=[Depends(get_current_user)])

@app.get("/document/{document_id}", response_model=DocumentResponse)
def document_detail(document_id: int, db=Depends(get_db)):
    return db.get(Document, document_id)
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const finding = report.signals.find((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check");
    assert.ok(finding);
    assert.equal(finding.metadata?.route, "GET /document/{document_id}");
    assert.deepEqual(finding.metadata?.ownerIdentityFields, ["tenant_id"]);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("FastAPI object authorization accepts a centralized ownership guard", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "fastapi-authorization", "near-miss"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(!report.signals.some((signal) => signal.ruleId === "fastapi.authorization.object-without-ownership-check"));
});

test("FastAPI analysis ignores route-like decorators inside triple-quoted disabled code", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-fastapi-disabled-route-"));
  try {
    await writeFile(join(temporary, "main.py"), `
from fastapi import Depends, FastAPI

app = FastAPI(dependencies=[Depends(get_current_user)])

'''disabled legacy route
@app.post("/resource/detail")
def detail(request: DetailRequest, db=Depends(get_db)):
    return db.get(Resource, request.resource_id)
'''

@app.post("/document/detail")
def live_detail(request: DetailRequest, db=Depends(get_db)):
    return db.get(Report, request.report_id)
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("POST /document/detail"));
    assert.ok(!report.profile.routes.includes("POST /resource/detail"));
    assert.ok(!report.signals.some((signal) => signal.metadata?.route === "POST /resource/detail"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express and NestJS analysis resolves routes and reports authentication and object-authorization gaps", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "node-api", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(report.profile.frameworks.includes("Express"));
  assert.ok(report.profile.frameworks.includes("NestJS"));
  assert.ok(report.profile.routes.includes("POST /api/document/detail"));
  assert.ok(report.profile.routes.includes("POST /reports/detail"));
  const rules = new Set(report.signals.map((signal) => signal.ruleId));
  assert.ok(rules.has("express.auth.sensitive-route-without-guard"));
  assert.ok(rules.has("express.authorization.object-without-ownership-check"));
  assert.ok(rules.has("nestjs.auth.sensitive-route-without-guard"));
  assert.ok(rules.has("nestjs.authorization.object-without-ownership-check"));
  const expressBola = report.signals.find((signal) => signal.ruleId === "express.authorization.object-without-ownership-check");
  assert.equal(expressBola?.metadata?.route, "POST /api/document/detail");
  assert.deepEqual(expressBola?.metadata?.objectIdFields, ["document_id"]);
  assert.deepEqual(expressBola?.metadata?.ownerIdentityFields, ["user_id"]);
  const nestBola = report.signals.find((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check");
  assert.deepEqual(nestBola?.metadata?.objectIdFields, ["report_id"]);
  assert.deepEqual(nestBola?.metadata?.ownerIdentityFields, ["tenantId"]);
});

test("Express and NestJS analysis accepts visible authentication and ownership constraints", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "node-api", "near-miss"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(report.profile.routes.includes("POST /api/document/detail"));
  assert.ok(!report.signals.some((signal) => /^(?:express|nestjs)\.(?:auth|authorization)\./.test(signal.ruleId)));
});

test("Express analysis resolves CommonJS routers through nested mounts and namespace handlers", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-commonjs-"));
  try {
    await mkdir(join(temporary, "routes"));
    await mkdir(join(temporary, "handlers"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.cjs"), `
const express = require("express");
const apiRouter = require("./routes/api");
const app = express();
app.use("/v1", apiRouter);
app.get("/v1/admin/status", (_req, res) => res.json({ ok: true }));
`);
    await writeFile(join(temporary, "routes", "api.cjs"), `
const { Router } = require("express");
const reportRouter = require("./reports");
const router = Router();
router.use("/reports", reportRouter);
module.exports = router;
`);
    await writeFile(join(temporary, "routes", "reports.cjs"), `
const { Router } = require("express");
const handlers = require("../handlers/reports");
const router = Router();
router.get("/:reportId", handlers.readReport);
module.exports = router;
`);
    await writeFile(join(temporary, "handlers", "reports.cjs"), `
exports.readReport = async function readReport(req, res) {
  const report = await db.reports.findById(req.params.reportId);
  return res.json({ id: report.id, tenantId: report.tenantId });
};
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("GET /v1/reports/:reportId"));
    assert.ok(report.profile.routes.includes("GET /v1/admin/status"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "GET /v1/reports/:reportId"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "GET /v1/admin/status"));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.doesNotMatch(coverage?.reason ?? "", /handler reference/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis resolves a router exported from a chained mount", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-chained-router-"));
  try {
    await mkdir(join(temporary, "routes"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
import routes from "./routes/index.js";
const app = express();
app.use(routes);
`);
    await writeFile(join(temporary, "routes", "index.ts"), `
import { Router } from "express";
const reports = Router();
reports.get("/reports", (_req, res) => res.json([]));
const api = Router().use(reports);
export default Router().use("/api", api);
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("GET /api/reports"));
    assert.ok(!report.profile.routes.includes("GET /reports"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis resolves an application passed to a CommonJS route registrar", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-registrar-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "4.18.1" } }));
    await writeFile(join(temporary, "server.js"), `
const express = require("express");
const registerRoutes = require("./routes");
const app = express();
registerRoutes(app);
`);
    await writeFile(join(temporary, "routes.js"), `
module.exports = (app) => {
  app.post("/admin/reload", (_req, res) => res.json({ ok: true }));
};
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("POST /admin/reload"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "POST /admin/reload"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis follows constructed CommonJS handlers into an authenticated object lookup", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-instance-handler-"));
  try {
    await mkdir(join(temporary, "routes"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "4.18.1" } }));
    await writeFile(join(temporary, "server.js"), `
const express = require("express");
const registerRoutes = require("./routes");
const app = express();
registerRoutes(app, {});
`);
    await writeFile(join(temporary, "routes", "index.js"), `
const SessionHandler = require("./session");
const AllocationsHandler = require("./allocations");
module.exports = (app, db) => {
  const sessionHandler = new SessionHandler(db);
  const allocationsHandler = new AllocationsHandler(db);
  const isLoggedIn = sessionHandler.isLoggedInMiddleware;
  app.get("/allocations/:userId", isLoggedIn, allocationsHandler.displayAllocations);
};
`);
    await writeFile(join(temporary, "routes", "session.js"), `
function SessionHandler() {
  this.isLoggedInMiddleware = (req, res, next) => {
    if (req.session?.userId) return next();
    return res.redirect("/login");
  };
}
module.exports = SessionHandler;
`);
    await writeFile(join(temporary, "routes", "allocations.js"), `
function AllocationsHandler(db) {
  this.displayAllocations = (req, res) => {
    const { userId } = req.params;
    return db.allocations.getByUserIdAndThreshold(userId, req.query.threshold, (_error, rows) => res.json(rows));
  };
}
module.exports = AllocationsHandler;
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("GET /allocations/:userId"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
      && signal.metadata?.route === "GET /allocations/:userId"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis reports an authenticated privileged operation without a role guard", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-privileged-handler-"));
  try {
    await mkdir(join(temporary, "routes"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "4.18.1" } }));
    await writeFile(join(temporary, "server.js"), `
const express = require("express");
const registerRoutes = require("./routes");
const app = express();
registerRoutes(app, {});
`);
    await writeFile(join(temporary, "routes", "index.js"), `
const SessionHandler = require("./session");
const BenefitsHandler = require("./benefits");
module.exports = (app, db) => {
  const sessionHandler = new SessionHandler();
  const benefitsHandler = new BenefitsHandler(db);
  app.post("/benefits", sessionHandler.isLoggedInMiddleware, benefitsHandler.updateBenefits);
};
`);
    await writeFile(join(temporary, "routes", "session.js"), `
function SessionHandler() {
  this.isLoggedInMiddleware = (req, res, next) => {
    if (!req.session?.userId) return res.status(401).end();
    return next();
  };
}
module.exports = SessionHandler;
`);
    await writeFile(join(temporary, "routes", "benefits.js"), `
function BenefitsHandler(db) {
  this.updateBenefits = (req, res) => {
    return db.benefits.updateBenefits(req.body.userId, req.body.startDate, () =>
      db.users.getAllNonAdminUsers((_error, users) => res.json({ users, user: { isAdmin: true } })));
  };
}
module.exports = BenefitsHandler;
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.privileged-operation-without-role-check"
      && signal.metadata?.route === "POST /benefits"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis accepts a visible instance role guard on a privileged operation", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-privileged-guard-"));
  try {
    await mkdir(join(temporary, "routes"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "4.18.1" } }));
    await writeFile(join(temporary, "server.js"), `
const express = require("express");
const registerRoutes = require("./routes");
const app = express();
registerRoutes(app, {});
`);
    await writeFile(join(temporary, "routes", "index.js"), `
const SessionHandler = require("./session");
const BenefitsHandler = require("./benefits");
module.exports = (app, db) => {
  const sessionHandler = new SessionHandler();
  const benefitsHandler = new BenefitsHandler(db);
  app.post(
    "/benefits",
    sessionHandler.isLoggedInMiddleware,
    sessionHandler.isAdminUserMiddleware,
    benefitsHandler.updateBenefits
  );
};
`);
    await writeFile(join(temporary, "routes", "session.js"), `
function SessionHandler() {
  this.isLoggedInMiddleware = (req, res, next) => {
    if (!req.session?.userId) return res.status(401).end();
    return next();
  };
  this.isAdminUserMiddleware = (req, res, next) => {
    if (req.session?.role !== "admin") return res.sendStatus(403);
    return next();
  };
}
module.exports = SessionHandler;
`);
    await writeFile(join(temporary, "routes", "benefits.js"), `
function BenefitsHandler(db) {
  this.updateBenefits = (req, res) => {
    return db.users.findById(req.body.userId, (_error, user) =>
      db.benefits.updateBenefits(user.id, req.body.startDate, () => res.json({ user })));
  };
}
module.exports = BenefitsHandler;
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("POST /benefits"));
    assert.ok(!report.signals.some((signal) => signal.ruleId === "express.authorization.privileged-operation-without-role-check"));
    assert.ok(!report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis does not treat a tenant guard as an administrator role guard", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-express-tenant-not-admin-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
function tenantGuard(req, res, next) {
  if (req.user.tenantId !== req.body.tenantId) return res.sendStatus(403);
  return next();
}
app.post("/admin/export", requireSession, tenantGuard, (_req, res) => res.json({ ok: true }));
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.privileged-operation-without-role-check"
      && signal.metadata?.route === "POST /admin/export"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Node API analysis accepts explicit public registration but keeps administrator user creation sensitive", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-public-registration-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0", "@nestjs/common": "11.1.6" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();
const router = express.Router();
router.post("/users", async (req, res) => res.json(await createUser(req.body.user)));
router.post("/users/login", async (req, res) => res.json(await login(req.body.user)));
router.get("/users", async (_req, res) => res.json(await createUserPreview()));
router.post("/admin/users", async (req, res) => res.json(await createUser(req.body.user)));
router.post("/admin/login", async (req, res) => res.json(await login(req.body.user)));
router.post("/admin/register", async (req, res) => res.json(await register(req.body.user)));
app.use("/api", router);
`);
    await writeFile(join(temporary, "user.controller.ts"), `
import { Controller, Post } from "@nestjs/common";
@Controller("user")
export class UserController {
  @Post()
  signupUser() { return this.userService.createUser(); }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(!report.signals.some((signal) => signal.metadata?.route === "POST /api/users"));
    assert.ok(!report.signals.some((signal) => signal.metadata?.route === "POST /user"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "POST /api/admin/users"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "POST /api/admin/register"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "GET /api/users"));
    assert.ok(!report.signals.some((signal) => signal.metadata?.route === "POST /api/admin/login"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis accepts authentication-entry handlers but keeps credential management sensitive", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-auth-entry-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@nestjs/common": "11.1.6" } }));
    await writeFile(join(temporary, "main.ts"), `
import { VersioningType } from "@nestjs/common";
app.enableVersioning({ type: VersioningType.URI, defaultVersion: "1" });
app.setGlobalPrefix("api");
`);
    await writeFile(join(temporary, "auth.controller.ts"), `
import { Controller, Post } from "@nestjs/common";
@Controller("auth")
export class AuthController {
  @Post("anonymous")
  accessTokenLogin() { return this.webAuthService.validateAnonymousLogin(); }

  @Post("webauthn/generate-authentication-options")
  generateAuthenticationOptions() { return this.webAuthService.generateAuthenticationOptions(); }

  @Post("webauthn/verify-authentication")
  verifyAuthentication() { return this.webAuthService.verifyAuthentication(); }

  @Post("webauthn/generate-registration-options")
  generateRegistrationOptions() { return this.webAuthService.generateRegistrationOptions(); }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const unguarded = report.signals.filter((signal) => signal.ruleId === "nestjs.auth.sensitive-route-without-guard");
    assert.ok(!unguarded.some((signal) => signal.metadata?.route === "POST /api/v1/auth/anonymous"));
    assert.ok(!unguarded.some((signal) => signal.metadata?.route === "POST /api/v1/auth/webauthn/generate-authentication-options"));
    assert.ok(!unguarded.some((signal) => signal.metadata?.route === "POST /api/v1/auth/webauthn/verify-authentication"));
    assert.ok(unguarded.some((signal) => signal.metadata?.route === "POST /api/v1/auth/webauthn/generate-registration-options"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis follows a same-controller ownership helper", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-controller-helper-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@nestjs/common": "11.1.6", "@nestjs/passport": "11.0.5" } }));
    await writeFile(join(temporary, "records.controller.ts"), `
import { Controller, Delete, ForbiddenException, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
@Controller("records")
export class RecordsController {
  @Delete(":id")
  @UseGuards(AuthGuard("jwt"))
  async deleteRecord(@Param("id") id: string, @Req() request: any) {
    const record = await this.records.findById(id);
    this.validateOwnership(record, request);
    return this.records.delete({ id });
  }

  private validateOwnership(record: any, request: any) {
    if (record.userId !== request.user.id) throw new ForbiddenException();
  }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("DELETE /records/:id"));
    assert.ok(!report.signals.some((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Node API analysis follows local service and repository wrappers into attacker-selected object lookups", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-service-wrapper-"));
  try {
    await mkdir(join(temporary, "express"));
    await mkdir(join(temporary, "nest"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      express: "5.1.0",
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
    } }));
    await writeFile(join(temporary, "express", "app.ts"), `
import express from "express";
import { ExpressDocumentService } from "./document.service";

const app = express();
const service = new ExpressDocumentService();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
app.get("/express/users/:userId/documents/:documentId", requireSession, async (req, res) => {
  const document = await service.loadDocument(req.params.documentId, req.params.userId);
  return res.json(document);
});
`);
    await writeFile(join(temporary, "express", "document.service.ts"), `
import { ExpressDocumentRepository } from "./document.repository";

export class ExpressDocumentService {
  private readonly repository = new ExpressDocumentRepository();

  loadDocument(documentId: string, userId: string) {
    return this.repository.fetchDocument(documentId, userId);
  }
}
`);
    await writeFile(join(temporary, "express", "document.repository.ts"), `
export class ExpressDocumentRepository {
  fetchDocument(documentId: string, userId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, author: { id: userId } } });
  }
}
`);
    await writeFile(join(temporary, "nest", "document.controller.ts"), `
import { Controller, Get, Param, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { NestDocumentService } from "./document.service";

@Controller("nest/users/:userId/documents")
@UseGuards(AuthGuard("jwt"))
export class NestDocumentController {
  constructor(private readonly service: NestDocumentService) {}

  @Get(":documentId")
  getDocument(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.loadDocument(documentId, userId);
  }
}
`);
    await writeFile(join(temporary, "nest", "document.service.ts"), `
import { Injectable } from "@nestjs/common";
import { NestDocumentRepository } from "./document.repository";

@Injectable()
export class NestDocumentService {
  constructor(private readonly repository: NestDocumentRepository) {}

  loadDocument(documentId: string, userId: string) {
    return this.repository.fetchDocument(documentId, userId);
  }
}
`);
    await writeFile(join(temporary, "nest", "document.repository.ts"), `
export class NestDocumentRepository {
  fetchDocument(documentId: string, userId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, userId } });
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    for (const [ruleId, route] of [
      ["express.authorization.object-without-ownership-check", "GET /express/users/:userId/documents/:documentId"],
      ["nestjs.authorization.object-without-ownership-check", "GET /nest/users/:userId/documents/:documentId"],
    ]) {
      assert.ok(report.signals.some((signal) => signal.ruleId === ruleId && signal.metadata?.route === route), `${route} should remain unsafe when the owner id comes from the route`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Node API analysis accepts an owner predicate propagated from the authenticated subject through local wrappers", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-service-owner-"));
  try {
    await mkdir(join(temporary, "express"));
    await mkdir(join(temporary, "nest"));
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      express: "5.1.0",
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
    } }));
    await writeFile(join(temporary, "express", "app.ts"), `
import express from "express";
import { ExpressDocumentService } from "./document.service";

const app = express();
const service = new ExpressDocumentService();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
app.get("/express/documents/:documentId", requireSession, async (req, res) => {
  const document = await service.loadDocumentForUser(req.params.documentId, req.user.id);
  return res.json(document);
});
`);
    await writeFile(join(temporary, "express", "document.service.ts"), `
import { ExpressDocumentRepository } from "./document.repository";

export class ExpressDocumentService {
  private readonly repository = new ExpressDocumentRepository();

  loadDocumentForUser(documentId: string, authenticatedUserId: string) {
    return this.repository.fetchOwnedDocument(documentId, authenticatedUserId);
  }
}
`);
    await writeFile(join(temporary, "express", "document.repository.ts"), `
export class ExpressDocumentRepository {
  fetchOwnedDocument(documentId: string, authenticatedUserId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, author: { id: authenticatedUserId } } });
  }
}
`);
    await writeFile(join(temporary, "nest", "document.controller.ts"), `
import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { NestDocumentService } from "./document.service";

@Controller("nest/documents")
@UseGuards(AuthGuard("jwt"))
export class NestDocumentController {
  constructor(private readonly service: NestDocumentService) {}

  @Get(":documentId")
  getDocument(@Param("documentId") documentId: string, @Req() request) {
    return this.service.loadDocumentForUser(documentId, request.user.id);
  }
}
`);
    await writeFile(join(temporary, "nest", "document.service.ts"), `
import { Injectable } from "@nestjs/common";
import { NestDocumentRepository } from "./document.repository";

@Injectable()
export class NestDocumentService {
  constructor(private readonly repository: NestDocumentRepository) {}

  loadDocumentForUser(documentId: string, authenticatedUserId: string) {
    return this.repository.fetchOwnedDocument(documentId, authenticatedUserId);
  }
}
`);
    await writeFile(join(temporary, "nest", "document.repository.ts"), `
export class NestDocumentRepository {
  fetchOwnedDocument(documentId: string, authenticatedUserId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, userId: authenticatedUserId } });
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    for (const route of ["GET /express/documents/:documentId", "GET /nest/documents/:documentId"]) {
      assert.ok(report.profile.routes.includes(route));
      assert.ok(!report.signals.some((signal) => /^(?:express|nestjs)\.authorization\./.test(signal.ruleId)
        && signal.metadata?.route === route), `${route} should accept the authenticated-subject owner predicate`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis follows bound ES-class controller instances through service and repository calls", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-express-class-controller-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
import { DocumentController } from "./document.controller";
import { DocumentRepository } from "./document.repository";
import { DocumentService } from "./document.service";

const app = express();
const controller = new DocumentController(new DocumentService(new DocumentRepository()));
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
app.get(
  "/class-controller/users/:userId/documents/:documentId",
  requireSession,
  controller.readDocument.bind(controller),
);
const readOwnedDocument = controller.readOwnedDocument.bind(controller);
app.get("/class-controller/documents/:documentId", requireSession, readOwnedDocument);
`);
    await writeFile(join(temporary, "document.controller.ts"), `
export class DocumentController {
  constructor(service) {
    this.service = service;
  }

  async readDocument(req, res) {
    const document = await this.service.loadDocument(req.params.documentId, req.params.userId);
    return res.json(document);
  }

  async readOwnedDocument(req, res) {
    const document = await this.service.loadOwnedDocument(req.params.documentId, req.user.id);
    return res.json(document);
  }
}
`);
    await writeFile(join(temporary, "document.service.ts"), `
export class DocumentService {
  constructor(repository) {
    this.repository = repository;
  }

  loadDocument(documentId: string, userId: string) {
    return this.repository.fetchDocument(documentId, userId);
  }

  loadOwnedDocument(documentId: string, authenticatedUserId: string) {
    return this.repository.fetchDocument(documentId, authenticatedUserId);
  }
}
`);
    await writeFile(join(temporary, "document.repository.ts"), `
export class DocumentRepository {
  fetchDocument(documentId: string, userId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, userId } });
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const vulnerableRoute = "GET /class-controller/users/:userId/documents/:documentId";
    const safeRoute = "GET /class-controller/documents/:documentId";
    assert.ok(report.profile.routes.includes(vulnerableRoute));
    assert.ok(report.profile.routes.includes(safeRoute));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
      && signal.metadata?.route === vulnerableRoute));
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("express.authorization.")
      && signal.metadata?.route === safeRoute));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.doesNotMatch(coverage?.reason ?? "", /handler reference/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis follows local token providers through useClass, useFactory and useExisting", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-nest-token-provider-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
    } }));
    await writeFile(join(temporary, "tokens.ts"), `
export const DOCUMENT_SERVICE = Symbol("DOCUMENT_SERVICE");
export const DOCUMENT_REPOSITORY = Symbol("DOCUMENT_REPOSITORY");
export const DOCUMENT_REPOSITORY_FACTORY = Symbol("DOCUMENT_REPOSITORY_FACTORY");
`);
    await writeFile(join(temporary, "document.controller.ts"), `
import { Controller, Get, Inject, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { DOCUMENT_SERVICE } from "./tokens";

interface DocumentPort {
  loadDocument(documentId: string, userId: string): unknown;
  loadOwnedDocument(documentId: string, userId: string): unknown;
}

@Controller("token-provider")
@UseGuards(AuthGuard("jwt"))
export class DocumentController {
  constructor(@Inject(DOCUMENT_SERVICE) private readonly service: DocumentPort) {}

  @Get("users/:userId/documents/:documentId")
  readDocument(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.loadDocument(documentId, userId);
  }

  @Get("documents/:documentId")
  readOwnedDocument(@Param("documentId") documentId: string, @Req() request) {
    return this.service.loadOwnedDocument(documentId, request.user.id);
  }
}
`);
    await writeFile(join(temporary, "document.service.ts"), `
import { Inject, Injectable } from "@nestjs/common";
import { DOCUMENT_REPOSITORY } from "./tokens";

interface DocumentRepositoryPort {
  fetchDocument(documentId: string, userId: string): unknown;
}

@Injectable()
export class DocumentService {
  @Inject(DOCUMENT_REPOSITORY)
  private readonly repository: DocumentRepositoryPort;

  loadDocument(documentId: string, userId: string) {
    return this.repository.fetchDocument(documentId, userId);
  }

  loadOwnedDocument(documentId: string, authenticatedUserId: string) {
    return this.repository.fetchDocument(documentId, authenticatedUserId);
  }
}
`);
    await writeFile(join(temporary, "document.repository.ts"), `
export class DocumentRepository {
  fetchDocument(documentId: string, userId: string) {
    return this.prisma.document.findFirst({ where: { id: documentId, author: { id: userId } } });
  }
}
`);
    await writeFile(join(temporary, "app.module.ts"), `
import { Module } from "@nestjs/common";
import { DocumentController } from "./document.controller";
import { DocumentRepository } from "./document.repository";
import { DocumentService } from "./document.service";
import {
  DOCUMENT_REPOSITORY,
  DOCUMENT_REPOSITORY_FACTORY,
  DOCUMENT_SERVICE,
} from "./tokens";

const createDocumentRepository = () => new DocumentRepository();

@Module({
  controllers: [DocumentController],
  providers: [
    { provide: DOCUMENT_SERVICE, useClass: DocumentService },
    { provide: DOCUMENT_REPOSITORY_FACTORY, useFactory: createDocumentRepository },
    { provide: DOCUMENT_REPOSITORY, useExisting: DOCUMENT_REPOSITORY_FACTORY },
  ],
})
export class AppModule {}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const vulnerableRoute = "GET /token-provider/users/:userId/documents/:documentId";
    const safeRoute = "GET /token-provider/documents/:documentId";
    assert.ok(report.profile.routes.includes(vulnerableRoute));
    assert.ok(report.profile.routes.includes(safeRoute));
    assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check"
      && signal.metadata?.route === vulnerableRoute));
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("nestjs.authorization.")
      && signal.metadata?.route === safeRoute));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.doesNotMatch(coverage?.reason ?? "", /injected provider dependency/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis reports a reachable injected dependency whose dynamic factory cannot be resolved", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-nest-dynamic-provider-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
    } }));
    await writeFile(join(temporary, "documents.controller.ts"), `
import { Controller, Get, Inject, Module, Param, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

const RUNTIME_DOCUMENT_SERVICE = Symbol("RUNTIME_DOCUMENT_SERVICE");
const createRuntimeDocumentService = () => loadRuntimePlugin();

interface RuntimeDocumentService {
  load(documentId: string): unknown;
}

@Controller("dynamic-provider")
@UseGuards(AuthGuard("jwt"))
class DocumentsController {
  constructor(@Inject(RUNTIME_DOCUMENT_SERVICE) private readonly service: RuntimeDocumentService) {}

  @Get(":documentId")
  readDocument(@Param("documentId") documentId: string) {
    return this.service.load(documentId);
  }
}

@Module({
  controllers: [DocumentsController],
  providers: [{
    provide: RUNTIME_DOCUMENT_SERVICE,
    useFactory: createRuntimeDocumentService,
  }],
})
class DocumentsModule {}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const route = "GET /dynamic-provider/:documentId";
    assert.ok(report.profile.routes.includes(route));
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("nestjs.authorization.")
      && signal.metadata?.route === route));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.match(coverage?.reason ?? "", /1 NestJS injected provider dependency could not be statically resolved/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis distinguishes authenticated ORM QueryBuilder ownership from route-controlled and dynamic predicates", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-typeorm-query-builder-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
      knex: "3.1.0",
      typeorm: "0.3.26",
    } }));
    await writeFile(join(temporary, "document.controller.ts"), `
import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { DocumentService } from "./document.service";

@Controller("query-builder")
@UseGuards(AuthGuard("jwt"))
export class DocumentController {
  constructor(private readonly service: DocumentService) {}

  @Get("users/:userId/documents/:documentId")
  readByRouteOwner(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.readByRouteOwner(documentId, userId);
  }

  @Get("documents/:documentId")
  readForActor(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readForActor(documentId, request.user.id);
  }

  @Get("dynamic/:documentId")
  readWithDynamicClause(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readWithDynamicClause(documentId, request.user.id);
  }

  @Get("computed-params/:documentId")
  readWithComputedParams(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readWithComputedParams(documentId, request.user.id);
  }

  @Get("or-clause/:documentId")
  readWithOrClause(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readWithOrClause(documentId, request.user.id);
  }

  @Get("or-method/:documentId")
  readWithOrMethod(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readWithOrMethod(documentId, request.user.id);
  }

  @Get("knex/users/:userId/documents/:documentId")
  readKnexByRouteOwner(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.readKnexByRouteOwner(documentId, userId);
  }

  @Get("knex/documents/:documentId")
  readKnexForActor(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readKnexForActor(documentId, request.user.id);
  }

  @Get("lookup/:documentId")
  readUnscoped(@Param("documentId") documentId: string) {
    return this.service.readUnscoped(documentId);
  }
}
`);
    await writeFile(join(temporary, "document.service.ts"), `
import { Injectable } from "@nestjs/common";
import { DocumentRepository } from "./document.repository";

@Injectable()
export class DocumentService {
  constructor(private readonly repository: DocumentRepository) {}

  readByRouteOwner(documentId: string, userId: string) {
    return this.repository.queryDocument(documentId, userId);
  }

  readForActor(documentId: string, authenticatedUserId: string) {
    return this.repository.queryDocument(documentId, authenticatedUserId);
  }

  readWithDynamicClause(documentId: string, authenticatedUserId: string) {
    return this.repository.queryDocumentDynamically(documentId, authenticatedUserId);
  }

  readWithComputedParams(documentId: string, authenticatedUserId: string) {
    return this.repository.queryDocumentWithComputedParams(documentId, authenticatedUserId);
  }

  readWithOrClause(documentId: string, authenticatedUserId: string) {
    return this.repository.queryDocumentWithOr(documentId, authenticatedUserId);
  }

  readWithOrMethod(documentId: string, authenticatedUserId: string) {
    return this.repository.queryDocumentWithOrMethod(documentId, authenticatedUserId);
  }

  readKnexByRouteOwner(documentId: string, userId: string) {
    return this.repository.queryKnexDocument(documentId, userId);
  }

  readKnexForActor(documentId: string, authenticatedUserId: string) {
    return this.repository.queryKnexDocument(documentId, authenticatedUserId);
  }

  readUnscoped(documentId: string) {
    return this.repository.findUnscoped(documentId);
  }
}
`);
    await writeFile(join(temporary, "document.repository.ts"), `
export class DocumentRepository {
  queryDocument(documentId: string, actorId: string) {
    return this.dataSource
      .createQueryBuilder("document")
      .where("document.id = :documentId", { documentId })
      .andWhere("document.user_id = :actorId", { actorId })
      .getOneOrFail();
  }

  queryDocumentDynamically(documentId: string, actorId: string) {
    const ownerColumn = "user_id";
    return this.dataSource
      .createQueryBuilder("document")
      .where("document.id = :documentId", { documentId })
      .andWhere(\`document.\${ownerColumn} = :actorId\`, { actorId })
      .getOneOrFail();
  }

  queryDocumentWithComputedParams(documentId: string, actorId: string) {
    const parameters = { actorId };
    return this.dataSource
      .createQueryBuilder("document")
      .where("document.id = :documentId", { documentId })
      .andWhere("document.user_id = :actorId", parameters)
      .getOneOrFail();
  }

  queryDocumentWithOr(documentId: string, actorId: string) {
    return this.dataSource
      .createQueryBuilder("document")
      .where("document.id = :documentId", { documentId })
      .andWhere("document.deleted_at IS NULL OR document.user_id = :actorId", { actorId })
      .getOneOrFail();
  }

  queryDocumentWithOrMethod(documentId: string, actorId: string) {
    return this.dataSource
      .createQueryBuilder("document")
      .where("document.id = :documentId", { documentId })
      .andWhere("document.user_id = :actorId", { actorId })
      .orWhere("document.is_public = true")
      .getOneOrFail();
  }

  queryKnexDocument(documentId: string, actorId: string) {
    return this.knex("documents")
      .where("documents.id", documentId)
      .andWhere("documents.user_id", "=", actorId)
      .first();
  }

  findUnscoped(documentId: string) {
    return this.repository.findOneByOrFail({ id: documentId });
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const unsafeRoutes = [
      "GET /query-builder/users/:userId/documents/:documentId",
      "GET /query-builder/dynamic/:documentId",
      "GET /query-builder/computed-params/:documentId",
      "GET /query-builder/or-clause/:documentId",
      "GET /query-builder/or-method/:documentId",
      "GET /query-builder/knex/users/:userId/documents/:documentId",
      "GET /query-builder/lookup/:documentId",
    ];
    for (const route of unsafeRoutes) {
      assert.ok(report.profile.routes.includes(route));
      assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check"
        && signal.metadata?.route === route), `${route} should remain unsafe`);
    }
    for (const safeRoute of [
      "GET /query-builder/documents/:documentId",
      "GET /query-builder/knex/documents/:documentId",
    ]) {
      assert.ok(report.profile.routes.includes(safeRoute));
      assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("nestjs.authorization.")
        && signal.metadata?.route === safeRoute), `${safeRoute} should bind the literal owner predicate to the authenticated subject`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis requires a local boolean ownership policy result to be enforced", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-policy-enforcement-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "document.policy.ts"), `
export class DocumentPolicy {
  canRead(actor: any, document: any) {
    return document.userId === actor.id;
  }

  canAccess(_actor: any, _document: any) {
    return true;
  }
}
`);
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
import { DocumentPolicy } from "./document.policy";

const app = express();
const policy = new DocumentPolicy();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}

app.get("/policy/enforced/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  if (!policy.canRead(req.user, document)) return res.status(403).end();
  return res.json(document);
});

app.get("/policy/ignored/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  void policy.canRead(req.user, document);
  return res.json(document);
});

app.get("/policy/conditional-denial/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  if (!policy.canRead(req.user, document)) {
    if (req.query.strict) return res.status(403).end();
  }
  return res.json(document);
});

app.get("/policy/name-only/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  if (!policy.canAccess(req.user, document)) return res.status(403).end();
  return res.json(document);
});
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const enforcedRoute = "GET /policy/enforced/:documentId";
    const unsafeRoutes = [
      "GET /policy/ignored/:documentId",
      "GET /policy/conditional-denial/:documentId",
      "GET /policy/name-only/:documentId",
    ];
    assert.ok(report.profile.routes.includes(enforcedRoute));
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("express.authorization.")
      && signal.metadata?.route === enforcedRoute), `${enforcedRoute} should accept the directly enforced policy predicate`);
    for (const route of unsafeRoutes) {
      assert.ok(report.profile.routes.includes(route));
      assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
        && signal.metadata?.route === route), `${route} should not accept incomplete policy enforcement`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis keeps Sequelize and Mongoose disjunctions distinct from mandatory owner predicates", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-orm-operators-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
      mongoose: "8.18.0",
      sequelize: "6.37.7",
    } }));
    await writeFile(join(temporary, "document.controller.ts"), `
import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { DocumentService } from "./document.service";

@Controller("orm-operators")
@UseGuards(AuthGuard("jwt"))
export class DocumentController {
  constructor(private readonly service: DocumentService) {}

  @Get("sequelize-or/:documentId")
  readSequelizeOr(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readSequelizeOr(documentId, request.user.id);
  }

  @Get("sequelize-and/:documentId")
  readSequelizeAnd(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readSequelizeAnd(documentId, request.user.id);
  }

  @Get("mongo-or/:documentId")
  readMongoOr(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readMongoOr(documentId, request.user.id);
  }

  @Get("mongo-nor/:documentId")
  readMongoNor(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readMongoNor(documentId, request.user.id);
  }

  @Get("mongoose/:documentId")
  readMongoose(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readMongoose(documentId, request.user.id);
  }

  @Get("mongoose-or/:documentId")
  readMongooseOr(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readMongooseOr(documentId, request.user.id);
  }

  @Get("mongoose/users/:userId/documents/:documentId")
  readMongooseByRouteOwner(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.readMongooseByRouteOwner(documentId, userId);
  }

  @Get("sequelize-pk/:documentId")
  readSequelizePk(@Param("documentId") documentId: string) {
    return this.service.readSequelizePk(documentId);
  }
}
`);
    await writeFile(join(temporary, "document.service.ts"), `
import { Injectable } from "@nestjs/common";
import { DocumentRepository } from "./document.repository";

@Injectable()
export class DocumentService {
  constructor(private readonly repository: DocumentRepository) {}

  readSequelizeOr(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithSequelizeOr(documentId, authenticatedUserId);
  }

  readSequelizeAnd(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithSequelizeAnd(documentId, authenticatedUserId);
  }

  readMongoOr(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithMongoOr(documentId, authenticatedUserId);
  }

  readMongoNor(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithMongoNor(documentId, authenticatedUserId);
  }

  readMongoose(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithMongoose(documentId, authenticatedUserId);
  }

  readMongooseOr(documentId: string, authenticatedUserId: string) {
    return this.repository.findWithMongooseOr(documentId, authenticatedUserId);
  }

  readMongooseByRouteOwner(documentId: string, userId: string) {
    return this.repository.findWithMongoose(documentId, userId);
  }

  readSequelizePk(documentId: string) {
    return this.repository.findWithSequelizePk(documentId);
  }
}
`);
    await writeFile(join(temporary, "document.repository.ts"), `
import { Op } from "sequelize";

export class DocumentRepository {
  findWithSequelizeOr(documentId: string, actorId: string) {
    return this.sequelizeDocument.findOne({
      where: {
        [Op.or]: [
          { id: documentId, ownerId: actorId },
          { id: documentId, isPublic: true },
        ],
      },
    });
  }

  findWithSequelizeAnd(documentId: string, actorId: string) {
    return this.sequelizeDocument.findOne({
      where: {
        id: documentId,
        ownerId: actorId,
        [Op.or]: [
          { state: "published" },
          { state: "draft" },
        ],
      },
    });
  }

  findWithMongoOr(documentId: string, actorId: string) {
    return this.mongoDocuments.findOne({
      _id: documentId,
      $or: [
        { ownerId: actorId },
        { isPublic: true },
      ],
    });
  }

  findWithMongoNor(documentId: string, actorId: string) {
    return this.mongoDocuments.findOne({
      _id: documentId,
      $nor: [
        { ownerId: actorId },
        { state: "archived" },
      ],
    });
  }

  findWithMongoose(documentId: string, actorId: string) {
    return this.mongoDocuments
      .findById(documentId)
      .where("ownerId")
      .equals(actorId)
      .exec();
  }

  findWithMongooseOr(documentId: string, actorId: string) {
    return this.mongoDocuments
      .findById(documentId)
      .or([{ ownerId: actorId }, { isPublic: true }])
      .exec();
  }

  findWithSequelizePk(documentId: string) {
    return this.sequelizeDocument.findByPk(documentId);
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    for (const route of [
      "GET /orm-operators/sequelize-or/:documentId",
      "GET /orm-operators/mongo-or/:documentId",
      "GET /orm-operators/mongo-nor/:documentId",
      "GET /orm-operators/mongoose-or/:documentId",
      "GET /orm-operators/mongoose/users/:userId/documents/:documentId",
      "GET /orm-operators/sequelize-pk/:documentId",
    ]) {
      assert.ok(report.profile.routes.includes(route));
      assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check"
        && signal.metadata?.route === route), `${route} should remain unsafe`);
    }
    for (const route of [
      "GET /orm-operators/sequelize-and/:documentId",
      "GET /orm-operators/mongoose/:documentId",
    ]) {
      assert.ok(report.profile.routes.includes(route));
      assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("nestjs.authorization.")
        && signal.metadata?.route === route), `${route} should require the authenticated owner`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis follows locally inherited repository methods without trusting wrapper names", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-inherited-repository-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: {
      "@nestjs/common": "11.1.6",
      "@nestjs/passport": "11.0.5",
    } }));
    await writeFile(join(temporary, "base.repository.ts"), `
export abstract class OwnedRepository {
  findDocument(documentId: string, ownerId: string) {
    return this.model.findOne({ where: { id: documentId, ownerId } });
  }
}
`);
    await writeFile(join(temporary, "document.repository.ts"), `
import { OwnedRepository } from "./base.repository";

export class DocumentRepository extends OwnedRepository {}
`);
    await writeFile(join(temporary, "document.service.ts"), `
import { Injectable } from "@nestjs/common";
import { DocumentRepository } from "./document.repository";

@Injectable()
export class DocumentService {
  constructor(private readonly repository: DocumentRepository) {}

  readByRouteOwner(documentId: string, userId: string) {
    return this.repository.findDocument(documentId, userId);
  }

  readForActor(documentId: string, authenticatedUserId: string) {
    return this.repository.findDocument(documentId, authenticatedUserId);
  }
}
`);
    await writeFile(join(temporary, "document.controller.ts"), `
import { Controller, Get, Param, Req, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";
import { DocumentService } from "./document.service";

@Controller("inherited-repository")
@UseGuards(AuthGuard("jwt"))
export class DocumentController {
  constructor(private readonly service: DocumentService) {}

  @Get("users/:userId/documents/:documentId")
  readByRouteOwner(@Param("documentId") documentId: string, @Param("userId") userId: string) {
    return this.service.readByRouteOwner(documentId, userId);
  }

  @Get("documents/:documentId")
  readForActor(@Param("documentId") documentId: string, @Req() request: any) {
    return this.service.readForActor(documentId, request.user.id);
  }
}
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const vulnerableRoute = "GET /inherited-repository/users/:userId/documents/:documentId";
    const safeRoute = "GET /inherited-repository/documents/:documentId";
    assert.ok(report.profile.routes.includes(vulnerableRoute));
    assert.ok(report.profile.routes.includes(safeRoute));
    assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.authorization.object-without-ownership-check"
      && signal.metadata?.route === vulnerableRoute));
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("nestjs.authorization.")
      && signal.metadata?.route === safeRoute));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis accepts only directly consumed static local owner-filter helper results", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-filter-helpers-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "filters.ts"), `
export function buildDocumentFilter(documentId: string, ownerId: string) {
  return { id: documentId, ownerId };
}

export function buildOwnerFilter(ownerId: string) {
  return { ownerId };
}

export const buildRelationFilter = (ownerId: string) => ({
  author: { id: ownerId },
});

export function buildOrFilter(documentId: string, ownerId: string) {
  return {
    id: documentId,
    $or: [{ ownerId }, { isPublic: true }],
  };
}

export function buildMandatoryOwnerWithOr(documentId: string, ownerId: string) {
  return {
    id: documentId,
    ownerId,
    $or: [{ state: "draft" }, { state: "published" }],
  };
}

export function buildConditionalFilter(documentId: string, ownerId: string, strict: boolean) {
  if (strict) return { id: documentId, ownerId };
  return { id: documentId };
}

export function buildMutableFilter(documentId: string, ownerId: string) {
  const filter: Record<string, unknown> = { id: documentId };
  filter.ownerId = ownerId;
  return filter;
}

export function buildSpreadFilter(documentId: string, ownerId: string, override: object) {
  return { id: documentId, ownerId, ...override };
}

export class FilterRepository {
  findOwned(documentId: string, ownerId: string) {
    return this.model.findFirst({ where: this.buildClassFilter(documentId, ownerId) });
  }

  private buildClassFilter(documentId: string, ownerId: string) {
    return { id: documentId, ownerId };
  }
}
`);
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
import {
  FilterRepository,
  buildConditionalFilter,
  buildDocumentFilter,
  buildMandatoryOwnerWithOr,
  buildMutableFilter,
  buildOrFilter,
  buildOwnerFilter,
  buildRelationFilter,
  buildSpreadFilter,
} from "./filters";

const app = express();
const repository = new FilterRepository();
const selectedFilter = buildDocumentFilter;

function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}

app.get("/filter-helper/direct/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildDocumentFilter(req.params.documentId, req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/spread/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: { id: req.params.documentId, ...buildOwnerFilter(req.user.id) },
  });
  return res.json(document);
});

app.get("/filter-helper/relation/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: { id: req.params.documentId, ...buildRelationFilter(req.user.id) },
  });
  return res.json(document);
});

app.get("/filter-helper/class/:documentId", requireSession, async (req, res) => {
  const document = await repository.findOwned(req.params.documentId, req.user.id);
  return res.json(document);
});

app.get("/filter-helper/direct-argument/:documentId", requireSession, async (req, res) => {
  const document = await db.documents.findOne(
    buildDocumentFilter(req.params.documentId, req.user.id),
  );
  return res.json(document);
});

app.get("/filter-helper/mandatory-owner-with-or/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildMandatoryOwnerWithOr(req.params.documentId, req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/users/:userId/documents/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildDocumentFilter(req.params.documentId, req.params.userId),
  });
  return res.json(document);
});

app.get("/filter-helper/or/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildOrFilter(req.params.documentId, req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/conditional/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildConditionalFilter(req.params.documentId, req.user.id, req.query.strict === "true"),
  });
  return res.json(document);
});

app.get("/filter-helper/mutable/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildMutableFilter(req.params.documentId, req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/returned-spread/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildSpreadFilter(req.params.documentId, req.user.id, req.query),
  });
  return res.json(document);
});

app.get("/filter-helper/spread-override/users/:userId/documents/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: {
      id: req.params.documentId,
      ...buildOwnerFilter(req.user.id),
      ownerId: req.params.userId,
    },
  });
  return res.json(document);
});

app.get("/filter-helper/where-override/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: buildDocumentFilter(req.params.documentId, req.user.id),
    ...req.query,
  });
  return res.json(document);
});

app.get("/filter-helper/secondary-options/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findByPk(req.params.documentId, {
    where: buildOwnerFilter(req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/response-decoy/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  return res.json({ document, suggestedFilter: buildOwnerFilter(req.user.id) });
});

app.get("/filter-helper/option-decoy/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: { id: req.params.documentId },
    include: buildOwnerFilter(req.user.id),
  });
  return res.json(document);
});

app.get("/filter-helper/computed/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findFirst({
    where: selectedFilter(req.params.documentId, req.user.id),
  });
  return res.json(document);
});
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const safeRoutes = [
      "GET /filter-helper/direct/:documentId",
      "GET /filter-helper/spread/:documentId",
      "GET /filter-helper/relation/:documentId",
      "GET /filter-helper/class/:documentId",
      "GET /filter-helper/direct-argument/:documentId",
      "GET /filter-helper/mandatory-owner-with-or/:documentId",
    ];
    const unsafeRoutes = [
      "GET /filter-helper/users/:userId/documents/:documentId",
      "GET /filter-helper/or/:documentId",
      "GET /filter-helper/conditional/:documentId",
      "GET /filter-helper/mutable/:documentId",
      "GET /filter-helper/returned-spread/:documentId",
      "GET /filter-helper/spread-override/users/:userId/documents/:documentId",
      "GET /filter-helper/where-override/:documentId",
      "GET /filter-helper/secondary-options/:documentId",
      "GET /filter-helper/response-decoy/:documentId",
      "GET /filter-helper/option-decoy/:documentId",
      "GET /filter-helper/computed/:documentId",
    ];
    for (const route of [...safeRoutes, ...unsafeRoutes]) assert.ok(report.profile.routes.includes(route));
    for (const route of safeRoutes) {
      assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("express.authorization.")
        && signal.metadata?.route === route), `${route} should accept the mandatory static helper filter`);
    }
    for (const route of unsafeRoutes) {
      assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
        && signal.metadata?.route === route), `${route} should remain unsafe`);
    }
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Node API analysis does not treat relation-shaped response metadata as an ORM owner predicate", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-response-owner-decoy-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
app.get("/documents/:documentId", requireSession, async (req, res) => {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  return res.json({ document, user: { id: req.user.id } });
});
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
      && signal.metadata?.route === "GET /documents/:documentId"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis expands local configuration-driven routes without losing authorization semantics", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-config-routes-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();

function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}

async function readDocument(req, res) {
  const document = await db.document.findUnique({ where: { id: req.params.documentId } });
  return res.json({ id: document.id, userId: document.userId });
}

async function readOwnedDocument(req, res) {
  const document = await db.document.findFirst({
    where: { id: req.params.documentId, userId: req.user.id },
  });
  return res.json({ id: document.id, userId: document.userId });
}

const vulnerableRoutes = [{
  method: "get",
  path: "/configured/documents/:documentId",
  guard: requireSession,
  handler: readDocument,
}, {
  method: "get",
  path: "/configured/archived-documents/:documentId",
  guard: requireSession,
  handler: readDocument,
}] as const;

const safeRoutes = [{
  method: "get",
  path: "/configured/owned-documents/:documentId",
  guard: requireSession,
  handler: readOwnedDocument,
}] as const;

const method = "get";
const path = "/configured/shorthand-documents/:documentId";
const guard = requireSession;
const handler = readOwnedDocument;
const shorthandRoutes = [{ method, path, guard, handler }] as const;

vulnerableRoutes.forEach((route) => {
  app[route.method](route.path, route.guard, route.handler);
});
safeRoutes.forEach(({ method, path, guard, handler }) => {
  app[method](path, guard, handler);
});
shorthandRoutes.forEach(({ method, path, guard, handler }) => {
  app[method](path, guard, handler);
});
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const vulnerableRoute = "GET /configured/documents/:documentId";
    const secondVulnerableRoute = "GET /configured/archived-documents/:documentId";
    const safeRoute = "GET /configured/owned-documents/:documentId";
    const shorthandRoute = "GET /configured/shorthand-documents/:documentId";
    assert.ok(report.profile.routes.includes(vulnerableRoute));
    assert.ok(report.profile.routes.includes(secondVulnerableRoute));
    assert.ok(report.profile.routes.includes(safeRoute));
    assert.ok(report.profile.routes.includes(shorthandRoute));
    const vulnerableSignals = report.signals.filter((signal) => signal.ruleId === "express.authorization.object-without-ownership-check"
      && [vulnerableRoute, secondVulnerableRoute].includes(String(signal.metadata?.route)));
    assert.deepEqual(vulnerableSignals.map((signal) => signal.metadata?.route).sort(), [secondVulnerableRoute, vulnerableRoute].sort());
    assert.equal(new Set(vulnerableSignals.map((signal) => signal.fingerprint)).size, 2);
    assert.ok(!report.signals.some((signal) => /^(?:express)\.authorization\./.test(signal.ruleId)
      && signal.metadata?.route === safeRoute));
    assert.ok(!report.signals.some((signal) => /^(?:express)\.authorization\./.test(signal.ruleId)
      && signal.metadata?.route === shorthandRoute));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.doesNotMatch(coverage?.reason ?? "", /route registration site/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express analysis reports dynamic registration sites that cannot be statically expanded", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-unresolved-config-routes-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();

function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
async function readDocument(req, res) {
  return res.json(await db.document.findUnique({ where: { id: req.params.documentId } }));
}

const runtimeRoutes = loadRoutesFromEnvironment();
runtimeRoutes.forEach((route) => {
  app[route.method](route.path, route.guard, route.handler);
});
let mutableRoutes = [{
  method: "get",
  path: "/mutable/documents/:documentId",
  guard: requireSession,
  handler: readDocument,
}];
mutableRoutes.forEach((route) => {
  app[route.method](route.path, route.guard, route.handler);
});
app.get(buildDocumentPath(), requireSession, readDocument);
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.deepEqual(report.profile.routes, []);
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("express.")));
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.match(coverage?.reason ?? "", /3 Express route registration site\(s\) could not be statically expanded/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Express configuration-driven route expansion refuses arrays above its static entry limit", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-config-route-limit-"));
  try {
    const routeRecords = Array.from({ length: 129 }, (_, index) => `{
      method: "get",
      path: "/oversized/${index}/:documentId",
      guard: requireSession,
      handler: readDocument,
    }`).join(",\n");
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();
function requireSession(req, res, next) {
  if (!req.user) return res.status(401).end();
  return next();
}
async function readDocument(req, res) {
  return res.json(await db.document.findUnique({ where: { id: req.params.documentId } }));
}
const oversizedRoutes = [${routeRecords}] as const;
oversizedRoutes.forEach((route) => {
  app[route.method](route.path, route.guard, route.handler);
});
`);

    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.deepEqual(report.profile.routes, []);
    const coverage = report.coverage.find((item) => item.domain === "node-api-security");
    assert.match(coverage?.reason ?? "", /1 Express route registration site\(s\) could not be statically expanded/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis does not treat a tenant guard as an administrator role guard", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-tenant-not-admin-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@nestjs/common": "11.1.6", "@nestjs/passport": "11.0.5" } }));
    await writeFile(join(temporary, "admin.controller.ts"), `
import { CanActivate, Controller, ExecutionContext, ForbiddenException, Injectable, Post, UseGuards } from "@nestjs/common";
import { AuthGuard } from "@nestjs/passport";

@Injectable()
class TenantScopeGuard implements CanActivate {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    if (request.user.tenantId !== request.body.tenantId) throw new ForbiddenException();
    return true;
  }
}

@Controller("admin")
export class AdminController {
  @Post("export")
  @UseGuards(AuthGuard("jwt"), TenantScopeGuard)
  exportUsers() { return this.users.findMany(); }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.authorization.privileged-operation-without-role-check"
      && signal.metadata?.route === "POST /admin/export"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis accepts a visible global administrator guard", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-global-admin-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@nestjs/common": "11.1.6", "@nestjs/core": "11.1.6" } }));
    await writeFile(join(temporary, "main.ts"), `
import { ForbiddenException, Injectable } from "@nestjs/common";
@Injectable()
class GlobalAdminGuard {
  canActivate(context) {
    const request = context.switchToHttp().getRequest();
    if (!request.user?.isAdmin) throw new ForbiddenException();
    return true;
  }
}
app.useGlobalGuards(new GlobalAdminGuard());
`);
    await writeFile(join(temporary, "admin.controller.ts"), `
import { Controller, Post } from "@nestjs/common";
@Controller("admin")
export class AdminController {
  @Post("export")
  exportUsers() { return this.users.findMany(); }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(!report.signals.some((signal) => signal.ruleId === "nestjs.authorization.privileged-operation-without-role-check"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("NestJS analysis composes global prefixes and URI versions into reported routes", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-nest-routing-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@nestjs/common": "11.1.6", "@nestjs/core": "11.1.6" } }));
    await writeFile(join(temporary, "main.ts"), `
import { VersioningType } from "@nestjs/common";
async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableVersioning({ type: VersioningType.URI, defaultVersion: "1" });
  app.setGlobalPrefix("api", { exclude: ["health"] });
}
`);
    await writeFile(join(temporary, "reports.controller.ts"), `
import { Controller, Get, VERSION_NEUTRAL, Version } from "@nestjs/common";
@Controller("reports")
export class ReportsController {
  @Get()
  listReports() { return []; }

  @Version("2")
  @Get("export")
  exportReports() { return []; }

  @Version(VERSION_NEUTRAL)
  @Get("callback")
  callback() { return {}; }
}

@Controller()
export class HealthController {
  @Version(VERSION_NEUTRAL)
  @Get("health")
  health() { return { ok: true }; }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.profile.routes.includes("GET /api/v1/reports"));
    assert.ok(report.profile.routes.includes("GET /api/v2/reports/export"));
    assert.ok(report.profile.routes.includes("GET /api/reports/callback"));
    assert.ok(report.profile.routes.includes("GET /health"));
    assert.ok(!report.profile.routes.includes("GET /reports"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Node API analysis ignores disabled route text and unresolved Nest APP_GUARD tokens", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-node-api-disabled-route-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0", "@nestjs/common": "11.1.6" } }));
    await writeFile(join(temporary, "app.ts"), `
import express from "express";
const app = express();
// app.post("/admin/commented", (_req, res) => res.json({ ok: true }));
const disabled = 'app.post("/admin/string", handler)';
app.get("/health", (_req, res) => res.json({ ok: true }));
app.post("/admin/audit", (req, res) => {
  console.log(req.user?.id);
  if (!req.query.format) return res.status(400).json({ error: "format required" });
  return res.json({ ok: true });
});
`);
    await writeFile(join(temporary, "reports.controller.ts"), `
import { Controller, Get } from "@nestjs/common";
const incompleteProvider = { provide: APP_GUARD };
@Controller("admin")
class AdminController {
  @Get("reports")
  reports() { return []; }
}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(!report.profile.routes.some((route) => /commented|string/.test(route)));
    assert.ok(report.signals.some((signal) => signal.ruleId === "express.auth.sensitive-route-without-guard"
      && signal.metadata?.route === "POST /admin/audit"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "nestjs.auth.sensitive-route-without-guard"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("project inspection does not interpret Angular page modules as Next.js API routes", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-angular-pages-api-"));
  try {
    await mkdir(join(temporary, "apps", "client", "src", "app", "pages", "api"), { recursive: true });
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { "@angular/core": "21.2.7" } }));
    await writeFile(join(temporary, "apps", "client", "src", "app", "pages", "api", "api-page.component.ts"), `
export class ApiPageComponent {}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(!report.profile.routes.includes("/api/api-page.component"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Python API dataflow detects URL, file, SQL, and model credential destination flows", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "python-dataflow", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const rules = new Set(report.signals.map((signal) => signal.ruleId));
  assert.ok(rules.has("python.dataflow.ssrf"));
  assert.ok(rules.has("python.dataflow.untrusted-file-path"));
  assert.ok(rules.has("python.dataflow.sql-injection"));
  assert.ok(rules.has("python.dataflow.client-url-with-server-secret"));
});

test("Python API dataflow accepts allowlisted URLs, fixed-root paths, bound SQL, and fixed model origins", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "python-dataflow", "near-miss"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("python.dataflow.")));
});

test("Python API configuration detects CORS, exception, JWT, and published unguarded service risks", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "python-api-config", "positive"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const rules = new Set(report.signals.map((signal) => signal.ruleId));
  assert.ok(rules.has("fastapi.config.wildcard-cors-with-credentials"));
  assert.ok(rules.has("fastapi.config.raw-exception-response"));
  assert.ok(rules.has("jwt.config.committed-signing-secret"));
  assert.ok(rules.has("jwt.config.long-lived-access-token"));
  assert.ok(rules.has("docker.config.unguarded-service-published"));
  assert.doesNotMatch(serializeReport(report, "json"), /aisec-benchmark-signing-secret-value/);
});

test("Python API configuration accepts explicit origins, safe errors, external keys, short tokens, and loopback ports", async () => {
  const { report } = await scanProject(join(fixtures, "corpus", "python-api-config", "near-miss"), {
    profile: "native",
    nativeOnly: true,
    persist: false,
  });
  const configRules = /^(?:fastapi\.config|jwt\.config|docker\.config)\./;
  assert.ok(!report.signals.some((signal) => configRules.test(signal.ruleId)));
});

test("Python API findings correlate published unauthenticated network flows into an attack path", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-python-api-path-"));
  try {
    await mkdir(join(temporary, "docker"), { recursive: true });
    await writeFile(join(temporary, "main.py"), `
import urllib.request
from fastapi import FastAPI

app = FastAPI()

@app.post("/generate")
def generate(payload: dict):
    target_url = payload.get("url")
    return urllib.request.urlopen(target_url)
`);
    await writeFile(join(temporary, "docker", "docker-compose.prod.yml"), `
services:
  algorithm:
    build: ..
    ports:
      - "7010:8000"
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.attackPaths.some((path) => path.title.includes("Published unauthenticated Python service")));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("FastAPI whitelist and object authorization findings correlate only for a shared route family", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-python-bola-path-"));
  try {
    await writeFile(join(temporary, "auth_middleware.py"), `
from fastapi import Request

class AuthMiddleware:
    whitelist_paths = {"/document/detail"}
    whitelist_prefixes = {"/public/"}

    def __init__(self, app):
        self.app = app

    async def dispatch(self, request: Request, call_next):
        authorization = request.headers.get("Authorization")
        if not authorization:
            raise RuntimeError("authentication required")
        return await call_next(request)
`);
    await writeFile(join(temporary, "main.py"), `
from fastapi import Depends, FastAPI
from auth_middleware import AuthMiddleware

app = FastAPI()
app.add_middleware(AuthMiddleware)

@app.post("/document/detail")
def detail(payload: dict, db=Depends(get_db)):
    return db.get(Report, payload.get("report_id"))

@app.post("/document/delete")
def delete(payload: dict, db=Depends(get_db)):
    report = db.get(Report, payload.get("report_id"))
    db.delete(report)
    return {"deleted": True}
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(report.attackPaths.some((path) => path.title.includes("authentication bypass combines")));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Python virtual environments are excluded from source and secret analysis", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-python-venv-"));
  try {
    await mkdir(join(temporary, ".venv", "lib", "python3.13", "site-packages"), { recursive: true });
    await writeFile(join(temporary, "main.py"), "print('application source')\n");
    await writeFile(join(temporary, ".venv", "lib", "python3.13", "site-packages", "fixture.py"), "-----BEGIN PRIVATE KEY-----\n");
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.ok(!report.signals.some((signal) => signal.ruleId === "secret.private-key"));
    assert.ok(report.coverage.find((item) => item.domain === "project-inventory")?.reason?.includes("excluded_directory"));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("findings merge repeated evidence with the same fingerprint", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-finding-dedup-"));
  try {
    await writeFile(join(temporary, "keys.py"), "-----BEGIN PRIVATE KEY-----\nfixture-one\n-----BEGIN PRIVATE KEY-----\nfixture-two\n");
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const signals = report.signals.filter((signal) => signal.ruleId === "secret.private-key");
    const findings = report.findings.filter((finding) => finding.title.includes("Private key"));
    assert.equal(signals.length, 2);
    assert.equal(findings.length, 1);
    assert.deepEqual(new Set(findings[0]?.signalIds), new Set(signals.map((signal) => signal.id)));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("an inferred attack path does not hide a stronger component finding", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-injection-"));
  try {
    await writeFile(join(temporary, "package.json"), '{"dependencies":{"next":"15.0.0"}}');
    await import("node:fs/promises").then(({ mkdir }) => mkdir(join(temporary, "app", "api", "admin"), { recursive: true }));
    await writeFile(join(temporary, "app", "api", "admin", "route.ts"), 'export async function POST(req: any) { const id = req.body.id; return db.query(`select * from users where id = ${id}`); }\n');
    const { report } = await scanProject(temporary, { nativeOnly: true, persist: false });
    assert.ok(report.attackPaths.some((path) => path.evidenceLevel === "inferred"));
    assert.ok(report.findings.some((finding) => finding.evidenceLevel === "static_confirmed" && finding.title.includes("database query")));
    assert.equal(report.decision, "block");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("missing optional engines make a normal predeploy scan incomplete, not clean", async () => {
  const oldPath = process.env.PATH;
  process.env.PATH = "";
  try {
    const { report } = await scanProject(join(fixtures, "safe"), { nativeOnly: false, persist: false });
    assert.equal(report.decision, "incomplete");
    assert.ok(report.coverage.some((item) => item.required && item.status === "not_run"));
  } finally {
    process.env.PATH = oldPath;
  }
});

test("fix contracts retain evidence, constraints and a baseline rescan", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const contract = createFixContract(report, report.findings[0]!.id);
    assert.equal(contract.scanId, report.scanId);
    assert.ok(contract.evidence.length > 0);
    assert.ok(contract.constraints.some((constraint) => constraint.includes("new high or critical")));
    assert.match(contract.rescan.command, new RegExp(report.scanId));
  } finally {
    await fixture.cleanup();
  }
});

test("baseline comparison distinguishes resolved from not rechecked", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report: baseline } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const { report: current } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
    const comparison = compareReports(current, baseline);
    assert.ok(comparison.resolved.length > 0);
    assert.equal(comparison.remaining.length, 0);
  } finally {
    await fixture.cleanup();
  }
});

test("partial coverage cannot close a baseline finding as resolved", async () => {
  const fixture = await materializeVulnerableFixture();
  try {
    const { report: baseline } = await scanProject(fixture.path, { nativeOnly: true, persist: false });
    const { report: current } = await scanProject(join(fixtures, "safe"), { nativeOnly: true, persist: false });
    const typescriptFinding = baseline.findings.find((finding) => finding.signalIds.some((id) => baseline.signals.find((signal) => signal.id === id)?.engine === "aisec-typescript"));
    assert.ok(typescriptFinding);
    const dataflowCoverage = current.coverage.find((item) => item.domain === "js-ts-dataflow");
    assert.ok(dataflowCoverage);
    dataflowCoverage.status = "partial";
    const comparison = compareReports(current, baseline);
    assert.ok(comparison.notRechecked.includes(typescriptFinding.fingerprint));
    assert.ok(!comparison.resolved.includes(typescriptFinding.fingerprint));
  } finally {
    await fixture.cleanup();
  }
});

test("authorization manifests reject production, host drift and excessive requests", () => {
  const valid = {
    schemaVersion: "1.0.0",
    targetBaseUrl: "https://staging.example.test",
    environment: "staging",
    ownedBy: "Example team",
    allowedHosts: ["staging.example.test"],
    dataPrefix: "aisec-fixture",
    maxRequests: 20,
    acknowledgment: "I am authorized to test this target",
  };
  assert.equal(validateAuthorization(valid).environment, "staging");
  assert.throws(() => validateAuthorization({ ...valid, environment: "production" }));
  assert.throws(() => validateAuthorization({ ...valid, allowedHosts: ["other.example.test"] }));
  assert.throws(() => validateAuthorization({ ...valid, maxRequests: 1000 }));
  assert.throws(() => validateAuthorization({ ...valid, targetBaseUrl: "https://127.0.0.1", allowedHosts: ["127.0.0.1"] }));
  assert.throws(() => validateAuthorization({ ...valid, targetBaseUrl: "https://metadata.google.internal", allowedHosts: ["metadata.google.internal"] }));
});

test("expired suppressions do not hide findings", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-fixture-"));
  try {
    await writeFile(join(temporary, "index.ts"), `const key = "${SYNTHETIC_STRIPE_LIVE_KEY}";\n`);
    const initial = await scanProject(temporary, { nativeOnly: true, persist: false });
    const finding = initial.report.findings[0]!;
    await writeFile(join(temporary, ".aisec.yml"), `version: 1\nsuppressions:\n  - fingerprint: ${finding.fingerprint}\n    reason: confirmed synthetic fixture\n    expires: 2000-01-01\n`);
    const rescanned = await scanProject(temporary, { nativeOnly: true, persist: false });
    assert.equal(rescanned.report.findings[0]?.status, "open");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Flutter source rules detect insecure storage, unrestricted WebView and disabled TLS validation", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-flutter-"));
  try {
    await mkdir(join(temporary, "lib"), { recursive: true });
    await writeFile(join(temporary, "pubspec.yaml"), "name: aisec_fixture\ndependencies:\n  flutter:\n    sdk: flutter\n");
    await writeFile(join(temporary, "lib", "main.dart"), `
      prefs.setString('refreshToken', token);
      final controller = WebViewController()..setJavaScriptMode(JavaScriptMode.unrestricted);
      client.badCertificateCallback = (cert, host, port) => true;
    `);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const rules = new Set(report.signals.map((signal) => signal.ruleId));
    assert.ok(rules.has("flutter.sensitive-shared-preferences"));
    assert.ok(rules.has("flutter.webview-unrestricted-javascript"));
    assert.ok(rules.has("flutter.accept-all-certificates"));
    assert.equal(report.decision, "block");
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("mobile source rules ignore cleartext URLs in a server-only project", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-server-http-context-"));
  try {
    await writeFile(join(temporary, "package.json"), JSON.stringify({ dependencies: { express: "5.1.0" } }));
    await writeFile(join(temporary, "server.ts"), `
export const rootUrl = "http://api.internal.test:3000";
`);
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.equal(report.coverage.find((item) => item.domain === "mobile-source-config")?.status, "not_run");
    assert.ok(!report.signals.some((signal) => signal.ruleId.startsWith("mobile.")
      || signal.ruleId.startsWith("react-native.") || signal.ruleId.startsWith("flutter.")));
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("framework-public privileged variables are detected at both definition and client reference", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-client-secret-"));
  try {
    await writeFile(join(temporary, ".env"), "NEXT_PUBLIC_ADMIN_SECRET=fixture-value-only\n");
    await writeFile(join(temporary, "client.ts"), "export const key = process.env.NEXT_PUBLIC_ADMIN_SECRET;\n");
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    const rules = new Set(report.signals.map((signal) => signal.ruleId));
    assert.ok(rules.has("secret.client-public-privileged-variable"));
    assert.ok(rules.has("secret.client-public-privileged-reference"));
    assert.doesNotMatch(serializeReport(report, "json"), /fixture-value-only/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});

test("project inventory skips symlinks and makes incomplete coverage explicit", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-symlink-"));
  const outside = await mkdtemp(join(tmpdir(), "aisec-outside-"));
  try {
    const outsideKey = ["sk", "live", "outsidefixture123456789"].join("_");
    await writeFile(join(outside, "secret.ts"), `const key = "${outsideKey}";\n`);
    await symlink(join(outside, "secret.ts"), join(temporary, "linked.ts"));
    const { report } = await scanProject(temporary, { profile: "native", nativeOnly: true, persist: false });
    assert.equal(report.signals.length, 0);
    const inventory = report.coverage.find((item) => item.domain === "project-inventory");
    assert.equal(inventory?.status, "partial");
    assert.match(inventory?.reason ?? "", /symbolic_link/);
    assert.equal(report.decision, "incomplete");
  } finally {
    await rm(temporary, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("managed engines are digest-pinned and tampering becomes invalid status", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engines-"));
  const oldDataDir = process.env.AISEC_DATA_DIR;
  process.env.AISEC_DATA_DIR = join(temporary, "data");
  const source = join(temporary, "gitleaks-fixture");
  try {
    await writeFile(source, "#!/bin/sh\nprintf 'fixture-engine 1.0\\n'\n");
    await chmod(source, 0o700);
    const digest = sha256(await readFile(source));
    await installManagedEngine("gitleaks", source, digest);
    assert.ok((await resolveEngineCommand("gitleaks"))?.endsWith("/engines/gitleaks"));
    await writeFile(join(temporary, "data", "engines", "gitleaks"), "#!/bin/sh\nprintf 'tampered\\n'\n");
    await chmod(join(temporary, "data", "engines", "gitleaks"), 0o700);
    await assert.rejects(() => resolveEngineCommand("gitleaks"), /integrity check/);
    assert.equal((await engineStatus()).find((item) => item.name === "gitleaks")?.source, "invalid");
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR;
    else process.env.AISEC_DATA_DIR = oldDataDir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("external engine version parsing permits only the verified Beta matrix", () => {
  assert.equal(parseEngineVersion("gitleaks", "gitleaks version 8.30.1"), "8.30.1");
  assert.equal(parseEngineVersion("opengrep", "1.26.0"), "1.26.0");
  assert.equal(parseEngineVersion("trivy", "Version: 0.73.0"), "0.73.0");
  assert.equal(engineCompatibility("gitleaks", "8.30.1").supported, true);
  assert.equal(engineCompatibility("opengrep", "1.25.0").supported, false);
  assert.match(engineCompatibility("trivy", "unknown").reason ?? "", /could not be determined/);
});

test("bundled Opengrep rule IDs are stable across installed config paths", () => {
  assert.equal(
    normalizeOpengrepRuleId("rules.opengrep.aisec.javascript.dynamic-code-execution"),
    "aisec.javascript.dynamic-code-execution",
  );
  assert.equal(normalizeOpengrepRuleId("third-party.rule"), "third-party.rule");
  assert.equal(normalizeOpengrepRuleId("third-party.notaisec.rule"), "third-party.notaisec.rule");
  assert.equal(normalizeOpengrepRuleId(undefined), "opengrep.unknown");
});

test("unverified external engine versions fail closed", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engine-failures-"));
  const project = join(temporary, "project");
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldGitleaks = process.env.AISEC_GITLEAKS_PATH;
  const oldOpengrep = process.env.AISEC_OPENGREP_PATH;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"engine-failure-fixture","private":true}');
    const scripts = {
      gitleaks: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'gitleaks version 8.29.0\\n'; exit 0; fi\nexit 0\n",
      opengrep: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '1.25.0\\n'; exit 0; fi\nexit 0\n",
      trivy: "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Version: 0.72.0\\n'; exit 0; fi\nprintf '{\"Results\":[]}'\nexit 0\n",
    };
    for (const [name, script] of Object.entries(scripts)) {
      const path = join(temporary, name);
      await writeFile(path, script);
      await chmod(path, 0o700);
      process.env[`AISEC_${name.toUpperCase()}_PATH`] = path;
    }
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const { report } = await scanProject(project, { persist: false, timeoutMs: 5_000 });
    const external = report.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine));
    assert.ok(external.every((item) => item.status === "failed"));
    assert.equal(report.decision, "incomplete");
    assert.ok(external.every((item) => /not verified/.test(item.reason ?? "")));
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldGitleaks === undefined) delete process.env.AISEC_GITLEAKS_PATH; else process.env.AISEC_GITLEAKS_PATH = oldGitleaks;
    if (oldOpengrep === undefined) delete process.env.AISEC_OPENGREP_PATH; else process.env.AISEC_OPENGREP_PATH = oldOpengrep;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("every external adapter fails closed on process failure, malformed output and timeout", async (t) => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-engine-faults-"));
  const project = join(temporary, "project");
  const oldPath = process.env.PATH;
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldGitleaks = process.env.AISEC_GITLEAKS_PATH;
  const oldOpengrep = process.env.AISEC_OPENGREP_PATH;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"engine-fault-fixture","private":true}');
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const database = join(process.env.AISEC_DATA_DIR, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString(), DownloadedAt: new Date().toISOString(), NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    process.env.PATH = "";
    const versions = {
      gitleaks: "gitleaks version 8.30.1",
      opengrep: "1.26.0",
      trivy: "Version: 0.73.0",
    } as const;
    for (const mode of ["failure", "malformed", "timeout"] as const) {
      await t.test(mode, async () => {
        for (const name of ["gitleaks", "opengrep", "trivy"] as const) {
          const command = join(temporary, `${name}-${mode}`);
          let behavior = "printf 'engine failed\\n' >&2\nexit 2";
          if (mode === "timeout") behavior = "while :; do :; done";
          if (mode === "malformed" && name === "gitleaks") {
            behavior = "printf 'not-json'\nexit 0";
          } else if (mode === "malformed" && name === "trivy") {
            behavior = "printf '{\"SchemaVersion\":2,\"Results\":\"not-an-array\"}\\n'\nexit 0";
          } else if (mode === "malformed") {
            behavior = "printf '{\"results\":[{\"path\":42}],\"errors\":[]}\\n'\nexit 0";
          }
          await writeFile(command, `#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf '%s\\n' '${versions[name]}'; exit 0; fi\n${behavior}\n`);
          await chmod(command, 0o700);
          process.env[`AISEC_${name.toUpperCase()}_PATH`] = command;
        }
        const { report } = await scanProject(project, { persist: false, timeoutMs: 100 });
        const external = report.coverage.filter((item) => ["gitleaks", "opengrep", "trivy"].includes(item.engine));
        assert.equal(external.length, 3);
        assert.ok(external.every((item) => item.status === "failed"));
        assert.ok(external.every((item) => mode === "failure"
          ? /engine failed/.test(item.reason ?? "")
          : mode === "malformed"
            ? /invalid JSON|unexpected JSON schema/.test(item.reason ?? "")
            : /timed out/.test(item.reason ?? "")));
        assert.equal(report.decision, "incomplete");
      });
    }
  } finally {
    if (oldPath === undefined) delete process.env.PATH; else process.env.PATH = oldPath;
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldGitleaks === undefined) delete process.env.AISEC_GITLEAKS_PATH; else process.env.AISEC_GITLEAKS_PATH = oldGitleaks;
    if (oldOpengrep === undefined) delete process.env.AISEC_OPENGREP_PATH; else process.env.AISEC_OPENGREP_PATH = oldOpengrep;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Trivy accepts its schema-v2 empty report with Results omitted", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-trivy-empty-"));
  const project = join(temporary, "project");
  const command = join(temporary, "trivy");
  const oldPath = process.env.PATH;
  const oldDataDir = process.env.AISEC_DATA_DIR;
  const oldTrivy = process.env.AISEC_TRIVY_PATH;
  try {
    await mkdir(project);
    await writeFile(join(project, "package.json"), '{"name":"trivy-empty-fixture","private":true}');
    process.env.AISEC_DATA_DIR = join(temporary, "data");
    const database = join(process.env.AISEC_DATA_DIR, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    await writeFile(command, "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then printf 'Version: 0.73.0\\n'; exit 0; fi\nprintf '{\"SchemaVersion\":2,\"Trivy\":{\"Version\":\"0.73.0\"}}\\n'\n");
    await chmod(command, 0o700);
    process.env.PATH = "";
    process.env.AISEC_TRIVY_PATH = command;
    const { report } = await scanProject(project, { persist: false });
    const coverage = report.coverage.find((item) => item.engine === "trivy");
    assert.equal(coverage?.status, "complete");
    assert.equal(report.signals.filter((signal) => signal.engine === "trivy").length, 0);
  } finally {
    if (oldPath === undefined) delete process.env.PATH; else process.env.PATH = oldPath;
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    if (oldTrivy === undefined) delete process.env.AISEC_TRIVY_PATH; else process.env.AISEC_TRIVY_PATH = oldTrivy;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("Trivy database readiness distinguishes missing, stale and ready caches", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-trivy-db-"));
  const oldDataDir = process.env.AISEC_DATA_DIR;
  process.env.AISEC_DATA_DIR = temporary;
  try {
    assert.equal((await trivyDatabaseStatus()).state, "missing");
    const database = join(temporary, "trivy-cache", "db");
    await mkdir(database, { recursive: true });
    await writeFile(join(database, "trivy.db"), "");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    assert.equal((await trivyDatabaseStatus()).state, "invalid");
    await writeFile(join(database, "trivy.db"), "fixture database marker");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: "2026-01-01T00:00:00Z", DownloadedAt: "2026-01-01T00:00:00Z", NextUpdate: "2026-01-02T00:00:00Z" }));
    assert.equal((await trivyDatabaseStatus()).state, "stale");
    await writeFile(join(database, "metadata.json"), JSON.stringify({ Version: 2, UpdatedAt: new Date().toISOString(), DownloadedAt: new Date().toISOString(), NextUpdate: new Date(Date.now() + 60_000).toISOString() }));
    assert.equal((await trivyDatabaseStatus()).state, "ready");
  } finally {
    if (oldDataDir === undefined) delete process.env.AISEC_DATA_DIR; else process.env.AISEC_DATA_DIR = oldDataDir;
    await rm(temporary, { recursive: true, force: true });
  }
});

test("authorized local passive verification is bounded and refuses redirect origin drift", async (t) => {
  let mode: "headers" | "redirect" = "headers";
  const server = createServer((_request, response) => {
    if (mode === "redirect") {
      response.writeHead(302, { location: "http://127.0.0.1:9/escaped" });
      response.end();
      return;
    }
    response.writeHead(200, { "set-cookie": "session=fixture; SameSite=Lax" });
    response.end("ok");
  });
  let listening = false;
  try {
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    listening = true;
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "EPERM") {
      t.skip("the execution sandbox forbids local loopback listeners");
      return;
    }
    throw error;
  }
  const address = server.address();
  assert.ok(address && typeof address === "object");
  const temporary = await mkdtemp(join(tmpdir(), "aisec-web-"));
  const manifest = join(temporary, "authorization.yml");
  await writeFile(manifest, `schemaVersion: 1.0.0\ntargetBaseUrl: http://127.0.0.1:${address.port}/\nenvironment: local\nownedBy: AIsec tests\nallowedHosts:\n  - 127.0.0.1\ndataPrefix: aisec-fixture\nmaxRequests: 6\nacknowledgment: I am authorized to test this target\n`);
  try {
    await assert.rejects(() => verifyWeb(manifest, false), /requires --confirm/);
    const report = await verifyWeb(manifest, true);
    assert.equal(report.requestCount, 1);
    assert.ok(report.signals.some((signal) => signal.ruleId === "web.session-cookie-flags"));
    assert.ok(report.signals.some((signal) => signal.ruleId === "web.missing-csp"));
    mode = "redirect";
    await assert.rejects(() => verifyWeb(manifest, true), /changed the explicitly authorized origin/);
  } finally {
    if (listening) {
      server.close();
      await once(server, "close");
    }
    await rm(temporary, { recursive: true, force: true });
  }
});

test("artifact paths require a real ZIP container before any scanner is invoked", async () => {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-artifact-"));
  try {
    const artifact = join(temporary, "fake.apk");
    await writeFile(artifact, "this is not an apk");
    await assert.rejects(() => scanProject(temporary, { artifacts: [artifact], nativeOnly: true, persist: false }), /valid ZIP container signature/);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});
