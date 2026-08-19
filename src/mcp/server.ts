import { createInterface } from "node:readline";
import { inspectOnly, scanProject } from "../core/scan.js";
import { loadReport } from "../core/store.js";
import { createFixContract } from "../core/contracts.js";
import { TOOL_VERSION } from "../core/constants.js";

type JsonRpcId = string | number | null;
type JsonRpcRequest = { jsonrpc?: string; id?: JsonRpcId; method?: string; params?: Record<string, unknown> };

const CURRENT_PROTOCOL = "2026-07-28";
const LEGACY_PROTOCOLS = new Set(["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"]);
const SERVER_INFO = { name: "aisec", version: TOOL_VERSION };

function requiredString(args: Record<string, unknown>, name: string): string {
  if (typeof args[name] !== "string" || !args[name].trim()) throw new Error(`${name} must be a non-empty string`);
  return args[name];
}

function optionalBoolean(args: Record<string, unknown>, name: string): boolean {
  if (args[name] === undefined) return false;
  if (typeof args[name] !== "boolean") throw new Error(`${name} must be a boolean`);
  return args[name];
}

function optionalString(args: Record<string, unknown>, name: string): string | undefined {
  if (args[name] === undefined) return undefined;
  if (typeof args[name] !== "string" || !args[name].trim()) throw new Error(`${name} must be a non-empty string`);
  return args[name];
}

function scanId(value: unknown): string {
  const id = String(value ?? "");
  if (!/^scan_[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id)) {
    throw new Error("MCP report references must be AIsec scan ids, not arbitrary file paths");
  }
  return id;
}

const annotations = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false };
const tools = [
  { name: "inspect_project", description: "Inspect a local project stack and attack surface without running external scanners.", annotations, inputSchema: { type: "object", properties: { path: { type: "string" } }, required: ["path"], additionalProperties: false } },
  { name: "run_predeploy_scan", description: "Run a non-persisting local pre-deploy security scan. This never runs project build or install scripts. An optional policy must be an explicit operator-owned file outside the target; its suppressions need a separate explicit confirmation.", annotations, inputSchema: { type: "object", properties: { path: { type: "string" }, artifacts: { type: "array", maxItems: 10, items: { type: "string" } }, nativeOnly: { type: "boolean" }, policy: { type: "string" }, confirmPolicySuppressions: { type: "boolean" } }, required: ["path"], additionalProperties: false } },
  { name: "get_report", description: "Read a previously stored scan report by its AIsec scan id.", annotations, inputSchema: { type: "object", properties: { reference: { type: "string", pattern: "^scan_" } }, required: ["reference"], additionalProperties: false } },
  { name: "create_fix_contract", description: "Create a constrained repair contract for one finding in a stored report.", annotations, inputSchema: { type: "object", properties: { scan: { type: "string", pattern: "^scan_" }, finding: { type: "string" } }, required: ["scan", "finding"], additionalProperties: false } },
  { name: "verify_fix", description: "Rescan a project without persisting output and compare it with a stored baseline scan. Policy baselines require the same explicit operator-owned policy file and separate suppression confirmation when applicable.", annotations, inputSchema: { type: "object", properties: { path: { type: "string" }, baseline: { type: "string", pattern: "^scan_" }, nativeOnly: { type: "boolean" }, policy: { type: "string" }, confirmPolicySuppressions: { type: "boolean" } }, required: ["path", "baseline"], additionalProperties: false } },
];

function success(id: JsonRpcId | undefined, result: unknown): object { return { jsonrpc: "2.0", id, result }; }
function failure(id: JsonRpcId | undefined, code: number, message: string, data?: unknown): object {
  return { jsonrpc: "2.0", id, error: { code, message, ...(data === undefined ? {} : { data }) } };
}
function textContent(value: unknown, modern: boolean): object {
  return {
    ...(modern ? { resultType: "complete" } : {}),
    content: [{ type: "text", text: JSON.stringify(value, null, 2) }],
    structuredContent: value,
    isError: false,
  };
}

function protocolVersion(request: JsonRpcRequest): string | undefined {
  const meta = request.params?._meta;
  if (!meta || typeof meta !== "object") return undefined;
  const value = (meta as Record<string, unknown>)["io.modelcontextprotocol/protocolVersion"];
  return typeof value === "string" ? value : undefined;
}

async function callTool(name: string, args: Record<string, unknown>, modern: boolean): Promise<object> {
  if (name === "inspect_project") return textContent(await inspectOnly(requiredString(args, "path")), modern);
  if (name === "run_predeploy_scan") {
    if (args.artifacts !== undefined && (!Array.isArray(args.artifacts) || args.artifacts.length > 10 || args.artifacts.some((item) => typeof item !== "string" || !item.trim()))) {
      throw new Error("artifacts must be an array of at most 10 non-empty paths");
    }
    return textContent((await scanProject(requiredString(args, "path"), {
      artifacts: (args.artifacts as string[] | undefined) ?? [],
      nativeOnly: optionalBoolean(args, "nativeOnly"),
      policyPath: optionalString(args, "policy"),
      confirmPolicySuppressions: optionalBoolean(args, "confirmPolicySuppressions"),
      persist: false,
    })).report, modern);
  }
  if (name === "get_report") return textContent(await loadReport(scanId(args.reference)), modern);
  if (name === "create_fix_contract") return textContent(createFixContract(await loadReport(scanId(args.scan)), requiredString(args, "finding")), modern);
  if (name === "verify_fix") return textContent((await scanProject(requiredString(args, "path"), {
    nativeOnly: optionalBoolean(args, "nativeOnly"),
    policyPath: optionalString(args, "policy"),
    confirmPolicySuppressions: optionalBoolean(args, "confirmPolicySuppressions"),
    persist: false,
  }, scanId(args.baseline))).report, modern);
  throw new Error(`Unknown tool: ${name}`);
}

export async function runMcpServer(): Promise<void> {
  const input = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of input) {
    if (!line.trim()) continue;
    let request: JsonRpcRequest;
    try {
      request = JSON.parse(line) as JsonRpcRequest;
    } catch {
      process.stdout.write(`${JSON.stringify(failure(null, -32700, "Parse error"))}\n`);
      continue;
    }
    if (request.id === undefined) continue;
    if (request.jsonrpc !== "2.0" || typeof request.method !== "string") {
      process.stdout.write(`${JSON.stringify(failure(request.id, -32600, "Invalid Request"))}\n`);
      continue;
    }
    const requestedProtocol = protocolVersion(request);
    const modern = requestedProtocol === CURRENT_PROTOCOL || request.method === "server/discover";
    if (requestedProtocol && requestedProtocol !== CURRENT_PROTOCOL && !LEGACY_PROTOCOLS.has(requestedProtocol)) {
      process.stdout.write(`${JSON.stringify(failure(request.id, -32022, "Unsupported protocol version", { supported: [CURRENT_PROTOCOL, ...LEGACY_PROTOCOLS], requested: requestedProtocol }))}\n`);
      continue;
    }
    try {
      let response: object;
      if (request.method === "server/discover") {
        response = success(request.id, {
          resultType: "complete",
          supportedVersions: [CURRENT_PROTOCOL],
          capabilities: { tools: {} },
          _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO },
          instructions: "Local, read-only project security inspection. Web verification is deliberately excluded from MCP.",
          ttlMs: 300_000,
          cacheScope: "public",
        });
      } else if (request.method === "initialize") {
        const requested = typeof request.params?.protocolVersion === "string" ? request.params.protocolVersion : "2025-11-25";
        const negotiated = LEGACY_PROTOCOLS.has(requested) ? requested : "2025-11-25";
        response = success(request.id, { protocolVersion: negotiated, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO, instructions: "Local, read-only project security inspection." });
      } else if (request.method === "ping") {
        response = success(request.id, modern ? { resultType: "complete" } : {});
      } else if (request.method === "tools/list") {
        response = success(request.id, modern
          ? { resultType: "complete", tools, ttlMs: 300_000, cacheScope: "public", _meta: { "io.modelcontextprotocol/serverInfo": SERVER_INFO } }
          : { tools });
      } else if (request.method === "tools/call") {
        const name = String(request.params?.name ?? "");
        const args = request.params?.arguments && typeof request.params.arguments === "object" && !Array.isArray(request.params.arguments)
          ? request.params.arguments as Record<string, unknown>
          : {};
        response = success(request.id, await callTool(name, args, modern));
      } else {
        response = failure(request.id, -32601, `Method not found: ${request.method}`);
      }
      process.stdout.write(`${JSON.stringify(response)}\n`);
    } catch (error) {
      process.stdout.write(`${JSON.stringify(failure(request.id, -32602, error instanceof Error ? error.message : String(error)))}\n`);
    }
  }
}
