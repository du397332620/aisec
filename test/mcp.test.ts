import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const here = dirname(fileURLToPath(import.meta.url));

test("MCP stdio server advertises only local read-oriented tools", async () => {
  const cli = join(here, "..", "src", "cli.js");
  const child = spawn(process.execPath, [cli, "mcp"], { stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => { output += chunk; });
  const meta = { "io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": {} };
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "server/discover", params: { _meta: meta } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: { _meta: meta } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 3, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "test", version: "1" } } })}\n`);
  child.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { _meta: meta, name: "get_report", arguments: { reference: "/etc/passwd" } } })}\n`);
  child.stdin.end();
  await once(child, "close");
  const responses = output.trim().split("\n").map((line) => JSON.parse(line));
  assert.deepEqual(responses[0].result.supportedVersions, ["2026-07-28"]);
  assert.equal(responses[0].result._meta["io.modelcontextprotocol/serverInfo"].name, "aisec");
  assert.equal(responses[1].result.resultType, "complete");
  assert.equal(responses[1].result.cacheScope, "public");
  const names = responses[1].result.tools.map((tool: { name: string }) => tool.name);
  assert.deepEqual(names, ["inspect_project", "run_predeploy_scan", "get_report", "create_fix_contract", "verify_fix"]);
  assert.ok(!names.includes("verify_web"));
  assert.ok(responses[1].result.tools.every((tool: { annotations: { readOnlyHint: boolean } }) => tool.annotations.readOnlyHint));
  assert.equal(responses[2].result.protocolVersion, "2025-11-25");
  assert.equal(responses[3].error.code, -32602);
  assert.match(responses[3].error.message, /not arbitrary file paths/);
});
