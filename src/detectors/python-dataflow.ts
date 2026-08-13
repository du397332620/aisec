import type { ProjectFile } from "../core/files.js";
import type { ScanContext } from "../core/context.js";
import type { DetectorResult } from "./types.js";
import type { Severity, Signal, SourceLocation } from "../schema.js";
import { analyzeFastApi } from "../api/fastapi.js";
import { createSignal, makeLocation } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

interface Parameter {
  name: string;
  declaration: string;
}

interface PythonCall {
  callee: string;
  arguments: string[];
  offset: number;
  snippet: string;
}

interface PythonFunction {
  id: string;
  name: string;
  className?: string;
  path: string;
  file: ProjectFile;
  start: number;
  end: number;
  source: string;
  parameters: Parameter[];
  calls: PythonCall[];
  aliases: Map<string, string[]>;
  routeRoot: boolean;
}

interface ClassBlock {
  name: string;
  path: string;
  file: ProjectFile;
  start: number;
  end: number;
  source: string;
}

interface LocalFlow {
  tainted: Set<string>;
  dynamicSql: Set<string>;
}

const NON_RUNTIME_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|scripts|old-archive)(?:\/|$)|(?:^|\/)(?:debug|test|example)[^/]*\.py$/i;
const EXTERNAL_PARAMETER = /^(?:_?input|payload|request|req|body|data|params|query|form|attachment|attachments)$/i;
const DEPENDENCY_PARAMETER = /\b(?:Depends|Security)\s*\(|^(?:self|cls|db|session|response|background_tasks|current_user|principal|identity)$/i;
const SANITIZER_CALL = /(?:(?:[A-Za-z_]\w*)\.)*(?:validate_(?:public_|allowed_|safe_)?(?:url|uri|path)|ensure_(?:public|allowed|safe)_(?:url|uri|path)|allowlist_(?:url|uri|host)|resolve_under_root|safe_join|secure_filename|sanitize_filename|safe_name|basename)\s*\(/i;
const DYNAMIC_STRING = /(?:\bf\s*["']|\.format\s*\(|%\s*(?:\(|[A-Za-z_])|(?:["']|\w)\s*\+\s*\w)/i;

function findClosing(text: string, opening: number): number {
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  const openingCharacter = text[opening];
  const closingCharacter = openingCharacter ? pairs[openingCharacter] : undefined;
  if (!openingCharacter || !closingCharacter) return -1;
  const stack: string[] = [];
  let quote = "";
  let triple = false;
  let escaped = false;
  for (let index = opening; index < text.length; index += 1) {
    const character = text[index]!;
    if (quote) {
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (triple) {
        if (text.slice(index, index + 3) === quote.repeat(3)) {
          index += 2;
          quote = "";
          triple = false;
        }
      } else if (character === quote) quote = "";
      continue;
    }
    if (character === "\"" || character === "'") {
      if (text.slice(index, index + 3) === character.repeat(3)) {
        quote = character;
        triple = true;
        index += 2;
      } else quote = character;
      continue;
    }
    if (character === "#") {
      const newline = text.indexOf("\n", index);
      if (newline === -1) return -1;
      index = newline;
      continue;
    }
    if (pairs[character]) stack.push(pairs[character]!);
    else if (character === stack[stack.length - 1]) {
      stack.pop();
      if (stack.length === 0) return index;
    }
  }
  return -1;
}

function splitTopLevel(value: string): string[] {
  const parts: string[] = [];
  let start = 0;
  const stack: string[] = [];
  let quote = "";
  let triple = false;
  let escaped = false;
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (triple && value.slice(index, index + 3) === quote.repeat(3)) {
        index += 2;
        quote = "";
        triple = false;
      } else if (!triple && character === quote) quote = "";
      continue;
    }
    if (character === "\"" || character === "'") {
      if (value.slice(index, index + 3) === character.repeat(3)) {
        quote = character;
        triple = true;
        index += 2;
      } else quote = character;
      continue;
    }
    if (pairs[character]) stack.push(pairs[character]!);
    else if (character === stack[stack.length - 1]) stack.pop();
    else if (character === "," && stack.length === 0) {
      parts.push(value.slice(start, index).trim());
      start = index + 1;
    }
  }
  const tail = value.slice(start).trim();
  if (tail) parts.push(tail);
  return parts;
}

function blockEnd(text: string, start: number, indent: number, headerEnd: number): number {
  let cursor = text.indexOf("\n", headerEnd);
  if (cursor === -1) return text.length;
  while (cursor + 1 < text.length) {
    const next = cursor + 1;
    const end = text.indexOf("\n", next);
    const line = text.slice(next, end === -1 ? text.length : end);
    if (line.trim() && !line.trimStart().startsWith("#")) {
      const lineIndent = line.match(/^\s*/)?.[0].length ?? 0;
      if (lineIndent <= indent) return next;
    }
    if (end === -1) break;
    cursor = end;
  }
  return text.length;
}

function classBlocks(file: ProjectFile): ClassBlock[] {
  const blocks: ClassBlock[] = [];
  const pattern = /^(\s*)class\s+([A-Za-z_]\w*)\b[^\n]*:/gm;
  for (const match of file.content.matchAll(pattern)) {
    const indent = match[1]?.length ?? 0;
    const start = match.index ?? 0;
    const headerEnd = start + match[0].length;
    const end = blockEnd(file.content, start, indent, headerEnd);
    blocks.push({ name: match[2]!, path: file.relativePath, file, start, end, source: file.content.slice(start, end) });
  }
  return blocks;
}

function parseCalls(source: string, sourceStart: number): PythonCall[] {
  const calls: PythonCall[] = [];
  const pattern = /\b([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(/g;
  for (const match of source.matchAll(pattern)) {
    const localOffset = match.index ?? 0;
    const before = source.slice(Math.max(0, localOffset - 12), localOffset);
    if (/(?:def|class)\s+$/.test(before)) continue;
    const opening = localOffset + match[0].lastIndexOf("(");
    const closing = findClosing(source, opening);
    if (closing === -1) continue;
    const lineStart = source.lastIndexOf("\n", localOffset) + 1;
    const lineEnd = source.indexOf("\n", localOffset);
    calls.push({
      callee: match[1]!,
      arguments: splitTopLevel(source.slice(opening + 1, closing)),
      offset: sourceStart + localOffset,
      snippet: source.slice(lineStart, lineEnd === -1 ? source.length : lineEnd),
    });
  }
  return calls;
}

function parseAliases(source: string): Map<string, string[]> {
  const aliases = new Map<string, string[]>();
  const conditional = /^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s+if\b[^\n]+\belse\s+([A-Za-z_]\w*)/gm;
  for (const match of source.matchAll(conditional)) aliases.set(match[1]!, [match[2]!, match[3]!]);
  const direct = /^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*$/gm;
  for (const match of source.matchAll(direct)) if (!aliases.has(match[1]!)) aliases.set(match[1]!, [match[2]!]);
  return aliases;
}

function extractFunctions(file: ProjectFile, classes: ClassBlock[], routeKeys: Set<string>): PythonFunction[] {
  const functions: PythonFunction[] = [];
  const pattern = /^(\s*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
  for (const match of file.content.matchAll(pattern)) {
    const indent = match[1]?.length ?? 0;
    const matchStart = match.index ?? 0;
    const start = matchStart + indent;
    const opening = file.content.indexOf("(", start);
    const closing = opening === -1 ? -1 : findClosing(file.content, opening);
    if (closing === -1) continue;
    const colon = file.content.indexOf(":", closing);
    if (colon === -1) continue;
    const end = blockEnd(file.content, start, indent, colon);
    const source = file.content.slice(start, end);
    const parameters = splitTopLevel(file.content.slice(opening + 1, closing)).flatMap((declaration): Parameter[] => {
      const cleaned = declaration.trim().replace(/^\*{1,2}/, "");
      const name = cleaned.match(/^([A-Za-z_]\w*)/)?.[1];
      return name ? [{ name, declaration }] : [];
    });
    const containing = classes
      .filter((block) => block.start < start && block.end >= end)
      .sort((a, b) => b.start - a.start)[0];
    const name = match[2]!;
    functions.push({
      id: `${file.relativePath}:${start}`,
      name,
      className: containing?.name,
      path: file.relativePath,
      file,
      start,
      end,
      source,
      parameters,
      calls: parseCalls(source, start),
      aliases: parseAliases(source),
      routeRoot: routeKeys.has(`${file.relativePath}\u0000${name}`),
    });
  }
  return functions;
}

function importAliases(files: ProjectFile[]): Map<string, Map<string, string>> {
  const result = new Map<string, Map<string, string>>();
  for (const file of files) {
    const aliases = new Map<string, string>();
    const pattern = /^\s*from\s+[.A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s+import\s+([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?/gm;
    for (const match of file.content.matchAll(pattern)) aliases.set(match[2] ?? match[1]!, match[1]!);
    result.set(file.relativePath, aliases);
  }
  return result;
}

function escaped(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function expressionHasName(expression: string, name: string): boolean {
  return new RegExp(`(?<![A-Za-z0-9_])${escaped(name)}(?![A-Za-z0-9_])`).test(expression);
}

function expressionTainted(expression: string, tainted: Set<string>): boolean {
  for (const name of tainted) if (expressionHasName(expression, name)) return true;
  return false;
}

function localFlow(fn: PythonFunction, inputTaint: Set<string>): LocalFlow {
  const tainted = new Set(inputTaint);
  const dynamicSql = new Set<string>();
  const assignments = [...fn.source.matchAll(/^\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)(?:\s*:[^=\n]+)?\s*=\s*(?!=)([^\n]+)/gm)];
  const loops = [...fn.source.matchAll(/^\s*(?:async\s+)?for\s+([A-Za-z_]\w*)\s+in\s+([^:\n]+)\s*:/gm)];
  for (let pass = 0; pass < 8; pass += 1) {
    let changed = false;
    for (const match of assignments) {
      const target = match[1]!;
      const expression = match[2]!.trim();
      if (SANITIZER_CALL.test(expression)) continue;
      if (expressionTainted(expression, tainted) && !tainted.has(target)) {
        tainted.add(target);
        changed = true;
      }
      const rawSqlString = /\btext\s*\(\s*f?["']\s*(?:select|insert|update|delete|with)\b/i.test(expression)
        || /f["']\s*(?:select|insert|update|delete|with)\b/i.test(expression);
      if (tainted.has(target) && rawSqlString && DYNAMIC_STRING.test(expression)) dynamicSql.add(target);
    }
    for (const match of loops) {
      if (expressionTainted(match[2]!, tainted) && !tainted.has(match[1]!)) {
        tainted.add(match[1]!);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return { tainted, dynamicSql };
}

function baseName(value: string): string {
  return value.split(".").at(-1) ?? value;
}

function keywordArgument(argument: string): { name?: string; expression: string } {
  const match = argument.match(/^\s*([A-Za-z_]\w*)\s*=\s*(?!=)([\s\S]*)$/);
  return match ? { name: match[1], expression: match[2]! } : { expression: argument };
}

function resolveCallNames(
  fn: PythonFunction,
  callee: string,
  imports: Map<string, Map<string, string>>,
): string[] {
  const initial = baseName(callee);
  const local = fn.aliases.get(initial) ?? [initial];
  const fileImports = imports.get(fn.path) ?? new Map<string, string>();
  return [...new Set(local.map((name) => fileImports.get(name) ?? name))];
}

function sourceParameters(fn: PythonFunction): Set<string> {
  const result = new Set<string>();
  const containsRawSqlInterpolation = /\btext\s*\(\s*f?["']\s*(?:select|insert|update|delete|with)\b/i.test(fn.source);
  for (const parameter of fn.parameters) {
    if (DEPENDENCY_PARAMETER.test(parameter.declaration) || DEPENDENCY_PARAMETER.test(parameter.name)) continue;
    if (fn.routeRoot || containsRawSqlInterpolation) result.add(parameter.name);
  }
  return result;
}

function propagateFlows(
  functions: PythonFunction[],
  imports: Map<string, Map<string, string>>,
): { active: Set<string>; input: Map<string, Set<string>>; local: Map<string, LocalFlow> } {
  const byName = new Map<string, PythonFunction[]>();
  for (const fn of functions) byName.set(fn.name, [...(byName.get(fn.name) ?? []), fn]);
  const active = new Set<string>();
  const input = new Map<string, Set<string>>();
  for (const fn of functions) {
    const sources = sourceParameters(fn);
    input.set(fn.id, sources);
    if (sources.size > 0) active.add(fn.id);
  }

  const local = new Map<string, LocalFlow>();
  for (let pass = 0; pass < 14; pass += 1) {
    let changed = false;
    for (const fn of functions) {
      if (!active.has(fn.id)) continue;
      const flow = localFlow(fn, input.get(fn.id) ?? new Set());
      local.set(fn.id, flow);
      for (const call of fn.calls) {
        let targetNames = resolveCallNames(fn, call.callee, imports);
        let callArguments = call.arguments;
        const wrapper = baseName(call.callee);
        if (wrapper === "to_thread" && call.arguments[0]) {
          targetNames = resolveCallNames(fn, call.arguments[0].trim(), imports);
          callArguments = call.arguments.slice(1);
        } else if (wrapper === "run_in_executor" && call.arguments[1]) {
          targetNames = resolveCallNames(fn, call.arguments[1].trim(), imports);
          callArguments = call.arguments.slice(2);
        }
        for (const targetName of targetNames) {
          for (const target of byName.get(targetName) ?? []) {
            if (!active.has(target.id)) {
              active.add(target.id);
              changed = true;
            }
            const targetInput = input.get(target.id) ?? new Set<string>();
            const positionalParameters = target.parameters.filter((parameter) => !/^(?:self|cls)$/.test(parameter.name));
            callArguments.forEach((rawArgument, index) => {
              const argument = keywordArgument(rawArgument);
              if (!expressionTainted(argument.expression, flow.tainted)) return;
              const parameter = argument.name
                ? target.parameters.find((item) => item.name === argument.name)
                : positionalParameters[index];
              if (parameter && !targetInput.has(parameter.name)) {
                targetInput.add(parameter.name);
                changed = true;
              }
            });
            input.set(target.id, targetInput);
          }
        }
      }
    }
    if (!changed) break;
  }
  for (const fn of functions) if (active.has(fn.id)) local.set(fn.id, localFlow(fn, input.get(fn.id) ?? new Set()));
  return { active, input, local };
}

function flowSignal(input: {
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string[];
  owasp: string[];
  tags: string[];
  remediation: string;
  locations: SourceLocation[];
  metadata?: Record<string, string | number | boolean | string[]>;
}): Signal {
  return createSignal({
    engine: "aisec-python",
    evidenceLevel: "static_confirmed",
    confidence: "high",
    ...input,
  });
}

function callLocation(fn: PythonFunction, call: PythonCall): SourceLocation {
  return makeLocation(fn.path, fn.file.content, call.offset, call.snippet);
}

function firstArgument(call: PythonCall): string {
  return keywordArgument(call.arguments[0] ?? "").expression;
}

function networkSink(call: PythonCall): boolean {
  const lower = call.callee.toLowerCase();
  const base = baseName(lower);
  return ["urlopen", "urlretrieve"].includes(base)
    || /(?:^|\.)(?:requests|httpx|aiohttp)\.(?:get|post|put|patch|delete|request|stream)$/.test(lower)
    || /(?:client|session)\.(?:get|post|put|patch|delete|request|stream)$/.test(lower);
}

function fileSink(call: PythonCall, tainted: Set<string>): boolean {
  const lower = call.callee.toLowerCase();
  const base = baseName(lower);
  if (base === "open" || /(?:^|\.)os\.(?:remove|unlink|rename|replace)$/.test(lower)) {
    return expressionTainted(firstArgument(call), tainted);
  }
  if (["read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rename"].includes(base)) {
    const receiver = call.callee.split(".").slice(0, -1).join(".");
    return expressionTainted(receiver, tainted) || expressionTainted(firstArgument(call), tainted);
  }
  return false;
}

function dynamicSqlSink(call: PythonCall, flow: LocalFlow): boolean {
  const base = baseName(call.callee).toLowerCase();
  if (!["text", "execute", "exec", "query", "exec_driver_sql"].includes(base)) return false;
  const argument = firstArgument(call);
  if (!expressionTainted(argument, flow.tainted)) return false;
  const directRawSql = /\btext\s*\(\s*f?["']\s*(?:select|insert|update|delete|with)\b/i.test(argument)
    || /^\s*f["']\s*(?:select|insert|update|delete|with)\b/i.test(argument);
  return (directRawSql && DYNAMIC_STRING.test(argument))
    || [...flow.dynamicSql].some((name) => expressionHasName(argument, name));
}

function storedPathFlow(fn: PythonFunction, flow: LocalFlow): PythonCall | undefined {
  if (!/(?:\bopen\s*\([^\n]*(?:\.url|\.path)|\bos\.(?:remove|unlink)\s*\([^\n]*(?:\.url|\.path))/i.test(fn.source)) return undefined;
  return fn.calls.find((call) => {
    if (!/^[A-Z][A-Za-z0-9_]*$/.test(baseName(call.callee))) return false;
    return call.arguments.some((raw) => {
      const argument = keywordArgument(raw);
      return Boolean(argument.name && /^(?:url|path|file_path|local_path|filename)$/i.test(argument.name)
        && expressionTainted(argument.expression, flow.tainted));
    });
  });
}

function credentialClients(classes: ClassBlock[]): Map<string, { secret: SourceLocation; authorization: SourceLocation }> {
  const result = new Map<string, { secret: SourceLocation; authorization: SourceLocation }>();
  for (const block of classes) {
    const base = /self\.base_url\s*=\s*[^\n]*\bbase_url\b[^\n]*(?:os\.getenv|settings\.|profile\.|config\.)/i.exec(block.source);
    const secret = /self\.api_key\s*=\s*[^\n]*\bapi_key\b[^\n]*(?:os\.getenv|settings\.|profile\.|config\.)/i.exec(block.source);
    const authorization = /["']Authorization["']\s*:\s*f?["'][^\n]*self\.api_key/i.exec(block.source);
    if (!base || !secret || !authorization || !/self\.base_url[\s\S]*(?:urlopen|urlretrieve|requests\.|httpx\.|Request\s*\()/i.test(block.source)) continue;
    result.set(block.name, {
      secret: makeLocation(block.path, block.file.content, block.start + (secret.index ?? 0), secret[0]),
      authorization: makeLocation(block.path, block.file.content, block.start + (authorization.index ?? 0), authorization[0]),
    });
  }
  return result;
}

export async function runPythonDataflow(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const files = context.inventory.files.filter((file) => file.relativePath.endsWith(".py") && !NON_RUNTIME_PATH.test(file.relativePath));
  if (files.length === 0) {
    return {
      signals: [],
      coverage: {
        domain: "python-dataflow",
        engine: "aisec-python",
        status: "not_run",
        required: false,
        reason: "No runtime Python source files detected",
        durationMs: Date.now() - started,
      },
    };
  }

  const fastApi = analyzeFastApi(context.inventory.files);
  const routeKeys = new Set(fastApi.routes.map((route) => `${route.sourcePath}\u0000${route.handlerName}`));
  const classes = files.flatMap(classBlocks);
  const functions = files.flatMap((file) => extractFunctions(file, classes.filter((block) => block.path === file.relativePath), routeKeys));
  const imports = importAliases(files);
  const propagated = propagateFlows(functions, imports);
  const clients = credentialClients(classes);
  const signals: Signal[] = [];
  const emitted = new Set<string>();
  let truncated = false;
  const add = (signal: Signal, key: string): void => {
    if (emitted.has(key)) return;
    emitted.add(key);
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) truncated = true;
    else signals.push(signal);
  };

  for (const fn of functions) {
    if (!propagated.active.has(fn.id) || truncated) continue;
    const flow = propagated.local.get(fn.id);
    if (!flow) continue;
    for (const call of fn.calls) {
      const argument = firstArgument(call);
      if (networkSink(call) && expressionTainted(argument, flow.tainted)) {
        add(flowSignal({
          ruleId: "python.dataflow.ssrf",
          title: "Request-derived URL reaches a Python network client",
          description: `Request-derived data reaches ${call.callee} in ${fn.name} without a recognized URL allowlist or public-address validation boundary.`,
          severity: "high",
          cwe: ["CWE-918"],
          owasp: ["A10:2021", "API7:2023"],
          tags: ["python", "dataflow", "ssrf", "api", "network"],
          remediation: "Allowlist HTTPS hosts and ports, resolve and reject private, loopback, link-local and metadata addresses, disable cross-origin redirects, and revalidate every redirect target.",
          locations: [callLocation(fn, call)],
          metadata: { function: fn.name, sink: call.callee },
        }), `${fn.id}:${call.offset}:ssrf`);
      }
      if (fileSink(call, flow.tainted)) {
        add(flowSignal({
          ruleId: "python.dataflow.untrusted-file-path",
          title: "Request-derived path reaches a server file operation",
          description: `Request-derived data reaches ${call.callee} in ${fn.name} without a recognized fixed-root path resolution or filename sanitization boundary.`,
          severity: "high",
          cwe: ["CWE-22", "CWE-73"],
          owasp: ["A01:2021", "API8:2023"],
          tags: ["python", "dataflow", "path-traversal", "file", "api"],
          remediation: "Ignore client filesystem paths. Generate server-side names, resolve under a fixed root, reject absolute paths and traversal, and verify the canonical target remains inside that root.",
          locations: [callLocation(fn, call)],
          metadata: { function: fn.name, sink: call.callee },
        }), `${fn.id}:${call.offset}:file`);
      }
      if (dynamicSqlSink(call, flow)) {
        add(flowSignal({
          ruleId: "python.dataflow.sql-injection",
          title: "Request-derived data is interpolated into Python SQL",
          description: `Request-derived data reaches dynamic SQL construction at ${call.callee} in ${fn.name}.`,
          severity: "high",
          cwe: ["CWE-89"],
          owasp: ["A03:2021", "API8:2023"],
          tags: ["python", "dataflow", "sql-injection", "database", "api"],
          remediation: "Use bound parameters for values and a strict allowlist for identifiers; never interpolate request-derived text into a SQL string.",
          locations: [callLocation(fn, call)],
          metadata: { function: fn.name, sink: call.callee },
        }), `${fn.id}:${call.offset}:sql`);
      }

      for (const resolved of resolveCallNames(fn, call.callee, imports)) {
        const client = clients.get(resolved);
        if (!client) continue;
        const baseUrl = call.arguments.map(keywordArgument).find((item) => item.name === "base_url");
        if (!baseUrl || !expressionTainted(baseUrl.expression, flow.tainted)) continue;
        add(flowSignal({
          ruleId: "python.dataflow.client-url-with-server-secret",
          title: "Client-controlled model URL can receive a server-side API key",
          description: `${fn.name} passes request-derived base_url into ${resolved}; that client falls back to a server-configured API key and sends it in an Authorization header to the resulting URL. This combines SSRF with credential disclosure.`,
          severity: "critical",
          cwe: ["CWE-918", "CWE-200", "CWE-441"],
          owasp: ["A02:2021", "A10:2021", "API7:2023"],
          tags: ["python", "dataflow", "ssrf", "credential-exfiltration", "llm", "api"],
          remediation: "Do not accept model base URLs from ordinary requests. Select providers from a server-side allowlist and bind each credential to its configured origin; never reuse a server secret for a caller-selected destination.",
          locations: [callLocation(fn, call), client.secret, client.authorization],
          metadata: { function: fn.name, client: resolved },
        }), `${fn.id}:${call.offset}:secret-url`);
      }
    }

    const storedPath = storedPathFlow(fn, flow);
    if (storedPath) {
      add(flowSignal({
        ruleId: "python.dataflow.untrusted-file-path",
        title: "Request-derived path is persisted for a later server file operation",
        description: `${fn.name} stores a request-derived filesystem-like field and also performs file operations through persisted path fields, creating a second-order arbitrary file read, write, or deletion risk.`,
        severity: "high",
        cwe: ["CWE-22", "CWE-73"],
        owasp: ["A01:2021", "API8:2023"],
        tags: ["python", "dataflow", "path-traversal", "file", "second-order"],
        remediation: "Persist only opaque storage identifiers. Derive canonical server paths from those identifiers under a fixed root and reject client-provided absolute or relative filesystem paths.",
        locations: [callLocation(fn, storedPath)],
        metadata: { function: fn.name, sink: baseName(storedPath.callee), secondOrder: true },
      }), `${fn.id}:${storedPath.offset}:stored-file`);
    }
  }

  return {
    signals,
    coverage: {
      domain: "python-dataflow",
      engine: "aisec-python",
      status: "partial",
      required: context.profile.languages.includes("Python") || fastApi.detected,
      reason: [
        "Lexical interprocedural analysis covers explicit Python calls and common wrappers; reflection, framework pipelines, ORM aliases, and runtime URL/path validation require review",
        truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
      ].filter(Boolean).join("; "),
      durationMs: Date.now() - started,
    },
  };
}
