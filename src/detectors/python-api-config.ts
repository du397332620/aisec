import { basename } from "node:path";
import type { ProjectFile } from "../core/files.js";
import type { ScanContext } from "../core/context.js";
import type { DetectorResult } from "./types.js";
import type { Signal } from "../schema.js";
import { analyzeFastApi } from "../api/fastapi.js";
import { createSignal, makeLocation } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const COMPOSE_FILE = /(?:^|\/)(?:docker-)?compose(?:\.[^/]+)?\.ya?ml$|(?:^|\/)docker-compose(?:\.[^/]+)?\.ya?ml$/i;
const PRODUCTION_FILE = /(?:^|\/)(?:\.config\.prod\.json|[^/]*(?:prod|production)[^/]*\.(?:json|ya?ml|toml))$/i;
const NON_RUNTIME_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|scripts|old-archive)(?:\/|$)|(?:^|\/)(?:debug|test|example)[^/]*\.py$/i;

interface Block {
  offset: number;
  text: string;
}

interface NamedExceptionBlock extends Block {
  variable: string;
}

type ExceptionSerialization = "str" | "repr" | "args" | "interpolation";

interface RawExceptionDisclosure extends Block {
  responseSink: string;
  exceptionSerialization: ExceptionSerialization;
}

function findClosing(text: string, opening: number, openCharacter = "(", closeCharacter = ")"): number {
  let depth = 0;
  let quote = "";
  let escaped = false;
  for (let index = opening; index < text.length; index += 1) {
    const character = text[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "#") {
      const newline = text.indexOf("\n", index);
      if (newline === -1) return -1;
      index = newline;
      continue;
    }
    if (character === openCharacter) depth += 1;
    else if (character === closeCharacter) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function broadExceptionBlocks(block: Block): NamedExceptionBlock[] {
  const result: NamedExceptionBlock[] = [];
  const pattern = /^([ \t]*)except[ \t]+Exception[ \t]+as[ \t]+([A-Za-z_]\w*)[ \t]*:[ \t]*(.*)$/gm;
  for (const match of block.text.matchAll(pattern)) {
    const start = match.index ?? 0;
    const headerIndent = (match[1] ?? "").length;
    const lineEnd = block.text.indexOf("\n", start);
    let end = lineEnd === -1 ? block.text.length : lineEnd;
    const inlineBody = (match[3] ?? "").trim();
    if ((!inlineBody || inlineBody.startsWith("#")) && lineEnd !== -1) {
      let cursor = lineEnd + 1;
      end = cursor;
      while (cursor < block.text.length) {
        const nextLineEnd = block.text.indexOf("\n", cursor);
        const line = block.text.slice(cursor, nextLineEnd === -1 ? block.text.length : nextLineEnd);
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("#") && (line.match(/^[ \t]*/)?.[0].length ?? 0) <= headerIndent) break;
        end = nextLineEnd === -1 ? block.text.length : nextLineEnd + 1;
        if (nextLineEnd === -1) break;
        cursor = nextLineEnd + 1;
      }
    }
    result.push({
      offset: block.offset + start,
      text: block.text.slice(start, end),
      variable: match[2]!,
    });
  }
  return result;
}

function escapedRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function exceptionSerialization(text: string, variable: string): ExceptionSerialization | undefined {
  const escaped = escapedRegExp(variable);
  if (new RegExp(`\\brepr\\s*\\(\\s*${escaped}\\s*\\)`, "i").test(text)) return "repr";
  if (new RegExp(`\\bstr\\s*\\(\\s*${escaped}\\s*\\)`, "i").test(text)) return "str";
  if (new RegExp(`\\b${escaped}\\s*\\.\\s*args\\b`, "i").test(text)) return "args";
  if (new RegExp(`\\{\\s*${escaped}\\s*(?:![ars])?(?:\\s*:[^}]*)?\\}`, "i").test(text)) return "interpolation";
  return undefined;
}

function topLevelValues(text: string): string[] {
  const result: string[] = [];
  let roundDepth = 0;
  let squareDepth = 0;
  let curlyDepth = 0;
  let quote = "";
  let escaped = false;
  let start = 0;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]!;
    if (quote) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = "";
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      continue;
    }
    if (character === "(") roundDepth += 1;
    else if (character === "[") squareDepth += 1;
    else if (character === "{") curlyDepth += 1;
    else if (character === ")") roundDepth = Math.max(0, roundDepth - 1);
    else if (character === "]") squareDepth = Math.max(0, squareDepth - 1);
    else if (character === "}") curlyDepth = Math.max(0, curlyDepth - 1);
    else if (character === "," && roundDepth === 0 && squareDepth === 0 && curlyDepth === 0) {
      result.push(text.slice(start, index));
      start = index + 1;
    }
  }
  result.push(text.slice(start));
  return result;
}

function responseField(text: string, variable: string, openingCharacter: "(" | "{"): { field: string; serialization: ExceptionSerialization } | undefined {
  const opening = text.indexOf(openingCharacter);
  if (opening === -1) return undefined;
  const body = text.slice(opening + 1, -1);
  const pattern = /^\s*(?:\b(content|detail|message|msg)\b|["'](content|detail|message|msg)["'])\s*(?:=|:)\s*([\s\S]*)$/i;
  for (const value of topLevelValues(body)) {
    const match = pattern.exec(value);
    if (!match) continue;
    const field = (match[1] ?? match[2])?.toLowerCase();
    const serialization = exceptionSerialization(match[3] ?? "", variable);
    if (field && serialization) return { field, serialization };
  }
  return undefined;
}

function rawExceptionResponse(block: NamedExceptionBlock): RawExceptionDisclosure | undefined {
  const responseCall = /\b((?:[A-Za-z_]\w*\.)*(?:HTTPException|[A-Za-z_]*JSONResponse|PlainTextResponse|Response))\s*\(/g;
  for (const match of block.text.matchAll(responseCall)) {
    const start = match.index ?? 0;
    const before = block.text.slice(Math.max(0, start - 80), start);
    if (!/(?:^|\n)\s*(?:raise|return)\s*(?:await\s+)?$/.test(before)) continue;
    const opening = block.text.indexOf("(", start);
    const closing = opening === -1 ? -1 : findClosing(block.text, opening);
    if (closing === -1) continue;
    const text = block.text.slice(start, closing + 1);
    const response = responseField(text, block.variable, "(");
    if (response) {
      const constructor = (match[1] ?? "Response").split(".").at(-1) ?? "Response";
      return {
        offset: block.offset + start,
        text,
        responseSink: `${constructor}.${response.field}`,
        exceptionSerialization: response.serialization,
      };
    }
  }

  for (const match of block.text.matchAll(/\breturn\s*\{/g)) {
    const start = match.index ?? 0;
    const opening = block.text.indexOf("{", start);
    const closing = opening === -1 ? -1 : findClosing(block.text, opening, "{", "}");
    if (closing === -1) continue;
    const text = block.text.slice(start, closing + 1);
    const response = responseField(text, block.variable, "{");
    if (response) {
      return {
        offset: block.offset + start,
        text,
        responseSink: `dict.${response.field}`,
        exceptionSerialization: response.serialization,
      };
    }
  }
  return undefined;
}

function callBlocks(file: ProjectFile, pattern: RegExp): Block[] {
  const blocks: Block[] = [];
  for (const match of file.content.matchAll(pattern)) {
    const offset = match.index ?? 0;
    const opening = file.content.indexOf("(", offset);
    const closing = opening === -1 ? -1 : findClosing(file.content, opening);
    if (closing !== -1) blocks.push({ offset, text: file.content.slice(offset, closing + 1) });
  }
  return blocks;
}

function decoratorFunctionBlocks(file: ProjectFile, decorator: RegExp): Block[] {
  const blocks: Block[] = [];
  for (const match of file.content.matchAll(decorator)) {
    const start = match.index ?? 0;
    const tail = file.content.slice(start + match[0].length);
    const definition = /\n(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/.exec(tail);
    if (!definition || definition.index === undefined) continue;
    const definitionStart = start + match[0].length + definition.index + 1;
    const indent = file.content.slice(file.content.lastIndexOf("\n", definitionStart) + 1, definitionStart).match(/^\s*/)?.[0].length ?? 0;
    let end = file.content.length;
    let cursor = file.content.indexOf("\n", definitionStart);
    while (cursor !== -1 && cursor + 1 < file.content.length) {
      const next = cursor + 1;
      const lineEnd = file.content.indexOf("\n", next);
      const line = file.content.slice(next, lineEnd === -1 ? file.content.length : lineEnd);
      if (line.trim() && !line.trimStart().startsWith("#") && (line.match(/^\s*/)?.[0].length ?? 0) <= indent) {
        end = next;
        break;
      }
      cursor = lineEnd;
    }
    blocks.push({ offset: start, text: file.content.slice(start, end) });
  }
  return blocks;
}

function configSignal(input: Omit<Signal, "id" | "fingerprint" | "engine" | "confidence"> & { confidence?: Signal["confidence"] }): Signal {
  return createSignal({ engine: "aisec-python", confidence: input.confidence ?? "high", ...input });
}

function quotedScalar(file: ProjectFile, key: string): { value: string; offset: number; raw: string } | undefined {
  const match = new RegExp(`["']${key}["']\\s*:\\s*["']([^"']+)["']`, "i").exec(file.content);
  if (!match || match.index === undefined) return undefined;
  return { value: match[1]!, offset: match.index, raw: match[0] };
}

function numericScalar(file: ProjectFile, key: string): { value: number; offset: number; raw: string } | undefined {
  const match = new RegExp(`["']${key}["']\\s*:\\s*(\\d+)`, "i").exec(file.content);
  if (!match || match.index === undefined) return undefined;
  return { value: Number(match[1]), offset: match.index, raw: match[0] };
}

function redactedConfigSnippet(key: string, value: string): string {
  return `"${key}": "${value.length > 8 ? `${value.slice(0, 3)}…${value.slice(-3)}` : "[REDACTED]"}"`;
}

function composeServiceBlocks(content: string): Array<{ name: string; offset: number; text: string }> {
  const result: Array<{ name: string; offset: number; text: string }> = [];
  const services = /^services\s*:\s*$/m.exec(content);
  if (!services || services.index === undefined) return result;
  const start = services.index + services[0].length;
  const pattern = /^  ([A-Za-z0-9_.-]+)\s*:\s*$/gm;
  pattern.lastIndex = start;
  const matches = [...content.matchAll(pattern)].filter((match) => (match.index ?? 0) >= start);
  for (let index = 0; index < matches.length; index += 1) {
    const current = matches[index]!;
    const offset = current.index ?? start;
    const end = matches[index + 1]?.index ?? content.length;
    result.push({ name: current[1]!, offset, text: content.slice(offset, end) });
  }
  return result;
}

function publishedPorts(block: string): string[] {
  const portsSection = /\n\s{4}ports\s*:\s*\n([\s\S]*?)(?=\n\s{4}[A-Za-z0-9_.-]+\s*:|$)/m.exec(block)?.[1] ?? "";
  return [...portsSection.matchAll(/^\s*-\s*["']?([^"'#\n]+)["']?/gm)].map((match) => (match[1] ?? "").trim()).filter(Boolean);
}

function bindsAllInterfaces(port: string): boolean {
  const normalized = port.replace(/\s+/g, "");
  if (/^(?:127\.0\.0\.1|\[?::1\]?):/.test(normalized)) return false;
  if (/^0\.0\.0\.0:/.test(normalized)) return true;
  return normalized.split(":").length <= 2;
}

export async function runPythonApiConfig(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const analysis = analyzeFastApi(context.inventory.files);
  const pythonFiles = context.inventory.files.filter((file) => file.relativePath.endsWith(".py") && !NON_RUNTIME_PATH.test(file.relativePath));
  if (!analysis.detected) {
    return {
      signals: [],
      coverage: {
        domain: "python-api-configuration",
        engine: "aisec-python",
        status: "not_run",
        required: false,
        reason: "No FastAPI project detected",
        durationMs: Date.now() - started,
      },
    };
  }

  const signals: Signal[] = [];
  const emitted = new Set<string>();
  let truncated = false;
  const add = (signal: Signal, key: string): void => {
    if (emitted.has(key)) return;
    emitted.add(key);
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) truncated = true;
    else signals.push(signal);
  };

  for (const file of pythonFiles) {
    for (const block of callBlocks(file, /\b[A-Za-z_]\w*\.add_middleware\s*\(\s*CORSMiddleware\b/g)) {
      if (!/\ballow_origins\s*=\s*[\[{(]\s*["']\*["']/i.test(block.text) || !/\ballow_credentials\s*=\s*True\b/.test(block.text)) continue;
      add(configSignal({
        ruleId: "fastapi.config.wildcard-cors-with-credentials",
        title: "FastAPI allows credentialed CORS from a wildcard origin",
        description: "The application combines allow_origins=['*'] with allow_credentials=True. Browser behavior and middleware normalization can be confusing, and this commonly indicates that cross-origin trust boundaries were not designed explicitly.",
        severity: "medium",
        evidenceLevel: "static_confirmed",
        locations: [makeLocation(file.relativePath, file.content, block.offset, block.text)],
        cwe: ["CWE-942"],
        owasp: ["A05:2021", "API8:2023"],
        tags: ["fastapi", "api", "cors", "configuration"],
        remediation: "Declare the exact trusted web origins, methods, and headers. If no browser credential flow is needed, disable credentials and test preflight responses in production.",
      }), `${file.relativePath}:cors`);
    }

    for (const block of decoratorFunctionBlocks(file, /@(?:[A-Za-z_]\w*\.)?exception_handler\s*\(\s*Exception\s*\)/g)) {
      const returnsException = /(?:content|detail|msg|message)\s*[:=][\s\S]{0,160}(?:str\s*\(\s*(?:exc|e|error)\s*\)|\b(?:exc|error)\.args\b)/i.test(block.text);
      if (!returnsException) continue;
      add(configSignal({
        ruleId: "fastapi.config.raw-exception-response",
        title: "FastAPI returns raw internal exception text to clients",
        description: "A catch-all exception handler serializes the exception message into the HTTP response, which may disclose database details, filesystem paths, internal hosts, query text, or implementation state.",
        severity: "medium",
        evidenceLevel: "static_confirmed",
        locations: [makeLocation(file.relativePath, file.content, block.offset, block.text)],
        cwe: ["CWE-209"],
        owasp: ["A05:2021", "API8:2023"],
        tags: ["fastapi", "api", "error-handling", "information-disclosure"],
        remediation: "Log a correlation ID and full exception only on the server. Return a fixed client-safe message with the real 5xx status code.",
      }), `${file.relativePath}:exception`);
    }
  }

  const pythonFilesByPath = new Map(pythonFiles.map((file) => [file.relativePath, file]));
  const routeHandlers = new Map<string, {
    file: ProjectFile;
    handlerName: string;
    handlerSource: string;
    handlerOffset: number;
    routes: Set<string>;
  }>();
  for (const route of analysis.routes) {
    const file = pythonFilesByPath.get(route.sourcePath);
    if (!file) continue;
    const handlerOffset = file.content.indexOf(route.handlerSource);
    if (handlerOffset === -1) continue;
    const handlerKey = `${file.relativePath}\u0000${route.handlerName}\u0000${handlerOffset}`;
    const existing = routeHandlers.get(handlerKey);
    if (existing) existing.routes.add(`${route.method} ${route.path}`);
    else routeHandlers.set(handlerKey, {
      file,
      handlerName: route.handlerName,
      handlerSource: route.handlerSource,
      handlerOffset,
      routes: new Set([`${route.method} ${route.path}`]),
    });
  }

  for (const handler of routeHandlers.values()) {
    const routes = [...handler.routes].sort();
    for (const caught of broadExceptionBlocks({ offset: handler.handlerOffset, text: handler.handlerSource })) {
      const disclosure = rawExceptionResponse(caught);
      if (!disclosure) continue;
      add(configSignal({
        ruleId: "fastapi.config.route-raw-exception-response",
        title: "FastAPI route returns raw catch-all exception text",
        description: `${routes.length === 1 ? routes[0] : `${routes.length} routes handled by ${handler.handlerName}`} ${routes.length === 1 ? "catches" : "catch"} a broad Exception and ${routes.length === 1 ? "serializes" : "serialize"} its text into a client response. Runtime failures may disclose database details, filesystem paths, internal hosts, query text or implementation state.`,
        severity: "medium",
        evidenceLevel: "static_confirmed",
        locations: [makeLocation(handler.file.relativePath, handler.file.content, disclosure.offset, disclosure.text)],
        cwe: ["CWE-209"],
        owasp: ["A05:2021", "API8:2023"],
        tags: ["fastapi", "api", "error-handling", "information-disclosure", "route"],
        remediation: "Log a correlation ID and the full exception only on the server. Return a fixed client-safe message from broad exception handlers.",
        metadata: {
          route: routes[0]!,
          routes,
          handler: handler.handlerName,
          responseSink: disclosure.responseSink,
          exceptionSerialization: disclosure.exceptionSerialization,
          findingGroup: "fastapi-route-raw-exception-response",
        },
      }), `${handler.file.relativePath}:${handler.handlerName}:${disclosure.offset}:route-exception`);
      if (truncated) break;
    }
    if (truncated) break;
  }

  for (const file of context.inventory.files.filter((candidate) => PRODUCTION_FILE.test(candidate.relativePath))) {
    const secret = quotedScalar(file, "secret_key");
    if (secret && secret.value.length >= 16 && !/(?:\$\{|env\(|changeme|example|fixture|placeholder)/i.test(secret.value)) {
      add(configSignal({
        ruleId: "jwt.config.committed-signing-secret",
        title: "JWT signing secret is committed in a production configuration",
        description: "A concrete JWT signing secret is stored in a production-named project file. Anyone who can read the repository or image layer may be able to forge access tokens.",
        severity: "critical",
        evidenceLevel: "static_confirmed",
        locations: [makeLocation(file.relativePath, file.content, secret.offset, redactedConfigSnippet("secret_key", secret.value))],
        cwe: ["CWE-321", "CWE-798"],
        owasp: ["A02:2021", "A07:2021"],
        tags: ["jwt", "secret", "authentication", "configuration"],
        remediation: "Rotate the signing key, remove it from source and image layers, load it from a production secret manager, and use separate keys per environment. Prefer asymmetric signing when multiple services verify tokens.",
        metadata: { config: file.relativePath },
      }), `${file.relativePath}:jwt-secret`);
    }
    const expiry = numericScalar(file, "access_token_expire_minute");
    if (expiry && expiry.value > 1440) {
      add(configSignal({
        ruleId: "jwt.config.long-lived-access-token",
        title: "JWT access token lifetime exceeds one day",
        description: `The configured access-token lifetime is ${expiry.value} minutes. Long-lived bearer tokens greatly extend the impact of theft and make revocation gaps more consequential.`,
        severity: "medium",
        evidenceLevel: "static_confirmed",
        locations: [makeLocation(file.relativePath, file.content, expiry.offset, expiry.raw)],
        cwe: ["CWE-613"],
        owasp: ["A07:2021", "API2:2023"],
        tags: ["jwt", "authentication", "session", "configuration"],
        remediation: "Use short-lived access tokens, rotate refresh tokens, enforce revocation or session version checks, and bind token validation to issuer, audience and token type.",
        metadata: { expiryMinutes: expiry.value, config: file.relativePath },
      }), `${file.relativePath}:jwt-expiry`);
    }
  }

  const unguardedServiceLocations = analysis.routes
    .filter((route) => !route.middlewareProtected && !route.locallyProtected && !/(?:health|ready|live|docs|openapi)/i.test(route.path))
    .map((route) => route.location);
  if (unguardedServiceLocations.length > 0) {
    for (const file of context.inventory.files.filter((candidate) => COMPOSE_FILE.test(candidate.relativePath) && /(?:prod|production)/i.test(basename(candidate.relativePath)))) {
      for (const service of composeServiceBlocks(file.content)) {
        const ports = publishedPorts(service.text).filter(bindsAllInterfaces);
        if (ports.length === 0) continue;
        if (!/(?:algorithm|chat|worker|internal|model|ai|api)/i.test(service.name)) continue;
        add(configSignal({
          ruleId: "docker.config.unguarded-service-published",
          title: "Production compose publishes an API service with unguarded FastAPI routes",
          description: `Service ${service.name} publishes ${ports.join(", ")} on all host interfaces while this project contains non-health FastAPI routes with no visible authentication guard. Network firewalls or a reverse proxy may still restrict access.`,
          severity: "high",
          evidenceLevel: "inferred",
          confidence: "medium",
          locations: [
            makeLocation(file.relativePath, file.content, service.offset, service.text),
            ...unguardedServiceLocations.slice(0, 3),
          ],
          cwe: ["CWE-306", "CWE-668"],
          owasp: ["A05:2021", "A07:2021", "API8:2023"],
          tags: ["docker", "fastapi", "api", "exposure", "authentication"],
          remediation: "Do not publish internal service ports. Use expose/internal networks, or bind to loopback and route through an authenticated gateway. Also require a service identity in the FastAPI application itself.",
          metadata: { service: service.name, publishedPorts: ports },
        }), `${file.relativePath}:${service.name}:published`);
      }
    }
  }

  return {
    signals,
    coverage: {
      domain: "python-api-configuration",
      engine: "aisec-python",
      status: truncated ? "partial" : "complete",
      required: true,
      reason: truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined,
      durationMs: Date.now() - started,
    },
  };
}
