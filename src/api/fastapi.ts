import { basename } from "node:path";
import type { ProjectFile } from "../core/files.js";
import type { SourceLocation } from "../schema.js";
import { makeLocation, unique } from "../core/utils.js";

export interface FastApiRoute {
  appKey: string;
  method: string;
  path: string;
  sourcePath: string;
  routerKey: string;
  handlerName: string;
  location: SourceLocation;
  responseOwnerFields: string[];
  handlerSource: string;
  locallyProtected: boolean;
  ownershipProtected: boolean;
  privilegeProtected: boolean;
  middlewareProtected: boolean;
  whitelist?: FastApiWhitelist;
}

export interface FastApiWhitelist {
  kind: "exact" | "prefix";
  value: string;
  location: SourceLocation;
}

export interface FastApiAnalysis {
  detected: boolean;
  routes: FastApiRoute[];
  unresolvedIncludes: number;
  authFunctionNames: string[];
  ownershipFunctionNames: string[];
  privilegeFunctionNames: string[];
}

interface ImportTarget {
  module: string;
  symbol?: string;
  importedAsModule?: boolean;
}

interface RouterNode {
  key: string;
  module: string;
  variable: string;
  kind: "app" | "router";
  prefix: string;
  dependencyProtected: boolean;
  dependencyOwnershipProtected: boolean;
  dependencyPrivilegeProtected: boolean;
  middlewareProtected: boolean;
  middlewareUsesWhitelist: boolean;
  sourcePath: string;
}

interface IncludeEdge {
  parentKey: string;
  childExpression: string;
  prefix: string;
  dependencyProtected: boolean;
  dependencyOwnershipProtected: boolean;
  dependencyPrivilegeProtected: boolean;
  module: string;
}

interface LocalRoute {
  routerKey: string;
  method: string;
  path: string;
  sourcePath: string;
  handlerName: string;
  location: SourceLocation;
  responseOwnerFields: string[];
  handlerSource: string;
  handlerProtected: boolean;
  ownershipProtected: boolean;
  privilegeProtected: boolean;
}

interface ParsedFile {
  file: ProjectFile;
  module: string;
  imports: Map<string, ImportTarget[]>;
}

const ROUTE_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head"]);
const NON_RUNTIME_APP_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|scripts|old-archive)(?:\/|$)|(?:^|\/)(?:debug|test|example)[^/]*\.py$/i;

function pythonModule(path: string): string {
  const withoutExtension = path.replace(/\.py$/i, "");
  const normalized = withoutExtension.split("/").join(".");
  return normalized.endsWith(".__init__") ? normalized.slice(0, -".__init__".length) : normalized;
}

function modulePackage(module: string, path: string): string {
  if (basename(path) === "__init__.py") return module;
  const index = module.lastIndexOf(".");
  return index === -1 ? "" : module.slice(0, index);
}

function resolveRelativeModule(currentModule: string, path: string, rawModule: string): string {
  const dots = rawModule.match(/^\.+/)?.[0].length ?? 0;
  if (dots === 0) return rawModule;
  const suffix = rawModule.slice(dots);
  const parts = modulePackage(currentModule, path).split(".").filter(Boolean);
  parts.splice(Math.max(0, parts.length - Math.max(0, dots - 1)));
  if (suffix) parts.push(...suffix.split("."));
  return parts.join(".");
}

function parseImports(file: ProjectFile, module: string): Map<string, ImportTarget[]> {
  const result = new Map<string, ImportTarget[]>();
  const add = (alias: string, target: ImportTarget): void => {
    result.set(alias, [...(result.get(alias) ?? []), target]);
  };
  const fromPattern = /^\s*from\s+([.\w]+)\s+import\s+([^\n#]+)/gm;
  for (const match of file.content.matchAll(fromPattern)) {
    const base = resolveRelativeModule(module, file.relativePath, match[1] ?? "");
    const names = (match[2] ?? "").replace(/[()]/g, "").split(",");
    for (const raw of names) {
      const parsed = raw.trim().match(/^([A-Za-z_]\w*)(?:\s+as\s+([A-Za-z_]\w*))?$/);
      if (!parsed?.[1]) continue;
      const imported = parsed[1];
      const alias = parsed[2] ?? imported;
      add(alias, { module: base, symbol: imported });
      add(alias, { module: [base, imported].filter(Boolean).join("."), importedAsModule: true });
    }
  }
  const importPattern = /^\s*import\s+([\w.]+)(?:\s+as\s+([A-Za-z_]\w*))?/gm;
  for (const match of file.content.matchAll(importPattern)) {
    if (!match[1]) continue;
    const alias = match[2] ?? match[1].split(".")[0]!;
    add(alias, { module: match[1], importedAsModule: true });
  }
  return result;
}

function findClosing(text: string, opening: number, openCharacter = "(", closeCharacter = ")"): number {
  let depth = 0;
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
    if (character === openCharacter) depth += 1;
    else if (character === closeCharacter) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function stringLiteral(value: string): string | undefined {
  const match = value.trim().match(/^(?:[rubf]{0,2})?(["'])([\s\S]*?)\1/i);
  if (!match) return undefined;
  return (match[2] ?? "").replace(/\\([\\"'])/g, "$1");
}

function keywordString(argumentsText: string, name: string): string {
  const match = argumentsText.match(new RegExp(`\\b${name}\\s*=\\s*((?:[rubf]{0,2})?["'][\\s\\S]*?["'])`, "i"));
  return match?.[1] ? stringLiteral(match[1]) ?? "" : "";
}

function normalizePath(value: string): string {
  if (!value) return "";
  const compact = value.replace(/\/{2,}/g, "/");
  return compact.startsWith("/") ? compact : `/${compact}`;
}

function joinPath(...parts: string[]): string {
  const meaningful = parts.filter(Boolean).map((part) => part.replace(/^\/+|\/+$/g, "")).filter(Boolean);
  return normalizePath(meaningful.join("/")) || "/";
}

function stripComments(text: string): string {
  return text.split("\n").map((line) => {
    let quote = "";
    let escaped = false;
    for (let index = 0; index < line.length; index += 1) {
      const character = line[index]!;
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (quote) {
        if (character === quote) quote = "";
      } else if (character === "\"" || character === "'") quote = character;
      else if (character === "#") return line.slice(0, index);
    }
    return line;
  }).join("\n");
}

export function pythonCodeMask(text: string): string {
  let quote = "";
  let triple = false;
  let escaped = false;
  let comment = false;
  const characters = [...text];
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]!;
    const newline = character === "\n" || character === "\r";
    if (comment) {
      if (newline) comment = false;
      else characters[index] = " ";
      continue;
    }
    if (quote) {
      if (triple) {
        if (text.slice(index, index + 3) === quote.repeat(3)) {
          characters[index] = characters[index + 1] = characters[index + 2] = " ";
          index += 2;
          quote = "";
          triple = false;
        } else if (!newline) characters[index] = " ";
        continue;
      }
      if (escaped) {
        escaped = false;
        if (!newline) characters[index] = " ";
        continue;
      }
      if (character === "\\") {
        escaped = true;
        characters[index] = " ";
        continue;
      }
      if (character === quote) quote = "";
      characters[index] = " ";
      continue;
    }
    if (character === "#") {
      comment = true;
      characters[index] = " ";
      continue;
    }
    if (character === "\"" || character === "'") {
      quote = character;
      triple = text.slice(index, index + 3) === character.repeat(3);
      characters[index] = " ";
      if (triple) {
        characters[index + 1] = characters[index + 2] = " ";
        index += 2;
      }
    }
  }
  return characters.join("");
}

function executableOffsets(text: string, pattern: RegExp): number[] {
  const mask = pythonCodeMask(text);
  return [...mask.matchAll(pattern)].map((match) => match.index ?? -1).filter((index) => index >= 0);
}

function functionSource(text: string, definitionStart: number): string {
  const lineStart = text.lastIndexOf("\n", definitionStart) + 1;
  const indent = text.slice(lineStart, definitionStart).match(/^\s*/)?.[0].length ?? 0;
  let end = text.length;
  const parametersStart = text.indexOf("(", definitionStart);
  const parametersEnd = parametersStart === -1 ? -1 : findClosing(text, parametersStart);
  let cursor = text.indexOf("\n", parametersEnd >= 0 ? parametersEnd : definitionStart);
  while (cursor !== -1 && cursor + 1 < text.length) {
    const next = cursor + 1;
    const lineEnd = text.indexOf("\n", next);
    const line = text.slice(next, lineEnd === -1 ? text.length : lineEnd);
    if (line.trim() && !line.trimStart().startsWith("#")) {
      const lineIndent = line.match(/^\s*/)?.[0].length ?? 0;
      if (lineIndent <= indent) {
        end = next;
        break;
      }
    }
    cursor = lineEnd;
  }
  return text.slice(definitionStart, end);
}

function discoverAuthFunctions(files: ProjectFile[]): Set<string> {
  const names = new Set([
    "get_current_user", "get_current_user_from_request", "require_auth", "require_admin",
    "verify_token", "verify_session", "authenticate_request",
  ]);
  for (const file of files.filter((candidate) => candidate.relativePath.endsWith(".py"))) {
    const pattern = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
    for (const match of file.content.matchAll(pattern)) {
      const name = match[1]!;
      const source = stripComments(functionSource(file.content, match.index ?? 0));
      const strongName = /(?:auth|current_user|require_.*(?:user|admin|role|permission|access)|verify_(?:token|session))/i.test(name);
      const semantics = /(?:authorization|jwt\.decode|HTTPBearer|status_code\s*=\s*(?:401|403)|HTTP_40[13]_)/i.test(source);
      if (strongName && semantics) names.add(name);
      if (/^_?require_.*(?:access|permission|admin|role)$/i.test(name)) names.add(name);
    }
  }
  return names;
}

function hasAuthGuard(source: string, authNames: Set<string>): boolean {
  const clean = stripComments(source);
  for (const name of authNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:Depends|Security)\\s*\\(\\s*(?:[A-Za-z_]\\w*\\.)*${escaped}\\b`).test(clean)) return true;
    if (new RegExp(`\\b${escaped}\\s*\\(`).test(clean)) return true;
  }
  return false;
}

function discoverOwnershipFunctions(files: ProjectFile[]): Set<string> {
  const names = new Set(["require_admin", "require_object_access", "require_owner"]);
  for (const file of files.filter((candidate) => candidate.relativePath.endsWith(".py"))) {
    const pattern = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
    for (const match of file.content.matchAll(pattern)) {
      const name = match[1]!;
      const source = stripComments(functionSource(file.content, match.index ?? 0));
      const accessName = /(?:require|verify|check|ensure|authorize).*(?:access|owner|permission|admin|role)|(?:access|owner|permission).*(?:check|guard)/i.test(name);
      const accessSemantics = /(?:current_user|owner_id|user_id|tenant_id|creator_id|role|permission|status_code\s*=\s*403|HTTP_403_)/i.test(source);
      if (accessName && accessSemantics) names.add(name);
    }
  }
  return names;
}

function hasOwnershipGuard(source: string, ownershipNames: Set<string>): boolean {
  const clean = stripComments(source);
  for (const name of ownershipNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:Depends|Security)\\s*\\(\\s*(?:[A-Za-z_]\\w*\\.)*${escaped}\\b`).test(clean)) return true;
    if (new RegExp(`\\b${escaped}\\s*\\(`).test(clean)) return true;
  }
  const identity = /\b(?:current_user|authenticated_user|request\.user|principal|identity)\b/i;
  const ownershipField = /\b(?:owner_id|user_id|tenant_id|creator_id|creator|created_by|account_id|organization_id|org_id)\b/i;
  const comparison = /(?:==|!=|\.where\s*\(|\.filter\s*\(|\bjoin\s*\()/;
  if (identity.test(clean) && ownershipField.test(clean) && comparison.test(clean)) return true;
  const roleDenial = /\b(?:current_user|principal|identity)\b[\s\S]{0,240}\b(?:role|user_type|is_admin|permissions?)\b[\s\S]{0,240}(?:status_code\s*=\s*403|HTTP_403_|Forbidden)/i;
  if (roleDenial.test(clean)) return true;
  const selfSubjectAccess = /\b(?:current_user|principal|identity)\s*\.\s*(?:id|username|user_id)\b[\s\S]{0,160}\b(?:get|find|load|count|info|tokens?|sessions?)\w*\s*\(/i;
  return selfSubjectAccess.test(clean);
}

function hasDirectPrivilegeSemantics(source: string, authNames: Set<string> = new Set()): boolean {
  const clean = pythonCodeMask(source);
  const authorityField = String.raw`(?:roles?|permissions?|user_type|is_admin|is_superuser|has_role|has_permission)`;
  const principalAuthority = new RegExp(String.raw`\b(?:current_user|authenticated_user|principal|identity|request\s*\.\s*user)\b\s*\.\s*${authorityField}\b`, "i");
  const authorityCall = /\b(?:has_role|has_permission|check_role|check_permission)\s*\(\s*(?:current_user|authenticated_user|principal|identity|request\s*\.\s*user)\b/i;
  const denial = /(?:HTTPException\s*\(\s*(?:status_code\s*=\s*)?403\b|status_code\s*=\s*(?:403\b|status\s*\.\s*HTTP_403_FORBIDDEN\b)|HTTP_403_FORBIDDEN\b|\bForbidden\b|\bPermissionDenied\b)/i;
  if (!denial.test(clean)) return false;
  if (principalAuthority.test(clean) || authorityCall.test(clean)) return true;
  for (const name of authNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const assignment = new RegExp(String.raw`^\s*([A-Za-z_]\w*)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:[A-Za-z_]\w*\.)*${escaped}\s*\(`, "gm");
    for (const match of clean.matchAll(assignment)) {
      const alias = match[1]?.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      if (alias && new RegExp(String.raw`\b${alias}\b\s*\.\s*${authorityField}\b`, "i").test(clean)) return true;
    }
  }
  return false;
}

function discoverPrivilegeFunctions(files: ProjectFile[], authNames: Set<string>): Set<string> {
  const names = new Set<string>();
  for (const file of files.filter((candidate) => candidate.relativePath.endsWith(".py"))) {
    const pattern = /^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
    for (const match of file.content.matchAll(pattern)) {
      const name = match[1]!;
      if (hasDirectPrivilegeSemantics(functionSource(file.content, match.index ?? 0), authNames)) names.add(name);
    }
  }
  return names;
}

function hasPrivilegeGuard(source: string, privilegeNames: Set<string>, authNames: Set<string>): boolean {
  const clean = pythonCodeMask(source);
  for (const name of privilegeNames) {
    const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`(?:Depends|Security)\\s*\\(\\s*(?:[A-Za-z_]\\w*\\.)*${escaped}\\b`).test(clean)) return true;
    if (new RegExp(`\\b${escaped}\\s*\\(`).test(clean)) return true;
  }
  return hasDirectPrivilegeSemantics(clean, authNames);
}

function parseWhitelists(files: ProjectFile[]): FastApiWhitelist[] {
  const result: FastApiWhitelist[] = [];
  for (const file of files.filter((candidate) => candidate.relativePath.endsWith(".py"))) {
    const assignment = /\b(whitelist_paths|whitelist_prefixes)\s*(?::[^=\n]+)?=\s*([\[{(])/g;
    for (const match of file.content.matchAll(assignment)) {
      const opening = (match.index ?? 0) + match[0].length - 1;
      const open = file.content[opening]!;
      const close = open === "[" ? "]" : open === "{" ? "}" : ")";
      const end = findClosing(file.content, opening, open, close);
      if (end === -1) continue;
      const collection = file.content.slice(opening + 1, end);
      const kind = match[1] === "whitelist_prefixes" ? "prefix" : "exact";
      for (const literal of collection.matchAll(/(["'])(.*?)\1/g)) {
        const value = normalizePath(literal[2] ?? "");
        if (!value) continue;
        const offset = opening + 1 + (literal.index ?? 0);
        result.push({ kind, value, location: makeLocation(file.relativePath, file.content, offset, literal[0]) });
      }
    }
  }
  return result;
}

function whitelistFor(path: string, values: FastApiWhitelist[]): FastApiWhitelist | undefined {
  return values.find((item) => item.kind === "exact" ? path === item.value : path.startsWith(item.value));
}

function resolveRouterExpression(
  expression: string,
  parsed: ParsedFile,
  nodes: Map<string, RouterNode>,
): string | undefined {
  const parts = expression.split(".");
  const first = parts[0];
  if (!first) return undefined;
  if (parts.length === 1) {
    const local = `${parsed.module}:${first}`;
    if (nodes.has(local)) return local;
  }
  for (const target of parsed.imports.get(first) ?? []) {
    const remaining = parts.slice(1);
    const candidates: string[] = [];
    if (target.importedAsModule && remaining.length > 0) candidates.push(`${target.module}:${remaining.join(".")}`);
    if (target.symbol && remaining.length === 0) candidates.push(`${target.module}:${target.symbol}`);
    if (target.symbol && remaining.length > 0) {
      candidates.push(`${target.module}.${target.symbol}:${remaining.join(".")}`);
      candidates.push(`${target.module}:${[target.symbol, ...remaining].join(".")}`);
    }
    for (const candidate of candidates) if (nodes.has(candidate)) return candidate;
  }
  return undefined;
}

function resolveImportedSymbol(
  expression: string,
  parsed: ParsedFile,
): { module: string; symbol: string } | undefined {
  const parts = expression.split(".");
  const first = parts[0];
  if (!first) return undefined;
  if (parts.length === 1) {
    for (const target of parsed.imports.get(first) ?? []) {
      if (target.symbol) return { module: target.module, symbol: target.symbol };
    }
    return { module: parsed.module, symbol: first };
  }
  for (const target of parsed.imports.get(first) ?? []) {
    if (target.importedAsModule) return { module: target.module, symbol: parts.slice(1).join(".") };
    if (target.symbol) return { module: `${target.module}.${target.symbol}`, symbol: parts.slice(1).join(".") };
  }
  return undefined;
}

function classSource(text: string, className: string): string | undefined {
  if (!/^[A-Za-z_]\w*$/.test(className)) return undefined;
  const escaped = className.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`^class\\s+${escaped}\\b`, "m").exec(text);
  if (!match || match.index === undefined) return undefined;
  return functionSource(text, match.index);
}

const RESPONSE_OWNER_FIELD = /^(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id)$/i;

function keywordExpression(argumentsText: string, name: string): string | undefined {
  const match = new RegExp(`\\b${name}\\s*=\\s*`).exec(argumentsText);
  if (!match || match.index === undefined) return undefined;
  const start = match.index + match[0].length;
  let round = 0;
  let square = 0;
  let curly = 0;
  let quote = "";
  let escaped = false;
  for (let index = start; index < argumentsText.length; index += 1) {
    const character = argumentsText[index]!;
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
    if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "{") curly += 1;
    else if (character === "}") curly -= 1;
    else if (character === "," && round === 0 && square === 0 && curly === 0) return argumentsText.slice(start, index).trim();
  }
  return argumentsText.slice(start).trim();
}

function ownerFieldsInClass(source: string | undefined): string[] {
  if (!source) return [];
  const fields = new Set<string>();
  for (const match of source.matchAll(/^\s+([A-Za-z_]\w*)\s*:/gm)) {
    if (match[1] && RESPONSE_OWNER_FIELD.test(match[1])) fields.add(match[1]);
  }
  return [...fields];
}

function responseOwnerFields(
  argumentsText: string,
  handlerSource: string,
  parsed: ParsedFile,
  parsedByModule: Map<string, ParsedFile>,
): string[] {
  const fields = new Set<string>();
  const responses = keywordExpression(argumentsText, "responses") ?? "";
  for (const match of responses.matchAll(/["']([A-Za-z_]\w*)["']\s*:/g)) {
    if (match[1] && RESPONSE_OWNER_FIELD.test(match[1])) fields.add(match[1]);
  }
  for (const match of handlerSource.matchAll(/\breturn\b[^\n]{0,1000}?["']([A-Za-z_]\w*)["']\s*:/g)) {
    if (match[1] && RESPONSE_OWNER_FIELD.test(match[1])) fields.add(match[1]);
  }
  const model = keywordExpression(argumentsText, "response_model");
  if (model) {
    const identifiers = model.match(/[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*/g) ?? [];
    for (const identifier of identifiers) {
      const target = resolveImportedSymbol(identifier, parsed);
      const targetFile = target ? parsedByModule.get(target.module) : undefined;
      const source = target && targetFile ? classSource(targetFile.file.content, target.symbol) : undefined;
      for (const field of ownerFieldsInClass(source)) fields.add(field);
    }
  }
  return [...fields].sort();
}

function routeKey(route: FastApiRoute): string {
  return [route.appKey, route.method, route.path, route.sourcePath, route.handlerName].join("\u0000");
}

export function analyzeFastApi(files: ProjectFile[]): FastApiAnalysis {
  const pythonFiles = files.filter((file) => file.relativePath.endsWith(".py"));
  const detected = files.some((file) => /(?:^|[\s"'])fastapi(?:\b|[=<>])/i.test(file.content))
    || pythonFiles.some((file) => /\bfrom\s+fastapi\s+import\b|\bimport\s+fastapi\b/.test(file.content));
  if (!detected) return {
    detected: false,
    routes: [],
    unresolvedIncludes: 0,
    authFunctionNames: [],
    ownershipFunctionNames: [],
    privilegeFunctionNames: [],
  };

  const authNames = discoverAuthFunctions(pythonFiles);
  const ownershipNames = discoverOwnershipFunctions(pythonFiles);
  const privilegeNames = discoverPrivilegeFunctions(pythonFiles, authNames);
  for (const name of privilegeNames) authNames.add(name);
  const whitelists = parseWhitelists(pythonFiles);
  const parsedFiles = pythonFiles.map((file) => {
    const module = pythonModule(file.relativePath);
    return { file, module, imports: parseImports(file, module) };
  });
  const parsedByModule = new Map(parsedFiles.map((file) => [file.module, file]));
  const nodes = new Map<string, RouterNode>();
  const edges: IncludeEdge[] = [];
  const localRoutes: LocalRoute[] = [];

  for (const parsed of parsedFiles) {
    const text = parsed.file.content;
    const constructors = /\b([A-Za-z_]\w*)\s*=\s*(FastAPI|APIRouter)\s*\(/g;
    const constructorOffsets = new Set(executableOffsets(text, new RegExp(constructors.source, constructors.flags)));
    for (const match of text.matchAll(constructors)) {
      if (!constructorOffsets.has(match.index ?? -1)) continue;
      const opening = (match.index ?? 0) + match[0].length - 1;
      const closing = findClosing(text, opening);
      if (closing === -1) continue;
      const argumentsText = text.slice(opening + 1, closing);
      const variable = match[1]!;
      const key = `${parsed.module}:${variable}`;
      nodes.set(key, {
        key,
        module: parsed.module,
        variable,
        kind: match[2] === "FastAPI" ? "app" : "router",
        prefix: keywordString(argumentsText, "prefix"),
        dependencyProtected: hasAuthGuard(argumentsText, authNames),
        dependencyOwnershipProtected: hasOwnershipGuard(argumentsText, ownershipNames),
        dependencyPrivilegeProtected: hasPrivilegeGuard(argumentsText, privilegeNames, authNames),
        middlewareProtected: false,
        middlewareUsesWhitelist: false,
        sourcePath: parsed.file.relativePath,
      });
    }
  }

  for (const parsed of parsedFiles) {
    const text = parsed.file.content;
    const middleware = /\b([A-Za-z_]\w*)\.add_middleware\s*\(\s*([A-Za-z_.]\w*)/g;
    const middlewareOffsets = new Set(executableOffsets(text, new RegExp(middleware.source, middleware.flags)));
    for (const match of text.matchAll(middleware)) {
      if (!middlewareOffsets.has(match.index ?? -1)) continue;
      const node = nodes.get(`${parsed.module}:${match[1]}`);
      const middlewareExpression = match[2] ?? "";
      if (node?.kind === "app" && /(?:auth|session|identity)/i.test(middlewareExpression)) {
        node.middlewareProtected = true;
        const target = resolveImportedSymbol(middlewareExpression, parsed);
        const targetFile = target ? parsedByModule.get(target.module) : undefined;
        const source = target && targetFile ? classSource(targetFile.file.content, target.symbol) : undefined;
        node.middlewareUsesWhitelist = Boolean(source && /\bwhitelist_(?:paths|prefixes)\b/.test(stripComments(source)));
      }
    }

    const includes = /\b([A-Za-z_]\w*)\.include_router\s*\(/g;
    const includeOffsets = new Set(executableOffsets(text, new RegExp(includes.source, includes.flags)));
    for (const match of text.matchAll(includes)) {
      if (!includeOffsets.has(match.index ?? -1)) continue;
      const opening = (match.index ?? 0) + match[0].length - 1;
      const closing = findClosing(text, opening);
      if (closing === -1) continue;
      const argumentsText = text.slice(opening + 1, closing);
      const childExpression = argumentsText.match(/^\s*([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)/)?.[1];
      if (!childExpression) continue;
      edges.push({
        parentKey: `${parsed.module}:${match[1]}`,
        childExpression,
        prefix: keywordString(argumentsText, "prefix"),
        dependencyProtected: hasAuthGuard(argumentsText, authNames),
        dependencyOwnershipProtected: hasOwnershipGuard(argumentsText, ownershipNames),
        dependencyPrivilegeProtected: hasPrivilegeGuard(argumentsText, privilegeNames, authNames),
        module: parsed.module,
      });
    }

    const decorators = /@([A-Za-z_]\w*)\.(get|post|put|patch|delete|options|head)\s*\(/gi;
    const decoratorOffsets = new Set(executableOffsets(text, new RegExp(decorators.source, decorators.flags)));
    for (const match of text.matchAll(decorators)) {
      if (!decoratorOffsets.has(match.index ?? -1)) continue;
      const method = (match[2] ?? "").toLowerCase();
      if (!ROUTE_METHODS.has(method)) continue;
      const opening = (match.index ?? 0) + match[0].length - 1;
      const closing = findClosing(text, opening);
      if (closing === -1) continue;
      const argumentsText = text.slice(opening + 1, closing);
      const path = stringLiteral(argumentsText);
      if (path === undefined) continue;
      const tail = text.slice(closing + 1);
      const definition = tail.match(/^[\s\S]*?^(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/m);
      if (!definition?.[1] || definition.index === undefined) continue;
      const definitionPrefix = definition[0].search(/^(?:async\s+)?def\s+/m);
      if (definitionPrefix === -1) continue;
      const definitionStart = closing + 1 + definition.index + definitionPrefix;
      const source = functionSource(text, definitionStart);
      const responseFields = responseOwnerFields(argumentsText, source, parsed, parsedByModule);
      localRoutes.push({
        routerKey: `${parsed.module}:${match[1]}`,
        method: method.toUpperCase(),
        path,
        sourcePath: parsed.file.relativePath,
        handlerName: definition[1],
        location: makeLocation(parsed.file.relativePath, text, match.index ?? 0, match[0] + argumentsText.slice(0, 120)),
        responseOwnerFields: responseFields,
        handlerSource: source,
        handlerProtected: hasAuthGuard(`${argumentsText}\n${source}`, authNames),
        ownershipProtected: hasOwnershipGuard(`${argumentsText}\n${source}`, ownershipNames),
        privilegeProtected: hasPrivilegeGuard(`${argumentsText}\n${source}`, privilegeNames, authNames),
      });
    }
  }

  const resolvedEdges = new Map<string, Array<IncludeEdge & { childKey: string }>>();
  let unresolvedIncludes = 0;
  for (const edge of edges) {
    const parent = nodes.get(edge.parentKey);
    const parsed = parsedByModule.get(edge.module);
    if (!parent || !parsed) {
      unresolvedIncludes += 1;
      continue;
    }
    const childKey = resolveRouterExpression(edge.childExpression, parsed, nodes);
    if (!childKey) {
      unresolvedIncludes += 1;
      continue;
    }
    resolvedEdges.set(edge.parentKey, [...(resolvedEdges.get(edge.parentKey) ?? []), { ...edge, childKey }]);
  }

  const routesByRouter = new Map<string, LocalRoute[]>();
  for (const route of localRoutes) routesByRouter.set(route.routerKey, [...(routesByRouter.get(route.routerKey) ?? []), route]);
  const routes: FastApiRoute[] = [];
  const seenTraversal = new Set<string>();
  const visit = (
    app: RouterNode,
    node: RouterNode,
    inheritedPrefix: string,
    dependencyProtected: boolean,
    ownershipProtected: boolean,
    privilegeProtected: boolean,
  ): void => {
    const nodePrefix = joinPath(inheritedPrefix, node.prefix);
    const traversalKey = [app.key, node.key, nodePrefix, dependencyProtected, ownershipProtected, privilegeProtected].join("\u0000");
    if (seenTraversal.has(traversalKey)) return;
    seenTraversal.add(traversalKey);
    const nodeProtected = dependencyProtected || node.dependencyProtected;
    const nodeOwnershipProtected = ownershipProtected || node.dependencyOwnershipProtected;
    const nodePrivilegeProtected = privilegeProtected || node.dependencyPrivilegeProtected;
    for (const route of routesByRouter.get(node.key) ?? []) {
      const path = joinPath(nodePrefix, route.path);
      routes.push({
        appKey: app.key,
        method: route.method,
        path,
        sourcePath: route.sourcePath,
        routerKey: node.key,
        handlerName: route.handlerName,
        location: route.location,
        responseOwnerFields: route.responseOwnerFields,
        handlerSource: route.handlerSource,
        locallyProtected: nodeProtected || route.handlerProtected,
        ownershipProtected: nodeOwnershipProtected || route.ownershipProtected,
        privilegeProtected: nodePrivilegeProtected || route.privilegeProtected,
        middlewareProtected: app.middlewareProtected,
        whitelist: app.middlewareProtected && app.middlewareUsesWhitelist ? whitelistFor(path, whitelists) : undefined,
      });
    }
    for (const edge of resolvedEdges.get(node.key) ?? []) {
      const child = nodes.get(edge.childKey);
      if (child) visit(
        app,
        child,
        joinPath(nodePrefix, edge.prefix),
        nodeProtected || edge.dependencyProtected,
        nodeOwnershipProtected || edge.dependencyOwnershipProtected,
        nodePrivilegeProtected || edge.dependencyPrivilegeProtected,
      );
    }
  };

  for (const app of [...nodes.values()].filter((node) => node.kind === "app" && !NON_RUNTIME_APP_PATH.test(node.sourcePath))) {
    visit(app, app, "", false, false, false);
  }
  const deduplicated = new Map(routes.map((route) => [routeKey(route), route]));
  return {
    detected: true,
    routes: [...deduplicated.values()].sort((a, b) => a.path.localeCompare(b.path) || a.method.localeCompare(b.method)),
    unresolvedIncludes,
    authFunctionNames: unique([...authNames]).sort(),
    ownershipFunctionNames: unique([...ownershipNames]).sort(),
    privilegeFunctionNames: unique([...privilegeNames]).sort(),
  };
}
