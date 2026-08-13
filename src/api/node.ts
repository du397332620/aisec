import { basename, extname } from "node:path";
import ts from "typescript";
import type { ProjectFile } from "../core/files.js";
import type { SourceLocation } from "../schema.js";
import { makeLocation } from "../core/utils.js";

export type NodeApiFramework = "Express" | "NestJS";

export interface NodeApiRoute {
  framework: NodeApiFramework;
  method: string;
  path: string;
  sourcePath: string;
  handlerName: string;
  handlerSource: string;
  location: SourceLocation;
  authenticationProtected: boolean;
  ownershipProtected: boolean;
  objectOperation: boolean;
  objectIdFields: string[];
  responseOwnerFields: string[];
}

export interface NodeApiAnalysis {
  detectedExpress: boolean;
  detectedNest: boolean;
  routes: NodeApiRoute[];
  filesWithParseErrors: number;
  unresolvedHandlers: number;
  unresolvedMounts: number;
}

interface ParsedSource {
  file: ProjectFile;
  source: ts.SourceFile;
  modules: Set<string>;
}

interface ExpressRouteCandidate {
  receiver: string;
  method: string;
  path: string;
  offset: number;
  handlerName: string;
  handler?: ts.FunctionLikeDeclaration;
  handlerSource: string;
  location: SourceLocation;
  locallyAuthenticated: boolean;
}

interface ExpressMiddleware {
  receiver: string;
  offset: number;
  prefix: string;
  authenticated: boolean;
}

interface ExpressMount {
  parent: string;
  child: string;
  offset: number;
  prefix: string;
  authenticated: boolean;
}

const NODE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const NON_RUNTIME_NODE_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|scripts|mocks?|__tests__|old-archive)(?:\/|$)|(?:^|\/)(?:debug|test|example)[^/]*\.(?:[cm]?[jt]sx?)$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);
const OWNER_FIELD = /^(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id|ownerId|userId|tenantId|creatorId|createdBy|accountId|organizationId|orgId)$/;
const AUTH_GUARD_NAME = /(?:^|[._])(?:auth(?:Middleware|Guard)?|authenticate|authenticated|authentication(?:Middleware)?|requireAuth|requireUser|ensureAuthenticated|isAuthenticated|verifyToken|verifySession|jwtAuth(?:Guard)?|jwtGuard|sessionAuth(?:Guard)?|bearerAuth|protect|passport\.authenticate)(?:$|[.(])/i;
const ACCESS_GUARD_NAME = /(?:^|[._])(?:require|verify|check|ensure|authorize|assert|can)[A-Za-z0-9_]*(?:access|owner|ownership|permission|policy|role|admin|tenant)|(?:owner|ownership|permission|policy|ability|role|admin|tenant)[A-Za-z0-9_]*(?:guard|check)(?:$|[.(])/i;
const ID_OPERATION = /(?:^|\.)(?:findById|findByIdAndUpdate|findByIdAndDelete|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne|findMany|getById|getOne|loadById|detail|update|updateOne|updateMany|delete|deleteOne|deleteMany|remove|destroy|where)$/i;

function scriptKind(path: string): ts.ScriptKind {
  const extension = extname(path).toLowerCase();
  if (extension === ".tsx") return ts.ScriptKind.TSX;
  if (extension === ".jsx") return ts.ScriptKind.JSX;
  if ([".js", ".mjs", ".cjs"].includes(extension)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function visit(node: ts.Node, callback: (candidate: ts.Node) => void): void {
  callback(node);
  ts.forEachChild(node, (child) => visit(child, callback));
}

function sourceSnippet(parsed: ParsedSource, node: ts.Node): string {
  const start = node.getStart(parsed.source);
  const line = parsed.source.getLineAndCharacterOfPosition(start).line;
  const lineStart = parsed.source.getLineStarts()[line] ?? start;
  const lineEnd = parsed.source.text.indexOf("\n", lineStart);
  return parsed.source.text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
}

function location(parsed: ParsedSource, node: ts.Node): SourceLocation {
  return makeLocation(parsed.file.relativePath, parsed.source.text, node.getStart(parsed.source), sourceSnippet(parsed, node));
}

function moduleNames(source: ts.SourceFile): Set<string> {
  const result = new Set<string>();
  visit(source, (node) => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) result.add(node.moduleSpecifier.text);
    if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) result.add(node.moduleSpecifier.text);
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "require"
      && node.arguments.length === 1 && ts.isStringLiteral(node.arguments[0]!)) result.add(node.arguments[0].text);
  });
  return result;
}

function packageNames(files: ProjectFile[]): Set<string> {
  const result = new Set<string>();
  for (const file of files.filter((candidate) => basename(candidate.relativePath) === "package.json")) {
    try {
      const manifest = JSON.parse(file.content) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
      for (const name of Object.keys({ ...manifest.dependencies, ...manifest.devDependencies })) result.add(name);
    } catch {
      // Package parsing is best effort; the normal manifest checks report invalid JSON.
    }
  }
  return result;
}

function literalText(node: ts.Expression | undefined): string | undefined {
  return node && (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) ? node.text : undefined;
}

function normalizePath(value: string): string {
  const compact = value.trim().replace(/\/{2,}/g, "/");
  if (!compact || compact === "*") return "/";
  return compact.startsWith("/") ? compact : `/${compact}`;
}

function joinPath(...values: string[]): string {
  const parts = values.map((value) => value.replace(/^\/+|\/+$/g, "")).filter(Boolean);
  return normalizePath(parts.join("/"));
}

function propertyName(node: ts.PropertyName | undefined): string | undefined {
  if (!node) return undefined;
  if (ts.isIdentifier(node) || ts.isStringLiteral(node) || ts.isNumericLiteral(node)) return node.text;
  return undefined;
}

function expressionName(node: ts.Expression): string {
  if (ts.isIdentifier(node)) return node.text;
  if (ts.isPropertyAccessExpression(node)) return `${expressionName(node.expression)}.${node.name.text}`;
  if (ts.isElementAccessExpression(node) && node.argumentExpression && ts.isStringLiteral(node.argumentExpression)) {
    return `${expressionName(node.expression)}.${node.argumentExpression.text}`;
  }
  if (ts.isCallExpression(node)) return `${expressionName(node.expression)}()`;
  return node.getText();
}

function unwrapExpression(node: ts.Expression): ts.Expression {
  let current = node;
  while (ts.isParenthesizedExpression(current) || ts.isAsExpression(current) || ts.isTypeAssertionExpression(current)
    || ts.isNonNullExpression(current) || ts.isSatisfiesExpression(current)) current = current.expression;
  return current;
}

function isObjectIdField(value: string): boolean {
  return /^(?:id|uuid|[A-Za-z_]\w*_(?:id|uuid)|[a-z][A-Za-z0-9_]*(?:Id|ID|Uuid|UUID))$/.test(value);
}

function accessSegments(node: ts.Expression): string[] | undefined {
  const current = unwrapExpression(node);
  if (ts.isIdentifier(current)) return [current.text];
  if (ts.isPropertyAccessExpression(current)) {
    const parent = accessSegments(current.expression);
    return parent ? [...parent, current.name.text] : undefined;
  }
  if (ts.isElementAccessExpression(current) && current.argumentExpression && ts.isStringLiteral(current.argumentExpression)) {
    const parent = accessSegments(current.expression);
    return parent ? [...parent, current.argumentExpression.text] : undefined;
  }
  return undefined;
}

function decorators(node: ts.Node): readonly ts.Decorator[] {
  return ts.canHaveDecorators(node) ? ts.getDecorators(node) ?? [] : [];
}

function decoratorDetails(decorator: ts.Decorator): { name: string; arguments: readonly ts.Expression[] } {
  const expression = decorator.expression;
  if (ts.isCallExpression(expression)) return { name: expressionName(expression.expression).split(".").pop() ?? "", arguments: expression.arguments };
  return { name: expressionName(expression).split(".").pop() ?? "", arguments: [] };
}

function routeFieldsFromPath(path: string): string[] {
  const fields = new Set<string>();
  for (const match of path.matchAll(/(?::|\{)([A-Za-z_]\w*)\}?/g)) if (match[1] && isObjectIdField(match[1])) fields.add(match[1]);
  return [...fields];
}

function collectBindingNames(name: ts.BindingName, fields: Set<string>): void {
  if (ts.isIdentifier(name)) {
    if (isObjectIdField(name.text)) fields.add(name.text);
    return;
  }
  for (const element of name.elements) {
    if (ts.isOmittedExpression(element)) continue;
    const candidate = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : undefined);
    if (candidate && isObjectIdField(candidate)) fields.add(candidate);
  }
}

function objectIdFields(
  handler: ts.FunctionLikeDeclaration | undefined,
  path: string,
  inputRoots: Set<string>,
  directFields: Set<string>,
): string[] {
  const fields = new Set<string>([...routeFieldsFromPath(path), ...directFields]);
  if (!handler) return [...fields].sort();
  visit(handler, (node) => {
    if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
      const segments = accessSegments(node);
      const candidate = segments?.at(-1);
      if (!segments || !candidate || !isObjectIdField(candidate)) return;
      const root = segments[0] ?? "";
      const requestField = ["req", "request", "ctx", "context"].includes(root)
        && segments.some((part) => ["body", "params", "query", "request"].includes(part));
      if (requestField || inputRoots.has(root)) fields.add(candidate);
    }
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const segments = accessSegments(node.initializer);
      const root = segments?.[0] ?? "";
      const requestObject = ["req", "request", "ctx", "context"].includes(root)
        && Boolean(segments?.some((part) => ["body", "params", "query", "request"].includes(part)));
      if (requestObject || inputRoots.has(root)) collectBindingNames(node.name, fields);
    }
  });
  return [...fields].sort();
}

function collectOwnerFields(expression: ts.Expression, fields: Set<string>): void {
  const current = unwrapExpression(expression);
  if (ts.isObjectLiteralExpression(current)) {
    for (const property of current.properties) {
      if (ts.isPropertyAssignment(property)) {
        const name = propertyName(property.name);
        if (name && OWNER_FIELD.test(name)) fields.add(name);
        collectOwnerFields(property.initializer, fields);
      } else if (ts.isShorthandPropertyAssignment(property) && OWNER_FIELD.test(property.name.text)) fields.add(property.name.text);
    }
  } else if (ts.isArrayLiteralExpression(current)) {
    for (const element of current.elements) if (ts.isExpression(element)) collectOwnerFields(element, fields);
  } else if (ts.isConditionalExpression(current)) {
    collectOwnerFields(current.whenTrue, fields);
    collectOwnerFields(current.whenFalse, fields);
  }
}

function responseOwnerFields(handler: ts.FunctionLikeDeclaration | undefined): string[] {
  const fields = new Set<string>();
  if (!handler) return [];
  visit(handler, (node) => {
    if (ts.isReturnStatement(node) && node.expression) collectOwnerFields(node.expression, fields);
    if (ts.isCallExpression(node) && node.arguments[0]) {
      const name = expressionName(node.expression);
      if (/(?:^|\.)(?:json|send)$/.test(name)) collectOwnerFields(node.arguments[0], fields);
    }
  });
  return [...fields].sort();
}

function hasObjectOperation(handler: ts.FunctionLikeDeclaration | undefined, fields: string[]): boolean {
  if (!handler || fields.length === 0) return false;
  let found = false;
  visit(handler, (node) => {
    if (found || !ts.isCallExpression(node)) return;
    const name = expressionName(node.expression).replace(/\(\)/g, "");
    if (ID_OPERATION.test(name)) found = true;
  });
  return found;
}

function explicitAuthentication(source: string): boolean {
  if (AUTH_GUARD_NAME.test(source)) return true;
  const identity = String.raw`(?:\b(?:req(?:uest)?|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session)\b|\b(?:currentUser|authenticatedUser|principal|identity)\b)`;
  const absentIdentity = String.raw`(?:!\s*${identity}|${identity}\s*(?:={2,3}|!={1,2})\s*(?:null|undefined|false))`;
  const denial = String.raw`(?:\b(?:Unauthorized|AuthenticationError|NotAuthenticated)\b|\.status\s*\(\s*401\s*\)|\bstatusCode\s*[:=]\s*401\b)`;
  return new RegExp(`if\\s*\\(\\s*${absentIdentity}[\\s\\S]{0,120}?\\)[\\s\\S]{0,240}?${denial}`, "i").test(source);
}

function ownershipGuard(source: string): boolean {
  if (ACCESS_GUARD_NAME.test(source)) return true;
  const identity = String.raw`(?:req(?:uest)?|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?|(?:currentUser|authenticatedUser|principal|identity)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?`;
  const owner = String.raw`(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id|ownerId|userId|tenantId|creatorId|createdBy|accountId|organizationId|orgId)`;
  const directBinding = new RegExp(`${owner}\\s*:\\s*${identity}`, "i");
  const comparison = new RegExp(`(?:\\.\\s*${owner}|\\b${owner}\\b)\\s*(?:===?|!==?)\\s*${identity}|${identity}\\s*(?:===?|!==?)\\s*(?:\\.\\s*${owner}|\\b${owner}\\b)`, "i");
  const roleDenial = new RegExp(`${identity}[\\s\\S]{0,180}?(?:role|isAdmin|permissions?|ability)[\\s\\S]{0,180}?(?:Forbidden|status\\s*\\(\\s*403|AccessDenied)`, "i");
  return directBinding.test(source) || comparison.test(source) || roleDenial.test(source);
}

function functionDeclarations(source: ts.SourceFile): Map<string, ts.FunctionLikeDeclaration> {
  const result = new Map<string, ts.FunctionLikeDeclaration>();
  for (const statement of source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.name && statement.body) result.set(statement.name.text, statement);
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = unwrapExpression(declaration.initializer);
      if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) result.set(declaration.name.text, initializer);
    }
  }
  return result;
}

function resolveFunction(expression: ts.Expression, declarations: Map<string, ts.FunctionLikeDeclaration>): ts.FunctionLikeDeclaration | undefined {
  const current = unwrapExpression(expression);
  if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) return current;
  if (ts.isIdentifier(current)) return declarations.get(current.text);
  return undefined;
}

function isExpressFactoryCall(expression: ts.Expression, expressFactories: Set<string>, routerFactories: Set<string>): "app" | "router" | undefined {
  const current = unwrapExpression(expression);
  if (!ts.isCallExpression(current)) return undefined;
  const name = expressionName(current.expression);
  if (expressFactories.has(name)) return "app";
  if (routerFactories.has(name) || [...expressFactories].some((factory) => name === `${factory}.Router`)) return "router";
  if (ts.isCallExpression(current.expression) && ts.isIdentifier(current.expression.expression)
    && current.expression.expression.text === "require" && literalText(current.expression.arguments[0]) === "express") return "app";
  return undefined;
}

function expressRoutes(parsed: ParsedSource): { routes: NodeApiRoute[]; unresolvedHandlers: number; unresolvedMounts: number } {
  const source = parsed.source;
  const expressFactories = new Set<string>();
  const routerFactories = new Set<string>();
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && literalText(statement.moduleSpecifier) === "express") {
      const clause = statement.importClause;
      if (clause?.name) expressFactories.add(clause.name.text);
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) expressFactories.add(clause.namedBindings.name.text);
      if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          const imported = element.propertyName?.text ?? element.name.text;
          if (imported === "Router") routerFactories.add(element.name.text);
        }
      }
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!declaration.initializer) continue;
      if (ts.isIdentifier(declaration.name) && ts.isCallExpression(declaration.initializer)
        && ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === "require"
        && literalText(declaration.initializer.arguments[0]) === "express") expressFactories.add(declaration.name.text);
      if (ts.isObjectBindingPattern(declaration.name) && ts.isCallExpression(declaration.initializer)
        && ts.isIdentifier(declaration.initializer.expression) && declaration.initializer.expression.text === "require"
        && literalText(declaration.initializer.arguments[0]) === "express") {
        for (const element of declaration.name.elements) {
          const imported = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : "");
          if (imported === "Router" && ts.isIdentifier(element.name)) routerFactories.add(element.name.text);
        }
      }
    }
  }

  const receivers = new Map<string, "app" | "router">();
  visit(source, (node) => {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) return;
    const kind = isExpressFactoryCall(node.initializer, expressFactories, routerFactories);
    if (kind) receivers.set(node.name.text, kind);
  });
  if (receivers.size === 0) return { routes: [], unresolvedHandlers: 0, unresolvedMounts: 0 };

  const declarations = functionDeclarations(source);
  const candidates: ExpressRouteCandidate[] = [];
  const middleware: ExpressMiddleware[] = [];
  const mounts: ExpressMount[] = [];
  let unresolvedHandlers = 0;
  let unresolvedMounts = 0;
  visit(source, (node) => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
    const receiver = expressionName(node.expression.expression);
    if (!receivers.has(receiver)) return;
    const callName = node.expression.name.text.toLowerCase();
    if (callName === "use") {
      const prefix = literalText(node.arguments[0]) === undefined ? "" : normalizePath(literalText(node.arguments[0])!);
      const start = prefix ? 1 : 0;
      const expressions = node.arguments.slice(start);
      const childExpression = expressions.at(-1);
      const child = childExpression && ts.isIdentifier(unwrapExpression(childExpression)) ? (unwrapExpression(childExpression) as ts.Identifier).text : undefined;
      const guardExpressions = child && receivers.has(child) ? expressions.slice(0, -1) : expressions;
      const authenticated = guardExpressions.some((expression) => {
        const resolved = resolveFunction(expression, declarations);
        return AUTH_GUARD_NAME.test(expressionName(expression)) || Boolean(resolved && explicitAuthentication(resolved.getText(source)));
      });
      middleware.push({ receiver, offset: node.getStart(source), prefix, authenticated });
      if (child && receivers.has(child) && child !== receiver) mounts.push({ parent: receiver, child, offset: node.getStart(source), prefix, authenticated });
      else if (childExpression && prefix && ts.isIdentifier(unwrapExpression(childExpression)) && !authenticated
        && /(?:router|routes?)/i.test((unwrapExpression(childExpression) as ts.Identifier).text)) unresolvedMounts += 1;
      return;
    }
    if (!HTTP_METHODS.has(callName) || node.arguments.length < 2) return;
    const rawPath = literalText(node.arguments[0]);
    if (rawPath === undefined) return;
    const path = normalizePath(rawPath);
    const handlerExpression = node.arguments.at(-1)!;
    const handler = resolveFunction(handlerExpression, declarations);
    if (!handler) unresolvedHandlers += 1;
    const middlewareExpressions = node.arguments.slice(1, -1);
    const handlerSource = handler?.getText(source) ?? handlerExpression.getText(source);
    const locallyAuthenticated = middlewareExpressions.some((expression) => {
      const resolved = resolveFunction(expression, declarations);
      return AUTH_GUARD_NAME.test(expressionName(expression)) || Boolean(resolved && explicitAuthentication(resolved.getText(source)));
    }) || explicitAuthentication(handlerSource);
    const handlerName = ts.isIdentifier(unwrapExpression(handlerExpression))
      ? (unwrapExpression(handlerExpression) as ts.Identifier).text
      : ts.isPropertyAccessExpression(unwrapExpression(handlerExpression))
        ? expressionName(unwrapExpression(handlerExpression)).split(".").pop() ?? "anonymous"
        : handler && "name" in handler && handler.name && ts.isIdentifier(handler.name) ? handler.name.text : "anonymous";
    candidates.push({
      receiver,
      method: callName === "all" ? "ALL" : callName.toUpperCase(),
      path,
      offset: node.getStart(source),
      handlerName,
      handler,
      handlerSource,
      location: location(parsed, node),
      locallyAuthenticated,
    });
  });

  const protectedByMiddleware = (receiver: string, path: string, before: number): boolean => middleware.some((item) => item.receiver === receiver
    && item.authenticated && item.offset < before && (!item.prefix || path === item.prefix || path.startsWith(`${item.prefix}/`)));
  const routes: NodeApiRoute[] = [];
  for (const candidate of candidates) {
    const matchingMounts = mounts.filter((mount) => mount.child === candidate.receiver);
    const routeVariants = matchingMounts.length > 0 ? matchingMounts.map((mount) => ({
      path: joinPath(mount.prefix, candidate.path),
      inheritedAuthentication: mount.authenticated || protectedByMiddleware(mount.parent, joinPath(mount.prefix, candidate.path), mount.offset),
    })) : [{ path: candidate.path, inheritedAuthentication: false }];
    for (const variant of routeVariants) {
      const fields = objectIdFields(candidate.handler, variant.path, new Set(), new Set());
      routes.push({
        framework: "Express",
        method: candidate.method,
        path: variant.path,
        sourcePath: parsed.file.relativePath,
        handlerName: candidate.handlerName,
        handlerSource: candidate.handlerSource,
        location: candidate.location,
        authenticationProtected: candidate.locallyAuthenticated || variant.inheritedAuthentication
          || protectedByMiddleware(candidate.receiver, candidate.path, candidate.offset),
        ownershipProtected: ownershipGuard(candidate.handlerSource),
        objectOperation: hasObjectOperation(candidate.handler, fields),
        objectIdFields: fields,
        responseOwnerFields: responseOwnerFields(candidate.handler),
      });
    }
  }
  return { routes, unresolvedHandlers, unresolvedMounts };
}

function hasGlobalNestGuard(sources: ParsedSource[]): boolean {
  let found = false;
  for (const parsed of sources) {
    visit(parsed.source, (node) => {
      if (found) return;
      const guardName = /(?:auth|jwt|session|identity|user|role|permission|policy|ability|access|owner|admin)/i;
      if (ts.isCallExpression(node) && /(?:^|\.)useGlobalGuards$/.test(expressionName(node.expression))
        && node.arguments.some((argument) => guardName.test(argument.getText(parsed.source)))) found = true;
      if (ts.isObjectLiteralExpression(node)) {
        const properties = new Map(node.properties.filter(ts.isPropertyAssignment)
          .map((property) => [propertyName(property.name), property.initializer]));
        const provide = properties.get("provide");
        const implementation = properties.get("useClass") ?? properties.get("useExisting") ?? properties.get("useValue");
        if (provide && ts.isIdentifier(unwrapExpression(provide)) && (unwrapExpression(provide) as ts.Identifier).text === "APP_GUARD"
          && implementation && guardName.test(implementation.getText(parsed.source))) found = true;
      }
    });
    if (found) break;
  }
  return found;
}

function nestDecoratorAuthentication(values: Array<{ name: string; arguments: readonly ts.Expression[] }>, source: ts.SourceFile): boolean {
  return values.some((item) => {
    if (/^(?:Auth|Authenticated|RequireAuth|Roles?|Permissions?|Policies|Authorize)$/i.test(item.name)) return true;
    return item.name === "UseGuards" && item.arguments.some((argument) => /(?:auth|jwt|session|identity|user|role|permission|policy|ability|access|owner|admin)/i.test(argument.getText(source)));
  });
}

function nestDecoratorOwnership(values: Array<{ name: string; arguments: readonly ts.Expression[] }>, source: ts.SourceFile): boolean {
  return values.some((item) => {
    if (/^(?:Roles?|Permissions?|Policies|CheckPolicies|Authorize|RequireOwner|RequireAccess)$/i.test(item.name)) return true;
    return item.name === "UseGuards"
      && item.arguments.some((argument) => /(?:owner|ownership|tenant|role|permission|policy|ability|access|admin)/i.test(argument.getText(source)));
  });
}

function nestInputDetails(method: ts.MethodDeclaration): { roots: Set<string>; fields: Set<string> } {
  const roots = new Set<string>();
  const fields = new Set<string>();
  for (const parameter of method.parameters) {
    const details = decorators(parameter).map(decoratorDetails);
    const input = details.find((item) => /^(?:Body|Param|Query|Req|Request)$/i.test(item.name));
    if (!input) continue;
    const selected = literalText(input.arguments[0]);
    if (selected && isObjectIdField(selected)) fields.add(selected);
    if (ts.isIdentifier(parameter.name)) {
      if (selected && isObjectIdField(parameter.name.text)) fields.add(selected);
      else if (/^(?:Param)$/i.test(input.name) && isObjectIdField(parameter.name.text)) fields.add(parameter.name.text);
      else if (!/^(?:Req|Request)$/i.test(input.name)) roots.add(parameter.name.text);
    }
  }
  return { roots, fields };
}

function nestRoutes(parsed: ParsedSource, globalGuard: boolean): NodeApiRoute[] {
  const routes: NodeApiRoute[] = [];
  for (const statement of parsed.source.statements) {
    if (!ts.isClassDeclaration(statement)) continue;
    const classDecorators = decorators(statement).map(decoratorDetails);
    const controller = classDecorators.find((item) => item.name === "Controller");
    if (!controller) continue;
    const prefix = normalizePath(literalText(controller.arguments[0]) ?? "");
    const classAuthenticated = nestDecoratorAuthentication(classDecorators, parsed.source);
    const classOwnership = nestDecoratorOwnership(classDecorators, parsed.source);
    for (const member of statement.members) {
      if (!ts.isMethodDeclaration(member) || !member.body) continue;
      const methodDecorators = decorators(member).map(decoratorDetails);
      const routeDecorators = methodDecorators.filter((item) => /^(?:Get|Post|Put|Patch|Delete|Options|Head|All)$/.test(item.name));
      if (routeDecorators.length === 0) continue;
      const isPublic = methodDecorators.some((item) => /^(?:Public|AllowAnonymous)$/.test(item.name));
      const methodAuthenticated = nestDecoratorAuthentication(methodDecorators, parsed.source);
      const source = member.getText(parsed.source);
      const inputs = nestInputDetails(member);
      for (const routeDecorator of routeDecorators) {
        const path = joinPath(prefix, literalText(routeDecorator.arguments[0]) ?? "");
        const fields = objectIdFields(member, path, inputs.roots, inputs.fields);
        routes.push({
          framework: "NestJS",
          method: routeDecorator.name === "All" ? "ALL" : routeDecorator.name.toUpperCase(),
          path,
          sourcePath: parsed.file.relativePath,
          handlerName: propertyName(member.name) ?? "anonymous",
          handlerSource: source,
          location: location(parsed, member),
          authenticationProtected: methodAuthenticated || (!isPublic && (classAuthenticated || globalGuard)) || explicitAuthentication(source),
          ownershipProtected: classOwnership || nestDecoratorOwnership(methodDecorators, parsed.source) || ownershipGuard(source),
          objectOperation: hasObjectOperation(member, fields),
          objectIdFields: fields,
          responseOwnerFields: responseOwnerFields(member),
        });
      }
    }
  }
  return routes;
}

function routeKey(route: NodeApiRoute): string {
  return [route.framework, route.method, route.path, route.sourcePath, route.handlerName].join("\u0000");
}

export function analyzeNodeApi(files: ProjectFile[]): NodeApiAnalysis {
  const packages = packageNames(files);
  const parsed: ParsedSource[] = [];
  let filesWithParseErrors = 0;
  for (const file of files.filter((candidate) => NODE_EXTENSIONS.has(extname(candidate.relativePath).toLowerCase())
    && !NON_RUNTIME_NODE_PATH.test(candidate.relativePath))) {
    const source = ts.createSourceFile(file.relativePath, file.content, ts.ScriptTarget.Latest, true, scriptKind(file.relativePath));
    const diagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (diagnostics.length > 0) filesWithParseErrors += 1;
    parsed.push({ file, source, modules: moduleNames(source) });
  }
  const detectedExpress = packages.has("express") || parsed.some((item) => item.modules.has("express"));
  const detectedNest = packages.has("@nestjs/core") || packages.has("@nestjs/common")
    || parsed.some((item) => [...item.modules].some((name) => name === "@nestjs/core" || name === "@nestjs/common"));
  const routes: NodeApiRoute[] = [];
  let unresolvedHandlers = 0;
  let unresolvedMounts = 0;
  if (detectedExpress) {
    for (const item of parsed.filter((candidate) => candidate.modules.has("express"))) {
      const result = expressRoutes(item);
      routes.push(...result.routes);
      unresolvedHandlers += result.unresolvedHandlers;
      unresolvedMounts += result.unresolvedMounts;
    }
  }
  if (detectedNest) {
    const globalGuard = hasGlobalNestGuard(parsed);
    for (const item of parsed) routes.push(...nestRoutes(item, globalGuard));
  }
  const deduplicated = [...new Map(routes.map((route) => [routeKey(route), route])).values()]
    .sort((left, right) => left.path.localeCompare(right.path) || left.method.localeCompare(right.method));
  return {
    detectedExpress,
    detectedNest,
    routes: deduplicated,
    filesWithParseErrors,
    unresolvedHandlers,
    unresolvedMounts,
  };
}
