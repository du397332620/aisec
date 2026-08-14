import { basename, extname, posix } from "node:path";
import ts from "typescript";
import type { ProjectFile } from "../core/files.js";
import type { SourceLocation } from "../schema.js";
import { makeLocation } from "../core/utils.js";

export type NodeApiFramework = "Express" | "NestJS";

export interface NodeApiRoute {
  framework: NodeApiFramework;
  method: string;
  path: string;
  declaredPath: string;
  sourcePath: string;
  handlerName: string;
  handlerSource: string;
  location: SourceLocation;
  authenticationProtected: boolean;
  ownershipProtected: boolean;
  roleProtected: boolean;
  privilegedOperation: boolean;
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
  imports: Map<string, ImportBinding>;
  exports: Map<string, ExportBinding>;
  starExports: string[];
}

interface ImportBinding {
  module: string;
  imported: string;
  namespace: boolean;
}

interface ExportBinding {
  local?: string;
  module?: string;
  imported?: string;
}

function syntheticExportLocal(exported: string): string {
  return exported === "default" ? "$default" : `$export$${exported}`;
}

function commonJsExportName(expression: ts.Expression): string | undefined {
  const name = expressionName(expression);
  if (name === "module.exports") return "default";
  return name.match(/^(?:module\.exports|exports)\.([A-Za-z_$][\w$]*)$/)?.[1];
}

interface ResolvedFunction {
  declaration: ts.FunctionLikeDeclaration;
  parsed: ParsedSource;
}

interface ResolvedClass {
  declaration: ts.ClassDeclaration;
  parsed: ParsedSource;
}

interface LocalCallSemantics {
  source: string;
  ownershipProtected: boolean;
  roleProtected: boolean;
  objectOperation: boolean;
  responseOwnerFields: string[];
}

interface LocalCallAnalyzer {
  analyze(
    parsed: ParsedSource,
    declaration: ts.FunctionLikeDeclaration,
    ownerClass: ResolvedClass | undefined,
    objectIdFields: string[],
  ): LocalCallSemantics;
}

interface ExpressRouteCandidate {
  receiver: string;
  parsed: ParsedSource;
  handlerParsed: ParsedSource;
  method: string;
  path: string;
  offset: number;
  handlerName: string;
  handler?: ts.FunctionLikeDeclaration;
  handlerSource: string;
  location: SourceLocation;
  locallyAuthenticated: boolean;
  locallyRoleProtected: boolean;
}

interface ExpressMiddleware {
  receiver: string;
  sourcePath: string;
  offset: number;
  prefix: string;
  authenticated: boolean;
  roleProtected: boolean;
}

interface ExpressMount {
  parent: string;
  child: string;
  sourcePath: string;
  offset: number;
  prefix: string;
  authenticated: boolean;
  roleProtected: boolean;
}

type NestVersion = string | null;

interface NestRoutingConfig {
  globalPrefix: string;
  prefixExcludes: Set<string>;
  uriVersioning: boolean;
  defaultVersions: NestVersion[];
  versionPrefix: string;
}

const NODE_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);
const NON_RUNTIME_NODE_PATH = /(?:^|\/)(?:test|tests|fixtures|examples?|scripts|mocks?|__tests__|old-archive)(?:\/|$)|(?:^|\/)(?:debug|test|example)[^/]*\.(?:[cm]?[jt]sx?)$/i;
const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "all"]);
const OWNER_FIELD = /^(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id|ownerId|userId|tenantId|creatorId|createdBy|accountId|organizationId|orgId)$/;
const OWNER_RELATION_FIELD = /^(?:owner|author|user|tenant|creator|account|organization|org)$/i;
const AUTH_GUARD_NAME = /(?:^|[._])(?:auth(?:Middleware|Guard)?|authenticate|authenticated|authentication(?:Middleware)?|requireAuth|requireUser|ensureAuthenticated|isAuthenticated|verifyToken|verifySession|jwtAuth(?:Guard)?|jwtGuard|sessionAuth(?:Guard)?|bearerAuth|protect|passport\.authenticate)(?:$|[.(])/i;
const ACCESS_GUARD_NAME = /(?:^|[._])(?:require|verify|check|ensure|authorize|assert|can)[A-Za-z0-9_]*(?:access|owner|ownership|permission|policy|role|admin|tenant)|(?:owner|ownership|permission|policy|ability|role|admin|tenant)[A-Za-z0-9_]*(?:guard|check)(?:$|[.(])/i;
const ROLE_GUARD_NAME = /(?:^|[._])(?:require|verify|check|ensure|authorize|assert|can)[A-Za-z0-9_]*(?:permission|policy|role|admin)|(?:permission|policy|ability|role|admin)[A-Za-z0-9_]*(?:guard|check|only|middleware)(?:$|[.(])/i;
const ID_OPERATION = /(?:^|\.)(?:findById|findByIdAndUpdate|findByIdAndDelete|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne|findMany|getById|getBy[A-Z][A-Za-z0-9_]*|getOne|loadById|detail|update|updateOne|updateMany|delete|deleteOne|deleteMany|remove|destroy|where)$/;
const NEST_AUTH_GUARD_HINT = /(?:auth|jwt|session|identity|loggedIn|signedIn|user|role|permission|policy|ability|access|owner|admin)/i;
const NEST_OWNERSHIP_GUARD_HINT = /(?:owner|ownership|tenant|role|permission|policy|ability|access|admin)/i;
const PRIVILEGED_ROUTE_HINT = /(?:^|\/)(?:admin|administration|manage|management|permissions?|roles?)(?:\/|$)/i;
const PRIVILEGED_HANDLER_HINT = /(?:admin|nonAdmin|allUsers?|manageUsers?|permissions?|roles?)/i;

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

function hasModifier(node: ts.Node, kind: ts.SyntaxKind): boolean {
  return Boolean(ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === kind));
}

function requireModule(expression: ts.Expression): string | undefined {
  const current = unwrapExpression(expression);
  if (!ts.isCallExpression(current) || !ts.isIdentifier(current.expression) || current.expression.text !== "require") return undefined;
  return literalText(current.arguments[0]);
}

function moduleBindings(source: ts.SourceFile): {
  imports: Map<string, ImportBinding>;
  exports: Map<string, ExportBinding>;
  starExports: string[];
} {
  const imports = new Map<string, ImportBinding>();
  const exports = new Map<string, ExportBinding>();
  const starExports: string[] = [];
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
      const module = statement.moduleSpecifier.text;
      const clause = statement.importClause;
      if (clause?.name) imports.set(clause.name.text, { module, imported: "default", namespace: false });
      if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        imports.set(clause.namedBindings.name.text, { module, imported: "default", namespace: true });
      }
      if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          imports.set(element.name.text, {
            module,
            imported: element.propertyName?.text ?? element.name.text,
            namespace: false,
          });
        }
      }
    }
    if (ts.isExportDeclaration(statement)) {
      const module = statement.moduleSpecifier && ts.isStringLiteral(statement.moduleSpecifier)
        ? statement.moduleSpecifier.text : undefined;
      if (!statement.exportClause && module) starExports.push(module);
      if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) {
          const imported = element.propertyName?.text ?? element.name.text;
          exports.set(element.name.text, module ? { module, imported } : { local: imported });
        }
      }
      continue;
    }
    if (ts.isExportAssignment(statement)) {
      const value = unwrapExpression(statement.expression);
      if (ts.isIdentifier(value)) exports.set("default", { local: value.text });
      else if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
        exports.set("default", { local: syntheticExportLocal("default") });
      } else if (ts.isCallExpression(value)) {
        exports.set("default", { local: syntheticExportLocal("default") });
      }
      continue;
    }
    if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement)) {
      if (!hasModifier(statement, ts.SyntaxKind.ExportKeyword)) continue;
      if (!statement.name) {
        if (hasModifier(statement, ts.SyntaxKind.DefaultKeyword)) exports.set("default", { local: syntheticExportLocal("default") });
        continue;
      }
      exports.set(statement.name.text, { local: statement.name.text });
      if (hasModifier(statement, ts.SyntaxKind.DefaultKeyword)) exports.set("default", { local: statement.name.text });
      continue;
    }
    if (ts.isVariableStatement(statement)) {
      const exported = hasModifier(statement, ts.SyntaxKind.ExportKeyword);
      for (const declaration of statement.declarationList.declarations) {
        if (!declaration.initializer) continue;
        const directModule = requireModule(declaration.initializer);
        const initializer = unwrapExpression(declaration.initializer);
        const requiredProperty = ts.isPropertyAccessExpression(initializer)
          ? requireModule(initializer.expression) : undefined;
        if (directModule && ts.isIdentifier(declaration.name)) {
          imports.set(declaration.name.text, { module: directModule, imported: "default", namespace: true });
        } else if (directModule && ts.isObjectBindingPattern(declaration.name)) {
          for (const element of declaration.name.elements) {
            if (!ts.isIdentifier(element.name)) continue;
            imports.set(element.name.text, {
              module: directModule,
              imported: propertyName(element.propertyName) ?? element.name.text,
              namespace: false,
            });
          }
        } else if (requiredProperty && ts.isIdentifier(declaration.name) && ts.isPropertyAccessExpression(initializer)) {
          imports.set(declaration.name.text, {
            module: requiredProperty,
            imported: initializer.name.text,
            namespace: false,
          });
        }
        if (exported && ts.isIdentifier(declaration.name)) exports.set(declaration.name.text, { local: declaration.name.text });
      }
      continue;
    }
    if (!ts.isExpressionStatement(statement) || !ts.isBinaryExpression(statement.expression)
      || statement.expression.operatorToken.kind !== ts.SyntaxKind.EqualsToken) continue;
    const exported = commonJsExportName(statement.expression.left);
    if (!exported) continue;
    const value = unwrapExpression(statement.expression.right);
    if (ts.isIdentifier(value)) exports.set(exported, { local: value.text });
    else if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
      exports.set(exported, { local: syntheticExportLocal(exported) });
    } else if (ts.isCallExpression(value)) {
      exports.set(exported, { local: syntheticExportLocal(exported) });
    } else if (exported === "default" && ts.isObjectLiteralExpression(value)) {
      for (const property of value.properties) {
        const name = propertyName(property.name);
        if (!name) continue;
        if (ts.isShorthandPropertyAssignment(property)) exports.set(name, { local: property.name.text });
        else if (ts.isPropertyAssignment(property)) {
          const initializer = unwrapExpression(property.initializer);
          exports.set(name, ts.isIdentifier(initializer)
            ? { local: initializer.text }
            : { local: syntheticExportLocal(name) });
        } else if (ts.isMethodDeclaration(property)) exports.set(name, { local: syntheticExportLocal(name) });
      }
    }
  }
  return { imports, exports, starExports };
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
  const deniedWhenAbsent = new RegExp(`if\\s*\\(\\s*${absentIdentity}[\\s\\S]{0,120}?\\)[\\s\\S]{0,240}?${denial}`, "i").test(source);
  const loginRedirect = String.raw`\.redirect\s*\(\s*["'][^"']*(?:login|log-in|sign-in)[^"']*["']`;
  const continuesWhenPresent = new RegExp(`if\\s*\\(\\s*${identity}[\\s\\S]{0,120}?\\)[\\s\\S]{0,180}?\\bnext\\s*\\([\\s\\S]{0,240}?${loginRedirect}`, "i").test(source);
  return deniedWhenAbsent || continuesWhenPresent;
}

function ownershipGuard(source: string, allowUnscopedDirectBinding = true): boolean {
  if (ACCESS_GUARD_NAME.test(source)) return true;
  const identity = String.raw`(?:(?:req(?:uest)?|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?|(?:currentUser|authenticatedUser|principal|identity)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?)`;
  const owner = String.raw`(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id|ownerId|userId|tenantId|creatorId|createdBy|accountId|organizationId|orgId)`;
  const directBinding = new RegExp(`${owner}\\s*:\\s*${identity}`, "i");
  const comparison = new RegExp(`(?:\\.\\s*${owner}|\\b${owner}\\b)\\s*(?:===?|!==?)\\s*${identity}|${identity}\\s*(?:===?|!==?)\\s*(?:\\.\\s*${owner}|\\b${owner}\\b)`, "i");
  const roleDenial = new RegExp(`${identity}[\\s\\S]{0,180}?(?:role|isAdmin|permissions?|ability)[\\s\\S]{0,180}?(?:Forbidden|status\\s*\\(\\s*403|AccessDenied)`, "i");
  return (allowUnscopedDirectBinding && directBinding.test(source)) || comparison.test(source) || roleDenial.test(source);
}

function roleGuard(source: string): boolean {
  if (ROLE_GUARD_NAME.test(source)) return true;
  const role = /(?:isAdmin|admin|roles?|permissions?|policies|abilities|canAccess)/i;
  const denial = /(?:Forbidden|AccessDenied|status\s*\(\s*403|sendStatus\s*\(\s*403|\.redirect\s*\(\s*["'][^"']*(?:login|log-in|sign-in))/i;
  return role.test(source) && denial.test(source);
}

function privilegedOperation(path: string, handlerName: string, source: string): boolean {
  return PRIVILEGED_ROUTE_HINT.test(path) || PRIVILEGED_HANDLER_HINT.test(handlerName)
    || /(?:getAllNonAdminUsers|listAllUsers|updateUserRole|assignRole|grantPermission|revokePermission)/i.test(source);
}

function functionDeclarations(source: ts.SourceFile): Map<string, ts.FunctionLikeDeclaration> {
  const result = new Map<string, ts.FunctionLikeDeclaration>();
  for (const statement of source.statements) {
    if (ts.isFunctionDeclaration(statement) && statement.body) {
      if (statement.name) result.set(statement.name.text, statement);
      else if (hasModifier(statement, ts.SyntaxKind.DefaultKeyword)) result.set(syntheticExportLocal("default"), statement);
    }
    if (ts.isExportAssignment(statement)) {
      const expression = unwrapExpression(statement.expression);
      if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression)) {
        result.set(syntheticExportLocal("default"), expression);
      }
    }
    if (ts.isExpressionStatement(statement) && ts.isBinaryExpression(statement.expression)
      && statement.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const exported = commonJsExportName(statement.expression.left);
      const expression = unwrapExpression(statement.expression.right);
      if (exported && (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression))) {
        result.set(syntheticExportLocal(exported), expression);
      }
      if (exported === "default" && ts.isObjectLiteralExpression(expression)) {
        for (const property of expression.properties) {
          const name = propertyName(property.name);
          if (!name) continue;
          if (ts.isPropertyAssignment(property)) {
            const initializer = unwrapExpression(property.initializer);
            if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) {
              result.set(syntheticExportLocal(name), initializer);
            }
          } else if (ts.isMethodDeclaration(property)) result.set(syntheticExportLocal(name), property);
        }
      }
    }
    if (!ts.isVariableStatement(statement)) continue;
    for (const declaration of statement.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) continue;
      const initializer = unwrapExpression(declaration.initializer);
      if (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer)) result.set(declaration.name.text, initializer);
    }
  }
  return result;
}

function parsedSourceLookup(sources: ParsedSource[]): Map<string, ParsedSource> {
  return new Map(sources.map((parsed) => [posix.normalize(parsed.file.relativePath), parsed]));
}

function resolveModule(parsed: ParsedSource, module: string, lookup: Map<string, ParsedSource>): ParsedSource | undefined {
  if (!module.startsWith(".")) return undefined;
  const joined = posix.normalize(posix.join(posix.dirname(parsed.file.relativePath), module));
  const extension = extname(joined).toLowerCase();
  const stem = NODE_EXTENSIONS.has(extension) ? joined.slice(0, -extension.length) : joined;
  const candidates = [joined, stem];
  for (const candidateExtension of NODE_EXTENSIONS) {
    candidates.push(`${stem}${candidateExtension}`);
    candidates.push(`${stem}/index${candidateExtension}`);
  }
  for (const candidate of candidates) {
    const target = lookup.get(posix.normalize(candidate));
    if (target) return target;
  }
  return undefined;
}

interface ResolvedSymbol {
  parsed: ParsedSource;
  local: string;
}

function resolveExportedSymbol(
  parsed: ParsedSource,
  exported: string,
  lookup: Map<string, ParsedSource>,
  seen = new Set<string>(),
): ResolvedSymbol | undefined {
  const key = `${parsed.file.relativePath}\u0000${exported}`;
  if (seen.has(key)) return undefined;
  seen.add(key);
  const binding = parsed.exports.get(exported);
  if (binding?.local) return resolveLocalSymbol(parsed, binding.local, lookup, seen);
  if (binding?.module) {
    const target = resolveModule(parsed, binding.module, lookup);
    if (target) return resolveExportedSymbol(target, binding.imported ?? exported, lookup, seen);
  }
  for (const module of parsed.starExports) {
    const target = resolveModule(parsed, module, lookup);
    const resolved = target && resolveExportedSymbol(target, exported, lookup, seen);
    if (resolved) return resolved;
  }
  return undefined;
}

function resolveLocalSymbol(
  parsed: ParsedSource,
  local: string,
  lookup: Map<string, ParsedSource>,
  seen = new Set<string>(),
): ResolvedSymbol | undefined {
  const binding = parsed.imports.get(local);
  if (!binding) return { parsed, local };
  const target = resolveModule(parsed, binding.module, lookup);
  if (!target) return undefined;
  return resolveExportedSymbol(target, binding.imported, lookup, seen);
}

function resolveExpressionSymbol(
  parsed: ParsedSource,
  expression: ts.Expression,
  lookup: Map<string, ParsedSource>,
): ResolvedSymbol | undefined {
  const current = unwrapExpression(expression);
  if (ts.isIdentifier(current)) return resolveLocalSymbol(parsed, current.text, lookup);
  if (ts.isPropertyAccessExpression(current) && ts.isIdentifier(current.expression)) {
    const namespace = parsed.imports.get(current.expression.text);
    if (!namespace?.namespace) return undefined;
    const target = resolveModule(parsed, namespace.module, lookup);
    return target ? resolveExportedSymbol(target, current.name.text, lookup) : undefined;
  }
  if (ts.isElementAccessExpression(current) && ts.isIdentifier(current.expression)
    && current.argumentExpression && ts.isStringLiteral(current.argumentExpression)) {
    const namespace = parsed.imports.get(current.expression.text);
    if (!namespace?.namespace) return undefined;
    const target = resolveModule(parsed, namespace.module, lookup);
    return target ? resolveExportedSymbol(target, current.argumentExpression.text, lookup) : undefined;
  }
  return undefined;
}

function resolveFunction(
  parsed: ParsedSource,
  expression: ts.Expression,
  lookup: Map<string, ParsedSource>,
  declarations: Map<string, Map<string, ts.FunctionLikeDeclaration>>,
): ResolvedFunction | undefined {
  const current = unwrapExpression(expression);
  if (ts.isArrowFunction(current) || ts.isFunctionExpression(current)) return { declaration: current, parsed };
  const symbol = resolveExpressionSymbol(parsed, current, lookup);
  const declaration = symbol && declarations.get(symbol.parsed.file.relativePath)?.get(symbol.local);
  return symbol && declaration ? { declaration, parsed: symbol.parsed } : undefined;
}

function createLocalCallAnalyzer(sources: ParsedSource[], lookup: Map<string, ParsedSource>): LocalCallAnalyzer {
  const declarations = new Map(sources.map((parsed) => [parsed.file.relativePath, functionDeclarations(parsed.source)]));
  const variables = new Map<string, { parsed: ParsedSource; expression: ts.Expression }>();
  const classes = new Map<string, ResolvedClass>();
  const classKey = (parsed: ParsedSource, local: string): string => `${parsed.file.relativePath}\u0000${local}`;
  for (const parsed of sources) {
    visit(parsed.source, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        variables.set(classKey(parsed, node.name.text), { parsed, expression: node.initializer });
      }
    });
    for (const statement of parsed.source.statements) {
      if (!ts.isClassDeclaration(statement)) continue;
      const local = statement.name?.text
        ?? (hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? syntheticExportLocal("default") : undefined);
      if (local) classes.set(classKey(parsed, local), { declaration: statement, parsed });
    }
  }

  const classFromSymbol = (symbol: ResolvedSymbol | undefined): ResolvedClass | undefined => symbol
    ? classes.get(classKey(symbol.parsed, symbol.local)) : undefined;
  const classFromLocal = (parsed: ParsedSource, local: string): ResolvedClass | undefined => classFromSymbol(resolveLocalSymbol(parsed, local, lookup));
  const classFromType = (parsed: ParsedSource, type: ts.TypeNode | undefined): ResolvedClass | undefined => {
    if (!type) return undefined;
    if (ts.isUnionTypeNode(type)) {
      for (const item of type.types) {
        const resolved = classFromType(parsed, item);
        if (resolved) return resolved;
      }
      return undefined;
    }
    if (!ts.isTypeReferenceNode(type)) return undefined;
    if (ts.isIdentifier(type.typeName)) return classFromLocal(parsed, type.typeName.text);
    if (ts.isQualifiedName(type.typeName) && ts.isIdentifier(type.typeName.left)) {
      const namespace = parsed.imports.get(type.typeName.left.text);
      const target = namespace?.namespace && resolveModule(parsed, namespace.module, lookup);
      return target ? classFromSymbol(resolveExportedSymbol(target, type.typeName.right.text, lookup)) : undefined;
    }
    return undefined;
  };

  const dependencyCache = new Map<string, ResolvedClass | null>();
  const resolveValueClass = (
    parsed: ParsedSource,
    expression: ts.Expression,
    ownerClass: ResolvedClass | undefined,
    seen?: Set<string>,
  ): ResolvedClass | undefined => {
    const current = unwrapExpression(expression);
    const nextSeen = seen ?? new Set<string>();
    if (ts.isNewExpression(current)) return resolveValueClass(parsed, current.expression, ownerClass, nextSeen);
    if (ts.isIdentifier(current)) {
      const symbol = resolveLocalSymbol(parsed, current.text, lookup);
      const resolved = classFromSymbol(symbol);
      if (resolved) return resolved;
      if (!symbol) return undefined;
      const key = classKey(symbol.parsed, symbol.local);
      if (nextSeen.has(key)) return undefined;
      const initializer = variables.get(key);
      return initializer && resolveValueClass(initializer.parsed, initializer.expression, ownerClass, new Set(nextSeen).add(key));
    }
    if (ts.isPropertyAccessExpression(current)) {
      const exported = classFromSymbol(resolveExpressionSymbol(parsed, current, lookup));
      if (exported) return exported;
      if (current.expression.kind === ts.SyntaxKind.ThisKeyword && ownerClass) {
        return resolveDependency(ownerClass, current.name.text);
      }
    }
    return undefined;
  };
  const parameterClass = (owner: ResolvedClass, parameter: ts.ParameterDeclaration): ResolvedClass | undefined => {
    if (parameter.initializer) {
      const initialized = resolveValueClass(owner.parsed, parameter.initializer, owner);
      if (initialized) return initialized;
    }
    return classFromType(owner.parsed, parameter.type);
  };
  const resolveDependency = (owner: ResolvedClass, property: string): ResolvedClass | undefined => {
    const cacheKey = `${owner.parsed.file.relativePath}\u0000${owner.declaration.pos}\u0000${property}`;
    const cached = dependencyCache.get(cacheKey);
    if (cached !== undefined) return cached ?? undefined;
    dependencyCache.set(cacheKey, null);
    for (const member of owner.declaration.members) {
      if (ts.isPropertyDeclaration(member) && propertyName(member.name) === property) {
        const initialized = member.initializer && resolveValueClass(owner.parsed, member.initializer, owner);
        const resolved = initialized || classFromType(owner.parsed, member.type);
        if (resolved) {
          dependencyCache.set(cacheKey, resolved);
          return resolved;
        }
      }
      if (!ts.isConstructorDeclaration(member)) continue;
      const directParameter = member.parameters.find((parameter) => ts.isIdentifier(parameter.name) && parameter.name.text === property);
      const direct = directParameter && parameterClass(owner, directParameter);
      if (direct) {
        dependencyCache.set(cacheKey, direct);
        return direct;
      }
      if (!member.body) continue;
      let assigned: ResolvedClass | undefined;
      visit(member.body, (node) => {
        if (assigned || !ts.isBinaryExpression(node) || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken
          || !ts.isPropertyAccessExpression(node.left) || node.left.expression.kind !== ts.SyntaxKind.ThisKeyword
          || node.left.name.text !== property) return;
        assigned = resolveValueClass(owner.parsed, node.right, owner);
        if (!assigned && ts.isIdentifier(unwrapExpression(node.right))) {
          const local = (unwrapExpression(node.right) as ts.Identifier).text;
          const parameter = member.parameters.find((item) => ts.isIdentifier(item.name) && item.name.text === local);
          assigned = parameter && parameterClass(owner, parameter);
        }
      });
      if (assigned) {
        dependencyCache.set(cacheKey, assigned);
        return assigned;
      }
    }
    return undefined;
  };

  const classMethod = (owner: ResolvedClass, name: string): ResolvedFunction | undefined => {
    for (const member of owner.declaration.members) {
      if (propertyName(member.name) !== name) continue;
      if (ts.isMethodDeclaration(member) && member.body) return { declaration: member, parsed: owner.parsed };
      if (ts.isPropertyDeclaration(member) && member.initializer) {
        const value = unwrapExpression(member.initializer);
        if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) return { declaration: value, parsed: owner.parsed };
      }
    }
    return undefined;
  };
  const classOwning = (resolved: ResolvedFunction): ResolvedClass | undefined => {
    for (const owner of classes.values()) {
      if (owner.parsed !== resolved.parsed) continue;
      if (owner.declaration.members.some((member) => member === resolved.declaration
        || (ts.isPropertyDeclaration(member) && member.initializer === resolved.declaration))) return owner;
    }
    return undefined;
  };
  const resolveCall = (
    parsed: ParsedSource,
    call: ts.CallExpression,
    ownerClass: ResolvedClass | undefined,
  ): { callable: ResolvedFunction; ownerClass?: ResolvedClass } | undefined => {
    const direct = resolveFunction(parsed, call.expression, lookup, declarations);
    if (direct) return { callable: direct, ownerClass: classOwning(direct) };
    const expression = unwrapExpression(call.expression);
    if (!ts.isPropertyAccessExpression(expression)) return undefined;
    let targetClass: ResolvedClass | undefined;
    if (expression.expression.kind === ts.SyntaxKind.ThisKeyword) targetClass = ownerClass;
    else if (ts.isPropertyAccessExpression(expression.expression)
      && expression.expression.expression.kind === ts.SyntaxKind.ThisKeyword && ownerClass) {
      targetClass = resolveDependency(ownerClass, expression.expression.name.text);
    } else targetClass = resolveValueClass(parsed, expression.expression, ownerClass);
    const callable = targetClass && classMethod(targetClass, expression.name.text);
    return callable ? { callable, ownerClass: targetClass } : undefined;
  };

  const identityDecorator = /^(?:CurrentUser|AuthenticatedUser|Principal|Identity|Actor)$/i;
  const expressionCarriesIdentity = (expression: ts.Expression, aliases: Set<string>): boolean => {
    const current = unwrapExpression(expression);
    if (ts.isAwaitExpression(current)) return expressionCarriesIdentity(current.expression, aliases);
    if (ts.isIdentifier(current)) return aliases.has(current.text);
    const segments = accessSegments(current);
    if (!segments || segments.length === 0) return false;
    const root = segments[0]!;
    if (aliases.has(root)) return true;
    if (!/^(?:req|request|ctx|context)$/.test(root)) return false;
    const requestOffset = segments[1] === "request" ? 2 : 1;
    return /^(?:user|auth|session)$/.test(segments[requestOffset] ?? "");
  };
  const collectBindingIdentifiers = (name: ts.BindingName, result: Set<string>): void => {
    if (ts.isIdentifier(name)) result.add(name.text);
    else for (const element of name.elements) if (!ts.isOmittedExpression(element)) collectBindingIdentifiers(element.name, result);
  };
  const identityAliases = (declaration: ts.FunctionLikeDeclaration, incoming: Set<string>): Set<string> => {
    const aliases = new Set(incoming);
    for (const parameter of declaration.parameters) {
      if (!ts.isIdentifier(parameter.name)) continue;
      if (decorators(parameter).map(decoratorDetails).some((item) => identityDecorator.test(item.name))) aliases.add(parameter.name.text);
    }
    let changed = true;
    while (changed) {
      changed = false;
      visit(declaration, (node) => {
        if (ts.isVariableDeclaration(node) && node.initializer && expressionCarriesIdentity(node.initializer, aliases)) {
          const additions = new Set<string>();
          collectBindingIdentifiers(node.name, additions);
          for (const addition of additions) if (!aliases.has(addition)) {
            aliases.add(addition);
            changed = true;
          }
        }
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
          && ts.isIdentifier(node.left) && expressionCarriesIdentity(node.right, aliases) && !aliases.has(node.left.text)) {
          aliases.add(node.left.text);
          changed = true;
        }
      });
    }
    return aliases;
  };
  const ownerExpression = (expression: ts.Expression): boolean => {
    const current = unwrapExpression(expression);
    if (ts.isIdentifier(current)) return OWNER_FIELD.test(current.text);
    const segments = accessSegments(current);
    return Boolean(segments?.at(-1) && OWNER_FIELD.test(segments.at(-1)!));
  };
  const astOwnershipBinding = (declaration: ts.FunctionLikeDeclaration, aliases: Set<string>): boolean => {
    let protectedByOwner = false;
    const insideObjectOperation = (node: ts.Node): boolean => {
      let current = node.parent;
      while (current && current !== declaration) {
        if (ts.isCallExpression(current)) {
          const name = expressionName(current.expression).replace(/\(\)/g, "");
          if (ID_OPERATION.test(name)) return true;
        }
        current = current.parent;
      }
      return false;
    };
    const relationBindsIdentity = (expression: ts.Expression): boolean => {
      const current = unwrapExpression(expression);
      if (!ts.isObjectLiteralExpression(current)) return false;
      let bound = false;
      visit(current, (node) => {
        if (bound) return;
        if (ts.isPropertyAssignment(node)) {
          const name = propertyName(node.name);
          if ((name === "id" || Boolean(name && OWNER_FIELD.test(name)))
            && expressionCarriesIdentity(node.initializer, aliases)) bound = true;
        } else if (ts.isShorthandPropertyAssignment(node)
          && (node.name.text === "id" || OWNER_FIELD.test(node.name.text)) && aliases.has(node.name.text)) bound = true;
      });
      return bound;
    };
    visit(declaration, (node) => {
      if (protectedByOwner) return;
      if (ts.isPropertyAssignment(node)) {
        const name = propertyName(node.name);
        if (insideObjectOperation(node) && name && OWNER_FIELD.test(name)
          && expressionCarriesIdentity(node.initializer, aliases)) protectedByOwner = true;
        else if (insideObjectOperation(node) && name && OWNER_RELATION_FIELD.test(name)
          && relationBindsIdentity(node.initializer)) protectedByOwner = true;
      } else if (ts.isShorthandPropertyAssignment(node) && insideObjectOperation(node)
        && OWNER_FIELD.test(node.name.text) && aliases.has(node.name.text)) {
        protectedByOwner = true;
      } else if (ts.isBinaryExpression(node) && [
        ts.SyntaxKind.EqualsEqualsToken,
        ts.SyntaxKind.EqualsEqualsEqualsToken,
        ts.SyntaxKind.ExclamationEqualsToken,
        ts.SyntaxKind.ExclamationEqualsEqualsToken,
      ].includes(node.operatorToken.kind)) {
        if ((ownerExpression(node.left) && expressionCarriesIdentity(node.right, aliases))
          || (ownerExpression(node.right) && expressionCarriesIdentity(node.left, aliases))) protectedByOwner = true;
      }
    });
    return protectedByOwner;
  };

  const cache = new Map<string, LocalCallSemantics>();
  const analyze = (
    parsed: ParsedSource,
    declaration: ts.FunctionLikeDeclaration,
    ownerClass: ResolvedClass | undefined,
    objectIdFields: string[],
  ): LocalCallSemantics => {
    const cacheKey = `${parsed.file.relativePath}\u0000${declaration.pos}\u0000${objectIdFields.join(",")}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;
    const queue: Array<{
      callable: ResolvedFunction;
      ownerClass?: ResolvedClass;
      aliases: Set<string>;
      depth: number;
    }> = [{ callable: { declaration, parsed }, ownerClass, aliases: new Set(), depth: 0 }];
    const visited = new Set<string>();
    const semanticSources: string[] = [];
    const responseFields = new Set<string>();
    let ownershipProtected = false;
    let roleProtected = false;
    let objectOperation = false;
    const maxDepth = 4;
    const maxCallables = 32;
    while (queue.length > 0 && visited.size < maxCallables) {
      const current = queue.shift()!;
      const aliases = identityAliases(current.callable.declaration, current.aliases);
      const visitKey = `${current.callable.parsed.file.relativePath}\u0000${current.callable.declaration.pos}\u0000${[...aliases].sort().join(",")}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);
      const source = current.callable.declaration.getText(current.callable.parsed.source);
      semanticSources.push(source);
      ownershipProtected ||= (current.depth === 0 && ownershipGuard(source, false))
        || ACCESS_GUARD_NAME.test(source) || astOwnershipBinding(current.callable.declaration, aliases);
      roleProtected ||= roleGuard(source);
      objectOperation ||= hasObjectOperation(current.callable.declaration, objectIdFields);
      for (const field of responseOwnerFields(current.callable.declaration)) responseFields.add(field);
      if (current.depth >= maxDepth) continue;
      visit(current.callable.declaration, (node) => {
        if (!ts.isCallExpression(node)) return;
        const target = resolveCall(current.callable.parsed, node, current.ownerClass);
        if (!target) return;
        const incoming = new Set<string>();
        for (let index = 0; index < Math.min(node.arguments.length, target.callable.declaration.parameters.length); index += 1) {
          const argument = node.arguments[index];
          const parameter = target.callable.declaration.parameters[index];
          if (!argument || !parameter || !ts.isIdentifier(parameter.name)) continue;
          if (expressionCarriesIdentity(argument, aliases)) incoming.add(parameter.name.text);
        }
        queue.push({ callable: target.callable, ownerClass: target.ownerClass, aliases: incoming, depth: current.depth + 1 });
      });
    }
    const result = {
      source: semanticSources.join("\n"),
      ownershipProtected,
      roleProtected,
      objectOperation,
      responseOwnerFields: [...responseFields].sort(),
    };
    cache.set(cacheKey, result);
    return result;
  };
  return { analyze };
}

function isExpressFactoryCall(expression: ts.Expression, expressFactories: Set<string>, routerFactories: Set<string>): "app" | "router" | undefined {
  const current = unwrapExpression(expression);
  if (!ts.isCallExpression(current)) return undefined;
  const name = expressionName(current.expression);
  if (expressFactories.has(name)) return "app";
  if (routerFactories.has(name) || [...expressFactories].some((factory) => name === `${factory}.Router`)) return "router";
  if (ts.isPropertyAccessExpression(current.expression) && current.expression.name.text === "Router"
    && requireModule(current.expression.expression) === "express") return "router";
  if (ts.isCallExpression(current.expression) && ts.isIdentifier(current.expression.expression)
    && current.expression.expression.text === "require" && literalText(current.expression.arguments[0]) === "express") return "app";
  return undefined;
}

function expressFactoryChain(
  expression: ts.Expression,
  expressFactories: Set<string>,
  routerFactories: Set<string>,
): { kind: "app" | "router"; expressions: ts.Expression[] } | undefined {
  const current = unwrapExpression(expression);
  const direct = isExpressFactoryCall(current, expressFactories, routerFactories);
  if (direct) return { kind: direct, expressions: [current] };
  if (!ts.isCallExpression(current) || !ts.isPropertyAccessExpression(current.expression)) return undefined;
  const parent = expressFactoryChain(current.expression.expression, expressFactories, routerFactories);
  return parent ? { kind: parent.kind, expressions: [...parent.expressions, current] } : undefined;
}

function expressRoutes(
  sources: ParsedSource[],
  localCalls: LocalCallAnalyzer,
): { routes: NodeApiRoute[]; unresolvedHandlers: number; unresolvedMounts: number } {
  const lookup = parsedSourceLookup(sources);
  const declarations = new Map(sources.map((parsed) => [parsed.file.relativePath, functionDeclarations(parsed.source)]));
  const variableInitializers = new Map<string, { parsed: ParsedSource; expression: ts.Expression }>();
  for (const parsed of sources) visit(parsed.source, (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      variableInitializers.set(`${parsed.file.relativePath}\u0000${node.name.text}`, { parsed, expression: node.initializer });
    }
  });
  const receivers = new Map<string, "app" | "router">();
  const expressionReceivers = new Map<ts.Expression, string>();
  const receiverKey = (parsed: ParsedSource, local: string): string => `${parsed.file.relativePath}\u0000${local}`;
  for (const parsed of sources) {
    const expressFactories = new Set<string>();
    const routerFactories = new Set<string>();
    for (const statement of parsed.source.statements) {
      if (ts.isImportDeclaration(statement) && literalText(statement.moduleSpecifier) === "express") {
        const clause = statement.importClause;
        if (clause?.name) expressFactories.add(clause.name.text);
        if (clause?.namedBindings && ts.isNamespaceImport(clause.namedBindings)) expressFactories.add(clause.namedBindings.name.text);
        if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            if ((element.propertyName?.text ?? element.name.text) === "Router") routerFactories.add(element.name.text);
          }
        }
      }
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!declaration.initializer) continue;
        const module = requireModule(declaration.initializer);
        if (module === "express" && ts.isIdentifier(declaration.name)) expressFactories.add(declaration.name.text);
        if (module === "express" && ts.isObjectBindingPattern(declaration.name)) {
          for (const element of declaration.name.elements) {
            const imported = propertyName(element.propertyName) ?? (ts.isIdentifier(element.name) ? element.name.text : "");
            if (imported === "Router" && ts.isIdentifier(element.name)) routerFactories.add(element.name.text);
          }
        }
      }
    }
    visit(parsed.source, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const chain = expressFactoryChain(node.initializer, expressFactories, routerFactories);
        if (chain) {
          const key = receiverKey(parsed, node.name.text);
          receivers.set(key, chain.kind);
          for (const item of chain.expressions) expressionReceivers.set(item, key);
        }
        return;
      }
      let exported: string | undefined;
      let expression: ts.Expression | undefined;
      if (ts.isExportAssignment(node)) {
        exported = "default";
        expression = node.expression;
      } else if (ts.isExpressionStatement(node) && ts.isBinaryExpression(node.expression)
        && node.expression.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
        exported = commonJsExportName(node.expression.left);
        expression = node.expression.right;
      }
      if (!exported || !expression) return;
      const chain = expressFactoryChain(expression, expressFactories, routerFactories);
      if (!chain) return;
      const key = receiverKey(parsed, syntheticExportLocal(exported));
      receivers.set(key, chain.kind);
      for (const item of chain.expressions) expressionReceivers.set(item, key);
    });
  }
  if (receivers.size === 0) return { routes: [], unresolvedHandlers: 0, unresolvedMounts: 0 };

  const resolvedReceiver = (parsed: ParsedSource, expression: ts.Expression): string | undefined => {
    const current = unwrapExpression(expression);
    const expressionReceiver = expressionReceivers.get(current);
    if (expressionReceiver) return expressionReceiver;
    const symbol = resolveExpressionSymbol(parsed, expression, lookup);
    if (!symbol) return undefined;
    const key = receiverKey(symbol.parsed, symbol.local);
    return receivers.has(key) ? key : undefined;
  };
  let receiversChanged = true;
  while (receiversChanged) {
    receiversChanged = false;
    for (const parsed of sources) visit(parsed.source, (node) => {
      if (!ts.isCallExpression(node)) return;
      const target = resolveFunction(parsed, node.expression, lookup, declarations);
      if (!target) return;
      for (let index = 0; index < Math.min(node.arguments.length, target.declaration.parameters.length); index += 1) {
        const argument = node.arguments[index];
        const parameter = target.declaration.parameters[index];
        if (!argument || !parameter || !ts.isIdentifier(parameter.name)) continue;
        const argumentReceiver = resolvedReceiver(parsed, argument);
        if (!argumentReceiver) continue;
        const parameterKey = receiverKey(target.parsed, parameter.name.text);
        if (receivers.has(parameterKey)) continue;
        receivers.set(parameterKey, receivers.get(argumentReceiver)!);
        receiversChanged = true;
      }
    });
  }
  const instances = new Map<string, ResolvedFunction>();
  for (const [key, initializer] of variableInitializers) {
    const current = unwrapExpression(initializer.expression);
    if (!ts.isNewExpression(current)) continue;
    const constructor = resolveFunction(initializer.parsed, current.expression, lookup, declarations);
    if (constructor) instances.set(key, constructor);
  }
  const assignedInstanceFunction = (
    instance: ResolvedFunction,
    property: string,
  ): ResolvedFunction | undefined => {
    let resolved: ResolvedFunction | undefined;
    visit(instance.declaration, (node) => {
      if (resolved || !ts.isBinaryExpression(node)
        || node.operatorToken.kind !== ts.SyntaxKind.EqualsToken
        || !ts.isPropertyAccessExpression(node.left)
        || node.left.expression.kind !== ts.SyntaxKind.ThisKeyword
        || node.left.name.text !== property) return;
      const value = unwrapExpression(node.right);
      if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) resolved = { declaration: value, parsed: instance.parsed };
      else resolved = resolveFunction(instance.parsed, value, lookup, declarations);
    });
    return resolved;
  };
  const resolveExpressFunction = (
    parsed: ParsedSource,
    expression: ts.Expression,
    seen = new Set<string>(),
  ): ResolvedFunction | undefined => {
    const direct = resolveFunction(parsed, expression, lookup, declarations);
    if (direct) return direct;
    const current = unwrapExpression(expression);
    const seenKey = `${parsed.file.relativePath}\u0000${current.getText(parsed.source)}`;
    if (seen.has(seenKey)) return undefined;
    const nextSeen = new Set(seen).add(seenKey);
    if (ts.isIdentifier(current)) {
      const initializer = variableInitializers.get(`${parsed.file.relativePath}\u0000${current.text}`);
      return initializer && resolveExpressFunction(initializer.parsed, initializer.expression, nextSeen);
    }
    if (ts.isPropertyAccessExpression(current) && ts.isIdentifier(current.expression)) {
      const instance = instances.get(`${parsed.file.relativePath}\u0000${current.expression.text}`);
      return instance && assignedInstanceFunction(instance, current.name.text);
    }
    return undefined;
  };
  const authenticatedExpression = (parsed: ParsedSource, expression: ts.Expression): boolean => {
    if (AUTH_GUARD_NAME.test(expressionName(expression))) return true;
    const resolved = resolveExpressFunction(parsed, expression);
    return Boolean(resolved && explicitAuthentication(resolved.declaration.getText(resolved.parsed.source)));
  };
  const roleExpression = (parsed: ParsedSource, expression: ts.Expression): boolean => {
    if (ROLE_GUARD_NAME.test(expressionName(expression))) return true;
    const resolved = resolveExpressFunction(parsed, expression);
    return Boolean(resolved && roleGuard(resolved.declaration.getText(resolved.parsed.source)));
  };
  const candidates: ExpressRouteCandidate[] = [];
  const middleware: ExpressMiddleware[] = [];
  const mounts: ExpressMount[] = [];
  let unresolvedHandlers = 0;
  let unresolvedMounts = 0;
  for (const parsed of sources) visit(parsed.source, (node) => {
      if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
      const receiver = resolvedReceiver(parsed, node.expression.expression);
      if (!receiver) return;
      const callName = node.expression.name.text.toLowerCase();
      if (callName === "use") {
        const prefixText = literalText(node.arguments[0]);
        const prefix = prefixText === undefined ? "" : normalizePath(prefixText);
        const expressions = node.arguments.slice(prefix ? 1 : 0);
        const childExpression = expressions.at(-1);
        const child = childExpression ? resolvedReceiver(parsed, childExpression) : undefined;
        const guardExpressions = child ? expressions.slice(0, -1) : expressions;
        const authenticated = guardExpressions.some((expression) => authenticatedExpression(parsed, expression));
        const roleProtected = guardExpressions.some((expression) => roleExpression(parsed, expression));
        if (child && child !== receiver) {
          const parentLocalPath = prefix || "/";
          mounts.push({
            parent: receiver,
            child,
            sourcePath: parsed.file.relativePath,
            offset: node.getStart(parsed.source),
            prefix,
            authenticated,
            roleProtected,
          });
          middleware.push({
            receiver,
            sourcePath: parsed.file.relativePath,
            offset: node.getStart(parsed.source),
            prefix: parentLocalPath,
            authenticated,
            roleProtected,
          });
        } else {
          middleware.push({ receiver, sourcePath: parsed.file.relativePath, offset: node.getStart(parsed.source), prefix, authenticated, roleProtected });
          if (childExpression && prefix && /(?:router|routes?)/i.test(expressionName(childExpression))
            && !authenticatedExpression(parsed, childExpression)) unresolvedMounts += 1;
        }
        return;
      }
      if (!HTTP_METHODS.has(callName) || node.arguments.length < 2) return;
      const rawPath = literalText(node.arguments[0]);
      if (rawPath === undefined) return;
      const path = normalizePath(rawPath);
      const handlerExpression = node.arguments.at(-1)!;
      const resolvedHandler = resolveExpressFunction(parsed, handlerExpression);
      if (!resolvedHandler) unresolvedHandlers += 1;
      const handler = resolvedHandler?.declaration;
      const handlerParsed = resolvedHandler?.parsed ?? parsed;
      const handlerSource = handler?.getText(handlerParsed.source) ?? handlerExpression.getText(parsed.source);
      const middlewareExpressions = node.arguments.slice(1, -1);
      const locallyAuthenticated = middlewareExpressions.some((expression) => authenticatedExpression(parsed, expression))
        || explicitAuthentication(handlerSource);
      const locallyRoleProtected = middlewareExpressions.some((expression) => roleExpression(parsed, expression))
        || roleGuard(handlerSource);
      const currentHandler = unwrapExpression(handlerExpression);
      const handlerName = ts.isIdentifier(currentHandler) ? currentHandler.text
        : ts.isPropertyAccessExpression(currentHandler) ? currentHandler.name.text
          : handler && "name" in handler && handler.name && ts.isIdentifier(handler.name) ? handler.name.text : "anonymous";
      candidates.push({
        receiver,
        parsed,
        handlerParsed,
        method: callName === "all" ? "ALL" : callName.toUpperCase(),
        path,
        offset: node.getStart(parsed.source),
        handlerName,
        handler,
        handlerSource,
        location: location(parsed, node),
        locallyAuthenticated,
        locallyRoleProtected,
      });
    });

  const protectedByMiddleware = (receiver: string, path: string, before: number, sourcePath: string): boolean => middleware.some((item) => item.receiver === receiver
    && item.sourcePath === sourcePath && item.authenticated && item.offset < before
    && (!item.prefix || path === item.prefix || path.startsWith(`${item.prefix}/`)));
  const roleProtectedByMiddleware = (receiver: string, path: string, before: number, sourcePath: string): boolean => middleware.some((item) => item.receiver === receiver
    && item.sourcePath === sourcePath && item.roleProtected && item.offset < before
    && (!item.prefix || path === item.prefix || path.startsWith(`${item.prefix}/`)));
  interface RouteVariant { path: string; inheritedAuthentication: boolean; inheritedRoleProtection: boolean }
  const routeVariants = (receiver: string, path: string, seen = new Set<string>()): RouteVariant[] => {
    if (seen.has(receiver)) return [{ path, inheritedAuthentication: false, inheritedRoleProtection: false }];
    const incoming = mounts.filter((mount) => mount.child === receiver);
    if (incoming.length === 0) return [{ path, inheritedAuthentication: false, inheritedRoleProtection: false }];
    const nextSeen = new Set(seen).add(receiver);
    return incoming.flatMap((mount) => {
      const mountedPath = joinPath(mount.prefix, path);
      const mountAuthentication = mount.authenticated
        || protectedByMiddleware(mount.parent, mount.prefix || "/", mount.offset, mount.sourcePath);
      const mountRoleProtection = mount.roleProtected
        || roleProtectedByMiddleware(mount.parent, mount.prefix || "/", mount.offset, mount.sourcePath);
      return routeVariants(mount.parent, mountedPath, nextSeen).map((parent) => ({
        path: parent.path,
        inheritedAuthentication: mountAuthentication || parent.inheritedAuthentication,
        inheritedRoleProtection: mountRoleProtection || parent.inheritedRoleProtection,
      }));
    });
  };
  const routes: NodeApiRoute[] = [];
  for (const candidate of candidates) {
    for (const variant of routeVariants(candidate.receiver, candidate.path)) {
      const fields = objectIdFields(candidate.handler, variant.path, new Set(), new Set());
      const semantics = candidate.handler
        ? localCalls.analyze(candidate.handlerParsed, candidate.handler, undefined, fields)
        : {
          source: candidate.handlerSource,
          ownershipProtected: ownershipGuard(candidate.handlerSource),
          roleProtected: roleGuard(candidate.handlerSource),
          objectOperation: false,
          responseOwnerFields: [],
        };
      routes.push({
        framework: "Express",
        method: candidate.method,
        path: variant.path,
        declaredPath: candidate.path,
        sourcePath: candidate.parsed.file.relativePath,
        handlerName: candidate.handlerName,
        handlerSource: candidate.handlerSource,
        location: candidate.location,
        authenticationProtected: candidate.locallyAuthenticated || variant.inheritedAuthentication
          || protectedByMiddleware(candidate.receiver, candidate.path, candidate.offset, candidate.parsed.file.relativePath),
        ownershipProtected: semantics.ownershipProtected,
        roleProtected: semantics.roleProtected || candidate.locallyRoleProtected || variant.inheritedRoleProtection
          || roleProtectedByMiddleware(candidate.receiver, candidate.path, candidate.offset, candidate.parsed.file.relativePath),
        privilegedOperation: privilegedOperation(variant.path, candidate.handlerName, semantics.source),
        objectOperation: semantics.objectOperation,
        objectIdFields: fields,
        responseOwnerFields: semantics.responseOwnerFields,
      });
    }
  }
  return { routes, unresolvedHandlers, unresolvedMounts };
}

interface NestSecuritySemantics {
  authenticationGuards: Set<string>;
  ownershipGuards: Set<string>;
  roleGuards: Set<string>;
  authenticationDecorators: Set<string>;
  ownershipDecorators: Set<string>;
  roleDecorators: Set<string>;
}

interface NestGlobalSecurity {
  authentication: boolean;
  ownership: boolean;
  role: boolean;
}

function semanticExpression(
  parsed: ParsedSource,
  expression: ts.Expression,
  names: Set<string>,
  lookup: Map<string, ParsedSource>,
): boolean {
  let current = unwrapExpression(expression);
  if (ts.isNewExpression(current) || ts.isCallExpression(current)) current = current.expression;
  const name = expressionName(current).split(".").pop() ?? "";
  if (names.has(name)) return true;
  const symbol = resolveExpressionSymbol(parsed, current, lookup);
  return Boolean(symbol && names.has(symbol.local));
}

function guardAuthentication(source: string): boolean {
  if (explicitAuthentication(source)) return true;
  const identity = /(?:request|req|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session)|\b(?:principal|identity|currentUser|authenticatedUser)\b/i;
  const decision = /(?:UnauthorizedException|AuthenticationError|NotAuthenticated|status\s*\(\s*401|isAuthenticated\s*\(|jwt\w*\s*\.\s*verify|verifyAsync\s*\(|verifyToken\s*\(|authorization[\s\S]{0,100}bearer|return\s+(?:Boolean\s*\(|!!\s*)?(?:request|req|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session))/i;
  return identity.test(source) && decision.test(source);
}

function discoverNestSecurity(sources: ParsedSource[], lookup: Map<string, ParsedSource>): NestSecuritySemantics {
  const semantics: NestSecuritySemantics = {
    authenticationGuards: new Set(),
    ownershipGuards: new Set(),
    roleGuards: new Set(),
    authenticationDecorators: new Set(),
    ownershipDecorators: new Set(),
    roleDecorators: new Set(),
  };
  for (const parsed of sources) {
    for (const statement of parsed.source.statements) {
      if (!ts.isClassDeclaration(statement) || !statement.name) continue;
      const source = statement.getText(parsed.source);
      const canActivate = statement.members.some((member) => ts.isMethodDeclaration(member)
        && propertyName(member.name) === "canActivate");
      const inheritedAuthGuard = statement.heritageClauses?.some((clause) => /\bAuthGuard\s*\(/.test(clause.getText(parsed.source))) ?? false;
      if (!canActivate && !inheritedAuthGuard) continue;
      const ownership = ownershipGuard(source)
        || (NEST_OWNERSHIP_GUARD_HINT.test(source) && /(?:ForbiddenException|AccessDenied|status\s*\(\s*403|canActivate[\s\S]{0,500}return)/i.test(source));
      const role = roleGuard(source);
      const authentication = inheritedAuthGuard || guardAuthentication(source) || ownership || role;
      if (authentication) semantics.authenticationGuards.add(statement.name.text);
      if (ownership) semantics.ownershipGuards.add(statement.name.text);
      if (role) semantics.roleGuards.add(statement.name.text);
    }
  }

  const declarations = sources.flatMap((parsed) => [...functionDeclarations(parsed.source)].map(([name, declaration]) => ({
    parsed,
    name,
    declaration,
  })));
  let changed = true;
  while (changed) {
    changed = false;
    for (const item of declarations) {
      let authentication = false;
      let ownership = false;
      let role = false;
      visit(item.declaration, (node) => {
        if (!ts.isCallExpression(node)) return;
        const callName = expressionName(node.expression).split(".").pop() ?? "";
        if (/^(?:Auth|Authenticated|RequireAuth|Roles?|Permissions?|Policies|Authorize)$/i.test(callName)
          || semanticExpression(item.parsed, node.expression, semantics.authenticationDecorators, lookup)) authentication = true;
        if (/^(?:Roles?|Permissions?|Policies|CheckPolicies|Authorize|RequireOwner|RequireAccess)$/i.test(callName)
          || semanticExpression(item.parsed, node.expression, semantics.ownershipDecorators, lookup)) ownership = true;
        if (/^(?:Roles?|Permissions?|Policies|CheckPolicies|Authorize|RequireAdmin|AdminOnly)$/i.test(callName)
          || semanticExpression(item.parsed, node.expression, semantics.roleDecorators, lookup)) role = true;
        if (callName === "UseGuards") {
          if (node.arguments.some((argument) => {
            const symbol = resolveExpressionSymbol(item.parsed, argument, lookup);
            const known = symbol && (semantics.authenticationGuards.has(symbol.local) || semantics.ownershipGuards.has(symbol.local));
            return semanticExpression(item.parsed, argument, semantics.authenticationGuards, lookup)
              || (!known && NEST_AUTH_GUARD_HINT.test(argument.getText(item.parsed.source)));
          })) authentication = true;
          if (node.arguments.some((argument) => {
            const symbol = resolveExpressionSymbol(item.parsed, argument, lookup);
            const known = symbol && (semantics.authenticationGuards.has(symbol.local) || semantics.ownershipGuards.has(symbol.local));
            return semanticExpression(item.parsed, argument, semantics.ownershipGuards, lookup)
              || (!known && NEST_OWNERSHIP_GUARD_HINT.test(argument.getText(item.parsed.source)));
          })) ownership = true;
          if (node.arguments.some((argument) => {
            const symbol = resolveExpressionSymbol(item.parsed, argument, lookup);
            const known = symbol && (semantics.authenticationGuards.has(symbol.local)
              || semantics.ownershipGuards.has(symbol.local) || semantics.roleGuards.has(symbol.local));
            return semanticExpression(item.parsed, argument, semantics.roleGuards, lookup)
              || (!known && /(?:role|permission|policy|ability|admin)/i.test(argument.getText(item.parsed.source)));
          })) role = true;
        }
        if (callName === "SetMetadata") {
          const key = literalText(node.arguments[0]) ?? "";
          if (/^(?:roles?|permissions?|policies|abilities|ownership|tenant)$/i.test(key)) ownership = true;
          if (/^(?:roles?|permissions?|policies|abilities)$/i.test(key)) role = true;
        }
      });
      if (role) ownership = true;
      if (ownership) authentication = true;
      if (authentication && !semantics.authenticationDecorators.has(item.name)) {
        semantics.authenticationDecorators.add(item.name);
        changed = true;
      }
      if (ownership && !semantics.ownershipDecorators.has(item.name)) {
        semantics.ownershipDecorators.add(item.name);
        changed = true;
      }
      if (role && !semantics.roleDecorators.has(item.name)) {
        semantics.roleDecorators.add(item.name);
        changed = true;
      }
    }
  }
  return semantics;
}

function globalNestSecurity(
  sources: ParsedSource[],
  semantics: NestSecuritySemantics,
  lookup: Map<string, ParsedSource>,
): NestGlobalSecurity {
  const result: NestGlobalSecurity = { authentication: false, ownership: false, role: false };
  const classify = (parsed: ParsedSource, expression: ts.Expression): void => {
    let current = unwrapExpression(expression);
    if (ts.isNewExpression(current) || ts.isCallExpression(current)) current = current.expression;
    const symbol = resolveExpressionSymbol(parsed, current, lookup);
    const known = Boolean(symbol && (semantics.authenticationGuards.has(symbol.local)
      || semantics.ownershipGuards.has(symbol.local) || semantics.roleGuards.has(symbol.local)));
    const source = expression.getText(parsed.source);
    const role = semanticExpression(parsed, expression, semantics.roleGuards, lookup)
      || (!known && /(?:role|permission|policy|ability|admin)/i.test(source));
    const ownership = role || semanticExpression(parsed, expression, semantics.ownershipGuards, lookup)
      || (!known && NEST_OWNERSHIP_GUARD_HINT.test(source));
    const authentication = ownership || semanticExpression(parsed, expression, semantics.authenticationGuards, lookup)
      || (!known && NEST_AUTH_GUARD_HINT.test(source));
    result.authentication ||= authentication;
    result.ownership ||= ownership;
    result.role ||= role;
  };
  for (const parsed of sources) {
    visit(parsed.source, (node) => {
      if (ts.isCallExpression(node) && /(?:^|\.)useGlobalGuards$/.test(expressionName(node.expression))) {
        for (const argument of node.arguments) classify(parsed, argument);
      }
      if (ts.isObjectLiteralExpression(node)) {
        const properties = new Map(node.properties.filter(ts.isPropertyAssignment)
          .map((property) => [propertyName(property.name), property.initializer]));
        const provide = properties.get("provide");
        const implementation = properties.get("useClass") ?? properties.get("useExisting") ?? properties.get("useValue");
        if (provide && ts.isIdentifier(unwrapExpression(provide)) && (unwrapExpression(provide) as ts.Identifier).text === "APP_GUARD"
          && implementation) classify(parsed, implementation);
      }
    });
  }
  return result;
}

function nestDecoratorAuthentication(
  values: Array<{ name: string; arguments: readonly ts.Expression[] }>,
  parsed: ParsedSource,
  semantics: NestSecuritySemantics,
  lookup: Map<string, ParsedSource>,
): boolean {
  return values.some((item) => {
    if (/^(?:Auth|Authenticated|RequireAuth|Roles?|Permissions?|Policies|Authorize)$/i.test(item.name)) return true;
    const local = resolveLocalSymbol(parsed, item.name, lookup);
    if (semantics.authenticationDecorators.has(item.name) || (local && semantics.authenticationDecorators.has(local.local))) return true;
    return item.name === "UseGuards" && item.arguments.some((argument) => semanticExpression(parsed, argument, semantics.authenticationGuards, lookup)
      || NEST_AUTH_GUARD_HINT.test(argument.getText(parsed.source)));
  });
}

function nestDecoratorOwnership(
  values: Array<{ name: string; arguments: readonly ts.Expression[] }>,
  parsed: ParsedSource,
  semantics: NestSecuritySemantics,
  lookup: Map<string, ParsedSource>,
): boolean {
  return values.some((item) => {
    if (/^(?:Roles?|Permissions?|Policies|CheckPolicies|Authorize|RequireOwner|RequireAccess)$/i.test(item.name)) return true;
    const local = resolveLocalSymbol(parsed, item.name, lookup);
    if (semantics.ownershipDecorators.has(item.name) || (local && semantics.ownershipDecorators.has(local.local))) return true;
    return item.name === "UseGuards"
      && item.arguments.some((argument) => semanticExpression(parsed, argument, semantics.ownershipGuards, lookup)
        || NEST_OWNERSHIP_GUARD_HINT.test(argument.getText(parsed.source)));
  });
}

function nestDecoratorRole(
  values: Array<{ name: string; arguments: readonly ts.Expression[] }>,
  parsed: ParsedSource,
  semantics: NestSecuritySemantics,
  lookup: Map<string, ParsedSource>,
): boolean {
  return values.some((item) => {
    if (/^(?:Roles?|Permissions?|Policies|CheckPolicies|Authorize|RequireAdmin|AdminOnly)$/i.test(item.name)) return true;
    const local = resolveLocalSymbol(parsed, item.name, lookup);
    if (semantics.roleDecorators.has(item.name) || (local && semantics.roleDecorators.has(local.local))) return true;
    return item.name === "UseGuards"
      && item.arguments.some((argument) => semanticExpression(parsed, argument, semantics.roleGuards, lookup)
        || /(?:role|permission|policy|ability|admin)/i.test(argument.getText(parsed.source)));
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

function objectProperty(expression: ts.Expression | undefined, name: string): ts.Expression | undefined {
  const current = expression && unwrapExpression(expression);
  if (!current || !ts.isObjectLiteralExpression(current)) return undefined;
  const property = current.properties.find((item): item is ts.PropertyAssignment => ts.isPropertyAssignment(item)
    && propertyName(item.name) === name);
  return property?.initializer;
}

function nestVersionValues(expression: ts.Expression | undefined): NestVersion[] {
  if (!expression) return [];
  const current = unwrapExpression(expression);
  if (ts.isIdentifier(current) && current.text === "VERSION_NEUTRAL") return [null];
  if (ts.isPropertyAccessExpression(current) && current.name.text === "VERSION_NEUTRAL") return [null];
  const literal = literalText(current);
  if (literal !== undefined) return [literal];
  if (ts.isArrayLiteralExpression(current)) return current.elements.flatMap((item) => ts.isExpression(item) ? nestVersionValues(item) : []);
  return [];
}

function nestRoutingConfig(sources: ParsedSource[]): NestRoutingConfig {
  const config: NestRoutingConfig = {
    globalPrefix: "",
    prefixExcludes: new Set(),
    uriVersioning: false,
    defaultVersions: [],
    versionPrefix: "v",
  };
  for (const parsed of sources) visit(parsed.source, (node) => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
    const name = node.expression.name.text;
    if (name === "setGlobalPrefix") {
      const prefix = literalText(node.arguments[0]);
      if (prefix !== undefined) config.globalPrefix = prefix;
      const exclude = objectProperty(node.arguments[1], "exclude");
      const current = exclude && unwrapExpression(exclude);
      if (current && ts.isArrayLiteralExpression(current)) {
        for (const item of current.elements) {
          if (!ts.isExpression(item)) continue;
          const excludedPath = literalText(item) ?? literalText(objectProperty(item, "path"));
          if (excludedPath !== undefined) config.prefixExcludes.add(normalizePath(excludedPath));
        }
      }
    }
    if (name !== "enableVersioning") return;
    const options = node.arguments[0];
    const type = objectProperty(options, "type");
    if (!type || !/(?:^|\.)URI$/.test(expressionName(unwrapExpression(type)))) return;
    config.uriVersioning = true;
    config.defaultVersions = nestVersionValues(objectProperty(options, "defaultVersion"));
    const prefix = objectProperty(options, "prefix");
    if (prefix?.kind === ts.SyntaxKind.FalseKeyword) config.versionPrefix = "";
    else {
      const literalPrefix = literalText(prefix);
      if (literalPrefix !== undefined) config.versionPrefix = literalPrefix;
    }
  });
  return config;
}

function nestRoutePaths(
  localPath: string,
  methodDecorators: Array<{ name: string; arguments: readonly ts.Expression[] }>,
  classDecorators: Array<{ name: string; arguments: readonly ts.Expression[] }>,
  config: NestRoutingConfig,
): string[] {
  const methodVersion = methodDecorators.find((item) => item.name === "Version");
  const classVersion = classDecorators.find((item) => item.name === "Version");
  const explicitVersions = nestVersionValues(methodVersion?.arguments[0] ?? classVersion?.arguments[0]);
  const versions = config.uriVersioning
    ? (explicitVersions.length > 0 ? explicitVersions : config.defaultVersions)
    : [];
  const variants = versions.length > 0 ? versions : [null];
  const excluded = config.prefixExcludes.has(normalizePath(localPath));
  return variants.map((version) => joinPath(
    excluded ? "" : config.globalPrefix,
    version === null ? "" : `${config.versionPrefix}${version}`,
    localPath,
  ));
}

function nestRoutes(
  parsed: ParsedSource,
  globalSecurity: NestGlobalSecurity,
  semantics: NestSecuritySemantics,
  lookup: Map<string, ParsedSource>,
  routing: NestRoutingConfig,
  localCalls: LocalCallAnalyzer,
): NodeApiRoute[] {
  const routes: NodeApiRoute[] = [];
  for (const statement of parsed.source.statements) {
    if (!ts.isClassDeclaration(statement)) continue;
    const classDecorators = decorators(statement).map(decoratorDetails);
    const controller = classDecorators.find((item) => item.name === "Controller");
    if (!controller) continue;
    const prefix = normalizePath(literalText(controller.arguments[0]) ?? "");
    const classAuthenticated = nestDecoratorAuthentication(classDecorators, parsed, semantics, lookup);
    const classOwnership = nestDecoratorOwnership(classDecorators, parsed, semantics, lookup);
    const classRole = nestDecoratorRole(classDecorators, parsed, semantics, lookup);
    for (const member of statement.members) {
      if (!ts.isMethodDeclaration(member) || !member.body) continue;
      const methodDecorators = decorators(member).map(decoratorDetails);
      const routeDecorators = methodDecorators.filter((item) => /^(?:Get|Post|Put|Patch|Delete|Options|Head|All)$/.test(item.name));
      if (routeDecorators.length === 0) continue;
      const isPublic = methodDecorators.some((item) => /^(?:Public|AllowAnonymous)$/.test(item.name));
      const methodAuthenticated = nestDecoratorAuthentication(methodDecorators, parsed, semantics, lookup);
      const methodRole = nestDecoratorRole(methodDecorators, parsed, semantics, lookup);
      const source = member.getText(parsed.source);
      const inputs = nestInputDetails(member);
      for (const routeDecorator of routeDecorators) {
        const localPath = joinPath(prefix, literalText(routeDecorator.arguments[0]) ?? "");
        for (const path of nestRoutePaths(localPath, methodDecorators, classDecorators, routing)) {
          const fields = objectIdFields(member, path, inputs.roots, inputs.fields);
          const callSemantics = localCalls.analyze(parsed, member, { parsed, declaration: statement }, fields);
          routes.push({
            framework: "NestJS",
            method: routeDecorator.name === "All" ? "ALL" : routeDecorator.name.toUpperCase(),
            path,
            declaredPath: localPath,
            sourcePath: parsed.file.relativePath,
            handlerName: propertyName(member.name) ?? "anonymous",
            handlerSource: source,
            location: location(parsed, member),
            authenticationProtected: methodAuthenticated
              || (!isPublic && (classAuthenticated || globalSecurity.authentication)) || explicitAuthentication(callSemantics.source),
            ownershipProtected: classOwnership || (!isPublic && globalSecurity.ownership)
              || nestDecoratorOwnership(methodDecorators, parsed, semantics, lookup) || callSemantics.ownershipProtected,
            roleProtected: classRole || methodRole || (!isPublic && globalSecurity.role) || callSemantics.roleProtected,
            privilegedOperation: privilegedOperation(path, propertyName(member.name) ?? "anonymous", callSemantics.source),
            objectOperation: callSemantics.objectOperation,
            objectIdFields: fields,
            responseOwnerFields: callSemantics.responseOwnerFields,
          });
        }
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
    const bindings = moduleBindings(source);
    parsed.push({ file, source, modules: moduleNames(source), ...bindings });
  }
  const detectedExpress = packages.has("express") || parsed.some((item) => item.modules.has("express"));
  const detectedNest = packages.has("@nestjs/core") || packages.has("@nestjs/common")
    || parsed.some((item) => [...item.modules].some((name) => name === "@nestjs/core" || name === "@nestjs/common"));
  const lookup = parsedSourceLookup(parsed);
  const localCalls = createLocalCallAnalyzer(parsed, lookup);
  const routes: NodeApiRoute[] = [];
  let unresolvedHandlers = 0;
  let unresolvedMounts = 0;
  if (detectedExpress) {
    const result = expressRoutes(parsed, localCalls);
    routes.push(...result.routes);
    unresolvedHandlers += result.unresolvedHandlers;
    unresolvedMounts += result.unresolvedMounts;
  }
  if (detectedNest) {
    const semantics = discoverNestSecurity(parsed, lookup);
    const globalSecurity = globalNestSecurity(parsed, semantics, lookup);
    const routing = nestRoutingConfig(parsed);
    for (const item of parsed) routes.push(...nestRoutes(item, globalSecurity, semantics, lookup, routing, localCalls));
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
