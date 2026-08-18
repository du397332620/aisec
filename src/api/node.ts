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
  unresolvedRegistrations: number;
  unresolvedProviderDependencies: number;
  unresolvedBootstrapRoots: number;
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
  ownerClass?: ResolvedClass;
}

interface ResolvedClass {
  declaration: ts.ClassDeclaration;
  parsed: ParsedSource;
  nestModule?: string;
  construction?: {
    parsed: ParsedSource;
    expression: ts.NewExpression;
    ownerClass?: ResolvedClass;
  };
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
  resolveMethod(parsed: ParsedSource, expression: ts.Expression): ResolvedFunction | undefined;
  nestControllerClass(parsed: ParsedSource, declaration: ts.ClassDeclaration): ResolvedClass;
  globalGuardProviders(ownerClass: ResolvedClass | undefined): ResolvedClass[];
  unresolvedProviderDependencies(): number;
  unresolvedBootstrapRoots(): number;
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
  handlerOwnerClass?: ResolvedClass;
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
const ID_OPERATION = /(?:^|\.)(?:findById|findByIdAndUpdate|findByIdAndDelete|findByPk|findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne|findOneBy|findOneByOrFail|findMany|getById|getBy[A-Z][A-Za-z0-9_]*|getOne|getOneOrFail|getRawOne|loadById|detail|update|updateOne|updateMany|delete|deleteOne|deleteMany|remove|destroy|where)$/;
const DIRECT_FILTER_ARGUMENT_OPERATION = /(?:^|\.)(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne|findOneBy|findOneByOrFail|findMany|where)$/;
const NEST_AUTH_GUARD_HINT = /(?:auth|jwt|session|identity|loggedIn|signedIn|user|role|permission|policy|ability|access|owner|admin)/i;
const NEST_OWNERSHIP_GUARD_HINT = /(?:owner|ownership|tenant|role|permission|policy|ability|access|admin)/i;
const PRIVILEGED_ROUTE_HINT = /(?:^|\/)(?:admin|administration|manage|management|permissions?|roles?)(?:\/|$)/i;
const PRIVILEGED_HANDLER_HINT = /(?:admin|nonAdmin|allUsers?|manageUsers?|permissions?|roles?)/i;
const MAX_STATIC_ROUTE_ENTRIES = 128;
const MAX_STATIC_ROUTE_EXPANSIONS = 512;
const MAX_STATIC_ROUTE_TRANSFORMS = 2;
const MAX_STATIC_ROUTE_TABLE_DEPTH = 8;
const MAX_STATIC_ROUTE_MAP_FIELDS = 32;
const MAX_STATIC_PROVIDER_ENTRIES = 256;
const MAX_PROVIDER_RESOLUTION_DEPTH = 8;
const MAX_NEST_MODULE_GRAPH_ENTRIES = 256;
const MAX_NEST_MODULE_GRAPH_DEPTH = 8;
const MAX_LOCAL_CLASS_HERITAGE_DEPTH = 4;
const NEST_BOOTSTRAP_ENTRY_PATH = /(?:^|\/)(?:main|server|bootstrap|index)\.(?:[cm]?[jt]sx?)$/i;

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

function ownershipGuard(
  source: string,
  allowUnscopedDirectBinding = true,
  allowNamedAccessGuard = true,
): boolean {
  if (allowNamedAccessGuard && ACCESS_GUARD_NAME.test(source)) return true;
  const identity = String.raw`(?:(?:req(?:uest)?|ctx|context)\s*(?:\?\.)?\.\s*(?:user|auth|session)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?|(?:currentUser|authenticatedUser|principal|identity)(?:\s*(?:\?\.)?\.\s*(?:id|userId|tenantId|role|isAdmin))?)`;
  const owner = String.raw`(?:owner_id|user_id|tenant_id|creator_id|created_by|account_id|organization_id|org_id|ownerId|userId|tenantId|creatorId|createdBy|accountId|organizationId|orgId)`;
  const directBinding = new RegExp(`${owner}\\s*:\\s*${identity}`, "i");
  const comparison = new RegExp(`(?:\\.\\s*${owner}|\\b${owner}\\b)\\s*(?:===?|!==?)\\s*${identity}|${identity}\\s*(?:===?|!==?)\\s*(?:\\.\\s*${owner}|\\b${owner}\\b)`, "i");
  const roleDenial = new RegExp(`${identity}[\\s\\S]{0,180}?(?:role|isAdmin|permissions?|ability)[\\s\\S]{0,180}?(?:Forbidden|status\\s*\\(\\s*403|AccessDenied)`, "i");
  return (allowUnscopedDirectBinding && directBinding.test(source)) || comparison.test(source) || roleDenial.test(source);
}

function roleGuard(source: string): boolean {
  if (ROLE_GUARD_NAME.test(source)) return true;
  const role = /(?:isAdmin|admin|roles?|permissions?|policies|abilities)/i;
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
  const variables = new Map<string, {
    parsed: ParsedSource;
    expression: ts.Expression;
    constant: boolean;
    topLevel: boolean;
  }>();
  const classes = new Map<string, ResolvedClass>();
  const directEsmImports = new Set<string>();
  const classKey = (parsed: ParsedSource, local: string): string => `${parsed.file.relativePath}\u0000${local}`;
  const classDeclarationIdentity = (resolved: ResolvedClass): string =>
    `class:${resolved.parsed.file.relativePath}:${resolved.declaration.pos}`;
  const resolvedClassIdentity = (resolved: ResolvedClass): string => {
    const base = resolved.construction
      ? `new:${resolved.construction.parsed.file.relativePath}:${resolved.construction.expression.pos}`
      : classDeclarationIdentity(resolved);
    return resolved.nestModule ? `${base}:nest-module:${resolved.nestModule}` : base;
  };
  for (const parsed of sources) {
    for (const statement of parsed.source.statements) {
      if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier)) continue;
      const clause = statement.importClause;
      if (!clause || clause.isTypeOnly) continue;
      if (clause.name) directEsmImports.add(classKey(parsed, clause.name.text));
      if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
        directEsmImports.add(classKey(parsed, clause.namedBindings.name.text));
      }
      if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
        for (const element of clause.namedBindings.elements) {
          if (!element.isTypeOnly) directEsmImports.add(classKey(parsed, element.name.text));
        }
      }
    }
    visit(parsed.source, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        variables.set(classKey(parsed, node.name.text), {
          parsed,
          expression: node.initializer,
          constant: (node.parent.flags & ts.NodeFlags.Const) !== 0,
          topLevel: node.parent.parent.parent === parsed.source,
        });
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

  interface ProviderTarget {
    implementation?: ResolvedClass;
    alias?: string;
    unresolved?: boolean;
    signature: string;
  }
  const unresolvedInjectedDependencies = new Set<string>();
  const importedReference = (
    parsed: ParsedSource,
    expression: ts.Expression,
    module: string,
    imported: string,
  ): boolean => {
    const current = unwrapExpression(expression);
    if (ts.isIdentifier(current)) {
      const binding = parsed.imports.get(current.text);
      return directEsmImports.has(classKey(parsed, current.text))
        && Boolean(binding && !binding.namespace && binding.module === module && binding.imported === imported);
    }
    if (ts.isPropertyAccessExpression(current) && ts.isIdentifier(current.expression)
      && current.name.text === imported) {
      const binding = parsed.imports.get(current.expression.text);
      return directEsmImports.has(classKey(parsed, current.expression.text))
        && Boolean(binding?.namespace && binding.module === module);
    }
    return false;
  };
  const forwardRefValue = (
    parsed: ParsedSource,
    expression: ts.Expression,
  ): { parsed: ParsedSource; expression: ts.Expression } | undefined => {
    const current = unwrapExpression(expression);
    if (!ts.isCallExpression(current) || current.arguments.length !== 1
      || !importedReference(parsed, current.expression, "@nestjs/common", "forwardRef")) return undefined;
    const callback = unwrapExpression(current.arguments[0]!);
    if ((!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))
      || callback.parameters.length !== 0 || hasModifier(callback, ts.SyntaxKind.AsyncKeyword)
      || (ts.isFunctionExpression(callback) && Boolean(callback.asteriskToken))) return undefined;
    if (!ts.isBlock(callback.body)) return { parsed, expression: callback.body };
    const returned = callback.body.statements[0];
    if (callback.body.statements.length !== 1 || !returned || !ts.isReturnStatement(returned)
      || !returned.expression) return undefined;
    return { parsed, expression: returned.expression };
  };
  const providerTokenKey = (
    parsed: ParsedSource,
    expression: ts.Expression | undefined,
    depth = 0,
  ): string | undefined => {
    if (!expression) return undefined;
    if (depth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    const forwarded = forwardRefValue(parsed, expression);
    if (forwarded) return providerTokenKey(forwarded.parsed, forwarded.expression, depth + 1);
    const current = unwrapExpression(expression);
    const literal = literalText(current);
    if (literal !== undefined) return `string:${literal}`;
    if (ts.isNumericLiteral(current)) return `number:${current.text}`;
    if (current.kind === ts.SyntaxKind.TrueKeyword || current.kind === ts.SyntaxKind.FalseKeyword) {
      return `boolean:${current.kind === ts.SyntaxKind.TrueKeyword}`;
    }
    const symbol = resolveExpressionSymbol(parsed, current, lookup);
    return symbol ? `symbol:${classKey(symbol.parsed, symbol.local)}` : undefined;
  };
  const nestDecoratorArguments = (
    parsed: ParsedSource,
    node: ts.Node,
    importedName: "Inject" | "Module",
  ): readonly ts.Expression[] | undefined => {
    for (const decorator of decorators(node)) {
      if (!ts.isCallExpression(decorator.expression)) continue;
      const callee = unwrapExpression(decorator.expression.expression);
      if (ts.isIdentifier(callee)) {
        const binding = parsed.imports.get(callee.text);
        if (binding?.module === "@nestjs/common" && !binding.namespace && binding.imported === importedName) {
          return decorator.expression.arguments;
        }
      }
      if (ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression)
        && callee.name.text === importedName) {
        const binding = parsed.imports.get(callee.expression.text);
        if (binding?.module === "@nestjs/common" && binding.namespace) return decorator.expression.arguments;
      }
    }
    return undefined;
  };
  const injectedProvider = (parsed: ParsedSource, node: ts.Node): { declared: boolean; key?: string } => {
    const arguments_ = nestDecoratorArguments(parsed, node, "Inject");
    return arguments_ ? { declared: true, key: providerTokenKey(parsed, arguments_[0]) } : { declared: false };
  };
  const factoryResultClass = (parsed: ParsedSource, expression: ts.Expression): ResolvedClass | undefined => {
    const current = unwrapExpression(expression);
    const factory = ts.isArrowFunction(current) || ts.isFunctionExpression(current)
      ? { declaration: current, parsed }
      : resolveFunction(parsed, current, lookup, declarations);
    if (!factory?.declaration.body) return undefined;
    let returned: ts.Expression | undefined;
    if (!ts.isBlock(factory.declaration.body)) returned = factory.declaration.body;
    else {
      const returns = factory.declaration.body.statements.filter(ts.isReturnStatement);
      if (returns.length !== 1) return undefined;
      returned = returns[0]?.expression;
    }
    const value = returned && unwrapExpression(returned);
    if (!value || !ts.isNewExpression(value)) return undefined;
    return classFromSymbol(resolveExpressionSymbol(factory.parsed, value.expression, lookup));
  };
  const providerArray = (
    parsed: ParsedSource,
    expression: ts.Expression | undefined,
    seen = new Set<string>(),
    depth = 0,
  ): Array<{ parsed: ParsedSource; expression: ts.Expression }> | undefined => {
    if (!expression || depth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    const current = unwrapExpression(expression);
    if (ts.isArrayLiteralExpression(current)) {
      if (current.elements.length > MAX_STATIC_PROVIDER_ENTRIES || current.elements.some(ts.isSpreadElement)) return undefined;
      return current.elements.filter(ts.isExpression).map((item) => ({ parsed, expression: item }));
    }
    if (!ts.isIdentifier(current)) return undefined;
    const symbol = resolveLocalSymbol(parsed, current.text, lookup);
    if (!symbol) return undefined;
    const key = classKey(symbol.parsed, symbol.local);
    if (seen.has(key)) return undefined;
    const initializer = variables.get(key);
    return initializer?.constant && initializer.topLevel
      ? providerArray(initializer.parsed, initializer.expression, new Set(seen).add(key), depth + 1)
      : undefined;
  };
  const providerObject = (
    parsed: ParsedSource,
    expression: ts.Expression,
    seen = new Set<string>(),
    depth = 0,
  ): { parsed: ParsedSource; object: ts.ObjectLiteralExpression } | undefined => {
    if (depth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    const current = unwrapExpression(expression);
    if (ts.isObjectLiteralExpression(current)) return { parsed, object: current };
    if (!ts.isIdentifier(current)) return undefined;
    const symbol = resolveLocalSymbol(parsed, current.text, lookup);
    if (!symbol) return undefined;
    const key = classKey(symbol.parsed, symbol.local);
    if (seen.has(key)) return undefined;
    const initializer = variables.get(key);
    return initializer?.constant && initializer.topLevel
      ? providerObject(initializer.parsed, initializer.expression, new Set(seen).add(key), depth + 1)
      : undefined;
  };
  const localProviderObject = (
    parsed: ParsedSource,
    expression: ts.Expression,
    seen = new Set<string>(),
    depth = 0,
  ): { parsed: ParsedSource; object: ts.ObjectLiteralExpression } | undefined => {
    if (depth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    const current = unwrapExpression(expression);
    if (ts.isObjectLiteralExpression(current)) return { parsed, object: current };
    if (!ts.isIdentifier(current)) return undefined;
    const key = classKey(parsed, current.text);
    if (seen.has(key)) return undefined;
    const initializer = variables.get(key);
    return initializer?.constant && initializer.topLevel && initializer.parsed === parsed
      ? localProviderObject(parsed, initializer.expression, new Set(seen).add(key), depth + 1)
      : undefined;
  };
  interface ProviderObject {
    parsed: ParsedSource;
    object: ts.ObjectLiteralExpression;
  }
  interface ProviderRecord extends ProviderObject {
    moduleKey: string;
  }
  interface NestModuleRecord {
    key: string;
    resolved: ResolvedClass;
    metadata?: ts.Expression;
    providers: Map<string, ProviderTarget>;
    providerRecords: Map<string, ProviderRecord>;
    imports: Set<string>;
    exports: Set<string>;
    reExports: Set<string>;
    global: boolean;
  }
  interface NestModuleResolutionBudget {
    modules: Set<string>;
    exceeded: boolean;
  }
  const moduleRecords = new Map<string, NestModuleRecord>();
  const moduleRecordForClass = (resolved: ResolvedClass | undefined): NestModuleRecord | undefined =>
    resolved ? moduleRecords.get(classDeclarationIdentity(resolved)) : undefined;
  const hasOfficialNestDecorator = (
    parsed: ParsedSource,
    node: ts.Node,
    importedName: "Global",
  ): boolean => decorators(node).some((decorator) => ts.isCallExpression(decorator.expression)
    && importedReference(parsed, decorator.expression.expression, "@nestjs/common", importedName));
  for (const parsed of sources) {
    for (const statement of parsed.source.statements) {
      if (!ts.isClassDeclaration(statement)) continue;
      const moduleArguments = nestDecoratorArguments(parsed, statement, "Module");
      if (moduleArguments === undefined) continue;
      const local = statement.name?.text
        ?? (hasModifier(statement, ts.SyntaxKind.DefaultKeyword) ? syntheticExportLocal("default") : undefined);
      const resolved = local ? classes.get(classKey(parsed, local)) : undefined;
      if (!resolved) continue;
      const key = classDeclarationIdentity(resolved);
      moduleRecords.set(key, {
        key,
        resolved,
        metadata: moduleArguments[0],
        providers: new Map(),
        providerRecords: new Map(),
        imports: new Set(),
        exports: new Set(),
        reExports: new Set(),
        global: hasOfficialNestDecorator(parsed, statement, "Global"),
      });
    }
  }
  const withNestModule = (resolved: ResolvedClass, moduleKey: string): ResolvedClass => ({
    ...resolved,
    nestModule: moduleKey,
  });
  const registerProvider = (module: NestModuleRecord, key: string, target: ProviderTarget): void => {
    const existing = module.providers.get(key);
    if (!existing || existing.signature === target.signature) {
      module.providers.set(key, target);
      return;
    }
    module.providers.set(key, { unresolved: true, signature: "ambiguous" });
  };
  const registerProviderEntry = (
    module: NestModuleRecord,
    entry: { parsed: ParsedSource; expression: ts.Expression },
  ): void => {
    const directKey = providerTokenKey(entry.parsed, entry.expression);
    const directClass = classFromSymbol(resolveExpressionSymbol(entry.parsed, entry.expression, lookup));
    if (directKey && directClass) {
      registerProvider(module, directKey, {
        implementation: directClass,
        signature: `class:${directClass.parsed.file.relativePath}:${directClass.declaration.pos}`,
      });
      return;
    }
    const record = providerObject(entry.parsed, entry.expression);
    if (!record) return;
    const scopedRecord = { ...record, moduleKey: module.key };
    module.providerRecords.set(`${record.parsed.file.relativePath}\u0000${record.object.pos}`, scopedRecord);
    const provide = objectProperty(record.object, "provide");
    const key = providerTokenKey(record.parsed, provide);
    if (!key) return;
    const useClass = objectProperty(record.object, "useClass");
    const implementation = useClass
      ? classFromSymbol(resolveExpressionSymbol(record.parsed, useClass, lookup))
      : undefined;
    if (implementation) {
      registerProvider(module, key, {
        implementation,
        signature: `class:${implementation.parsed.file.relativePath}:${implementation.declaration.pos}`,
      });
      return;
    }
    const useExisting = objectProperty(record.object, "useExisting");
    const alias = providerTokenKey(record.parsed, useExisting);
    if (alias) {
      registerProvider(module, key, { alias, signature: `alias:${alias}` });
      return;
    }
    const useFactory = objectProperty(record.object, "useFactory");
    const factoryClass = useFactory && factoryResultClass(record.parsed, useFactory);
    if (factoryClass) {
      registerProvider(module, key, {
        implementation: factoryClass,
        signature: `factory-class:${factoryClass.parsed.file.relativePath}:${factoryClass.declaration.pos}`,
      });
      return;
    }
    registerProvider(module, key, { unresolved: true, signature: "unresolved" });
  };
  const dynamicModuleObject = (
    parsed: ParsedSource,
    expression: ts.Expression,
  ): { module: NestModuleRecord; metadata: ProviderObject } | undefined => {
    const current = unwrapExpression(expression);
    if (!ts.isCallExpression(current) || !ts.isPropertyAccessExpression(current.expression)) return undefined;
    const owner = classFromSymbol(resolveExpressionSymbol(parsed, current.expression.expression, lookup));
    const ownerModule = moduleRecordForClass(owner);
    if (!owner || !ownerModule) return undefined;
    const methodName = current.expression.name.text;
    const candidates = owner.declaration.members.filter((member): member is ts.MethodDeclaration =>
      ts.isMethodDeclaration(member) && Boolean(member.body)
      && hasModifier(member, ts.SyntaxKind.StaticKeyword)
      && propertyName(member.name) === methodName);
    if (candidates.length !== 1) return undefined;
    const method = candidates[0]!;
    if (!method.body || method.asteriskToken || hasModifier(method, ts.SyntaxKind.AsyncKeyword)
      || method.body.statements.length !== 1) return undefined;
    const returned = method.body.statements[0];
    if (!returned || !ts.isReturnStatement(returned) || !returned.expression) return undefined;
    const record = localProviderObject(owner.parsed, returned.expression);
    if (!record) return undefined;
    const moduleExpression = objectProperty(record.object, "module");
    const moduleClass = moduleExpression
      ? classFromSymbol(resolveExpressionSymbol(record.parsed, moduleExpression, lookup))
      : undefined;
    if (!moduleClass || moduleClass.parsed !== owner.parsed || moduleClass.declaration !== owner.declaration) return undefined;
    return { module: ownerModule, metadata: record };
  };
  const moduleFromExpression = (
    parsed: ParsedSource,
    expression: ts.Expression,
  ): NestModuleRecord | undefined => {
    const forwarded = forwardRefValue(parsed, expression);
    const candidate = forwarded ?? { parsed, expression };
    return moduleRecordForClass(classFromSymbol(resolveExpressionSymbol(candidate.parsed, candidate.expression, lookup)));
  };
  const exportedTokenKey = (
    parsed: ParsedSource,
    expression: ts.Expression,
  ): string | undefined => {
    const direct = providerTokenKey(parsed, expression);
    if (direct) return direct;
    const record = providerObject(parsed, expression);
    return record ? providerTokenKey(record.parsed, objectProperty(record.object, "provide")) : undefined;
  };
  const controllerModules = new Map<string, Set<string>>();
  const metadataJobs: Array<{
    module: NestModuleRecord;
    parsed: ParsedSource;
    metadata: ts.Expression;
    dynamic: boolean;
  }> = [];
  for (const module of moduleRecords.values()) {
    if (module.metadata) metadataJobs.push({
      module,
      parsed: module.resolved.parsed,
      metadata: module.metadata,
      dynamic: false,
    });
  }
  const processedMetadata = new Set<string>();
  for (let index = 0; index < metadataJobs.length; index += 1) {
    const job = metadataJobs[index]!;
    const metadata = unwrapExpression(job.metadata);
    if (!ts.isObjectLiteralExpression(metadata)) continue;
    const metadataKey = `${job.module.key}\u0000${job.parsed.file.relativePath}\u0000${metadata.pos}`;
    if (processedMetadata.has(metadataKey)) continue;
    processedMetadata.add(metadataKey);
    if (job.dynamic && objectProperty(metadata, "global")?.kind === ts.SyntaxKind.TrueKeyword) {
      job.module.global = true;
    }
    const providers = providerArray(job.parsed, objectProperty(metadata, "providers"));
    for (const provider of providers ?? []) registerProviderEntry(job.module, provider);
    const controllers = providerArray(job.parsed, objectProperty(metadata, "controllers"));
    for (const controller of controllers ?? []) {
      const resolved = classFromSymbol(resolveExpressionSymbol(controller.parsed, controller.expression, lookup));
      if (!resolved) continue;
      const identity = classDeclarationIdentity(resolved);
      const hosts = controllerModules.get(identity) ?? new Set<string>();
      hosts.add(job.module.key);
      controllerModules.set(identity, hosts);
    }
    const imports = providerArray(job.parsed, objectProperty(metadata, "imports"));
    for (const imported of imports ?? []) {
      const dynamic = dynamicModuleObject(imported.parsed, imported.expression);
      if (dynamic) {
        job.module.imports.add(dynamic.module.key);
        metadataJobs.push({
          module: dynamic.module,
          parsed: dynamic.metadata.parsed,
          metadata: dynamic.metadata.object,
          dynamic: true,
        });
        continue;
      }
      const target = moduleFromExpression(imported.parsed, imported.expression);
      if (target) job.module.imports.add(target.key);
    }
    const exported = providerArray(job.parsed, objectProperty(metadata, "exports"));
    for (const item of exported ?? []) {
      const target = moduleFromExpression(item.parsed, item.expression);
      if (target && job.module.imports.has(target.key)) {
        job.module.reExports.add(target.key);
        continue;
      }
      const token = exportedTokenKey(item.parsed, item.expression);
      if (token) job.module.exports.add(token);
    }
  }
  const moduleParents = new Map<string, Set<string>>();
  for (const module of moduleRecords.values()) {
    for (const imported of module.imports) {
      const parents = moduleParents.get(imported) ?? new Set<string>();
      parents.add(module.key);
      moduleParents.set(imported, parents);
    }
  }
  const bindingContainsName = (binding: ts.BindingName, name: string): boolean => {
    if (ts.isIdentifier(binding)) return binding.text === name;
    return binding.elements.some((element) => ts.isBindingElement(element)
      && bindingContainsName(element.name, name));
  };
  const statementDeclaresName = (statement: ts.Statement, name: string): boolean => {
    if (ts.isVariableStatement(statement)) {
      return statement.declarationList.declarations.some((declaration) => bindingContainsName(declaration.name, name));
    }
    return (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement))
      && statement.name?.text === name;
  };
  const nestedReferenceShadowed = (node: ts.Node, local: string): boolean => {
    let current: ts.Node | undefined = node.parent;
    while (current && !ts.isSourceFile(current)) {
      if (ts.isFunctionLike(current)
        && current.parameters.some((parameter) => bindingContainsName(parameter.name, local))) return true;
      if (ts.isCatchClause(current) && current.variableDeclaration
        && bindingContainsName(current.variableDeclaration.name, local)) return true;
      if (ts.isBlock(current)
        && current.statements.some((statement) => statementDeclaresName(statement, local))) return true;
      current = current.parent;
    }
    return false;
  };
  const importReferenceShadowed = (node: ts.Node, local: string): boolean => nestedReferenceShadowed(node, local)
    || node.getSourceFile().statements.some((statement) => !ts.isImportDeclaration(statement)
      && statementDeclaresName(statement, local));
  const officialNestFactoryReference = (
    parsed: ParsedSource,
    expression: ts.Expression,
    site: ts.Node,
  ): boolean => {
    const current = unwrapExpression(expression);
    let local: string | undefined;
    let binding: ImportBinding | undefined;
    if (ts.isIdentifier(current)) {
      local = current.text;
      binding = parsed.imports.get(local);
      if (!binding || binding.namespace || binding.module !== "@nestjs/core" || binding.imported !== "NestFactory") {
        return false;
      }
    } else if (ts.isPropertyAccessExpression(current) && ts.isIdentifier(current.expression)
      && current.name.text === "NestFactory") {
      local = current.expression.text;
      binding = parsed.imports.get(local);
      if (!binding?.namespace || binding.module !== "@nestjs/core") return false;
    } else return false;
    return directEsmImports.has(classKey(parsed, local)) && !importReferenceShadowed(site, local);
  };
  const topLevelInvocationName = (expression: ts.Expression): string | undefined => {
    let current = unwrapExpression(expression);
    while (ts.isAwaitExpression(current) || ts.isVoidExpression(current)) current = unwrapExpression(current.expression);
    if (!ts.isCallExpression(current)) return undefined;
    const called = unwrapExpression(current.expression);
    if (ts.isIdentifier(called)) return called.text;
    if (!ts.isPropertyAccessExpression(called) || !["catch", "finally", "then"].includes(called.name.text)) {
      return undefined;
    }
    const result = unwrapExpression(called.expression);
    if (!ts.isCallExpression(result)) return undefined;
    const base = unwrapExpression(result.expression);
    return ts.isIdentifier(base) ? base.text : undefined;
  };
  const directlyInvokedFunctions = new Map<string, Set<string>>();
  for (const parsed of sources) {
    const invoked = new Set<string>();
    for (const statement of parsed.source.statements) {
      if (!ts.isExpressionStatement(statement)) continue;
      const name = topLevelInvocationName(statement.expression);
      if (name) invoked.add(name);
    }
    directlyInvokedFunctions.set(parsed.file.relativePath, invoked);
  }
  const topLevelFunctionName = (
    parsed: ParsedSource,
    declaration: ts.FunctionLikeDeclaration,
  ): string | undefined => {
    if (ts.isFunctionDeclaration(declaration) && declaration.parent === parsed.source) {
      return declaration.name?.text;
    }
    if (!ts.isArrowFunction(declaration) && !ts.isFunctionExpression(declaration)) return undefined;
    const variable = declaration.parent;
    if (!ts.isVariableDeclaration(variable) || !ts.isIdentifier(variable.name)) return undefined;
    const declarationList = variable.parent;
    const statement = declarationList.parent;
    return ts.isVariableDeclarationList(declarationList)
      && (declarationList.flags & ts.NodeFlags.Const) !== 0
      && ts.isVariableStatement(statement)
      && statement.parent === parsed.source
      ? variable.name.text
      : undefined;
  };
  const directBootstrapExpression = (node: ts.Node, expression: ts.Expression): boolean => {
    let current = unwrapExpression(expression);
    while (ts.isAwaitExpression(current) || ts.isVoidExpression(current)) current = unwrapExpression(current.expression);
    return current === node;
  };
  const directBootstrapStatement = (node: ts.Node, container: ts.Block | ts.SourceFile): boolean => {
    let current: ts.Node | undefined = node;
    while (current && !ts.isStatement(current)) current = current.parent;
    if (!current || current.parent !== container) return false;
    if (ts.isExpressionStatement(current)) return directBootstrapExpression(node, current.expression);
    if (ts.isReturnStatement(current)) return Boolean(current.expression
      && directBootstrapExpression(node, current.expression));
    return ts.isVariableStatement(current) && current.declarationList.declarations.some((declaration) =>
      Boolean(declaration.initializer && directBootstrapExpression(node, declaration.initializer)));
  };
  const runtimeFunctionLike = (node: ts.Node): node is ts.FunctionLikeDeclaration =>
    ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node) || ts.isArrowFunction(node)
      || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node)
      || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node);
  const bootstrapCallReachable = (parsed: ParsedSource, node: ts.CallExpression): boolean => {
    let owner: ts.Node | undefined = node.parent;
    while (owner && !runtimeFunctionLike(owner) && !ts.isSourceFile(owner)) owner = owner.parent;
    if (!owner || ts.isSourceFile(owner)) return directBootstrapStatement(node, parsed.source);
    const name = topLevelFunctionName(parsed, owner);
    if (!name || !directlyInvokedFunctions.get(parsed.file.relativePath)?.has(name) || !owner.body) return false;
    return ts.isBlock(owner.body)
      ? directBootstrapStatement(node, owner.body)
      : directBootstrapExpression(node, owner.body);
  };
  const directBootstrapModule = (
    parsed: ParsedSource,
    expression: ts.Expression,
    site: ts.CallExpression,
  ): NestModuleRecord | undefined => {
    const current = unwrapExpression(expression);
    if (!ts.isIdentifier(current) || nestedReferenceShadowed(site, current.text)) return undefined;
    const local = moduleRecordForClass(classes.get(classKey(parsed, current.text)));
    if (local) return local;
    const importKey = classKey(parsed, current.text);
    const binding = parsed.imports.get(current.text);
    if (!directEsmImports.has(importKey) || !binding || binding.namespace || !binding.module.startsWith(".")) {
      return undefined;
    }
    const target = resolveModule(parsed, binding.module, lookup);
    const exported = target?.exports.get(binding.imported);
    if (!target || !exported?.local || exported.module) return undefined;
    return moduleRecordForClass(classes.get(classKey(target, exported.local)));
  };
  const staticBootstrapRoots = new Set<string>();
  const unresolvedNestBootstrapRoots = new Set<string>();
  const unresolvedBootstrap = (parsed: ParsedSource, node: ts.CallExpression): void => {
    unresolvedNestBootstrapRoots.add(`${parsed.file.relativePath}\u0000${node.pos}`);
  };
  for (const parsed of sources) visit(parsed.source, (node) => {
    if (!ts.isCallExpression(node)) return;
    const called = unwrapExpression(node.expression);
    if (ts.isPropertyAccessExpression(called) && called.name.text === "create"
      && officialNestFactoryReference(parsed, called.expression, node)) {
      if (!NEST_BOOTSTRAP_ENTRY_PATH.test(parsed.file.relativePath)
        || node.questionDotToken || called.questionDotToken || !bootstrapCallReachable(parsed, node)) {
        unresolvedBootstrap(parsed, node);
        return;
      }
      const root = node.arguments[0] && directBootstrapModule(parsed, node.arguments[0], node);
      if (root) staticBootstrapRoots.add(root.key);
      else unresolvedBootstrap(parsed, node);
      return;
    }
    if (ts.isElementAccessExpression(called) && literalText(called.argumentExpression) === "create"
      && officialNestFactoryReference(parsed, called.expression, node)) unresolvedBootstrap(parsed, node);
  });
  const useStaticBootstrapRoots = staticBootstrapRoots.size > 0 && unresolvedNestBootstrapRoots.size === 0;
  const boundedModuleWalk = (
    start: string,
    adjacent: (key: string) => Iterable<string>,
  ): Set<string> | undefined => {
    const result = new Set<string>();
    const queue: Array<{ key: string; depth: number }> = [{ key: start, depth: 0 }];
    for (let index = 0; index < queue.length; index += 1) {
      const current = queue[index]!;
      if (result.has(current.key)) continue;
      if (result.size >= MAX_NEST_MODULE_GRAPH_ENTRIES) return undefined;
      result.add(current.key);
      const next = [...adjacent(current.key)].filter((key) => !result.has(key));
      if (current.depth >= MAX_NEST_MODULE_GRAPH_DEPTH) {
        if (next.length > 0) return undefined;
        continue;
      }
      for (const key of next) queue.push({ key, depth: current.depth + 1 });
    }
    return result;
  };
  const applicationGraphCache = new Map<string, Set<string>[] | null>();
  const applicationGraphs = (moduleKey: string): Set<string>[] | undefined => {
    const cached = applicationGraphCache.get(moduleKey);
    if (cached !== undefined) return cached ?? undefined;
    if (useStaticBootstrapRoots) {
      const graphs: Set<string>[] = [];
      for (const root of staticBootstrapRoots) {
        const graph = boundedModuleWalk(root, (key) => moduleRecords.get(key)?.imports ?? []);
        if (!graph) {
          applicationGraphCache.set(moduleKey, null);
          return undefined;
        }
        if (graph.has(moduleKey)) graphs.push(graph);
      }
      applicationGraphCache.set(moduleKey, graphs);
      return graphs;
    }
    const ancestors = boundedModuleWalk(moduleKey, (key) => moduleParents.get(key) ?? []);
    if (!ancestors) {
      applicationGraphCache.set(moduleKey, null);
      return undefined;
    }
    let roots = [...ancestors].filter((key) => (moduleParents.get(key)?.size ?? 0) === 0);
    if (roots.length === 0) roots = [moduleKey];
    const graphs: Set<string>[] = [];
    for (const root of roots) {
      const graph = boundedModuleWalk(root, (key) => moduleRecords.get(key)?.imports ?? []);
      if (!graph || !graph.has(moduleKey)) {
        applicationGraphCache.set(moduleKey, null);
        return undefined;
      }
      graphs.push(graph);
    }
    applicationGraphCache.set(moduleKey, graphs);
    return graphs;
  };
  const globalModuleCache = new Map<string, Set<string>>();
  const globallyVisibleModules = (moduleKey: string): Set<string> => {
    const cached = globalModuleCache.get(moduleKey);
    if (cached) return cached;
    const graphs = applicationGraphs(moduleKey);
    if (!graphs || graphs.length === 0) return new Set();
    const globalSets = graphs.map((graph) => new Set([...graph].filter((key) => moduleRecords.get(key)?.global)));
    const intersection = new Set(globalSets[0]);
    for (const candidates of globalSets.slice(1)) {
      for (const key of intersection) if (!candidates.has(key)) intersection.delete(key);
    }
    globalModuleCache.set(moduleKey, intersection);
    return intersection;
  };
  const uniqueResolvedClass = (values: ResolvedClass[]): ResolvedClass | undefined => {
    const unique = new Map(values.map((value) => [resolvedClassIdentity(value), value]));
    return unique.size === 1 ? [...unique.values()][0] : undefined;
  };
  const enterNestModuleResolution = (budget: NestModuleResolutionBudget, moduleKey: string): boolean => {
    if (budget.exceeded) return false;
    if (budget.modules.has(moduleKey)) return true;
    if (budget.modules.size >= MAX_NEST_MODULE_GRAPH_ENTRIES) {
      budget.exceeded = true;
      return false;
    }
    budget.modules.add(moduleKey);
    return true;
  };
  function localProviderClass(
    moduleKey: string,
    token: string,
    seen: Set<string>,
    moduleDepth: number,
    providerDepth: number,
    budget: NestModuleResolutionBudget,
  ): ResolvedClass | undefined {
    if (moduleDepth > MAX_NEST_MODULE_GRAPH_DEPTH || providerDepth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    if (!enterNestModuleResolution(budget, moduleKey)) return undefined;
    const module = moduleRecords.get(moduleKey);
    const target = module?.providers.get(token);
    if (!module || !target || target.unresolved) return undefined;
    const marker = `local:${moduleKey}:${token}`;
    if (seen.has(marker)) return undefined;
    const nextSeen = new Set(seen).add(marker);
    if (target.implementation) return withNestModule(target.implementation, moduleKey);
    return target.alias
      ? visibleProviderClass(moduleKey, target.alias, nextSeen, moduleDepth, providerDepth + 1, budget)
      : undefined;
  }
  function exportedProviderClasses(
    moduleKey: string,
    token: string,
    seen: Set<string>,
    moduleDepth: number,
    providerDepth: number,
    budget: NestModuleResolutionBudget,
  ): ResolvedClass[] {
    if (moduleDepth > MAX_NEST_MODULE_GRAPH_DEPTH || providerDepth > MAX_PROVIDER_RESOLUTION_DEPTH) return [];
    if (!enterNestModuleResolution(budget, moduleKey)) return [];
    const module = moduleRecords.get(moduleKey);
    if (!module) return [];
    const marker = `export:${moduleKey}:${token}`;
    if (seen.has(marker)) return [];
    const nextSeen = new Set(seen).add(marker);
    const result: ResolvedClass[] = [];
    if (module.exports.has(token)) {
      const resolved = visibleProviderClass(moduleKey, token, nextSeen, moduleDepth, providerDepth, budget);
      if (resolved) result.push(resolved);
    }
    for (const reExported of module.reExports) {
      result.push(...exportedProviderClasses(
        reExported,
        token,
        nextSeen,
        moduleDepth + 1,
        providerDepth,
        budget,
      ));
    }
    if (budget.exceeded) return [];
    return [...new Map(result.map((value) => [resolvedClassIdentity(value), value])).values()];
  }
  function visibleProviderClass(
    moduleKey: string,
    token: string,
    seen = new Set<string>(),
    moduleDepth = 0,
    providerDepth = 0,
    budget: NestModuleResolutionBudget = { modules: new Set<string>(), exceeded: false },
  ): ResolvedClass | undefined {
    if (moduleDepth > MAX_NEST_MODULE_GRAPH_DEPTH || providerDepth > MAX_PROVIDER_RESOLUTION_DEPTH) return undefined;
    if (!enterNestModuleResolution(budget, moduleKey)) return undefined;
    const module = moduleRecords.get(moduleKey);
    if (!module) return undefined;
    const marker = `visible:${moduleKey}:${token}`;
    if (seen.has(marker)) return undefined;
    const nextSeen = new Set(seen).add(marker);
    if (module.providers.has(token)) {
      return localProviderClass(moduleKey, token, nextSeen, moduleDepth, providerDepth, budget);
    }
    const candidates: ResolvedClass[] = [];
    for (const imported of module.imports) {
      candidates.push(...exportedProviderClasses(
        imported,
        token,
        nextSeen,
        moduleDepth + 1,
        providerDepth,
        budget,
      ));
    }
    for (const globalModule of globallyVisibleModules(moduleKey)) {
      if (globalModule === moduleKey || module.imports.has(globalModule)) continue;
      candidates.push(...exportedProviderClasses(
        globalModule,
        token,
        nextSeen,
        moduleDepth + 1,
        providerDepth,
        budget,
      ));
    }
    return budget.exceeded ? undefined : uniqueResolvedClass(candidates);
  }
  const nestControllerClass = (parsed: ParsedSource, declaration: ts.ClassDeclaration): ResolvedClass => {
    const resolved: ResolvedClass = { parsed, declaration };
    const hosts = controllerModules.get(classDeclarationIdentity(resolved));
    return hosts?.size === 1 ? withNestModule(resolved, [...hosts][0]!) : resolved;
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
    if (ts.isNewExpression(current)) {
      const constructed = resolveValueClass(parsed, current.expression, ownerClass, nextSeen);
      return constructed ? {
        declaration: constructed.declaration,
        parsed: constructed.parsed,
        nestModule: constructed.nestModule,
        construction: { parsed, expression: current, ownerClass },
      } : undefined;
    }
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
    const injected = injectedProvider(owner.parsed, parameter);
    if (injected.declared) {
      const resolved = owner.nestModule && injected.key
        ? visibleProviderClass(owner.nestModule, injected.key)
        : undefined;
      if (resolved) return resolved;
      unresolvedInjectedDependencies.add(`${owner.parsed.file.relativePath}\u0000${owner.declaration.pos}\u0000${parameter.pos}\u0000${injected.key ?? "unknown"}`);
      return undefined;
    }
    if (owner.construction && ts.isConstructorDeclaration(parameter.parent)) {
      const index = parameter.parent.parameters.indexOf(parameter);
      const argument = index >= 0 ? owner.construction.expression.arguments?.[index] : undefined;
      const resolved = argument && resolveValueClass(
        owner.construction.parsed,
        argument,
        owner.construction.ownerClass,
      );
      if (resolved) return resolved;
    }
    if (parameter.initializer) {
      const initialized = resolveValueClass(owner.parsed, parameter.initializer, owner);
      if (initialized) return initialized;
    }
    return classFromType(owner.parsed, parameter.type);
  };
  const resolveDependency = (owner: ResolvedClass, property: string): ResolvedClass | undefined => {
    const cacheKey = `${resolvedClassIdentity(owner)}\u0000${property}`;
    const cached = dependencyCache.get(cacheKey);
    if (cached !== undefined) return cached ?? undefined;
    dependencyCache.set(cacheKey, null);
    for (const member of owner.declaration.members) {
      if (ts.isPropertyDeclaration(member) && propertyName(member.name) === property) {
        const injected = injectedProvider(owner.parsed, member);
        if (injected.declared) {
          const provider = owner.nestModule && injected.key
            ? visibleProviderClass(owner.nestModule, injected.key)
            : undefined;
          if (provider) {
            dependencyCache.set(cacheKey, provider);
            return provider;
          }
          unresolvedInjectedDependencies.add(`${owner.parsed.file.relativePath}\u0000${owner.declaration.pos}\u0000${member.pos}\u0000${injected.key ?? "unknown"}`);
          return undefined;
        }
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

  const localBaseClass = (owner: ResolvedClass): ResolvedClass | undefined => {
    const clause = owner.declaration.heritageClauses
      ?.find((item) => item.token === ts.SyntaxKind.ExtendsKeyword);
    if (!clause || clause.types.length !== 1) return undefined;
    const expression = unwrapExpression(clause.types[0]!.expression);
    // Calls represent mixins or runtime-generated bases. They intentionally stay
    // outside the static inheritance boundary.
    if (ts.isCallExpression(expression)) return undefined;
    const base = classFromSymbol(resolveExpressionSymbol(owner.parsed, expression, lookup));
    return base && owner.nestModule ? withNestModule(base, owner.nestModule) : base;
  };
  const classMethod = (owner: ResolvedClass, name: string): ResolvedFunction | undefined => {
    const seen = new Set<string>();
    let current: ResolvedClass | undefined = owner;
    for (let depth = 0; current && depth <= MAX_LOCAL_CLASS_HERITAGE_DEPTH; depth += 1) {
      const identity = resolvedClassIdentity(current);
      if (seen.has(identity)) return undefined;
      seen.add(identity);
      let declaredByCurrentClass = false;
      for (const member of current.declaration.members) {
        if (propertyName(member.name) !== name) continue;
        declaredByCurrentClass = true;
        if (ts.isMethodDeclaration(member) && member.body) {
          return { declaration: member, parsed: current.parsed, ownerClass: owner };
        }
        if (ts.isPropertyDeclaration(member) && member.initializer) {
          const value = unwrapExpression(member.initializer);
          if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
            return { declaration: value, parsed: current.parsed, ownerClass: owner };
          }
        }
      }
      // An unsupported override shadows the base member. Falling through would
      // attribute base-class semantics to code that is not actually invoked.
      if (declaredByCurrentClass) return undefined;
      current = localBaseClass(current);
    }
    return undefined;
  };
  const classOwning = (resolved: ResolvedFunction): ResolvedClass | undefined => {
    if (resolved.ownerClass) return resolved.ownerClass;
    for (const owner of classes.values()) {
      if (owner.parsed !== resolved.parsed) continue;
      if (owner.declaration.members.some((member) => member === resolved.declaration
        || (ts.isPropertyDeclaration(member) && member.initializer === resolved.declaration))) return owner;
    }
    return undefined;
  };
  const resolveMethod = (parsed: ParsedSource, expression: ts.Expression): ResolvedFunction | undefined => {
    const current = unwrapExpression(expression);
    let methodExpression: ts.Expression = current;
    let boundClass: ResolvedClass | undefined;
    if (ts.isCallExpression(current) && ts.isPropertyAccessExpression(current.expression)
      && current.expression.name.text === "bind") {
      methodExpression = unwrapExpression(current.expression.expression);
      const boundTarget = current.arguments[0];
      boundClass = boundTarget && resolveValueClass(parsed, boundTarget, undefined);
      if (!boundClass) return undefined;
    }
    if (!ts.isPropertyAccessExpression(methodExpression)) return undefined;
    const targetClass = resolveValueClass(parsed, methodExpression.expression, undefined);
    if (!targetClass || (boundClass && resolvedClassIdentity(boundClass) !== resolvedClassIdentity(targetClass))) return undefined;
    return classMethod(targetClass, methodExpression.name.text);
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
  const queryOwnerColumn = (value: string): boolean => {
    const identifiers = value.match(/[A-Za-z_][A-Za-z0-9_]*/g);
    const field = identifiers?.at(-1);
    return Boolean(field && OWNER_FIELD.test(field));
  };
  const objectLiteralBinding = (
    expression: ts.Expression | undefined,
    parameter: string,
  ): ts.Expression | undefined => {
    const current = expression && unwrapExpression(expression);
    if (!current || !ts.isObjectLiteralExpression(current)) return undefined;
    for (const property of current.properties) {
      if (ts.isPropertyAssignment(property) && propertyName(property.name) === parameter) return property.initializer;
      if (ts.isShorthandPropertyAssignment(property) && property.name.text === parameter) return property.name;
    }
    return undefined;
  };
  const queryBuilderBindsIdentity = (call: ts.CallExpression, aliases: Set<string>): boolean => {
    const callee = unwrapExpression(call.expression);
    const method = ts.isPropertyAccessExpression(callee)
      ? callee.name.text
      : ts.isElementAccessExpression(callee) && callee.argumentExpression && ts.isStringLiteral(callee.argumentExpression)
        ? callee.argumentExpression.text
        : undefined;
    if (method === "equals" && ts.isPropertyAccessExpression(callee)) {
      const receiver = unwrapExpression(callee.expression);
      if (!ts.isCallExpression(receiver)) return false;
      const receiverCallee = unwrapExpression(receiver.expression);
      const receiverMethod = ts.isPropertyAccessExpression(receiverCallee)
        ? receiverCallee.name.text
        : ts.isElementAccessExpression(receiverCallee) && receiverCallee.argumentExpression
          && ts.isStringLiteral(receiverCallee.argumentExpression)
          ? receiverCallee.argumentExpression.text
          : undefined;
      const field = receiverMethod === "where" ? literalText(receiver.arguments[0]) : undefined;
      const binding = call.arguments[0];
      return Boolean(field && queryOwnerColumn(field) && binding && expressionCarriesIdentity(binding, aliases));
    }
    if (method !== "where" && method !== "andWhere") return false;
    // Query text stays literal-only: resolving or evaluating target-owned query
    // builders would cross the scanner's no-execution trust boundary.
    const query = literalText(call.arguments[0]);
    if (query === undefined || /\bOR\b/i.test(query)) return false;

    const parameters = call.arguments[1];
    for (const match of query.matchAll(/:([A-Za-z_$][A-Za-z0-9_$]*)/g)) {
      const placeholder = match[1];
      const offset = match.index;
      if (!placeholder || offset === undefined) continue;
      const end = offset + match[0].length;
      const before = query.slice(0, offset);
      const after = query.slice(end);
      const leftColumn = before.match(/([A-Za-z_][A-Za-z0-9_.$`"\[\]]*)\s*=\s*$/)?.[1];
      const rightColumn = after.match(/^\s*=\s*([A-Za-z_][A-Za-z0-9_.$`"\[\]]*)/)?.[1];
      if ((!leftColumn || !queryOwnerColumn(leftColumn)) && (!rightColumn || !queryOwnerColumn(rightColumn))) continue;
      const binding = objectLiteralBinding(parameters, placeholder);
      if (binding && expressionCarriesIdentity(binding, aliases)) return true;
    }

    if (!queryOwnerColumn(query)) return false;
    let binding = call.arguments[1];
    if (call.arguments.length >= 3) {
      if (literalText(call.arguments[1]) !== "=") return false;
      binding = call.arguments[2];
    }
    return Boolean(binding && expressionCarriesIdentity(binding, aliases));
  };
  const authorizationPredicateName = (name: string | undefined): boolean => Boolean(name && /^(?:(?:can|may|allow|allows|permit|permits)(?:Read|Write|View|Edit|Update|Delete|Access|Manage|Own|Use)[A-Za-z0-9_]*|(?:is|has)(?:Owner|Ownership|Authorized|Allowed|Permission|Access)[A-Za-z0-9_]*)$/i.test(name));
  const staticReturnedExpression = (
    declaration: ts.FunctionLikeDeclaration,
  ): ts.Expression | undefined => {
    if (!declaration.body) return undefined;
    if (!ts.isBlock(declaration.body)) return declaration.body;
    const statement = declaration.body.statements[0];
    if (declaration.body.statements.length !== 1 || !statement || !ts.isReturnStatement(statement)) return undefined;
    return statement.expression;
  };
  const callableReturnsValue = (declaration: ts.FunctionLikeDeclaration): boolean => {
    if (!declaration.body) return false;
    if (!ts.isBlock(declaration.body)) return true;
    let returnsValue = false;
    const walk = (node: ts.Node): void => {
      if (returnsValue) return;
      if (node !== declaration.body && (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)
        || ts.isArrowFunction(node) || ts.isMethodDeclaration(node) || ts.isConstructorDeclaration(node)
        || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node))) return;
      if (ts.isReturnStatement(node) && node.expression) {
        returnsValue = true;
        return;
      }
      ts.forEachChild(node, walk);
    };
    walk(declaration.body);
    return returnsValue;
  };
  const staticDenialPayload = (expression: ts.Expression | undefined): boolean => {
    if (!expression) return true;
    const current = unwrapExpression(expression);
    if (ts.isStringLiteral(current) || ts.isNumericLiteral(current)
      || ts.isNoSubstitutionTemplateLiteral(current)
      || current.kind === ts.SyntaxKind.TrueKeyword || current.kind === ts.SyntaxKind.FalseKeyword
      || current.kind === ts.SyntaxKind.NullKeyword) return true;
    if (ts.isPrefixUnaryExpression(current)) {
      return (current.operator === ts.SyntaxKind.PlusToken || current.operator === ts.SyntaxKind.MinusToken)
        && ts.isNumericLiteral(unwrapExpression(current.operand));
    }
    if (ts.isArrayLiteralExpression(current)) {
      return current.elements.every((element) => !ts.isSpreadElement(element) && staticDenialPayload(element));
    }
    if (!ts.isObjectLiteralExpression(current)) return false;
    return current.properties.every((property) => ts.isPropertyAssignment(property)
      && !ts.isComputedPropertyName(property.name) && staticDenialPayload(property.initializer));
  };
  const expressionDeniesAccess = (node: ts.Node): boolean => {
    let denied = false;
    visit(node, (candidate) => {
      if (denied || !ts.isCallExpression(candidate)) return;
      const name = expressionName(candidate.expression).replace(/\(\)/g, "");
      if (!/(?:^|\.)(?:status|sendStatus)$/.test(name)) return;
      const status = candidate.arguments[0];
      if (!status || !ts.isNumericLiteral(status) || status.text !== "403") return;
      if (/(?:^|\.)sendStatus$/.test(name)) {
        denied = true;
        return;
      }
      const completion = candidate.parent;
      if (!ts.isPropertyAccessExpression(completion) || completion.expression !== candidate
        || !/^(?:end|send|json)$/.test(completion.name.text)) return;
      if (ts.isCallExpression(completion.parent) && completion.parent.expression === completion
        && staticDenialPayload(completion.parent.arguments[0])) denied = true;
    });
    return denied;
  };
  const statementDeniesAccess = (statement: ts.Statement): boolean => {
    if (ts.isThrowStatement(statement)) {
      return Boolean(statement.expression
        && /(?:Forbidden|AccessDenied|PermissionDenied|Unauthorized)/i.test(statement.expression.getText()));
    }
    if (ts.isReturnStatement(statement)) return Boolean(statement.expression && expressionDeniesAccess(statement.expression));
    if (ts.isExpressionStatement(statement)) return false;
    if (ts.isIfStatement(statement)) {
      return statementDeniesAccess(statement.thenStatement)
        && Boolean(statement.elseStatement && statementDeniesAccess(statement.elseStatement));
    }
    if (!ts.isBlock(statement)) return false;
    for (let index = 0; index < statement.statements.length; index += 1) {
      const item = statement.statements[index]!;
      const previous = index > 0 ? statement.statements[index - 1] : undefined;
      if (ts.isReturnStatement(item) && !item.expression && previous && ts.isExpressionStatement(previous)
        && expressionDeniesAccess(previous.expression)) return true;
      if (statementDeniesAccess(item)) return true;
      if (!ts.isExpressionStatement(item) && !ts.isVariableStatement(item) && !ts.isEmptyStatement(item)) return false;
    }
    return false;
  };
  const authorizationCondition = (expression: ts.Expression): ts.Expression => {
    let current = expression;
    while (true) {
      const unwrapped = unwrapExpression(current);
      if (unwrapped !== current) {
        current = unwrapped;
        continue;
      }
      if (ts.isAwaitExpression(current)) {
        current = current.expression;
        continue;
      }
      return current;
    }
  };
  const authorizationExpressionEnforced = (
    target: ts.Expression,
    declaration: ts.FunctionLikeDeclaration,
    allowsAccessWhenTrue: boolean,
  ): boolean => {
    const inside = (node: ts.Node, ancestor: ts.Node): boolean => {
      let current: ts.Node | undefined = node;
      while (current && current !== declaration) {
        if (current === ancestor) return true;
        current = current.parent;
      }
      return false;
    };
    let current: ts.Node | undefined = target.parent;
    while (current && current !== declaration) {
      if (ts.isIfStatement(current) && inside(target, current.expression)) {
        const condition = authorizationCondition(current.expression);
        const negated = ts.isPrefixUnaryExpression(condition)
          && condition.operator === ts.SyntaxKind.ExclamationToken
          && authorizationCondition(condition.operand) === target;
        if (allowsAccessWhenTrue) {
          if (negated && statementDeniesAccess(current.thenStatement)) return true;
          if (condition === target && current.elseStatement && statementDeniesAccess(current.elseStatement)) return true;
        } else {
          if (condition === target && statementDeniesAccess(current.thenStatement)) return true;
          if (negated && current.elseStatement && statementDeniesAccess(current.elseStatement)) return true;
        }
      }
      current = current.parent;
    }
    return false;
  };
  const ownershipComparisonAllowsAccessWhenTrue = (
    expression: ts.Expression,
    aliases: Set<string>,
  ): boolean | undefined => {
    const current = authorizationCondition(expression);
    if (!ts.isBinaryExpression(current)) return undefined;
    const binding = (ownerExpression(current.left) && expressionCarriesIdentity(current.right, aliases))
      || (ownerExpression(current.right) && expressionCarriesIdentity(current.left, aliases));
    if (!binding) return undefined;
    if (current.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken
      || current.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) return true;
    if (current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsToken
      || current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) return false;
    return undefined;
  };
  const returnedOwnershipPredicate = (
    declaration: ts.FunctionLikeDeclaration,
    aliases: Set<string>,
  ): boolean => {
    const expression = staticReturnedExpression(declaration);
    return Boolean(expression && ownershipComparisonAllowsAccessWhenTrue(expression, aliases) === true);
  };
  const expressionUse = (expression: ts.Expression): ts.Expression => {
    let current = expression;
    while (true) {
      const parent = current.parent;
      if ((ts.isParenthesizedExpression(parent) || ts.isAsExpression(parent)
        || ts.isTypeAssertionExpression(parent) || ts.isNonNullExpression(parent)
        || ts.isSatisfiesExpression(parent) || ts.isAwaitExpression(parent))
        && parent.expression === current) {
        current = parent;
        continue;
      }
      return current;
    }
  };
  const singleUseImmutableBinding = (
    call: ts.CallExpression,
    declaration: ts.FunctionLikeDeclaration,
  ): ts.Identifier | undefined => {
    const current = expressionUse(call);
    const variable = current.parent;
    if (!ts.isVariableDeclaration(variable) || variable.initializer !== current
      || !ts.isIdentifier(variable.name)) return undefined;
    const variableName = variable.name.text;
    const declarationList = variable.parent;
    if (!ts.isVariableDeclarationList(declarationList)
      || (declarationList.flags & ts.NodeFlags.Const) === 0
      || !ts.isVariableStatement(declarationList.parent)) return undefined;
    const directlyInsideCallable = (node: ts.Node): boolean => {
      let ancestor: ts.Node | undefined = node.parent;
      while (ancestor && ancestor !== declaration) {
        if (ts.isFunctionDeclaration(ancestor) || ts.isFunctionExpression(ancestor)
          || ts.isArrowFunction(ancestor) || ts.isMethodDeclaration(ancestor)
          || ts.isConstructorDeclaration(ancestor) || ts.isGetAccessorDeclaration(ancestor)
          || ts.isSetAccessorDeclaration(ancestor)) return false;
        ancestor = ancestor.parent;
      }
      return ancestor === declaration;
    };
    if (!directlyInsideCallable(declarationList.parent)) return undefined;
    const uses: ts.Identifier[] = [];
    // Any second same-named reference, shadow or nested capture is an escape
    // from this deliberately syntax-only single-use seam.
    visit(declaration, (node) => {
      if (ts.isIdentifier(node) && node !== variable.name && node.text === variableName) uses.push(node);
    });
    const use = uses[0];
    return uses.length === 1 && use && use.getStart() > variable.getEnd()
      && directlyInsideCallable(use) ? use : undefined;
  };
  const callAuthorizationEnforced = (
    call: ts.CallExpression,
    declaration: ts.FunctionLikeDeclaration,
  ): boolean => {
    if (authorizationExpressionEnforced(call, declaration, true)) return true;
    const use = singleUseImmutableBinding(call, declaration);
    return Boolean(use && authorizationExpressionEnforced(use, declaration, true));
  };
  const callDirectlyReturnsResult = (
    call: ts.CallExpression,
    declaration: ts.FunctionLikeDeclaration,
  ): boolean => {
    const expression = staticReturnedExpression(declaration);
    return Boolean(expression && authorizationCondition(expression) === call);
  };
  const accessGuardCall = (
    declaration: ts.FunctionLikeDeclaration,
    parsed: ParsedSource,
    ownerClass: ResolvedClass | undefined,
  ): boolean => {
    let protectedByAccessCall = false;
    visit(declaration, (node) => {
      if (protectedByAccessCall || !ts.isCallExpression(node)) return;
      const name = expressionName(node.expression).replace(/\(\)/g, "");
      if (!ACCESS_GUARD_NAME.test(name)) return;
      const terminal = name.split(".").at(-1);
      if (authorizationPredicateName(terminal)) return;
      const target = resolveCall(parsed, node, ownerClass);
      // A locally visible value-returning helper may be a boolean predicate;
      // its name alone cannot make an ignored result an imperative guard.
      if (target && callableReturnsValue(target.callable.declaration)) return;
      protectedByAccessCall = true;
    });
    return protectedByAccessCall;
  };
  const directCallArgument = (
    expression: ts.Expression,
  ): { call: ts.CallExpression; index: number } | undefined => {
    const current = expressionUse(expression);
    if (!ts.isCallExpression(current.parent)) return undefined;
    const index = current.parent.arguments.findIndex((argument) => argument === current);
    return index >= 0 ? { call: current.parent, index } : undefined;
  };
  const operationName = (call: ts.CallExpression): string => expressionName(call.expression).replace(/\(\)/g, "");
  const directWhereProperty = (property: ts.PropertyAssignment): boolean => {
    if (propertyName(property.name) !== "where" || !ts.isObjectLiteralExpression(property.parent)) return false;
    const properties = property.parent.properties;
    const index = properties.findIndex((candidate) => candidate === property);
    if (index < 0) return false;
    const canOverrideWhere = properties.slice(index + 1).some((candidate) => {
      if (ts.isSpreadAssignment(candidate)) return true;
      return ts.isComputedPropertyName(candidate.name) || propertyName(candidate.name) === "where";
    });
    if (canOverrideWhere) return false;
    const argument = directCallArgument(property.parent);
    return Boolean(argument?.index === 0 && ID_OPERATION.test(operationName(argument.call)));
  };
  const filterObjectConsumed = (object: ts.ObjectLiteralExpression): boolean => {
    const argument = directCallArgument(object);
    if (argument?.index === 0 && DIRECT_FILTER_ARGUMENT_OPERATION.test(operationName(argument.call))) return true;
    const current = expressionUse(object);
    return ts.isPropertyAssignment(current.parent) && current.parent.initializer === current
      && directWhereProperty(current.parent);
  };
  const expressionFeedsObjectFilter = (expression: ts.Expression): boolean => {
    const direct = directCallArgument(expression);
    if (direct?.index === 0 && DIRECT_FILTER_ARGUMENT_OPERATION.test(operationName(direct.call))) return true;
    const current = expressionUse(expression);
    const parent = current.parent;
    if (ts.isPropertyAssignment(parent) && parent.initializer === current) return directWhereProperty(parent);
    if (!ts.isSpreadAssignment(parent) || !ts.isObjectLiteralExpression(parent.parent)) return false;
    const properties = parent.parent.properties;
    return properties[properties.length - 1] === parent && filterObjectConsumed(parent.parent);
  };
  const callResultFeedsObjectFilter = (
    call: ts.CallExpression,
    declaration: ts.FunctionLikeDeclaration,
  ): boolean => {
    if (expressionFeedsObjectFilter(call)) return true;
    const use = singleUseImmutableBinding(call, declaration);
    return Boolean(use && expressionFeedsObjectFilter(use));
  };
  const staticReturnedFilter = (
    declaration: ts.FunctionLikeDeclaration,
  ): ts.ObjectLiteralExpression | undefined => {
    const expression = staticReturnedExpression(declaration);
    const current = expression && unwrapExpression(expression);
    if (!current || !ts.isObjectLiteralExpression(current)) return undefined;
    let containsSpread = false;
    visit(current, (node) => {
      if (ts.isSpreadAssignment(node) || ts.isSpreadElement(node)) containsSpread = true;
    });
    return containsSpread ? undefined : current;
  };
  const astOwnershipBinding = (
    declaration: ts.FunctionLikeDeclaration,
    aliases: Set<string>,
    filterResultConsumed: boolean,
  ): boolean => {
    let protectedByOwner = false;
    let disjunctiveQueryBuilder = false;
    visit(declaration, (node) => {
      if (disjunctiveQueryBuilder || !ts.isCallExpression(node)) return;
      const callee = unwrapExpression(node.expression);
      const method = ts.isPropertyAccessExpression(callee)
        ? callee.name.text
        : ts.isElementAccessExpression(callee) && callee.argumentExpression && ts.isStringLiteral(callee.argumentExpression)
          ? callee.argumentExpression.text
          : undefined;
      // A later disjunction can widen an otherwise owner-scoped query, so one
      // visible or/orWhere invalidates query-derived ownership for this callable.
      if (method === "or" || (method && /^orWhere/.test(method))) disjunctiveQueryBuilder = true;
    });
    const nonMandatoryFilterProperty = (name: ts.PropertyName | undefined): boolean => {
      const direct = propertyName(name);
      if (direct && /^\$(?:or|nor|not)$/.test(direct)) return true;
      if (!name || !ts.isComputedPropertyName(name)) return false;
      const terminal = expressionName(name.expression).split(".").at(-1);
      return terminal === "or" || terminal === "nor" || terminal === "not";
    };
    const insideNonMandatoryObjectFilter = (node: ts.Node): boolean => {
      let current = node.parent;
      while (current && current !== declaration) {
        if (ts.isPropertyAssignment(current) && nonMandatoryFilterProperty(current.name)) return true;
        current = current.parent;
      }
      return false;
    };
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
            && !insideNonMandatoryObjectFilter(node)
            && expressionCarriesIdentity(node.initializer, aliases)) bound = true;
        } else if (ts.isShorthandPropertyAssignment(node)
          && !insideNonMandatoryObjectFilter(node)
          && (node.name.text === "id" || OWNER_FIELD.test(node.name.text)) && aliases.has(node.name.text)) bound = true;
      });
      return bound;
    };
    const returnedFilterBindsIdentity = (): boolean => {
      const filter = filterResultConsumed ? staticReturnedFilter(declaration) : undefined;
      if (!filter) return false;
      let bound = false;
      visit(filter, (node) => {
        if (bound) return;
        if (ts.isPropertyAssignment(node)) {
          const name = propertyName(node.name);
          if (!insideNonMandatoryObjectFilter(node) && name && OWNER_FIELD.test(name)
            && expressionCarriesIdentity(node.initializer, aliases)) bound = true;
          else if (!insideNonMandatoryObjectFilter(node) && name && OWNER_RELATION_FIELD.test(name)
            && relationBindsIdentity(node.initializer)) bound = true;
        } else if (ts.isShorthandPropertyAssignment(node) && !insideNonMandatoryObjectFilter(node)
          && OWNER_FIELD.test(node.name.text) && aliases.has(node.name.text)) bound = true;
      });
      return bound;
    };
    if (returnedFilterBindsIdentity()) return true;
    visit(declaration, (node) => {
      if (protectedByOwner) return;
      if (ts.isCallExpression(node) && !disjunctiveQueryBuilder && queryBuilderBindsIdentity(node, aliases)) {
        protectedByOwner = true;
      } else if (ts.isPropertyAssignment(node)) {
        const name = propertyName(node.name);
        if (!disjunctiveQueryBuilder && !insideNonMandatoryObjectFilter(node)
          && insideObjectOperation(node) && name && OWNER_FIELD.test(name)
          && expressionCarriesIdentity(node.initializer, aliases)) protectedByOwner = true;
        else if (!disjunctiveQueryBuilder && !insideNonMandatoryObjectFilter(node)
          && insideObjectOperation(node) && name && OWNER_RELATION_FIELD.test(name)
          && relationBindsIdentity(node.initializer)) protectedByOwner = true;
      } else if (ts.isShorthandPropertyAssignment(node) && !disjunctiveQueryBuilder
        && !insideNonMandatoryObjectFilter(node) && insideObjectOperation(node)
        && OWNER_FIELD.test(node.name.text) && aliases.has(node.name.text)) {
        protectedByOwner = true;
      } else if (ts.isBinaryExpression(node)) {
        const allowsAccessWhenTrue = ownershipComparisonAllowsAccessWhenTrue(node, aliases);
        if (allowsAccessWhenTrue !== undefined
          && authorizationExpressionEnforced(node, declaration, allowsAccessWhenTrue)) protectedByOwner = true;
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
    const ownerKey = ownerClass ? resolvedClassIdentity(ownerClass) : "";
    const cacheKey = `${parsed.file.relativePath}\u0000${declaration.pos}\u0000${ownerKey}\u0000${objectIdFields.join(",")}`;
    const cached = cache.get(cacheKey);
    if (cached) return cached;
    const queue: Array<{
      callable: ResolvedFunction;
      ownerClass?: ResolvedClass;
      aliases: Set<string>;
      depth: number;
      authorizationEnforced: boolean;
      authorizationForwardDepth: number;
      filterResultConsumed: boolean;
    }> = [{
      callable: { declaration, parsed },
      ownerClass,
      aliases: new Set(),
      depth: 0,
      authorizationEnforced: false,
      authorizationForwardDepth: 0,
      filterResultConsumed: false,
    }];
    const visited = new Set<string>();
    const semanticSources: string[] = [];
    const responseFields = new Set<string>();
    let ownershipProtected = false;
    let roleProtected = false;
    let objectOperation = false;
    const maxDepth = 4;
    const maxCallables = 32;
    const maxAuthorizationForwardDepth = 1;
    while (queue.length > 0 && visited.size < maxCallables) {
      const current = queue.shift()!;
      const aliases = identityAliases(current.callable.declaration, current.aliases);
      const currentOwnerKey = current.ownerClass ? resolvedClassIdentity(current.ownerClass) : "";
      const visitKey = `${current.callable.parsed.file.relativePath}\u0000${current.callable.declaration.pos}\u0000${currentOwnerKey}\u0000${[...aliases].sort().join(",")}\u0000${current.authorizationEnforced ? "enforced" : "observed"}\u0000forward:${current.authorizationForwardDepth}\u0000${current.filterResultConsumed ? "filter" : "value"}`;
      if (visited.has(visitKey)) continue;
      visited.add(visitKey);
      const source = current.callable.declaration.getText(current.callable.parsed.source);
      semanticSources.push(source);
      const predicateBinding = returnedOwnershipPredicate(current.callable.declaration, aliases);
      const binding = astOwnershipBinding(current.callable.declaration, aliases, current.filterResultConsumed);
      const callableProtection = accessGuardCall(
        current.callable.declaration,
        current.callable.parsed,
        current.ownerClass,
      ) || binding;
      // A local boolean predicate contributes evidence only through its return
      // shape and a statically proven caller denial path, never through its name.
      ownershipProtected ||= callableProtection || (predicateBinding && current.authorizationEnforced);
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
        const directlyEnforced = callAuthorizationEnforced(node, current.callable.declaration);
        const forwardedEnforcement = !directlyEnforced && current.authorizationEnforced
          && current.authorizationForwardDepth < maxAuthorizationForwardDepth
          && callDirectlyReturnsResult(node, current.callable.declaration);
        queue.push({
          callable: target.callable,
          ownerClass: target.ownerClass,
          aliases: incoming,
          depth: current.depth + 1,
          authorizationEnforced: directlyEnforced || forwardedEnforcement,
          authorizationForwardDepth: forwardedEnforcement ? current.authorizationForwardDepth + 1 : 0,
          filterResultConsumed: callResultFeedsObjectFilter(node, current.callable.declaration),
        });
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
  const globalGuardProviders = (ownerClass: ResolvedClass | undefined): ResolvedClass[] => {
    if (!ownerClass?.nestModule) return [];
    const graphs = applicationGraphs(ownerClass.nestModule);
    if (!graphs || graphs.length === 0) return [];
    const guardsByGraph = graphs.map((graph) => {
      const guards = new Map<string, ResolvedClass>();
      for (const moduleKey of graph) {
        const module = moduleRecords.get(moduleKey);
        if (!module) continue;
        for (const record of module.providerRecords.values()) {
          const provide = objectProperty(record.object, "provide");
          if (!provide || !importedReference(record.parsed, provide, "@nestjs/core", "APP_GUARD")) continue;
          const useClass = objectProperty(record.object, "useClass");
          const useExisting = objectProperty(record.object, "useExisting");
          const useFactory = objectProperty(record.object, "useFactory");
          const useValue = objectProperty(record.object, "useValue");
          const existingKey = providerTokenKey(record.parsed, useExisting);
          const directValue = useValue && unwrapExpression(useValue);
          const directClass = useClass
            ? classFromSymbol(resolveExpressionSymbol(record.parsed, useClass, lookup))
            : undefined;
          const factoryClass = useFactory && factoryResultClass(record.parsed, useFactory);
          const valueClass = directValue && ts.isNewExpression(directValue)
            ? resolveValueClass(record.parsed, directValue, undefined)
            : undefined;
          const resolved = (directClass && withNestModule(directClass, moduleKey))
            || (existingKey && visibleProviderClass(moduleKey, existingKey))
            || (factoryClass && withNestModule(factoryClass, moduleKey))
            || (valueClass && withNestModule(valueClass, moduleKey));
          if (resolved) guards.set(resolvedClassIdentity(resolved), resolved);
        }
      }
      return guards;
    });
    const intersection = new Map(guardsByGraph[0]);
    for (const guards of guardsByGraph.slice(1)) {
      for (const key of intersection.keys()) if (!guards.has(key)) intersection.delete(key);
    }
    return [...intersection.values()];
  };
  return {
    analyze,
    resolveMethod,
    nestControllerClass,
    globalGuardProviders,
    unresolvedProviderDependencies: () => unresolvedInjectedDependencies.size,
    unresolvedBootstrapRoots: () => unresolvedNestBootstrapRoots.size,
  };
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
): { routes: NodeApiRoute[]; unresolvedHandlers: number; unresolvedMounts: number; unresolvedRegistrations: number } {
  const lookup = parsedSourceLookup(sources);
  const declarations = new Map(sources.map((parsed) => [parsed.file.relativePath, functionDeclarations(parsed.source)]));
  const variableInitializers = new Map<string, { parsed: ParsedSource; expression: ts.Expression }>();
  const staticInitializers = new Map<string, { parsed: ParsedSource; expression: ts.Expression }>();
  const directEsmImports = new Set<string>();
  const directEsmExports = new Map<string, string>();
  for (const parsed of sources) visit(parsed.source, (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      variableInitializers.set(`${parsed.file.relativePath}\u0000${node.name.text}`, { parsed, expression: node.initializer });
    }
  });
  for (const parsed of sources) {
    for (const statement of parsed.source.statements) {
      if (!ts.isVariableStatement(statement) || !(statement.declarationList.flags & ts.NodeFlags.Const)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (ts.isIdentifier(declaration.name) && declaration.initializer) {
          staticInitializers.set(`${parsed.file.relativePath}\u0000${declaration.name.text}`, {
            parsed,
            expression: declaration.initializer,
          });
        }
      }
    }
  }
  for (const parsed of sources) {
    for (const statement of parsed.source.statements) {
      if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) {
        const clause = statement.importClause;
        if (!clause || clause.isTypeOnly) continue;
        if (clause.name) directEsmImports.add(`${parsed.file.relativePath}\u0000${clause.name.text}`);
        if (clause.namedBindings && ts.isNamedImports(clause.namedBindings)) {
          for (const element of clause.namedBindings.elements) {
            if (!element.isTypeOnly) directEsmImports.add(`${parsed.file.relativePath}\u0000${element.name.text}`);
          }
        }
        continue;
      }
      if (ts.isVariableStatement(statement) && hasModifier(statement, ts.SyntaxKind.ExportKeyword)) {
        for (const declaration of statement.declarationList.declarations) {
          if (ts.isIdentifier(declaration.name)) {
            directEsmExports.set(`${parsed.file.relativePath}\u0000${declaration.name.text}`, declaration.name.text);
          }
        }
        continue;
      }
      if (ts.isExportDeclaration(statement) && !statement.isTypeOnly && !statement.moduleSpecifier
        && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        for (const element of statement.exportClause.elements) {
          if (!element.isTypeOnly) {
            directEsmExports.set(
              `${parsed.file.relativePath}\u0000${element.name.text}`,
              element.propertyName?.text ?? element.name.text,
            );
          }
        }
        continue;
      }
      if (ts.isExportAssignment(statement) && !statement.isExportEquals) {
        const expression = unwrapExpression(statement.expression);
        if (ts.isIdentifier(expression)) {
          directEsmExports.set(`${parsed.file.relativePath}\u0000default`, expression.text);
        }
      }
    }
  }
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
  if (receivers.size === 0) return { routes: [], unresolvedHandlers: 0, unresolvedMounts: 0, unresolvedRegistrations: 0 };

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
    const localMethod = localCalls.resolveMethod(parsed, expression);
    if (localMethod) return localMethod;
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

  interface StaticValue {
    parsed: ParsedSource;
    expression: ts.Expression;
    members?: ReadonlyMap<string, StaticValue>;
  }
  interface StaticRouteTable {
    elements: StaticValue[];
    transforms: number;
  }
  type StaticBindings = Map<string, StaticValue>;
  const objectMemberExpression = (object: ts.ObjectLiteralExpression, name: string): ts.Expression | undefined => {
    for (const member of object.properties) {
      if (propertyName(member.name) !== name) continue;
      if (ts.isPropertyAssignment(member)) return member.initializer;
      if (ts.isShorthandPropertyAssignment(member)) return member.name;
    }
    return undefined;
  };
  const staticExpression = (
    parsed: ParsedSource,
    expression: ts.Expression,
    bindings: StaticBindings,
    seen = new Set<string>(),
    depth = 0,
  ): StaticValue | undefined => {
    if (depth > 12 || ts.isSpreadElement(expression)) return undefined;
    const current = unwrapExpression(expression);
    if (ts.isIdentifier(current)) {
      const bound = bindings.get(current.text);
      if (bound?.members) return bound;
      if (bound && (bound.parsed !== parsed || !ts.isIdentifier(bound.expression)
        || bound.expression.text !== current.text)) {
        return staticExpression(bound.parsed, bound.expression, bindings, seen, depth + 1);
      }
      const key = `${parsed.file.relativePath}\u0000${current.text}`;
      if (seen.has(key)) return undefined;
      const initializer = staticInitializers.get(key);
      return initializer
        ? staticExpression(initializer.parsed, initializer.expression, bindings, new Set(seen).add(key), depth + 1)
        : { parsed, expression: current };
    }
    if (ts.isPropertyAccessExpression(current)) {
      const owner = staticExpression(parsed, current.expression, bindings, seen, depth + 1);
      if (owner?.members) return owner.members.get(current.name.text);
      const ownerExpression = owner && unwrapExpression(owner.expression);
      if (owner && ownerExpression && ts.isObjectLiteralExpression(ownerExpression)) {
        const member = objectMemberExpression(ownerExpression, current.name.text);
        return member ? staticExpression(owner.parsed, member, bindings, seen, depth + 1) : undefined;
      }
      return { parsed, expression: current };
    }
    if (ts.isElementAccessExpression(current) && current.argumentExpression) {
      const owner = staticExpression(parsed, current.expression, bindings, seen, depth + 1);
      const memberName = literalText(current.argumentExpression);
      if (owner?.members && memberName !== undefined) return owner.members.get(memberName);
      const ownerExpression = owner && unwrapExpression(owner.expression);
      if (owner && memberName !== undefined && ownerExpression && ts.isObjectLiteralExpression(ownerExpression)) {
        const member = objectMemberExpression(ownerExpression, memberName);
        return member ? staticExpression(owner.parsed, member, bindings, seen, depth + 1) : undefined;
      }
      return { parsed, expression: current };
    }
    return { parsed, expression: current };
  };
  const staticString = (
    parsed: ParsedSource,
    expression: ts.Expression | undefined,
    bindings: StaticBindings,
  ): string | undefined => {
    if (!expression) return undefined;
    const resolved = staticExpression(parsed, expression, bindings);
    return resolved && literalText(resolved.expression);
  };
  const staticArrayTable = (parsed: ParsedSource, expression: ts.Expression): StaticRouteTable | undefined => {
    const resolved = staticExpression(parsed, expression, new Map());
    const current = resolved && unwrapExpression(resolved.expression);
    if (!current || !ts.isArrayLiteralExpression(current) || current.elements.length > MAX_STATIC_ROUTE_ENTRIES) return undefined;
    const elements: StaticValue[] = [];
    for (const element of current.elements) {
      if (!ts.isExpression(element) || ts.isSpreadElement(element)) return undefined;
      const resolvedElement = staticExpression(resolved.parsed, element, new Map());
      if (!resolvedElement) return undefined;
      elements.push(resolvedElement);
    }
    return { elements, transforms: 0 };
  };
  const bindingsForElement = (
    element: StaticValue,
    bindingParsed: ParsedSource,
    bindingName: ts.BindingName,
  ): StaticBindings | undefined => {
    const resolved = element.members ? element : staticExpression(element.parsed, element.expression, new Map());
    if (!resolved) return undefined;
    const bindings: StaticBindings = new Map();
    if (ts.isIdentifier(bindingName)) {
      bindings.set(bindingName.text, resolved);
      return bindings;
    }
    if (!ts.isObjectBindingPattern(bindingName)) return undefined;
    const object = unwrapExpression(resolved.expression);
    if (!resolved.members && !ts.isObjectLiteralExpression(object)) return undefined;
    for (const binding of bindingName.elements) {
      if (binding.dotDotDotToken || !ts.isIdentifier(binding.name)) return undefined;
      const sourceName = propertyName(binding.propertyName) ?? binding.name.text;
      const mappedMember = resolved.members?.get(sourceName);
      const member = ts.isObjectLiteralExpression(object) ? objectMemberExpression(object, sourceName) : undefined;
      const resolvedMember = mappedMember
        ?? (member ? staticExpression(resolved.parsed, member, new Map()) : undefined);
      if (resolvedMember) bindings.set(binding.name.text, resolvedMember);
      else if (binding.initializer) bindings.set(binding.name.text, { parsed: bindingParsed, expression: binding.initializer });
      else return undefined;
    }
    return bindings;
  };
  interface StaticTransformCallback {
    parsed: ParsedSource;
    parameter: ts.ParameterDeclaration;
    returned: ts.Expression;
  }
  const staticTransformCallback = (
    parsed: ParsedSource,
    expression: ts.Expression,
  ): StaticTransformCallback | undefined => {
    const callback = unwrapExpression(expression);
    if ((!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback))
      || hasModifier(callback, ts.SyntaxKind.AsyncKeyword)
      || (ts.isFunctionExpression(callback) && callback.asteriskToken)
      || callback.parameters.length !== 1) return undefined;
    const parameter = callback.parameters[0]!;
    if (parameter.dotDotDotToken || parameter.initializer || parameter.questionToken
      || (!ts.isIdentifier(parameter.name) && !ts.isObjectBindingPattern(parameter.name))) return undefined;
    if (ts.isObjectBindingPattern(parameter.name)
      && parameter.name.elements.some((binding) => binding.dotDotDotToken || binding.initializer
        || !ts.isIdentifier(binding.name)
        || (binding.propertyName !== undefined && propertyName(binding.propertyName) === undefined))) return undefined;
    let returned: ts.Expression;
    if (ts.isBlock(callback.body)) {
      if (callback.body.statements.length !== 1) return undefined;
      const statement = callback.body.statements[0]!;
      if (!ts.isReturnStatement(statement) || !statement.expression) return undefined;
      returned = statement.expression;
    } else returned = callback.body;
    return { parsed, parameter, returned };
  };
  type StaticPrimitive = string | number | boolean | null;
  const staticPrimitive = (
    parsed: ParsedSource,
    expression: ts.Expression,
    bindings: StaticBindings,
  ): StaticPrimitive | undefined => {
    const resolved = staticExpression(parsed, expression, bindings);
    if (!resolved || resolved.members) return undefined;
    const current = unwrapExpression(resolved.expression);
    if (ts.isStringLiteral(current) || ts.isNoSubstitutionTemplateLiteral(current)) return current.text;
    if (ts.isNumericLiteral(current)) return Number(current.text);
    if (current.kind === ts.SyntaxKind.TrueKeyword) return true;
    if (current.kind === ts.SyntaxKind.FalseKeyword) return false;
    if (current.kind === ts.SyntaxKind.NullKeyword) return null;
    return undefined;
  };
  const staticBoolean = (
    parsed: ParsedSource,
    expression: ts.Expression,
    bindings: StaticBindings,
  ): boolean | undefined => {
    const resolved = staticExpression(parsed, expression, bindings);
    if (!resolved || resolved.members) return undefined;
    const current = unwrapExpression(resolved.expression);
    if (ts.isPrefixUnaryExpression(current) && current.operator === ts.SyntaxKind.ExclamationToken) {
      const value = staticBoolean(resolved.parsed, current.operand, bindings);
      return value === undefined ? undefined : !value;
    }
    if (ts.isBinaryExpression(current)) {
      if (current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
        || current.operatorToken.kind === ts.SyntaxKind.BarBarToken) {
        const left = staticBoolean(resolved.parsed, current.left, bindings);
        const right = staticBoolean(resolved.parsed, current.right, bindings);
        if (left === undefined || right === undefined) return undefined;
        return current.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken
          ? left && right
          : left || right;
      }
      if (current.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken
        || current.operatorToken.kind === ts.SyntaxKind.ExclamationEqualsEqualsToken) {
        const left = staticPrimitive(resolved.parsed, current.left, bindings);
        const right = staticPrimitive(resolved.parsed, current.right, bindings);
        if (left === undefined || right === undefined) return undefined;
        const equal = left === right;
        return current.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken ? equal : !equal;
      }
      return undefined;
    }
    const primitive = staticPrimitive(resolved.parsed, current, bindings);
    return typeof primitive === "boolean" ? primitive : undefined;
  };
  const staticMapSelector = (
    parsed: ParsedSource,
    expression: ts.Expression,
    bindings: StaticBindings,
  ): StaticValue | undefined => {
    const current = unwrapExpression(expression);
    const literal = ts.isStringLiteral(current) || ts.isNoSubstitutionTemplateLiteral(current)
      || ts.isNumericLiteral(current)
      || current.kind === ts.SyntaxKind.TrueKeyword
      || current.kind === ts.SyntaxKind.FalseKeyword
      || current.kind === ts.SyntaxKind.NullKeyword;
    const identifier = ts.isIdentifier(current);
    const property = ts.isPropertyAccessExpression(current) && !current.questionDotToken;
    const element = ts.isElementAccessExpression(current) && !current.questionDotToken
      && current.argumentExpression !== undefined && literalText(current.argumentExpression) !== undefined;
    return literal || identifier || property || element
      ? staticExpression(parsed, current, bindings)
      : undefined;
  };
  const filterStaticRouteTable = (
    table: StaticRouteTable,
    callback: StaticTransformCallback,
  ): StaticRouteTable | undefined => {
    const elements: StaticValue[] = [];
    for (const element of table.elements) {
      const bindings = bindingsForElement(element, callback.parsed, callback.parameter.name);
      if (!bindings) return undefined;
      const included = staticBoolean(callback.parsed, callback.returned, bindings);
      if (included === undefined) return undefined;
      if (included) elements.push(element);
    }
    return { elements, transforms: table.transforms + 1 };
  };
  const mapStaticRouteTable = (
    table: StaticRouteTable,
    callback: StaticTransformCallback,
  ): StaticRouteTable | undefined => {
    const object = unwrapExpression(callback.returned);
    if (!ts.isObjectLiteralExpression(object) || object.properties.length > MAX_STATIC_ROUTE_MAP_FIELDS) return undefined;
    const elements: StaticValue[] = [];
    for (const element of table.elements) {
      const bindings = bindingsForElement(element, callback.parsed, callback.parameter.name);
      if (!bindings) return undefined;
      const members = new Map<string, StaticValue>();
      for (const property of object.properties) {
        if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) return undefined;
        if (ts.isShorthandPropertyAssignment(property) && property.objectAssignmentInitializer) return undefined;
        const name = propertyName(property.name);
        if (name === undefined || members.has(name)) return undefined;
        const initializer = ts.isPropertyAssignment(property) ? property.initializer : property.name;
        const value = staticMapSelector(callback.parsed, initializer, bindings);
        if (!value) return undefined;
        members.set(name, value);
      }
      elements.push({ parsed: callback.parsed, expression: object, members });
    }
    return { elements, transforms: table.transforms + 1 };
  };
  const staticRouteTable = (
    parsed: ParsedSource,
    expression: ts.Expression,
    seen = new Set<string>(),
    depth = 0,
    importDepth = 0,
  ): StaticRouteTable | undefined => {
    if (depth > MAX_STATIC_ROUTE_TABLE_DEPTH) return undefined;
    const current = unwrapExpression(expression);
    if (ts.isCallExpression(current) && !current.questionDotToken
      && ts.isPropertyAccessExpression(current.expression) && !current.expression.questionDotToken
      && (current.expression.name.text === "filter" || current.expression.name.text === "map")) {
      if (current.arguments.length !== 1 || current.typeArguments?.length) return undefined;
      const table = staticRouteTable(parsed, current.expression.expression, seen, depth + 1, importDepth);
      if (!table || table.transforms >= MAX_STATIC_ROUTE_TRANSFORMS) return undefined;
      const callback = staticTransformCallback(parsed, current.arguments[0]!);
      if (!callback) return undefined;
      return current.expression.name.text === "filter"
        ? filterStaticRouteTable(table, callback)
        : mapStaticRouteTable(table, callback);
    }
    const direct = staticArrayTable(parsed, current);
    if (direct) return direct;
    if (!ts.isIdentifier(current)) return undefined;
    const key = `${parsed.file.relativePath}\u0000${current.text}`;
    if (seen.has(key)) return undefined;
    const nextSeen = new Set(seen).add(key);
    const localInitializer = staticInitializers.get(key);
    if (localInitializer) {
      return staticRouteTable(localInitializer.parsed, localInitializer.expression, nextSeen, depth + 1, importDepth);
    }
    if (importDepth >= 1 || !directEsmImports.has(key)) return undefined;
    const binding = parsed.imports.get(current.text);
    if (!binding || binding.namespace || !binding.module.startsWith(".")) return undefined;
    const target = resolveModule(parsed, binding.module, lookup);
    if (!target) return undefined;
    const exportedLocal = directEsmExports.get(`${target.file.relativePath}\u0000${binding.imported}`);
    if (!exportedLocal) return undefined;
    const targetKey = `${target.file.relativePath}\u0000${exportedLocal}`;
    if (nextSeen.has(targetKey)) return undefined;
    const targetInitializer = staticInitializers.get(targetKey);
    return targetInitializer
      ? staticRouteTable(targetInitializer.parsed, targetInitializer.expression,
        new Set(nextSeen).add(targetKey), depth + 1, importDepth + 1)
      : undefined;
  };
  const resolvedArguments = (
    parsed: ParsedSource,
    values: readonly ts.Expression[],
    bindings: StaticBindings,
  ): StaticValue[] | undefined => {
    const result: StaticValue[] = [];
    for (const value of values) {
      const resolved = staticExpression(parsed, value, bindings);
      if (!resolved) return undefined;
      result.push(resolved);
    }
    return result;
  };

  const candidates: ExpressRouteCandidate[] = [];
  const middleware: ExpressMiddleware[] = [];
  const mounts: ExpressMount[] = [];
  let unresolvedHandlers = 0;
  let unresolvedMounts = 0;
  let expandedRouteCount = 0;
  const unresolvedRegistrationCalls = new Set<ts.CallExpression>();
  const expandedRegistrationCalls = new Set<ts.CallExpression>();
  const registrationTarget = (
    parsed: ParsedSource,
    node: ts.CallExpression,
    bindings: StaticBindings,
  ): { receiver: string; method?: string } | undefined => {
    const called = unwrapExpression(node.expression);
    let receiverExpression: ts.Expression;
    let method: string | undefined;
    if (ts.isPropertyAccessExpression(called)) {
      receiverExpression = called.expression;
      method = called.name.text.toLowerCase();
    } else if (ts.isElementAccessExpression(called) && called.argumentExpression) {
      receiverExpression = called.expression;
      method = staticString(parsed, called.argumentExpression, bindings)?.toLowerCase();
    } else return undefined;
    const receiver = resolvedReceiver(parsed, receiverExpression);
    return receiver ? { receiver, method } : undefined;
  };
  const addRouteCandidate = (
    parsed: ParsedSource,
    node: ts.CallExpression,
    receiver: string,
    callName: string,
    expressions: StaticValue[],
    evidence: StaticValue = { parsed, expression: node },
  ): boolean => {
    if (!HTTP_METHODS.has(callName) || expressions.length < 2) return false;
    const rawPath = literalText(expressions[0]!.expression);
    if (rawPath === undefined) return false;
    const path = normalizePath(rawPath);
    const handlerValue = expressions.at(-1)!;
    const handlerExpression = handlerValue.expression;
    const resolvedHandler = resolveExpressFunction(handlerValue.parsed, handlerExpression);
    if (!resolvedHandler) unresolvedHandlers += 1;
    const handler = resolvedHandler?.declaration;
    const handlerParsed = resolvedHandler?.parsed ?? handlerValue.parsed;
    const handlerSource = handler?.getText(handlerParsed.source) ?? handlerExpression.getText(handlerValue.parsed.source);
    const middlewareExpressions = expressions.slice(1, -1);
    const locallyAuthenticated = middlewareExpressions.some((value) => authenticatedExpression(value.parsed, value.expression))
      || explicitAuthentication(handlerSource);
    const locallyRoleProtected = middlewareExpressions.some((value) => roleExpression(value.parsed, value.expression))
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
      handlerOwnerClass: resolvedHandler?.ownerClass,
      handlerSource,
      location: location(evidence.parsed, evidence.expression),
      locallyAuthenticated,
      locallyRoleProtected,
    });
    return true;
  };

  const registrationCanExpand = (parsed: ParsedSource, candidate: ts.CallExpression): boolean => {
    if (candidate.arguments.length < 2 || !registrationTarget(parsed, candidate, new Map())) return false;
    const called = unwrapExpression(candidate.expression);
    return !ts.isPropertyAccessExpression(called) || HTTP_METHODS.has(called.name.text.toLowerCase());
  };
  const expandRegistrationCall = (
    parsed: ParsedSource,
    candidate: ts.CallExpression,
    table: StaticRouteTable,
    bindingName: ts.BindingName,
  ): void => {
    expandedRegistrationCalls.add(candidate);
    let fullyExpanded = true;
    for (const element of table.elements) {
      const bindings = bindingsForElement(element, parsed, bindingName);
      const target = bindings && registrationTarget(parsed, candidate, bindings);
      const expressions = bindings && resolvedArguments(parsed, candidate.arguments, bindings);
      if (!bindings || !target?.method || !expressions || expandedRouteCount >= MAX_STATIC_ROUTE_EXPANSIONS
        || !addRouteCandidate(parsed, candidate, target.receiver, target.method, expressions, expressions[0])) fullyExpanded = false;
      else expandedRouteCount += 1;
    }
    if (!fullyExpanded) unresolvedRegistrationCalls.add(candidate);
  };

  for (const parsed of sources) visit(parsed.source, (node) => {
    if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)
      || node.expression.name.text !== "forEach" || !node.arguments[0]) return;
    const table = staticRouteTable(parsed, node.expression.expression);
    const callback = unwrapExpression(node.arguments[0]);
    if (!table || (!ts.isArrowFunction(callback) && !ts.isFunctionExpression(callback)) || !callback.parameters[0]) return;
    visit(callback, (candidate) => {
      if (ts.isCallExpression(candidate) && registrationCanExpand(parsed, candidate)) {
        expandRegistrationCall(parsed, candidate, table, callback.parameters[0]!.name);
      }
    });
  });

  const directLoopCalls = (body: ts.Statement): ts.CallExpression[] | undefined => {
    const statements = ts.isBlock(body) ? [...body.statements] : [body];
    if (statements.length === 0) return undefined;
    const calls: ts.CallExpression[] = [];
    for (const statement of statements) {
      if (!ts.isExpressionStatement(statement)) return undefined;
      const expression = unwrapExpression(statement.expression);
      if (!ts.isCallExpression(expression)) return undefined;
      calls.push(expression);
    }
    return calls;
  };
  for (const parsed of sources) visit(parsed.source, (node) => {
    if (!ts.isForOfStatement(node) || node.awaitModifier
      || !ts.isVariableDeclarationList(node.initializer)
      || (node.initializer.flags & ts.NodeFlags.Const) === 0
      || node.initializer.declarations.length !== 1) return;
    const declaration = node.initializer.declarations[0]!;
    if (declaration.initializer
      || (!ts.isIdentifier(declaration.name) && !ts.isObjectBindingPattern(declaration.name))) return;
    const table = staticRouteTable(parsed, node.expression);
    const calls = directLoopCalls(node.statement);
    if (!table || !calls || calls.some((candidate) => !registrationCanExpand(parsed, candidate))) return;
    for (const candidate of calls) expandRegistrationCall(parsed, candidate, table, declaration.name);
  });

  for (const parsed of sources) visit(parsed.source, (node) => {
      if (!ts.isCallExpression(node) || expandedRegistrationCalls.has(node)) return;
      const target = registrationTarget(parsed, node, new Map());
      if (!target) return;
      if (!target.method) {
        if (node.arguments.length >= 2) unresolvedRegistrationCalls.add(node);
        return;
      }
      const { receiver, method: callName } = target;
      if (callName === "use") {
        const prefixText = staticString(parsed, node.arguments[0], new Map());
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
      const expressions = resolvedArguments(parsed, node.arguments, new Map());
      if (!expressions || !addRouteCandidate(parsed, node, receiver, callName, expressions)) {
        unresolvedRegistrationCalls.add(node);
      }
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
        ? localCalls.analyze(candidate.handlerParsed, candidate.handler, candidate.handlerOwnerClass, fields)
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
  return { routes, unresolvedHandlers, unresolvedMounts, unresolvedRegistrations: unresolvedRegistrationCalls.size };
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
  localCalls: LocalCallAnalyzer,
  ownerClass: ResolvedClass | undefined,
  base?: NestGlobalSecurity,
): NestGlobalSecurity {
  const result: NestGlobalSecurity = base ? { ...base } : { authentication: false, ownership: false, role: false };
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
  if (!base) {
    for (const parsed of sources) {
      visit(parsed.source, (node) => {
        if (ts.isCallExpression(node) && /(?:^|\.)useGlobalGuards$/.test(expressionName(node.expression))) {
          for (const argument of node.arguments) classify(parsed, argument);
        }
      });
    }
  }
  for (const provider of localCalls.globalGuardProviders(ownerClass)) {
    if (provider.declaration.name) classify(provider.parsed, provider.declaration.name);
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
  sources: ParsedSource[],
  baseGlobalSecurity: NestGlobalSecurity,
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
    const ownerClass = localCalls.nestControllerClass(parsed, statement);
    const globalSecurity = globalNestSecurity(sources, semantics, lookup, localCalls, ownerClass, baseGlobalSecurity);
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
          const callSemantics = localCalls.analyze(parsed, member, ownerClass, fields);
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
  let unresolvedRegistrations = 0;
  if (detectedExpress) {
    const result = expressRoutes(parsed, localCalls);
    routes.push(...result.routes);
    unresolvedHandlers += result.unresolvedHandlers;
    unresolvedMounts += result.unresolvedMounts;
    unresolvedRegistrations += result.unresolvedRegistrations;
  }
  if (detectedNest) {
    const semantics = discoverNestSecurity(parsed, lookup);
    const baseGlobalSecurity = globalNestSecurity(parsed, semantics, lookup, localCalls, undefined);
    const routing = nestRoutingConfig(parsed);
    for (const item of parsed) routes.push(...nestRoutes(item, parsed, baseGlobalSecurity, semantics, lookup, routing, localCalls));
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
    unresolvedRegistrations,
    unresolvedProviderDependencies: localCalls.unresolvedProviderDependencies(),
    unresolvedBootstrapRoots: localCalls.unresolvedBootstrapRoots(),
  };
}
