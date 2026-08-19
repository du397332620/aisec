const MAX_SQL_STATEMENTS = 10_000;
const MAX_SQL_POLICIES = 2_000;
const MAX_FIREBASE_FUNCTIONS = 256;
const MAX_FIREBASE_ALLOWS = 2_000;
const MAX_STATEMENT_CHARS = 256 * 1024;
const MAX_EXPRESSION_CHARS = 64 * 1024;
const MAX_HELPER_EXPANSION_DEPTH = 8;
const MAX_EXPRESSION_NESTING = 64;
const MAX_FIREBASE_HELPER_PARAMETERS = 7;

interface SourceExpression {
  text: string;
  start: number;
}

export interface SqlTableDeclaration {
  table: string;
  start: number;
  text: string;
}

export interface SupabasePolicy {
  table: string;
  start: number;
  text: string;
  command: "all" | "select" | "insert" | "update" | "delete";
  roles: string[];
  restrictive: boolean;
  using?: SourceExpression;
  check?: SourceExpression;
}

export interface SupabaseSqlAnalysis {
  createdTables: SqlTableDeclaration[];
  rlsTables: string[];
  policies: SupabasePolicy[];
  partialReasons: string[];
}

export interface FirebaseAllow {
  methods: string[];
  start: number;
  text: string;
  expression: string;
  unconditional: boolean;
  authenticationOnly: boolean;
  storageUploadWithoutSizeLimit: boolean;
  unresolvedLocalHelper: boolean;
}

export interface FirebaseRulesAnalysis {
  service: "firestore" | "storage" | "unknown";
  allows: FirebaseAllow[];
  partialReasons: string[];
}

type Language = "sql" | "firebase";

function blank(output: string[], source: string, start: number, end: number): void {
  for (let index = start; index < end; index += 1) {
    const value = source[index];
    if (value !== "\n" && value !== "\r") output[index] = " ";
  }
}

function quotedEnd(source: string, start: number, quote: string, doubledQuotes: boolean, backslashEscapes: boolean): { end: number; closed: boolean } {
  for (let index = start + 1; index < source.length; index += 1) {
    if (backslashEscapes && source[index] === "\\") {
      index += 1;
      continue;
    }
    if (source[index] !== quote) continue;
    if (doubledQuotes && source[index + 1] === quote) {
      index += 1;
      continue;
    }
    return { end: index + 1, closed: true };
  }
  return { end: source.length, closed: false };
}

function blockCommentEnd(source: string, start: number): { end: number; closed: boolean } {
  let depth = 1;
  for (let index = start + 2; index < source.length - 1; index += 1) {
    const pair = source.slice(index, index + 2);
    if (pair === "/*") {
      depth += 1;
      index += 1;
    } else if (pair === "*/") {
      depth -= 1;
      index += 1;
      if (depth === 0) return { end: index + 1, closed: true };
    }
  }
  return { end: source.length, closed: false };
}

function lexicalMask(source: string, language: Language, maskQuoted: boolean, partialReasons?: string[]): string {
  const output = source.split("");
  for (let index = 0; index < source.length;) {
    const pair = source.slice(index, index + 2);
    const lineComment = language === "sql" ? pair === "--" : pair === "//";
    if (lineComment) {
      const newline = source.indexOf("\n", index + 2);
      const end = newline === -1 ? source.length : newline;
      blank(output, source, index, end);
      index = end;
      continue;
    }
    if (pair === "/*") {
      const comment = blockCommentEnd(source, index);
      if (!comment.closed) partialReasons?.push(`${language === "sql" ? "SQL" : "Firebase"} block comment is not terminated`);
      blank(output, source, index, comment.end);
      index = comment.end;
      continue;
    }
    const value = source[index];
    if (value === "'" || value === '"') {
      const sqlEscapeString = language === "sql" && value === "'" && /[eE]/.test(source[index - 1] ?? "")
        && !/[A-Za-z0-9_$]/.test(source[index - 2] ?? "");
      const quoted = quotedEnd(source, index, value, language === "sql", language === "firebase" || sqlEscapeString);
      if (!quoted.closed) partialReasons?.push(`${language === "sql" ? "SQL" : "Firebase"} quoted value is not terminated`);
      if (maskQuoted) blank(output, source, index, quoted.end);
      index = quoted.end;
      continue;
    }
    if (language === "sql" && value === "$") {
      const delimiter = source.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/)?.[0];
      if (delimiter) {
        const closing = source.indexOf(delimiter, index + delimiter.length);
        const end = closing === -1 ? source.length : closing + delimiter.length;
        if (closing === -1) partialReasons?.push(`SQL dollar-quoted value ${delimiter} is not terminated`);
        blank(output, source, index, end);
        index = end;
        continue;
      }
    }
    index += 1;
  }
  return output.join("");
}

function expressionNesting(value: string, language: Language): number {
  const structural = lexicalMask(value, language, true);
  let depth = 0;
  let maximum = 0;
  for (const character of structural) {
    if (character === "(" || character === "[" || character === "{") {
      depth += 1;
      maximum = Math.max(maximum, depth);
    } else if (character === ")" || character === "]" || character === "}") depth = Math.max(0, depth - 1);
  }
  return maximum;
}

function normalizeIdentifier(value: string): string {
  return value.replaceAll('"', "").replace(/\s+/g, "").toLowerCase();
}

const SQL_IDENTIFIER = '(?:"(?:[^"]|"")*"|[A-Za-z_][A-Za-z0-9_$]*)';
const SQL_RELATION = `${SQL_IDENTIFIER}(?:\\s*\\.\\s*${SQL_IDENTIFIER})?`;

function relationAfter(source: string, prefix: RegExp): string | undefined {
  const match = source.match(prefix);
  return match?.[1] ? normalizeIdentifier(match[1]) : undefined;
}

function expressionAfter(statement: string, structural: string, statementStart: number, pattern: RegExp): SourceExpression | undefined {
  const match = pattern.exec(structural);
  if (!match) return undefined;
  const open = structural.indexOf("(", match.index);
  if (open === -1) return undefined;
  let depth = 0;
  for (let index = open; index < structural.length; index += 1) {
    if (structural[index] === "(") depth += 1;
    else if (structural[index] === ")") {
      depth -= 1;
      if (depth === 0) return { text: statement.slice(open + 1, index), start: statementStart + open + 1 };
    }
  }
  return undefined;
}

function compactAtom(value: string, language: Language): string {
  return lexicalMask(value, language, false).toLowerCase().replace(/[\s()]/g, "");
}

type GrantKind = "unconditional" | "authentication_only" | "constrained";

function trimOuterParentheses(value: string, language: Language): string {
  let result = value.trim();
  for (let depth = 0; depth < MAX_EXPRESSION_NESTING && result.startsWith("("); depth += 1) {
    const structural = lexicalMask(result, language, true);
    const close = findClosing(structural, 0, "(", ")");
    if (close !== structural.length - 1) break;
    result = result.slice(1, -1).trim();
  }
  return result;
}

function splitTopLevelBoolean(value: string, language: Language, operator: "or" | "and"): string[] {
  const structural = lexicalMask(value, language, true);
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let index = 0; index < structural.length; index += 1) {
    if (structural[index] === "(") {
      depth += 1;
      continue;
    }
    if (structural[index] === ")") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth !== 0) continue;
    const symbolic = operator === "or" ? "||" : "&&";
    const symbolicMatch = language === "firebase" && structural.slice(index, index + 2) === symbolic;
    const keyword = language === "sql" ? structural.slice(index).match(new RegExp(`^${operator}\\b`, "i"))?.[0] : undefined;
    const previous = structural[index - 1];
    const keywordMatch = keyword !== undefined && (previous === undefined || !/[A-Za-z0-9_$]/.test(previous));
    if (!symbolicMatch && !keywordMatch) continue;
    parts.push(value.slice(start, index));
    const length = symbolicMatch ? 2 : keyword!.length;
    index += length - 1;
    start = index + 1;
  }
  if (parts.length === 0) return [value];
  parts.push(value.slice(start));
  return parts;
}

function classifyBooleanGrant(value: string, language: Language, isAuthenticationAtom: (atom: string) => boolean): GrantKind {
  const expression = trimOuterParentheses(value, language);
  const orParts = splitTopLevelBoolean(expression, language, "or");
  if (orParts.length > 1) {
    const kinds = orParts.map((part) => classifyBooleanGrant(part, language, isAuthenticationAtom));
    if (kinds.includes("unconditional")) return "unconditional";
    if (kinds.includes("authentication_only")) return "authentication_only";
    return "constrained";
  }
  const andParts = splitTopLevelBoolean(expression, language, "and");
  if (andParts.length > 1) {
    const kinds = andParts.map((part) => classifyBooleanGrant(part, language, isAuthenticationAtom));
    if (kinds.includes("constrained")) return "constrained";
    return kinds.includes("authentication_only") ? "authentication_only" : "unconditional";
  }
  const atom = compactAtom(expression, language);
  if (atom === "true") return "unconditional";
  return isAuthenticationAtom(atom) ? "authentication_only" : "constrained";
}

function isSqlTrue(expression: SourceExpression | undefined): boolean {
  return expression !== undefined && classifySqlGrant(expression) === "unconditional";
}

function classifySqlGrant(expression: SourceExpression): GrantKind {
  const withoutSelectWrapper = lexicalMask(expression.text, "sql", false)
    .replace(/\(\s*select\s+(auth\.(?:uid|role)\s*\(\s*\))\s*\)/gi, "$1");
  return classifyBooleanGrant(withoutSelectWrapper, "sql", (atom) => atom === "auth.uidisnotnull"
    || atom === "auth.role='authenticated'"
    || atom === "'authenticated'=auth.role"
    || atom === "current_user='authenticated'"
    || atom === "'authenticated'=current_user");
}

function sqlAuthenticationOnly(expression: SourceExpression): boolean {
  return classifySqlGrant(expression) === "authentication_only";
}

function clientReachable(roles: string[]): boolean {
  return roles.some((role) => role === "public" || role === "anon" || role === "authenticated");
}

export function supabasePolicyIsUnconditional(policy: SupabasePolicy): boolean {
  if (policy.restrictive || !clientReachable(policy.roles)) return false;
  return (!policy.using && !policy.check) || isSqlTrue(policy.using) || isSqlTrue(policy.check);
}

export function supabasePolicyIsAuthenticationOnly(policy: SupabasePolicy): boolean {
  if (policy.restrictive || !clientReachable(policy.roles)) return false;
  return [policy.using, policy.check].some((expression) => expression !== undefined && sqlAuthenticationOnly(expression));
}

export function supabasePolicyUsesUserMetadata(policy: SupabasePolicy): boolean {
  if (!clientReachable(policy.roles)) return false;
  return [policy.using, policy.check].some((expression) => {
    if (!expression) return false;
    const structural = lexicalMask(expression.text, "sql", true);
    return [...structural.matchAll(/auth\s*\.\s*jwt\s*\(\s*\)/gi)].some((match) => {
      const start = match.index ?? 0;
      const tail = expression.text.slice(start + match[0].length, start + 160);
      return /^\s*(?:(?:->>?|#>>?)\s*['"](?:\{[^'"]*)?(?:raw_user_meta_data|user_metadata)\b|\[\s*['"](?:raw_user_meta_data|user_metadata)['"]\s*\]|,\s*['"](?:raw_user_meta_data|user_metadata)['"])/i.test(tail);
    });
  });
}

export function analyzeSupabaseSql(source: string): SupabaseSqlAnalysis {
  const partialReasons: string[] = [];
  const structural = lexicalMask(source, "sql", true, partialReasons);
  const statements: Array<{ source: string; structural: string; start: number }> = [];
  let start = 0;
  let statementCount = 0;
  for (let index = 0; index <= structural.length; index += 1) {
    if (index !== structural.length && structural[index] !== ";") continue;
    const masked = structural.slice(start, index + (index < structural.length ? 1 : 0));
    if (masked.trim()) {
      statementCount += 1;
      if (statementCount > MAX_SQL_STATEMENTS) {
        partialReasons.push(`SQL statement count exceeded ${MAX_SQL_STATEMENTS}`);
        break;
      }
      if (masked.length > MAX_STATEMENT_CHARS) partialReasons.push(`SQL statement exceeded ${MAX_STATEMENT_CHARS} characters`);
      else statements.push({ source: source.slice(start, start + masked.length), structural: masked, start });
    }
    start = index + 1;
  }

  const createdTables: SqlTableDeclaration[] = [];
  const rlsTables: string[] = [];
  const policies: SupabasePolicy[] = [];
  const createTable = new RegExp(`create\\s+(?:(?:unlogged|temporary|temp)\\s+)?table(?:\\s+if\\s+not\\s+exists)?\\s+(${SQL_RELATION})`, "i");
  const alterTable = new RegExp(`alter\\s+table(?:\\s+only)?\\s+(${SQL_RELATION})`, "i");
  const policyTable = new RegExp(`create\\s+policy\\s+(?:${SQL_IDENTIFIER})\\s+on(?:\\s+only)?\\s+(${SQL_RELATION})`, "i");
  let policyCount = 0;
  for (const statement of statements) {
    const createStart = statement.structural.search(/\bcreate\s+(?:(?:unlogged|temporary|temp)\s+)?table\b/i);
    if (createStart !== -1) {
      const table = relationAfter(statement.source.slice(createStart), createTable);
      if (table) createdTables.push({ table, start: statement.start + createStart, text: statement.source.slice(createStart) });
    }
    const alterStart = statement.structural.search(/\balter\s+table\b/i);
    if (alterStart !== -1 && /\benable\s+row\s+level\s+security\b/i.test(statement.structural)) {
      const table = relationAfter(statement.source.slice(alterStart), alterTable);
      if (table) rlsTables.push(table);
    }
    const policyStart = statement.structural.search(/\bcreate\s+policy\b/i);
    if (policyStart === -1) continue;
    policyCount += 1;
    if (policyCount > MAX_SQL_POLICIES) {
      partialReasons.push(`SQL policy count exceeded ${MAX_SQL_POLICIES}`);
      break;
    }
    const policySource = statement.source.slice(policyStart);
    const policyStructural = statement.structural.slice(policyStart);
    const table = relationAfter(policySource, policyTable) ?? "unknown";
    const using = expressionAfter(policySource, policyStructural, statement.start + policyStart, /\busing\s*\(/i);
    const check = expressionAfter(policySource, policyStructural, statement.start + policyStart, /\bwith\s+check\s*\(/i);
    if ((/\busing\s*\(/i.test(policyStructural) && !using) || (/\bwith\s+check\s*\(/i.test(policyStructural) && !check)) {
      partialReasons.push(`policy on ${table} contains an unbalanced expression`);
      continue;
    }
    if ([using, check].some((expression) => expression && expression.text.length > MAX_EXPRESSION_CHARS)) {
      partialReasons.push(`policy on ${table} exceeded ${MAX_EXPRESSION_CHARS} expression characters`);
      continue;
    }
    if ([using, check].some((expression) => expression && expressionNesting(expression.text, "sql") > MAX_EXPRESSION_NESTING)) {
      partialReasons.push(`policy on ${table} exceeded ${MAX_EXPRESSION_NESTING} expression nesting levels`);
      continue;
    }
    const firstExpression = Math.min(using?.start ?? Number.POSITIVE_INFINITY, check?.start ?? Number.POSITIVE_INFINITY) - statement.start - policyStart;
    const header = policyStructural.slice(0, Number.isFinite(firstExpression) ? firstExpression : undefined);
    const toMatch = /\bto\b/i.exec(header);
    let roles = ["public"];
    if (toMatch) {
      const rolesStart = toMatch.index + toMatch[0].length;
      const boundary = header.slice(rolesStart).search(/\b(?:using|with\s+check)\b/i);
      const rolesEnd = boundary === -1 ? header.length : rolesStart + boundary;
      roles = policySource.slice(rolesStart, rolesEnd).split(",")
        .map((role) => normalizeIdentifier(role.replace(/^\s*group\s+/i, "")).replace(/;$/, ""))
        .filter((role) => ["public", "anon", "authenticated", "service_role", "postgres"].includes(role));
    }
    const command = (header.match(/\bfor\s+(all|select|insert|update|delete)\b/i)?.[1]?.toLowerCase() ?? "all") as SupabasePolicy["command"];
    policies.push({
      table,
      start: statement.start + policyStart,
      text: policySource,
      command,
      roles: roles.length > 0 ? roles : ["custom"],
      restrictive: /\bas\s+restrictive\b/i.test(header),
      using,
      check,
    });
  }
  return { createdTables, rlsTables, policies, partialReasons: [...new Set(partialReasons)] };
}

interface FirebaseFunction {
  expression?: string;
  parameters?: string[];
}

function findClosing(value: string, open: number, left: string, right: string): number | undefined {
  let depth = 0;
  for (let index = open; index < value.length; index += 1) {
    if (value[index] === left) depth += 1;
    else if (value[index] === right) {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return undefined;
}

function firebaseAllowEnd(value: string, start: number): { end: number; includesTerminator: boolean } | undefined {
  let round = 0;
  let square = 0;
  let brace = 0;
  for (let index = start; index < value.length; index += 1) {
    const character = value[index];
    if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "{") brace += 1;
    else if (character === "}") {
      if (round === 0 && square === 0 && brace === 0) return { end: index, includesTerminator: false };
      brace -= 1;
    } else if (character === ";" && round === 0 && square === 0 && brace === 0) {
      return { end: index, includesTerminator: true };
    }
    if (round < 0 || square < 0 || brace < 0) return undefined;
  }
  return undefined;
}

function firebaseAuthenticationOnly(expression: string): boolean {
  return classifyBooleanGrant(expression, "firebase", (atom) => atom === "request.auth!=null"
    || atom === "request.auth.uid!=null") === "authentication_only";
}

function firebaseTrue(expression: string): boolean {
  return classifyBooleanGrant(expression, "firebase", (atom) => atom === "request.auth!=null"
    || atom === "request.auth.uid!=null") === "unconditional";
}

function upperBoundsStorageSize(expression: string): boolean {
  const value = lexicalMask(expression, "firebase", true).toLowerCase();
  return /request\s*\.\s*resource\s*\.\s*size\s*<=?\s*[^=]/i.test(value)
    || /(?:\d|\bmax[a-z0-9_]*)[\w\s*+/_-]*>=?\s*request\s*\.\s*resource\s*\.\s*size/i.test(value);
}

function firebaseArguments(value: string, open: number, close: number): string[] | undefined {
  const structural = lexicalMask(value.slice(open + 1, close), "firebase", true);
  const arguments_: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let brace = 0;
  for (let index = 0; index <= structural.length; index += 1) {
    const character = structural[index];
    if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "{") brace += 1;
    else if (character === "}") brace -= 1;
    if (round < 0 || square < 0 || brace < 0) return undefined;
    if (index !== structural.length && (character !== "," || round !== 0 || square !== 0 || brace !== 0)) continue;
    arguments_.push(value.slice(open + 1 + start, open + 1 + index).trim());
    start = index + 1;
  }
  if (round !== 0 || square !== 0 || brace !== 0) return undefined;
  if (arguments_.length === 1 && arguments_[0] === "") return [];
  return arguments_;
}

function substituteFirebaseParameter(expression: string, parameter: string, argument: string): string {
  const structural = lexicalMask(expression, "firebase", true);
  const matches = [...structural.matchAll(new RegExp(`(?<![A-Za-z0-9_$.])${parameter}\\b`, "g"))];
  let substituted = expression;
  for (const match of matches.reverse()) {
    const start = match.index ?? 0;
    substituted = `${substituted.slice(0, start)}(${argument})${substituted.slice(start + parameter.length)}`;
  }
  return substituted;
}

function expandFirebaseFunctions(expression: string, functions: Map<string, FirebaseFunction>, forceUnresolved: boolean): { expression: string; unresolved: boolean; exceeded: boolean } {
  let expanded = expression;
  let exceeded = false;
  for (let depth = 0; depth < MAX_HELPER_EXPANSION_DEPTH; depth += 1) {
    let changed = false;
    for (const [name, helper] of functions) {
      if (helper.parameters === undefined || helper.expression === undefined) continue;
      const structural = lexicalMask(expanded, "firebase", true);
      const pattern = new RegExp(`(?<![A-Za-z0-9_$.])${name}\\s*\\(`, "g");
      const replacements: Array<{ start: number; end: number; value: string }> = [];
      let coveredUntil = -1;
      for (const match of structural.matchAll(pattern)) {
        const start = match.index ?? 0;
        if (start < coveredUntil) continue;
        const open = structural.indexOf("(", start + name.length);
        const close = open === -1 ? undefined : findClosing(structural, open, "(", ")");
        if (close === undefined) continue;
        coveredUntil = close + 1;
        const arguments_ = firebaseArguments(expanded, open, close);
        if (arguments_ === undefined || arguments_.length !== helper.parameters.length) continue;
        let replacement = helper.expression;
        for (let index = 0; index < helper.parameters.length; index += 1) {
          replacement = substituteFirebaseParameter(replacement, helper.parameters[index]!, arguments_[index]!);
        }
        replacements.push({ start, end: close + 1, value: `(${replacement})` });
      }
      if (replacements.length === 0) continue;
      for (const replacement of replacements.reverse()) {
        expanded = `${expanded.slice(0, replacement.start)}${replacement.value}${expanded.slice(replacement.end)}`;
        if (expanded.length > MAX_EXPRESSION_CHARS) {
          exceeded = true;
          break;
        }
      }
      changed = true;
      if (exceeded) break;
    }
    if (!changed || exceeded) break;
  }
  const finalStructural = lexicalMask(expanded, "firebase", true);
  const unresolved = exceeded || forceUnresolved
    || [...functions].some(([name]) => new RegExp(`(?<![A-Za-z0-9_$.])${name}\\s*\\(`).test(finalStructural));
  return { expression: expanded, unresolved, exceeded };
}

export function analyzeFirebaseRules(source: string): FirebaseRulesAnalysis {
  const partialReasons: string[] = [];
  const structural = lexicalMask(source, "firebase", true, partialReasons);
  const service: FirebaseRulesAnalysis["service"] = /\bservice\s+firebase\s*\.\s*storage\b/i.test(structural)
    ? "storage"
    : /\bservice\s+cloud\s*\.\s*firestore\b/i.test(structural) ? "firestore" : "unknown";
  const functions = new Map<string, FirebaseFunction>();
  let helperEnumerationIncomplete = false;
  let helperCount = 0;
  const functionPattern = /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{/g;
  for (const match of structural.matchAll(functionPattern)) {
    helperCount += 1;
    if (helperCount > MAX_FIREBASE_FUNCTIONS) {
      partialReasons.push(`Firebase helper count exceeded ${MAX_FIREBASE_FUNCTIONS}`);
      helperEnumerationIncomplete = true;
      break;
    }
    const name = match[1]!;
    const duplicate = functions.has(name);
    if (duplicate) partialReasons.push(`Firebase helper ${name} is declared more than once and has ambiguous static scope`);
    const open = structural.indexOf("{", match.index ?? 0);
    const close = open === -1 ? undefined : findClosing(structural, open, "{", "}");
    if (close === undefined) {
      partialReasons.push(`Firebase helper ${name} has an unbalanced body`);
      functions.set(name, {});
      continue;
    }
    const body = structural.slice(open + 1, close);
    const returned = body.match(/^\s*return\b([\s\S]*?);\s*$/);
    const expressionOffset = returned?.[1] === undefined ? -1 : body.indexOf(returned[1]);
    let expression = expressionOffset === -1 ? undefined : source.slice(open + 1 + expressionOffset, open + 1 + expressionOffset + returned![1]!.length);
    if (expression !== undefined && expression.length > MAX_EXPRESSION_CHARS) {
      partialReasons.push(`Firebase helper ${name} exceeded ${MAX_EXPRESSION_CHARS} expression characters`);
      expression = undefined;
    }
    if (expression !== undefined && expressionNesting(expression, "firebase") > MAX_EXPRESSION_NESTING) {
      partialReasons.push(`Firebase helper ${name} exceeded ${MAX_EXPRESSION_NESTING} expression nesting levels`);
      expression = undefined;
    }
    const rawParameters = match[2]!.trim() ? match[2]!.split(",").map((parameter) => parameter.trim()) : [];
    const parameters = rawParameters.length <= MAX_FIREBASE_HELPER_PARAMETERS
      && rawParameters.every((parameter) => /^[A-Za-z_][A-Za-z0-9_]*$/.test(parameter)) ? rawParameters : undefined;
    if (parameters === undefined) partialReasons.push(`Firebase helper ${name} has unsupported parameters`);
    functions.set(name, duplicate ? {} : { expression, parameters });
  }

  const allows: FirebaseAllow[] = [];
  const methodGroup = "(?:read|write|get|list|create|update|delete)(?:\\s*,\\s*(?:read|write|get|list|create|update|delete))*";
  const conditional = new RegExp(`\\ballow\\s+(${methodGroup})\\s*:\\s*if\\b`, "gi");
  for (const match of structural.matchAll(conditional)) {
    if (allows.length >= MAX_FIREBASE_ALLOWS) {
      partialReasons.push(`Firebase allow count exceeded ${MAX_FIREBASE_ALLOWS}`);
      break;
    }
    let expressionStart = (match.index ?? 0) + match[0].length;
    while (/\s/.test(structural[expressionStart] ?? "")) expressionStart += 1;
    const termination = firebaseAllowEnd(structural, expressionStart);
    if (termination === undefined) {
      partialReasons.push("Firebase allow expression is not terminated");
      continue;
    }
    const end = termination.end;
    const expression = source.slice(expressionStart, end);
    if (expression.length > MAX_EXPRESSION_CHARS) {
      partialReasons.push(`Firebase allow expression exceeded ${MAX_EXPRESSION_CHARS} characters`);
      continue;
    }
    if (expressionNesting(expression, "firebase") > MAX_EXPRESSION_NESTING) {
      partialReasons.push(`Firebase allow expression exceeded ${MAX_EXPRESSION_NESTING} nesting levels`);
      continue;
    }
    const expanded = expandFirebaseFunctions(expression, functions, helperEnumerationIncomplete);
    if (expanded.exceeded) partialReasons.push(`Firebase helper expansion exceeded ${MAX_EXPRESSION_CHARS} characters`);
    if (expressionNesting(expanded.expression, "firebase") > MAX_EXPRESSION_NESTING) {
      partialReasons.push(`Firebase expanded allow expression exceeded ${MAX_EXPRESSION_NESTING} nesting levels`);
      continue;
    }
    const methods = match[1]!.toLowerCase().split(",").map((method) => method.trim());
    const upload = service === "storage" && methods.some((method) => method === "write" || method === "create" || method === "update");
    allows.push({
      methods,
      start: match.index ?? 0,
      text: source.slice(match.index ?? 0, end + (termination.includesTerminator ? 1 : 0)),
      expression,
      unconditional: firebaseTrue(expanded.expression),
      authenticationOnly: firebaseAuthenticationOnly(expanded.expression),
      storageUploadWithoutSizeLimit: upload && !expanded.unresolved && !upperBoundsStorageSize(expanded.expression),
      unresolvedLocalHelper: expanded.unresolved,
    });
  }

  const unconditional = new RegExp(`\\ballow\\s+(${methodGroup})\\s*(?:;|(?=\\}))`, "gi");
  for (const match of structural.matchAll(unconditional)) {
    if (allows.length >= MAX_FIREBASE_ALLOWS) {
      partialReasons.push(`Firebase allow count exceeded ${MAX_FIREBASE_ALLOWS}`);
      break;
    }
    const methods = match[1]!.toLowerCase().split(",").map((method) => method.trim());
    const upload = service === "storage" && methods.some((method) => method === "write" || method === "create" || method === "update");
    allows.push({
      methods,
      start: match.index ?? 0,
      text: match[0],
      expression: "true",
      unconditional: true,
      authenticationOnly: false,
      storageUploadWithoutSizeLimit: upload,
      unresolvedLocalHelper: false,
    });
  }
  if (service === "unknown" && allows.length > 0) partialReasons.push("Firebase service declaration could not be resolved");
  if (allows.some((allow) => allow.unresolvedLocalHelper)) {
    partialReasons.push(`Firebase ${service === "unknown" ? "security" : service} rule uses a local helper outside the bounded single-return model`);
  }
  allows.sort((left, right) => left.start - right.start);
  return { service, allows, partialReasons: [...new Set(partialReasons)] };
}
