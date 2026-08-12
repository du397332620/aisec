import ts from "typescript";
import { extname } from "node:path";
import type { DetectorResult } from "./types.js";
import type { ScanContext } from "../core/context.js";
import type { Severity, Signal } from "../schema.js";
import { createSignal, makeLocation } from "../core/utils.js";
import { MAX_SIGNALS_PER_DETECTOR } from "../core/constants.js";

const TS_EXTENSIONS = new Set([".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"]);

function scriptKind(path: string): ts.ScriptKind {
  const extension = extname(path).toLowerCase();
  if (extension === ".tsx") return ts.ScriptKind.TSX;
  if (extension === ".jsx") return ts.ScriptKind.JSX;
  if ([".js", ".mjs", ".cjs"].includes(extension)) return ts.ScriptKind.JS;
  return ts.ScriptKind.TS;
}

function rootIdentifier(expression: ts.Expression): string | undefined {
  let current = expression;
  while (ts.isPropertyAccessExpression(current) || ts.isElementAccessExpression(current)) current = current.expression;
  return ts.isIdentifier(current) ? current.text : undefined;
}

function calleeName(expression: ts.Expression): string {
  if (ts.isIdentifier(expression)) return expression.text;
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression) && ts.isStringLiteral(expression.argumentExpression)) return expression.argumentExpression.text;
  return expression.getText();
}

function containsAny(value: string, fragments: string[]): boolean {
  return fragments.some((fragment) => value.includes(fragment));
}

function expressionHasIdentifier(expression: ts.Node, names: Set<string>): boolean {
  let found = false;
  const visit = (node: ts.Node): void => {
    if (ts.isIdentifier(node) && names.has(node.text)) found = true;
    if (!found) ts.forEachChild(node, visit);
  };
  visit(expression);
  return found;
}

function directUserInput(expression: ts.Expression): boolean {
  const text = expression.getText();
  const root = rootIdentifier(expression);
  if (root && ["req", "request", "ctx", "event"].includes(root)
    && /(?:body|query|params|headers|cookies|searchParams|formData|json)/.test(text)) return true;
  if (ts.isCallExpression(expression)) {
    const call = expression.expression.getText();
    if (/(?:searchParams|formData|cookies|headers)\.get$/.test(call)) return true;
    if (/\.(?:json|text|formData)$/.test(call) && /(?:req|request)/i.test(call)) return true;
  }
  return false;
}

function directModelOutput(expression: ts.Expression, modelObjects: Set<string>): boolean {
  const text = expression.getText();
  const root = rootIdentifier(expression);
  return Boolean(
    (root && modelObjects.has(root) && /(?:content|text|output|arguments|tool_calls|function_call)/i.test(text))
    || /(?:output_text|generatedText|completion\.choices|response\.choices)/.test(text),
  );
}

function sourceSnippet(source: ts.SourceFile, node: ts.Node): string {
  const lineStart = source.getLineStarts()[source.getLineAndCharacterOfPosition(node.getStart(source)).line] ?? node.getStart(source);
  const lineEnd = source.text.indexOf("\n", lineStart);
  return source.text.slice(lineStart, lineEnd === -1 ? undefined : lineEnd);
}

function makeFlowSignal(
  source: ts.SourceFile,
  path: string,
  node: ts.Node,
  input: { ruleId: string; title: string; description: string; severity: Severity; cwe: string; tags: string[]; remediation: string },
): Signal {
  return createSignal({
    engine: "aisec-typescript",
    ruleId: input.ruleId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    evidenceLevel: "static_confirmed",
    confidence: "high",
    locations: [makeLocation(path, source.text, node.getStart(source), sourceSnippet(source, node))],
    cwe: [input.cwe],
    owasp: [input.ruleId.includes("ssrf") ? "A10:2021" : "A03:2021"],
    tags: input.tags,
    remediation: input.remediation,
  });
}

export async function runTypeScriptDataflow(context: ScanContext): Promise<DetectorResult> {
  const started = Date.now();
  const signals: Signal[] = [];
  const files = context.inventory.files.filter((file) => TS_EXTENSIONS.has(extname(file.relativePath).toLowerCase()));
  let filesWithParseErrors = 0;
  let truncated = false;

  const add = (signal: Signal): void => {
    if (signals.length >= MAX_SIGNALS_PER_DETECTOR) truncated = true;
    else signals.push(signal);
  };

  for (const file of files) {
    if (truncated) break;
    const source = ts.createSourceFile(file.relativePath, file.content, ts.ScriptTarget.Latest, true, scriptKind(file.relativePath));
    const parseDiagnostics = (source as ts.SourceFile & { parseDiagnostics?: readonly ts.Diagnostic[] }).parseDiagnostics ?? [];
    if (parseDiagnostics.length > 0) filesWithParseErrors += 1;
    const userTainted = new Set<string>();
    const modelObjects = new Set<string>();
    const modelTainted = new Set<string>();

    const isUserTainted = (expression: ts.Expression): boolean => directUserInput(expression) || expressionHasIdentifier(expression, userTainted);
    const isModelTainted = (expression: ts.Expression): boolean => directModelOutput(expression, modelObjects) || expressionHasIdentifier(expression, modelTainted);

    const visit = (node: ts.Node): void => {
      if (truncated) return;
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const initText = node.initializer.getText();
        if (isUserTainted(node.initializer)) userTainted.add(node.name.text);
        if (containsAny(initText, ["chat.completions.create", "responses.create", "generateText(", "generateContent(", "messages.create("])) modelObjects.add(node.name.text);
        if (isModelTainted(node.initializer)) modelTainted.add(node.name.text);
      }
      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken && ts.isIdentifier(node.left)) {
        if (isUserTainted(node.right)) userTainted.add(node.left.text);
        if (isModelTainted(node.right)) modelTainted.add(node.left.text);
      }

      if (ts.isCallExpression(node)) {
        const name = calleeName(node.expression);
        const first = node.arguments[0];
        if (first && isUserTainted(first)) {
          if (["query", "execute", "exec", "run", "$queryRawUnsafe", "$executeRawUnsafe"].includes(name)
            && /(?:select|insert|update|delete|sql|query|`|\+)/i.test(first.getText())) {
            add(makeFlowSignal(source, file.relativePath, node, {
              ruleId: "dataflow.sql-injection",
              title: "Request data reaches a database query without a visible parameter boundary",
              description: "The local data-flow analyzer traced request-controlled data into a query-like sink.",
              severity: "high", cwe: "CWE-89", tags: ["dataflow", "injection", "database"],
              remediation: "Use a parameterized query or typed query builder and validate the identifier/value before use.",
            }));
          }
          if (["exec", "execSync", "spawn", "spawnSync", "system", "eval", "Function"].includes(name)) {
            add(makeFlowSignal(source, file.relativePath, node, {
              ruleId: "dataflow.command-injection",
              title: "Request data reaches code or command execution",
              description: "Request-controlled data flows into an execution primitive.",
              severity: "critical", cwe: "CWE-78", tags: ["dataflow", "injection", "rce"],
              remediation: "Remove the execution primitive or use a fixed executable with an allowlisted argument vector; never construct a shell command.",
            }));
          }
          if (["fetch", "request", "get", "post"].includes(name) && /(?:url|uri|href|req|request|params|query)/i.test(first.getText())) {
            add(makeFlowSignal(source, file.relativePath, node, {
              ruleId: "dataflow.ssrf",
              title: "Request-controlled URL reaches a server-side network client",
              description: "An attacker-controlled URL may let the server contact internal or privileged services.",
              severity: "high", cwe: "CWE-918", tags: ["dataflow", "ssrf", "network"],
              remediation: "Resolve and allowlist schemes, hostnames, ports and IP ranges; reject redirects and private/metadata addresses.",
            }));
          }
        }
        if (first && isModelTainted(first) && ["exec", "execSync", "spawn", "spawnSync", "system", "eval", "Function", "query", "execute"].includes(name)) {
          add(makeFlowSignal(source, file.relativePath, node, {
            ruleId: "ai.model-output-dangerous-sink",
            title: "Model output reaches a privileged execution sink",
            description: "Untrusted model output flows into command, code, or database execution. Prompt injection can turn this into remote code execution or data loss.",
            severity: "critical", cwe: "CWE-94", tags: ["llm", "agent", "prompt-injection", "rce"],
            remediation: "Replace free-form execution with a typed tool schema, strict allowlists, least privilege, user confirmation and bounded arguments.",
          }));
        }
      }

      if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken
        && /(?:innerHTML|outerHTML)$/.test(node.left.getText()) && isUserTainted(node.right)) {
        add(makeFlowSignal(source, file.relativePath, node, {
          ruleId: "dataflow.dom-xss",
          title: "Untrusted data is assigned to an HTML execution sink",
          description: "Request-controlled data reaches innerHTML or outerHTML.",
          severity: "high", cwe: "CWE-79", tags: ["dataflow", "xss", "client"],
          remediation: "Render as text or sanitize with a well-maintained HTML sanitizer configured for the exact allowed markup.",
        }));
      }

      if (ts.isJsxAttribute(node) && node.name.getText() === "dangerouslySetInnerHTML" && node.initializer
        && expressionHasIdentifier(node.initializer, userTainted)) {
        add(makeFlowSignal(source, file.relativePath, node, {
          ruleId: "dataflow.react-xss",
          title: "Untrusted data reaches dangerouslySetInnerHTML",
          description: "A tainted value is rendered as raw HTML in React.",
          severity: "high", cwe: "CWE-79", tags: ["dataflow", "xss", "react"],
          remediation: "Avoid raw HTML; otherwise sanitize with a strict allowlist before creating the __html object.",
        }));
      }
      if (!truncated) ts.forEachChild(node, visit);
    };
    visit(source);
  }

  return {
    signals,
    coverage: {
      domain: "js-ts-dataflow",
      engine: "aisec-typescript",
      status: files.length > 0 ? (filesWithParseErrors > 0 || truncated ? "partial" : "complete") : "not_run",
      required: context.profile.languages.some((language) => ["JavaScript", "TypeScript"].includes(language)),
      reason: files.length > 0
        ? [filesWithParseErrors > 0 ? `${filesWithParseErrors} source file(s) had parser diagnostics` : undefined, truncated ? `finding output reached the ${MAX_SIGNALS_PER_DETECTOR} signal safety limit` : undefined].filter(Boolean).join("; ") || undefined
        : "No JavaScript or TypeScript source files detected",
      durationMs: Date.now() - started,
    },
  };
}
