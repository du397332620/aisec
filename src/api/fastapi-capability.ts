import type { ProjectFile } from "../core/files.js";
import { makeLocation } from "../core/utils.js";
import type {
  FastApiObjectCapabilityAnalysisDepth,
  FastApiObjectCapabilityEntropyEvidence,
  FastApiObjectCapabilityIdentifierSource,
  FastApiObjectCapabilityLifecycleEvidence,
  FastApiObjectCapabilityMutationImpact,
  FastApiObjectCapabilityOneTimeEvidence,
  SourceLocation,
} from "../schema.js";
import { pythonCodeMask, type FastApiRoute } from "./fastapi.js";

const MAX_IDENTIFIER_FIELDS = 4;
const MAX_DEFINITIONS = 2_048;
const MAX_INHERITANCE_EDGES = 6;
const MAX_EVIDENCE_LOCATIONS = 4;
const IDENTIFIER_FIELD = /(?:^id$|_id$|uuid$|_uuid$|token$|_token$|key$|_key$|ref$|_ref$|reference$|_reference$)/i;
const MUTATION_METHOD = /(?:^|_)(?:update|set|submit|delete|remove|approve|reject|cancel|complete|activate|deactivate|assign|attach|detach|redeem|consume|rotate|reset)(?:_|$)/i;
const CREATE_OR_MUTATE_METHOD = /(?:^|_)(?:get_or_create|create_or_get|update_or_create|create_or_update|set_or_create|create_or_set|upsert)(?:_|$)/i;

interface DefinitionBlock {
  name: string;
  source: string;
  file: ProjectFile;
  start: number;
  end: number;
  indent: number;
  owner?: string;
  location: SourceLocation;
}

interface ClassBlock extends DefinitionBlock {
  bases: string;
}

interface ProjectIndex {
  classes: Map<string, ClassBlock[]>;
  methods: Map<string, DefinitionBlock[]>;
  functions: Map<string, DefinitionBlock[]>;
}

interface ReceiverCall {
  receiver: string;
  method: string;
  receiverType?: string;
}

interface GeneratorResult {
  evidence: FastApiObjectCapabilityEntropyEvidence;
  locations: SourceLocation[];
}

interface ClassReference {
  name: string;
  qualifier?: string;
}

export interface FastApiObjectCapabilityMutationEvidence {
  identifierFields: string[];
  identifierSource: FastApiObjectCapabilityIdentifierSource;
  entropyEvidence: FastApiObjectCapabilityEntropyEvidence;
  lifecycleEvidence: FastApiObjectCapabilityLifecycleEvidence;
  oneTimeEvidence: FastApiObjectCapabilityOneTimeEvidence;
  mutationImpact: FastApiObjectCapabilityMutationImpact;
  analysisDepth: FastApiObjectCapabilityAnalysisDepth;
  locations: SourceLocation[];
}

function lineIndent(text: string): number {
  return text.match(/^[ \t]*/)?.[0].replace(/\t/g, "    ").length ?? 0;
}

function definitionEnd(text: string, start: number, indent: number): number {
  let cursor = text.indexOf("\n", start);
  while (cursor !== -1 && cursor + 1 < text.length) {
    const next = cursor + 1;
    const lineEnd = text.indexOf("\n", next);
    const line = text.slice(next, lineEnd === -1 ? text.length : lineEnd);
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#") && lineIndent(line) <= indent) return next;
    cursor = lineEnd;
  }
  return text.length;
}

function indexProject(files: ProjectFile[]): ProjectIndex {
  const classes = new Map<string, ClassBlock[]>();
  const methods = new Map<string, DefinitionBlock[]>();
  const functions = new Map<string, DefinitionBlock[]>();
  let definitions = 0;
  const add = <T>(map: Map<string, T[]>, key: string, value: T): void => {
    map.set(key, [...(map.get(key) ?? []), value]);
  };

  for (const file of files.filter((candidate) => candidate.relativePath.endsWith(".py"))) {
    if (definitions >= MAX_DEFINITIONS) break;
    const fileMask = pythonCodeMask(file.content);
    const classRecords: ClassBlock[] = [];
    const classPattern = /^([ \t]*)class\s+([A-Za-z_]\w*)\s*(?:\(([^:\n]{0,1000})\))?\s*:/gm;
    for (const match of fileMask.matchAll(classPattern)) {
      if (definitions >= MAX_DEFINITIONS || !match[2]) break;
      const start = match.index ?? 0;
      const indent = lineIndent(match[1] ?? "");
      const end = definitionEnd(fileMask, start, indent);
      const record: ClassBlock = {
        name: match[2],
        bases: match[3] ?? "",
        source: file.content.slice(start, end),
        file,
        start,
        end,
        indent,
        location: makeLocation(file.relativePath, file.content, start, file.content.slice(start, start + match[0].length)),
      };
      classRecords.push(record);
      add(classes, record.name, record);
      definitions += 1;
    }

    const functionPattern = /^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/gm;
    for (const match of fileMask.matchAll(functionPattern)) {
      if (definitions >= MAX_DEFINITIONS || !match[2]) break;
      const start = match.index ?? 0;
      const indent = lineIndent(match[1] ?? "");
      const owner = classRecords
        .filter((record) => start > record.start && start < record.end && indent > record.indent)
        .sort((left, right) => right.indent - left.indent)[0]?.name;
      const end = definitionEnd(fileMask, start, indent);
      const record: DefinitionBlock = {
        name: match[2],
        source: file.content.slice(start, end),
        file,
        start,
        end,
        indent,
        ...(owner ? { owner } : {}),
        location: makeLocation(file.relativePath, file.content, start, file.content.slice(start, start + match[0].length)),
      };
      if (owner) add(methods, `${owner}\u0000${record.name}`, record);
      else add(functions, record.name, record);
      definitions += 1;
    }
  }
  return { classes, methods, functions };
}

function closingParenthesis(text: string, opening: number): number {
  let depth = 0;
  for (let index = opening; index < text.length; index += 1) {
    const character = text[index];
    if (character === "(") depth += 1;
    else if (character === ")") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  return -1;
}

function splitTopLevel(value: string): string[] {
  const result: string[] = [];
  let start = 0;
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "{") curly += 1;
    else if (character === "}") curly -= 1;
    else if (character === "," && round === 0 && square === 0 && curly === 0) {
      result.push(value.slice(start, index));
      start = index + 1;
    }
  }
  result.push(value.slice(start));
  return result;
}

function topLevelDefault(value: string): number {
  let round = 0;
  let square = 0;
  let curly = 0;
  for (let index = 0; index < value.length; index += 1) {
    const character = value[index];
    if (character === "(") round += 1;
    else if (character === ")") round -= 1;
    else if (character === "[") square += 1;
    else if (character === "]") square -= 1;
    else if (character === "{") curly += 1;
    else if (character === "}") curly -= 1;
    else if (character === "=" && round === 0 && square === 0 && curly === 0) return index;
  }
  return -1;
}

function parameterAnnotations(source: string): Map<string, string> {
  const result = new Map<string, string>();
  const mask = pythonCodeMask(source);
  const definition = /\b(?:async\s+)?def\s+[A-Za-z_]\w*\s*\(/.exec(mask);
  if (!definition || definition.index === undefined) return result;
  const opening = definition.index + definition[0].length - 1;
  const closing = closingParenthesis(mask, opening);
  if (closing === -1) return result;
  for (const raw of splitTopLevel(source.slice(opening + 1, closing))) {
    const segment = raw.trim();
    const name = segment.match(/^([A-Za-z_]\w*)\s*:/)?.[1];
    if (!name) continue;
    const colon = segment.indexOf(":");
    const defaultAt = topLevelDefault(segment.slice(colon + 1));
    const annotation = segment.slice(colon + 1, defaultAt === -1 ? undefined : colon + 1 + defaultAt).trim();
    if (annotation) result.set(name, annotation);
  }
  return result;
}

function routeIdentifierFields(path: string): string[] {
  const fields = new Set<string>();
  for (const match of path.matchAll(/\{([A-Za-z_]\w*)(?::[^}]*)?\}/g)) {
    if (match[1] && IDENTIFIER_FIELD.test(match[1])) fields.add(match[1]);
  }
  const result = [...fields].sort();
  return result.length <= MAX_IDENTIFIER_FIELDS ? result : [];
}

function containsIdentifier(value: string, fields: readonly string[]): boolean {
  return fields.some((field) => new RegExp(`\\b${field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`).test(value));
}

function uniqueClass(index: ProjectIndex, name: string | undefined): ClassBlock | undefined {
  if (!name) return undefined;
  const records = index.classes.get(name) ?? [];
  return records.length === 1 ? records[0] : undefined;
}

function modulePath(path: string): string {
  const withoutExtension = path.replace(/\.py$/i, "");
  return withoutExtension.endsWith("/__init__")
    ? withoutExtension.slice(0, -"/__init__".length)
    : withoutExtension;
}

function referencedClass(
  index: ProjectIndex,
  reference: ClassReference,
  context?: ClassBlock,
): ClassBlock | undefined {
  const records = index.classes.get(reference.name) ?? [];
  if (reference.qualifier) {
    const expectedSuffix = reference.qualifier.replace(/\./g, "/");
    const qualified = records.filter((record) => {
      const candidate = modulePath(record.file.relativePath);
      return candidate === expectedSuffix || candidate.endsWith(`/${expectedSuffix}`);
    });
    if (qualified.length === 1) return qualified[0];
    return undefined;
  }
  if (records.length === 1) return records[0];
  if (context) {
    const sameModule = records.filter((record) => record.file.relativePath === context.file.relativePath);
    if (sameModule.length === 1) return sameModule[0];
  }
  return undefined;
}

function receiverType(annotation: string | undefined, index: ProjectIndex): string | undefined {
  const identifiers = annotation?.match(/[A-Za-z_]\w*/g) ?? [];
  return identifiers.reverse().find((identifier) => uniqueClass(index, identifier));
}

function receiverCalls(
  source: string,
  fields: readonly string[],
  annotations: Map<string, string>,
  index: ProjectIndex,
): ReceiverCall[] {
  const calls: ReceiverCall[] = [];
  const mask = pythonCodeMask(source);
  const pattern = /\b([A-Za-z_]\w*)\s*\.\s*([A-Za-z_]\w*)\s*\(/g;
  for (const match of mask.matchAll(pattern)) {
    const opening = (match.index ?? 0) + match[0].length - 1;
    const closing = closingParenthesis(mask, opening);
    if (closing === -1 || !containsIdentifier(mask.slice(opening + 1, closing), fields)) continue;
    calls.push({
      receiver: match[1]!,
      method: match[2]!,
      receiverType: receiverType(annotations.get(match[1]!), index),
    });
  }
  return calls;
}

function directExistingObjectMutation(source: string, fields: readonly string[]): boolean {
  const mask = pythonCodeMask(source);
  for (const field of fields) {
    const escaped = field.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const load = new RegExp(
      `\\b([A-Za-z_]\\w*)\\s*=\\s*(?:await\\s+)?[A-Za-z_]\\w*\\s*\\.\\s*(?:get|get_or_none|find|find_one|load|fetch|retrieve)\\s*\\(\\s*${escaped}\\b`,
      "g",
    );
    for (const match of mask.matchAll(load)) {
      if (!match[1]) continue;
      const alias = match[1].replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const tail = mask.slice((match.index ?? 0) + match[0].length);
      if (new RegExp(`\\b${alias}\\s*\\.\\s*(?:update|delete|remove|save|set|assign|submit)\\s*\\(`, "i").test(tail)
        || new RegExp(`\\b${alias}\\s*\\.\\s*[A-Za-z_]\\w*\\s*=(?!=)`, "i").test(tail)) return true;
    }
  }
  return false;
}

function methodSource(index: ProjectIndex, owner: string | undefined, method: string): DefinitionBlock | undefined {
  if (!owner) return undefined;
  const records = index.methods.get(`${owner}\u0000${method}`) ?? [];
  return records.length === 1 ? records[0] : undefined;
}

function classBaseReferences(record: ClassBlock): ClassReference[] {
  const result = new Map<string, ClassReference>();
  for (const raw of splitTopLevel(record.bases)) {
    const value = raw.trim().match(/^((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)/)?.[1];
    if (!value) continue;
    const parts = value.split(".");
    const name = parts.pop();
    if (!name) continue;
    result.set(value, {
      name,
      ...(parts.length > 0 ? { qualifier: parts.join(".") } : {}),
    });
  }
  return [...result.values()];
}

function serviceModel(record: ClassBlock): ClassReference | undefined {
  const value = record.bases.match(
    /\b(?:CRUDService|Repository|Service)\s*\[\s*((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*\]/,
  )?.[1];
  if (!value) return undefined;
  const parts = value.split(".");
  const name = parts.pop();
  if (!name) return undefined;
  return {
    name,
    ...(parts.length > 0 ? { qualifier: parts.join(".") } : {}),
  };
}

function classifyGenerator(source: string): FastApiObjectCapabilityEntropyEvidence | undefined {
  const mask = pythonCodeMask(source);
  if (/\bULID\s*\(/.test(mask)) return "ulid_generator_observed";
  if (/\b(?:uuid\s*\.\s*)?uuid4\s*\(/i.test(mask)) return "uuid4_generator_observed";
  if (/\bsecrets\s*\.\s*(?:token_urlsafe|token_hex|token_bytes|choice)\s*\(/.test(mask)
    || /\bnanoid\s*\(/i.test(mask)) return "secrets_generator_observed";
  return undefined;
}

function dottedReference(value: string): ClassReference | undefined {
  const normalized = value.replace(/\s+/g, "");
  const parts = normalized.split(".");
  const name = parts.pop();
  if (!name) return undefined;
  return {
    name,
    ...(parts.length > 0 ? { qualifier: parts.join(".") } : {}),
  };
}

function referencedFunction(
  index: ProjectIndex,
  reference: ClassReference,
  context: ClassBlock,
): DefinitionBlock | undefined {
  const records = index.functions.get(reference.name) ?? [];
  if (reference.qualifier) {
    const expectedSuffix = reference.qualifier.replace(/\./g, "/");
    const qualified = records.filter((record) => {
      const candidate = modulePath(record.file.relativePath);
      return candidate === expectedSuffix || candidate.endsWith(`/${expectedSuffix}`);
    });
    return qualified.length === 1 ? qualified[0] : undefined;
  }
  if (records.length === 1) return records[0];
  const sameModule = records.filter((record) => record.file.relativePath === context.file.relativePath);
  return sameModule.length === 1 ? sameModule[0] : undefined;
}

function generatorFromModel(
  index: ProjectIndex,
  modelReference: ClassReference,
  service: ClassBlock,
): GeneratorResult | undefined {
  const queue: Array<{ reference: ClassReference; context?: ClassBlock }> = [{
    reference: modelReference,
    context: service,
  }];
  const seen = new Set<string>();
  let edges = 0;
  while (queue.length > 0 && edges <= MAX_INHERITANCE_EDGES) {
    const current = queue.shift()!;
    const record = referencedClass(index, current.reference, current.context);
    if (!record) continue;
    const recordKey = `${record.file.relativePath}\u0000${record.name}`;
    if (seen.has(recordKey)) continue;
    seen.add(recordKey);
    const generators = index.methods.get(`${record.name}\u0000id_generator`) ?? [];
    const scopedGenerators = generators.filter((generator) => generator.file.relativePath === record.file.relativePath);
    if (scopedGenerators.length === 1) {
      const generator = scopedGenerators[0]!;
      const direct = classifyGenerator(generator.source);
      if (direct) return { evidence: direct, locations: [generator.location] };
      const calls = [...pythonCodeMask(generator.source).matchAll(/\b((?:[A-Za-z_]\w*\s*\.\s*)*[A-Za-z_]\w*)\s*\(/g)]
        .map((match) => dottedReference(match[1]!))
        .filter((reference): reference is ClassReference => reference !== undefined)
        .filter((reference) => !["def", "str", "classmethod", "staticmethod"].includes(reference.name));
      const seenCalls = new Set<string>();
      for (const reference of calls) {
        const callKey = `${reference.qualifier ?? ""}.${reference.name}`;
        if (seenCalls.has(callKey)) continue;
        seenCalls.add(callKey);
        const nestedFunction = referencedFunction(index, reference, record);
        if (!nestedFunction) continue;
        const nested = classifyGenerator(nestedFunction.source);
        if (nested) return { evidence: nested, locations: [generator.location, nestedFunction.location] };
      }
      return { evidence: "not_proven", locations: [generator.location] };
    }
    for (const base of classBaseReferences(record)) {
      if (edges >= MAX_INHERITANCE_EDGES) break;
      if (referencedClass(index, base, record)) {
        queue.push({ reference: base, context: record });
        edges += 1;
      }
    }
  }
  return undefined;
}

function entropyEvidence(
  index: ProjectIndex,
  calls: readonly ReceiverCall[],
  annotations: Map<string, string>,
  fields: readonly string[],
): GeneratorResult {
  const results: GeneratorResult[] = [];
  const receiverTypes = new Set(calls.map((call) => call.receiverType).filter((value): value is string => Boolean(value)));
  for (const type of receiverTypes) {
    const service = uniqueClass(index, type);
    const model = service ? serviceModel(service) : undefined;
    const result = service && model ? generatorFromModel(index, model, service) : undefined;
    if (result) results.push(result);
  }
  const proven = [...new Set(results.map((result) => result.evidence).filter((value) => value !== "not_proven"))];
  if (proven.length === 1) {
    return {
      evidence: proven[0]!,
      locations: results.filter((result) => result.evidence === proven[0]).flatMap((result) => result.locations),
    };
  }
  const typedUuid = fields.some((field) => /\bUUID\b/i.test(annotations.get(field) ?? ""));
  return { evidence: typedUuid ? "typed_uuid_only" : "not_proven", locations: [] };
}

function lifecycleEvidence(source: string): FastApiObjectCapabilityLifecycleEvidence {
  const mask = pythonCodeMask(source);
  if (/\bif\b[^:\n]{0,320}\b(?:expiration|expires?|expired|expires_at|valid_until|ttl)\b[^:\n]{0,320}:/i.test(mask)) {
    return "expiration_guard_observed";
  }
  if (/\bif\b[^:\n]{0,320}(?:\.\s*(?:status|state)\b|\b[A-Za-z_]\w*(?:Status|State)\s*\.)[^:\n]{0,320}:/i.test(mask)) {
    return "state_guard_observed";
  }
  return "not_proven";
}

function rejectingFieldGuard(source: string): boolean {
  const mask = pythonCodeMask(source);
  return /\bif\s+(?:not\s+)?[A-Za-z_]\w*\s*\.\s*[A-Za-z_]\w*(?:\s+is\s+(?:not\s+)?None)?\s*:[\s\S]{0,320}\braise\b/i.test(mask);
}

function oneTimeEvidence(source: string): FastApiObjectCapabilityOneTimeEvidence {
  const mask = pythonCodeMask(source);
  const guard = rejectingFieldGuard(source)
    || /\bif\s+not\s+getattr\s*\([^)]{1,160}\)/i.test(mask)
    || /\bif\b[^:\n]{0,240}\b(?:already|consumed|used|redeemed)\b[^:\n]{0,240}:/i.test(mask);
  if (guard && /\batomic_update\s*=\s*True\b/.test(mask)) return "atomic_state_guard_observed";
  return guard ? "write_once_guard_observed" : "not_proven";
}

function mutationImpact(route: FastApiRoute, sources: readonly string[]): FastApiObjectCapabilityMutationImpact {
  const text = `${route.path}\n${route.handlerName}\n${sources.map(pythonCodeMask).join("\n")}`.toLowerCase();
  if (/\b(?:payout|refund)\w*\b/.test(text) && /\bdestination\b/.test(text)) return "payout_destination";
  if (/\bpayment\w*\b/.test(text) && /\b(?:address|destination)\b/.test(text)) return "payment_address";
  if (/\b(?:buyer_email|shipping_address|customer|contact|profile|personal)\w*\b/.test(text)) return "personal_data";
  if (/\b(?:role|permission|administrator|is_admin|access_policy)\w*\b/.test(text)) return "authorization_state";
  if (/\b(?:password|credential|secret|api_key|token)\w*\b/.test(text)) return "credential_state";
  if (route.method === "DELETE" || /(?:^|_)(?:delete|remove)(?:_|$)/i.test(route.handlerName)) return "destructive_operation";
  if (/\b(?:status|state|approve|reject|cancel|submit|complete|activate|deactivate)\w*\b/.test(text)) return "workflow_state";
  return "generic_sensitive_state";
}

function uniqueLocations(locations: readonly SourceLocation[]): SourceLocation[] {
  const seen = new Set<string>();
  const result: SourceLocation[] = [];
  for (const location of locations) {
    const key = `${location.path}\u0000${location.line ?? ""}\u0000${location.column ?? ""}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(location);
    if (result.length >= MAX_EVIDENCE_LOCATIONS) break;
  }
  return result;
}

export function createFastApiObjectCapabilityAnalyzer(
  files: ProjectFile[],
): (route: FastApiRoute) => FastApiObjectCapabilityMutationEvidence | undefined {
  const index = indexProject(files);
  return (route): FastApiObjectCapabilityMutationEvidence | undefined => {
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(route.method)) return undefined;
    const identifierFields = routeIdentifierFields(route.path);
    if (identifierFields.length === 0) return undefined;
    const annotations = parameterAnnotations(route.handlerSource);
    const calls = receiverCalls(route.handlerSource, identifierFields, annotations, index);
    const mutationCalls = calls.filter((call) => (
      MUTATION_METHOD.test(call.method) && !CREATE_OR_MUTATE_METHOD.test(call.method)
    ));
    const directMutation = directExistingObjectMutation(route.handlerSource, identifierFields);
    if (!directMutation && mutationCalls.length === 0) return undefined;

    const localMethods = mutationCalls
      .map((call) => methodSource(index, call.receiverType, call.method))
      .filter((record): record is DefinitionBlock => Boolean(record));
    const sourceTexts = [route.handlerSource, ...localMethods.map((record) => record.source)];
    const combined = sourceTexts.join("\n");
    const entropy = entropyEvidence(index, calls, annotations, identifierFields);
    return {
      identifierFields,
      identifierSource: "path_parameter",
      entropyEvidence: entropy.evidence,
      lifecycleEvidence: lifecycleEvidence(combined),
      oneTimeEvidence: oneTimeEvidence(combined),
      mutationImpact: mutationImpact(route, sourceTexts),
      analysisDepth: localMethods.length > 0 ? "one_local_method" : "handler_only",
      locations: uniqueLocations([
        route.location,
        ...localMethods.map((record) => record.location),
        ...entropy.locations,
      ]),
    };
  };
}
