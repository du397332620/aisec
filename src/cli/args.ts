export interface ParsedArgs {
  command?: string;
  subcommand?: string;
  positionals: string[];
  flags: Map<string, string[]>;
}

export function parseArgs(argv: string[]): ParsedArgs {
  const command = argv[0];
  const flags = new Map<string, string[]>();
  const positionals: string[] = [];
  let subcommand: string | undefined;
  let index = 1;
  if (command === "engines" && argv[1] && !argv[1].startsWith("-")) {
    subcommand = argv[1];
    index = 2;
  }
  for (; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token) continue;
    if (token === "--") {
      positionals.push(...argv.slice(index + 1));
      break;
    }
    if (!token.startsWith("--")) {
      positionals.push(token);
      continue;
    }
    const equals = token.indexOf("=");
    const key = token.slice(2, equals === -1 ? undefined : equals);
    let value = equals === -1 ? undefined : token.slice(equals + 1);
    if (value === undefined && argv[index + 1] && !argv[index + 1]!.startsWith("--")) {
      value = argv[index + 1];
      index += 1;
    }
    const list = flags.get(key) ?? [];
    list.push(value ?? "true");
    flags.set(key, list);
  }
  return { command, subcommand, positionals, flags };
}

export function flag(parsed: ParsedArgs, name: string): string | undefined {
  return parsed.flags.get(name)?.at(-1);
}

export function flags(parsed: ParsedArgs, name: string): string[] {
  return parsed.flags.get(name) ?? [];
}

export function booleanFlag(parsed: ParsedArgs, name: string): boolean {
  const value = flag(parsed, name);
  if (value === undefined) return false;
  if (["true", "1", "yes"].includes(value.toLowerCase())) return true;
  if (["false", "0", "no"].includes(value.toLowerCase())) return false;
  throw new Error(`--${name} expects a boolean value`);
}

export function requireFlag(parsed: ParsedArgs, name: string): string {
  const value = flag(parsed, name);
  if (!value || value === "true") throw new Error(`--${name} is required`);
  return value;
}
