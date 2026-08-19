const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/gu;
const HAS_CONTROL_CHARACTER = /[\u0000-\u001f\u007f]/u;

export function singleLine(value: unknown, maxLength: number, fallback = "not recorded"): string {
  const normalized = String(value ?? "")
    .replace(CONTROL_CHARACTERS, " ")
    .replace(/\s+/gu, " ")
    .trim();
  const source = normalized || fallback;
  const characters = [...source];
  if (characters.length <= maxLength) return source;
  return `${characters.slice(0, Math.max(0, maxLength - 1)).join("")}…`;
}

export function safeRelativePath(value: unknown): string | undefined {
  if (typeof value !== "string" || !value || HAS_CONTROL_CHARACTER.test(value)) return undefined;
  const normalized = value.replaceAll("\\", "/");
  if (normalized.startsWith("/") || normalized.startsWith("//") || /^[A-Za-z]:\//u.test(normalized) || /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(normalized)) return undefined;
  const segments = normalized.split("/").filter((part) => part && part !== ".");
  if (segments.length === 0 || segments.some((part) => part === ".." || /%(?:2e|2f|5c)/iu.test(part))) return undefined;
  const result = segments.join("/");
  return [...result].length <= 1024 ? result : undefined;
}

export function sarifArtifactUri(value: unknown): string | undefined {
  const path = safeRelativePath(value);
  return path?.split("/").map((part) => encodeURIComponent(part)).join("/");
}

export function markdownText(value: unknown, maxLength: number): string {
  return singleLine(value, maxLength)
    .replace(/\bhttps:/giu, "hxxps:")
    .replace(/\bhttp:/giu, "hxxp:")
    .replace(/\bmailto:/giu, "mailto[:]")
    .replace(/\bwww\./giu, "www[.]")
    .replaceAll("@", "[at]")
    .replaceAll("\\", "\\\\")
    .replace(/([`*_\[\]{}()<>#!|])/gu, "\\$1");
}

export function githubData(value: unknown): string {
  return singleLine(value, 2000)
    .replaceAll("%", "%25")
    .replaceAll("\r", "%0D")
    .replaceAll("\n", "%0A");
}

export function githubProperty(value: unknown): string {
  return githubData(value)
    .replaceAll(":", "%3A")
    .replaceAll(",", "%2C");
}
