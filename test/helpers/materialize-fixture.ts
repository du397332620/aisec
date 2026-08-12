import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

export const SYNTHETIC_STRIPE_LIVE_KEY = ["sk", "live", "aisecfixtureonly1234567890"].join("_");
export const SYNTHETIC_EXTERNAL_STRIPE_LIVE_KEY = ["sk", "live", "aisecfixtureexternal1234567890"].join("_");

export async function materializeFixture(
  source: string,
  replacements: Array<{ relativePath: string; placeholder: string; value: string }>,
): Promise<{ path: string; cleanup: () => Promise<void> }> {
  const temporary = await mkdtemp(join(tmpdir(), "aisec-materialized-fixture-"));
  const target = join(temporary, "fixture");
  await cp(source, target, { recursive: true });
  for (const replacement of replacements) {
    const path = join(target, replacement.relativePath);
    const content = await readFile(path, "utf8");
    if (!content.includes(replacement.placeholder)) throw new Error(`Fixture placeholder not found: ${replacement.placeholder}`);
    await writeFile(path, content.replaceAll(replacement.placeholder, replacement.value));
  }
  return { path: target, cleanup: () => rm(temporary, { recursive: true, force: true }) };
}
