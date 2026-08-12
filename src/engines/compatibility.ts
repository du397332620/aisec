import { commandVersion } from "./process.js";
import type { EngineName } from "./manager.js";

export const VERIFIED_ENGINE_VERSIONS: Readonly<Record<EngineName, readonly string[]>> = {
  gitleaks: ["8.30.1"],
  opengrep: ["1.26.0"],
  trivy: ["0.73.0"],
};

export function parseEngineVersion(name: EngineName, output: string | undefined): string | undefined {
  if (!output) return undefined;
  const pattern = name === "gitleaks"
    ? /(?:gitleaks\s+version\s+)?v?(\d+\.\d+\.\d+)/i
    : /(?:version:\s*)?v?(\d+\.\d+\.\d+)/i;
  return output.match(pattern)?.[1];
}

export function engineCompatibility(name: EngineName, output: string | undefined): {
  detected?: string;
  verified: readonly string[];
  supported: boolean;
  reason?: string;
} {
  const detected = parseEngineVersion(name, output);
  const verified = VERIFIED_ENGINE_VERSIONS[name];
  if (!detected) return { verified, supported: false, reason: `${name} version could not be determined; verified versions: ${verified.join(", ")}` };
  if (!verified.includes(detected)) return { detected, verified, supported: false, reason: `${name} ${detected} is not verified; supported Beta versions: ${verified.join(", ")}` };
  return { detected, verified, supported: true };
}

export async function inspectEngineCompatibility(name: EngineName, command: string): Promise<ReturnType<typeof engineCompatibility> & { rawVersion?: string }> {
  const rawVersion = await commandVersion(command);
  return { ...engineCompatibility(name, rawVersion), rawVersion };
}
