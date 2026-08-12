import type { CoverageRecord, Signal } from "../schema.js";
import type { ScanContext } from "../core/context.js";
import { runGitleaks } from "./gitleaks.js";
import { runOpengrep } from "./opengrep.js";
import { runTrivy } from "./trivy.js";
import { redactSnippet } from "../core/utils.js";

export async function runExternalEngines(context: ScanContext): Promise<{ signals: Signal[]; coverage: CoverageRecord[] }> {
  if (context.options.nativeOnly) {
    return {
      signals: [],
      coverage: [
        { domain: "secrets-history", engine: "gitleaks", status: "not_run", required: false, reason: "Disabled by --native-only" },
        { domain: "sast-general", engine: "opengrep", status: "not_run", required: false, reason: "Disabled by --native-only" },
        { domain: "dependencies-iac", engine: "trivy", status: "not_run", required: false, reason: "Disabled by --native-only" },
      ],
    };
  }
  const engines = [
    { domain: "secrets-history", name: "gitleaks", run: runGitleaks },
    { domain: "sast-general", name: "opengrep", run: runOpengrep },
    { domain: "dependencies-iac", name: "trivy", run: runTrivy },
  ] as const;
  const settled = await Promise.allSettled(engines.map((engine) => engine.run(context)));
  const results = settled.map((result, index) => {
    if (result.status === "fulfilled") return result.value;
    const engine = engines[index]!;
    const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
    return {
      signals: [],
      coverage: {
        domain: engine.domain,
        engine: engine.name,
        status: "failed" as const,
        required: true,
        reason: redactSnippet(reason).slice(0, 500),
      },
    };
  });
  return { signals: results.flatMap((result) => result.signals), coverage: results.map((result) => result.coverage) };
}
