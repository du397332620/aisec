import type { CoverageRecord, Signal } from "../schema.js";
import type { ScanContext } from "../core/context.js";
import { appConfigDetector } from "./app-config.js";
import { baasDetector } from "./baas.js";
import { platformDetector } from "./platform.js";
import { secretDetector } from "./secrets.js";
import { runTypeScriptDataflow } from "./typescript-dataflow.js";
import { redactSnippet } from "../core/utils.js";

export async function runNativeDetectors(context: ScanContext): Promise<{ signals: Signal[]; coverage: CoverageRecord[] }> {
  const detectors = [
    { domain: "secrets", run: secretDetector.run.bind(secretDetector) },
    { domain: "baas-authorization", run: baasDetector.run.bind(baasDetector) },
    { domain: "mobile-source-config", run: platformDetector.run.bind(platformDetector) },
    { domain: "application-config", run: appConfigDetector.run.bind(appConfigDetector) },
    { domain: "typescript-dataflow", run: runTypeScriptDataflow },
  ];
  const settled = await Promise.allSettled(detectors.map((detector) => detector.run(context)));
  const results = settled.map((result, index) => {
    if (result.status === "fulfilled") return result.value;
    const reason = result.reason instanceof Error ? result.reason.message : String(result.reason);
    return {
      signals: [],
      coverage: {
        domain: detectors[index]!.domain,
        engine: "aisec-native",
        status: "failed" as const,
        required: true,
        reason: redactSnippet(reason).slice(0, 500),
      },
    };
  });
  return {
    signals: results.flatMap((result) => result.signals),
    coverage: results.map((result) => result.coverage),
  };
}
