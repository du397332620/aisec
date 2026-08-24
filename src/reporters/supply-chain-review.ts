import { SEVERITY_RANK } from "../core/constants.js";
import type { Finding, ScanReport, Severity, Signal } from "../schema.js";
import { safeRelativePath, singleLine } from "./safety.js";

export type SupplyChainRelationship = "direct" | "transitive" | "unknown";

export interface SupplyChainDependencyGroup {
  key: string;
  packageName: string;
  installedVersion: string;
  relationship: SupplyChainRelationship;
  fixAvailable: boolean;
  dependencyClass: string;
  ecosystem: string;
  severity: Severity;
  advisoryIds: string[];
  fixedVersions: string[];
  targets: string[];
  signalCount: number;
  findingCount: number;
  hasOpenFinding: boolean;
}

export interface SupplyChainReview {
  counts: {
    trivySignals: number;
    dependencies: number;
    iac: number;
    secrets: number;
    unclassified: number;
  };
  dependencies: {
    advisories: number;
    packages: number;
    relationships: { direct: number; transitive: number; unknown: number };
    fixes: { available: number; unavailable: number };
    groups: SupplyChainDependencyGroup[];
  };
  iac: { signals: number; targets: number; types: Array<{ type: string; signals: number }> };
  secrets: { signals: number; targets: number };
}

interface MutableDependencyGroup {
  packageName: string;
  installedVersion: string;
  relationship: SupplyChainRelationship;
  fixAvailable: boolean;
  dependencyClass: string;
  ecosystem: string;
  severity: Severity;
  advisoryIds: Set<string>;
  fixedVersions: Set<string>;
  targets: Set<string>;
  signalIds: Set<string>;
  findingIds: Set<string>;
  hasOpenFinding: boolean;
}

function metadataText(signal: Signal, key: string, maxLength = 160, fallback = "unknown"): string {
  const value = signal.metadata?.[key];
  return typeof value === "string" ? singleLine(value, maxLength, fallback) : fallback;
}

function relationship(signal: Signal): SupplyChainRelationship {
  const value = metadataText(signal, "dependencyRelationship", 32).toLowerCase();
  if (value === "direct") return "direct";
  if (value === "indirect" || value === "transitive") return "transitive";
  return "unknown";
}

function fixAvailable(signal: Signal): boolean {
  const explicit = signal.metadata?.fixAvailable;
  if (typeof explicit === "boolean") return explicit;
  const fixedVersion = metadataText(signal, "fixedVersion", 160);
  return fixedVersion !== "unknown" && fixedVersion !== "not recorded";
}

function category(signal: Signal): "dependency" | "iac" | "secret" | "unclassified" {
  if (signal.tags.includes("dependency") || signal.metadata?.trivyCategory === "dependency") return "dependency";
  if (signal.tags.includes("iac") || signal.metadata?.trivyCategory === "iac") return "iac";
  if (signal.tags.includes("secret") || signal.metadata?.trivyCategory === "secret") return "secret";
  return "unclassified";
}

function findingsBySignal(findings: Finding[]): Map<string, Finding[]> {
  const result = new Map<string, Finding[]>();
  for (const finding of findings) {
    for (const signalId of finding.signalIds) {
      const current = result.get(signalId);
      if (current) current.push(finding);
      else result.set(signalId, [finding]);
    }
  }
  return result;
}

function increment(values: Map<string, number>, key: string): void {
  values.set(key, (values.get(key) ?? 0) + 1);
}

function safeTarget(signal: Signal): string | undefined {
  return safeRelativePath(signal.locations[0]?.path);
}

export function buildSupplyChainReview(report: ScanReport): SupplyChainReview {
  const trivySignals = report.signals.filter((signal) => signal.engine === "trivy");
  const dependencySignals = trivySignals.filter((signal) => category(signal) === "dependency");
  const iacSignals = trivySignals.filter((signal) => category(signal) === "iac");
  const secretSignals = trivySignals.filter((signal) => category(signal) === "secret");
  const unclassified = trivySignals.length - dependencySignals.length - iacSignals.length - secretSignals.length;
  const signalFindings = findingsBySignal(report.findings);
  const relationships = { direct: 0, transitive: 0, unknown: 0 };
  const fixes = { available: 0, unavailable: 0 };
  const groups = new Map<string, MutableDependencyGroup>();

  for (const signal of dependencySignals) {
    const packageName = metadataText(signal, "package", 200);
    const installedVersion = metadataText(signal, "installedVersion", 160);
    const dependencyRelationship = relationship(signal);
    const dependencyClass = metadataText(signal, "dependencyClass", 64);
    const ecosystem = metadataText(signal, "dependencyEcosystem", 64);
    relationships[dependencyRelationship] += 1;
    const hasFix = fixAvailable(signal);
    fixes[hasFix ? "available" : "unavailable"] += 1;
    const key = [packageName, installedVersion, dependencyRelationship, hasFix ? "fix-available" : "no-fix", dependencyClass, ecosystem].join("\u0000");
    let group = groups.get(key);
    if (!group) {
      group = {
        packageName,
        installedVersion,
        relationship: dependencyRelationship,
        fixAvailable: hasFix,
        dependencyClass,
        ecosystem,
        severity: signal.severity,
        advisoryIds: new Set(),
        fixedVersions: new Set(),
        targets: new Set(),
        signalIds: new Set(),
        findingIds: new Set(),
        hasOpenFinding: false,
      };
      groups.set(key, group);
    }
    if (SEVERITY_RANK[signal.severity] > SEVERITY_RANK[group.severity]) group.severity = signal.severity;
    group.advisoryIds.add(singleLine(signal.ruleId, 160, "unknown-advisory"));
    if (hasFix) group.fixedVersions.add(metadataText(signal, "fixedVersion", 160));
    const target = safeTarget(signal);
    if (target) group.targets.add(target);
    group.signalIds.add(signal.id);
    for (const finding of signalFindings.get(signal.id) ?? []) {
      group.findingIds.add(finding.id);
      if (finding.status === "open") group.hasOpenFinding = true;
    }
  }

  const dependencyGroups: SupplyChainDependencyGroup[] = [...groups.entries()].map(([key, group]) => ({
    key,
    packageName: group.packageName,
    installedVersion: group.installedVersion,
    relationship: group.relationship,
    fixAvailable: group.fixAvailable,
    dependencyClass: group.dependencyClass,
    ecosystem: group.ecosystem,
    severity: group.severity,
    advisoryIds: [...group.advisoryIds].sort(),
    fixedVersions: [...group.fixedVersions].filter((value) => value !== "unknown").sort(),
    targets: [...group.targets].sort(),
    signalCount: group.signalIds.size,
    findingCount: group.findingIds.size,
    hasOpenFinding: group.hasOpenFinding,
  })).sort((left, right) => (left.hasOpenFinding === right.hasOpenFinding ? 0 : left.hasOpenFinding ? -1 : 1)
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || ({ direct: 0, transitive: 1, unknown: 2 }[left.relationship] - { direct: 0, transitive: 1, unknown: 2 }[right.relationship])
    || Number(right.fixAvailable) - Number(left.fixAvailable)
    || left.packageName.localeCompare(right.packageName)
    || left.installedVersion.localeCompare(right.installedVersion)
    || left.ecosystem.localeCompare(right.ecosystem)
    || left.dependencyClass.localeCompare(right.dependencyClass)
    || left.key.localeCompare(right.key));

  const iacTypes = new Map<string, number>();
  for (const signal of iacSignals) increment(iacTypes, metadataText(signal, "trivyType", 64));
  return {
    counts: {
      trivySignals: trivySignals.length,
      dependencies: dependencySignals.length,
      iac: iacSignals.length,
      secrets: secretSignals.length,
      unclassified,
    },
    dependencies: {
      advisories: new Set(dependencySignals.map((signal) => signal.ruleId)).size,
      packages: new Set(dependencySignals.map((signal) => `${metadataText(signal, "package", 200)}\u0000${metadataText(signal, "installedVersion", 160)}`)).size,
      relationships,
      fixes,
      groups: dependencyGroups,
    },
    iac: {
      signals: iacSignals.length,
      targets: new Set(iacSignals.map(safeTarget).filter((value): value is string => Boolean(value))).size,
      types: [...iacTypes.entries()].map(([type, signals]) => ({ type, signals })).sort((left, right) => right.signals - left.signals || left.type.localeCompare(right.type)),
    },
    secrets: {
      signals: secretSignals.length,
      targets: new Set(secretSignals.map(safeTarget).filter((value): value is string => Boolean(value))).size,
    },
  };
}
