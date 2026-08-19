import { SEVERITY_RANK } from "../core/constants.js";
import type { Finding, ScanReport, Signal, SourceLocation } from "../schema.js";

export interface FindingGroupMember {
  finding: Finding;
  signal: Signal;
  location: SourceLocation;
  handler?: string;
  routes: string[];
  pattern?: string;
}

export interface FindingPresentationGroup {
  key: string;
  groupId: string;
  ruleId: string;
  title: string;
  path: string;
  severity: Finding["severity"];
  status: Finding["status"];
  members: FindingGroupMember[];
  findingCount: number;
  handlers: string[];
  routes: string[];
  patterns: string[];
}

function metadataString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function metadataStrings(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && Boolean(item.trim())).map((item) => item.trim());
}

function membersForFinding(signalById: Map<string, Signal>, finding: Finding): FindingGroupMember[] {
  if (finding.attackPathId) return [];
  const signals = finding.signalIds
    .map((id) => signalById.get(id))
    .filter((candidate): candidate is Signal => Boolean(candidate));
  if (signals.length !== finding.signalIds.length || signals.length === 0) return [];
  const groupId = metadataString(signals[0]!.metadata?.findingGroup);
  const ruleId = signals[0]!.ruleId;
  const path = signals[0]!.locations[0]?.path;
  if (!groupId || !path || signals.some((signal) => metadataString(signal.metadata?.findingGroup) !== groupId
    || signal.ruleId !== ruleId || signal.locations[0]?.path !== path)) return [];
  return signals.map((signal) => {
    const location = signal.locations[0]!;
    const routes = metadataStrings(signal.metadata?.routes);
    const fallbackRoute = metadataString(signal.metadata?.route);
    if (routes.length === 0 && fallbackRoute) routes.push(fallbackRoute);
    const handler = metadataString(signal.metadata?.handler);
    const serialization = metadataString(signal.metadata?.exceptionSerialization);
    const sink = metadataString(signal.metadata?.responseSink);
    return {
      finding,
      signal,
      location,
      ...(handler ? { handler } : {}),
      routes: [...new Set(routes)].sort(),
      ...(serialization || sink ? { pattern: [serialization, sink].filter(Boolean).join(" → ") } : {}),
    };
  });
}

export function partitionFindingGroups(
  report: ScanReport,
  findings: Finding[] = report.findings,
): { groups: FindingPresentationGroup[]; ungrouped: Finding[] } {
  const signalById = new Map(report.signals.map((signal) => [signal.id, signal]));
  const groupsByKey = new Map<string, FindingPresentationGroup>();

  for (const finding of findings) {
    for (const member of membersForFinding(signalById, finding)) {
      const groupId = metadataString(member.signal.metadata?.findingGroup);
      if (!groupId) continue;
      const key = [groupId, finding.status, finding.severity, member.signal.ruleId, member.location.path].join("\u0000");
      const existing = groupsByKey.get(key);
      if (existing) existing.members.push(member);
      else groupsByKey.set(key, {
        key,
        groupId,
        ruleId: member.signal.ruleId,
        title: member.signal.title,
        path: member.location.path,
        severity: finding.severity,
        status: finding.status,
        members: [member],
        findingCount: 0,
        handlers: [],
        routes: [],
        patterns: [],
      });
    }
  }

  const groups = [...groupsByKey.values()].filter((group) => group.members.length > 1);
  for (const group of groups) {
    group.members.sort((left, right) => (left.location.line ?? 0) - (right.location.line ?? 0)
      || (left.handler ?? "").localeCompare(right.handler ?? "")
      || left.finding.id.localeCompare(right.finding.id));
    group.findingCount = new Set(group.members.map((member) => member.finding.id)).size;
    group.handlers = [...new Set(group.members.map((member) => member.handler).filter((value): value is string => Boolean(value)))].sort();
    group.routes = [...new Set(group.members.flatMap((member) => member.routes))].sort();
    group.patterns = [...new Set(group.members.map((member) => member.pattern).filter((value): value is string => Boolean(value)))].sort();
  }
  groups.sort((left, right) => (left.status === right.status ? 0 : left.status === "open" ? -1 : 1)
    || SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity]
    || left.path.localeCompare(right.path)
    || left.ruleId.localeCompare(right.ruleId));

  const groupedFindingIds = new Set(groups.flatMap((group) => group.members.map((member) => member.finding.id)));
  return {
    groups,
    ungrouped: findings.filter((finding) => !groupedFindingIds.has(finding.id)),
  };
}
