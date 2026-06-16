import type {
  AttentionDismissal,
  PendingApproval,
  Policy,
  RiskBanner,
  SourceSuggestion,
  ToolInventoryRow,
} from "../types";

export type AttentionKind =
  | "approval"
  | "risk"
  | "source"
  | "egress-tool"
  | "read-tool"
  | "info";

export type AttentionTargetTab = "activity" | "whats-yours" | "reading" | "sharing" | "protection";

export interface BaseAttentionItem {
  id: string;
  kind: AttentionKind;
  title: string;
  detail: string;
  meta?: string[];
  targetTab?: AttentionTargetTab;
  dismissKey?: string;
}

export interface ApprovalAttentionItem extends BaseAttentionItem {
  kind: "approval";
  approval: PendingApproval;
  covered: boolean;
  createdAt: number;
}

export interface SourceAttentionItem extends BaseAttentionItem {
  kind: "source";
  server: string;
}

export interface ToolAttentionItem extends BaseAttentionItem {
  kind: "egress-tool" | "read-tool";
  match: string;
  row: ToolInventoryRow;
}

export interface BannerAttentionItem extends BaseAttentionItem {
  kind: "risk" | "info";
  banner: RiskBanner;
  severity: string;
}

export type AttentionItem =
  | ApprovalAttentionItem
  | SourceAttentionItem
  | ToolAttentionItem
  | BannerAttentionItem;

export interface BuildAttentionInput {
  approvals?: PendingApproval[];
  policy?: Policy | null;
  sourceSuggestions?: SourceSuggestion[];
  attentionDismissals?: AttentionDismissal[];
}

function valueText(value: unknown): string {
  return value == null ? "" : String(value).trim();
}

function numberValue(value: unknown): number {
  const out = Number(value || 0);
  return Number.isFinite(out) ? out : 0;
}

function keyPart(value: unknown): string {
  return valueText(value).replace(/[^A-Za-z0-9_.:@|=-]+/g, "_").replace(/^_+|_+$/g, "");
}

function dedupeKey(value: unknown): string {
  return valueText(value).toLowerCase();
}

function pushUnique<T extends BaseAttentionItem>(
  out: T[],
  seen: Set<string>,
  item: T,
): void {
  const key = dedupeKey(item.id);
  if (!key || seen.has(key)) return;
  seen.add(key);
  out.push(item);
}

function bannerIsInfo(banner: RiskBanner): boolean {
  const severity = dedupeKey(banner.severity || "risk");
  return severity === "info" || severity === "notice" || severity === "low";
}

function bannerTargetTab(banner: RiskBanner): AttentionTargetTab | undefined {
  const id = dedupeKey(banner.id);
  if (id.indexOf("taint_classification") >= 0) return "reading";
  if (id.indexOf("intrinsic_exfiltration") >= 0) return "protection";
  if (id.indexOf("self_trust") >= 0) return "whats-yours";
  if (id.indexOf("llm") >= 0 || id.indexOf("egress") >= 0 || id.indexOf("sharing") >= 0) {
    return "sharing";
  }
  return undefined;
}

function bannerTitle(banner: RiskBanner): string {
  const severity = valueText(banner.severity || "risk");
  return severity ? severity.charAt(0).toUpperCase() + severity.slice(1) + " posture" : "Posture";
}

function rowHasActivePolicy(row: ToolInventoryRow): boolean {
  const state = dedupeKey(row.policy_state);
  const policy = row.policy;
  return Boolean(policy && policy.enabled !== false && state !== "none");
}

function rowMatch(row: ToolInventoryRow): string {
  return valueText(row.match || row.tool_name || row.group);
}

function rowFamilies(row: ToolInventoryRow, key: "observed_read_families" | "observed_egress_families"): string[] {
  return Array.isArray(row[key])
    ? (row[key] || []).map((item) => valueText(item)).filter(Boolean)
    : [];
}

function rowSeenCount(row: ToolInventoryRow): number {
  return numberValue(row.seen_count) || numberValue(row.call_count) + numberValue(row.result_count);
}

function toolEvidenceKey(kind: "egress-tool" | "read-tool", match: string, row: ToolInventoryRow, families: string[]): string {
  return [
    kind + ":" + keyPart(match),
    "last=" + numberValue(row.last_seen),
    "seen=" + rowSeenCount(row),
    "families=" + families.slice().sort().map(keyPart).join(","),
  ].join("|");
}

function sourceEvidenceKey(suggestion: SourceSuggestion): string {
  return [
    "source:" + keyPart(suggestion.server),
    "last=" + numberValue(suggestion.last_ts),
    "hits=" + numberValue(suggestion.hits),
  ].join("|");
}

function bannerEvidenceKey(kind: "risk" | "info", id: string): string {
  return kind + ":" + keyPart(id);
}

function activeDismissedKeys(input: BuildAttentionInput): Set<string> {
  const now = Math.floor(Date.now() / 1000);
  const dismissals = input.attentionDismissals || (input.policy && input.policy.attention_dismissals) || [];
  return new Set(
    dismissals
      .filter((item) => numberValue(item.expires_at) > now)
      .map((item) => valueText(item.dismiss_key))
      .filter(Boolean),
  );
}

function filterDismissed(items: AttentionItem[], dismissedKeys: Set<string>): AttentionItem[] {
  return items.filter((item) => item.kind === "approval" || !item.dismissKey || !dismissedKeys.has(item.dismissKey));
}

function sourceMatchForServer(server: string): string {
  return dedupeKey(server).replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "") + "_*";
}

function sourceServerKeys(suggestions: SourceSuggestion[]): Set<string> {
  const keys = new Set<string>();
  suggestions.forEach((suggestion) => {
    const server = dedupeKey(suggestion.server);
    if (!server) return;
    keys.add(server);
    keys.add(sourceMatchForServer(server));
  });
  return keys;
}

function rowCoveredBySourceSuggestion(row: ToolInventoryRow, servers: Set<string>): boolean {
  const match = dedupeKey(rowMatch(row));
  const prefix = dedupeKey(row.mcp_server_prefix);
  return Boolean((match && servers.has(match)) || (prefix && servers.has(prefix)));
}

function sortedToolRows(rows: ToolInventoryRow[] | undefined): ToolInventoryRow[] {
  return (rows || [])
    .filter((row) => row.row_type === "tool" && !rowHasActivePolicy(row))
    .slice()
    .sort((left, right) => {
      const lastSeen = numberValue(right.last_seen) - numberValue(left.last_seen);
      if (lastSeen) return lastSeen;
      return rowMatch(left).localeCompare(rowMatch(right));
    });
}

export function buildAttentionItems(input: BuildAttentionInput): AttentionItem[] {
  const dismissedKeys = activeDismissedKeys(input);
  const approvals = (input.approvals || [])
    .slice()
    .sort((left, right) => {
      const covered = Number(left.covered_by_rule === true) - Number(right.covered_by_rule === true);
      if (covered) return covered;
      const created = numberValue(right.created_at) - numberValue(left.created_at);
      if (created) return created;
      return valueText(left.id).localeCompare(valueText(right.id));
    });
  const policy = input.policy || {};
  const sourceSuggestions = (input.sourceSuggestions || [])
    .slice()
    .sort((left, right) => {
      const lastSeen = numberValue(right.last_ts) - numberValue(left.last_ts);
      if (lastSeen) return lastSeen;
      return valueText(left.server).localeCompare(valueText(right.server));
    });
  const sourceKeys = sourceServerKeys(sourceSuggestions);
  const items: AttentionItem[] = [];

  approvals.forEach((approval, index) => {
    const id = valueText(approval.id) || "approval-" + index;
    const action = valueText(approval.action_family) || "outbound action";
    const destination = valueText(approval.destination) || "unknown destination";
    items.push({
      id: "approval:" + id,
      kind: "approval",
      title: action + " -> " + destination,
      detail: valueText(approval.reason),
      approval,
      covered: approval.covered_by_rule === true,
      createdAt: numberValue(approval.created_at),
    });
  });

  const seenHighRiskBanners = new Set<string>();
  (policy.risk_banners || []).filter((banner) => !bannerIsInfo(banner)).forEach((banner, index) => {
    const id = valueText(banner.id) || valueText(banner.message) || "risk-" + index;
    pushUnique(items, seenHighRiskBanners, {
      id: "risk:" + id,
      kind: "risk",
      title: bannerTitle(banner),
      detail: valueText(banner.message),
      meta: [valueText(banner.severity || "risk")].filter(Boolean),
      targetTab: bannerTargetTab(banner),
      dismissKey: bannerEvidenceKey("risk", id),
      banner,
      severity: valueText(banner.severity || "risk"),
    });
  });

  const seenSources = new Set<string>();
  sourceSuggestions.forEach((suggestion) => {
    const server = valueText(suggestion.server);
    if (!server) return;
    const hits = numberValue(suggestion.hits);
    pushUnique(items, seenSources, {
      id: "source:" + server,
      kind: "source",
      title: "Classify source " + server,
      detail: "Guardian has seen undeclared reads from this MCP server.",
      meta: [hits ? hits + " read" + (hits === 1 ? "" : "s") + " seen" : ""].filter(Boolean),
      targetTab: "reading",
      dismissKey: sourceEvidenceKey(suggestion),
      server,
    });
  });

  const seenEgressTools = new Set<string>();
  sortedToolRows(policy.sharing_tool_inventory).forEach((row) => {
    const families = rowFamilies(row, "observed_egress_families");
    if (!families.some((family) => family === "tool_unknown" || family === "mcp_unknown")) return;
    const match = rowMatch(row);
    if (!match) return;
    pushUnique(items, seenEgressTools, {
      id: "egress-tool:" + match,
      kind: "egress-tool",
      title: "Classify egress tool " + match,
      detail: "This tool has reached the unknown egress fallback under taint.",
      meta: families,
      targetTab: "sharing",
      dismissKey: toolEvidenceKey("egress-tool", match, row, families),
      match,
      row,
    });
  });

  const seenReadTools = new Set<string>();
  sortedToolRows(policy.reading_tool_inventory).forEach((row) => {
    if (rowCoveredBySourceSuggestion(row, sourceKeys)) return;
    const families = rowFamilies(row, "observed_read_families");
    if (!families.length) return;
    const match = rowMatch(row);
    if (!match) return;
    pushUnique(items, seenReadTools, {
      id: "read-tool:" + match,
      kind: "read-tool",
      title: "Classify read tool " + match,
      detail: "Guardian has read-result metadata for this tool but no source policy.",
      meta: families,
      targetTab: "reading",
      dismissKey: toolEvidenceKey("read-tool", match, row, families),
      match,
      row,
    });
  });

  const seenInfoBanners = new Set<string>();
  (policy.risk_banners || []).filter(bannerIsInfo).forEach((banner, index) => {
    const id = valueText(banner.id) || valueText(banner.message) || "info-" + index;
    pushUnique(items, seenInfoBanners, {
      id: "info:" + id,
      kind: "info",
      title: "Informational posture",
      detail: valueText(banner.message),
      meta: [valueText(banner.severity || "info")].filter(Boolean),
      targetTab: bannerTargetTab(banner),
      dismissKey: bannerEvidenceKey("info", id),
      banner,
      severity: valueText(banner.severity || "info"),
    });
  });

  return filterDismissed(items, dismissedKeys);
}
