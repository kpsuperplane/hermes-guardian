// Shapes returned by the Guardian backend (dashboard/plugin_api.py) and the
// local form state used by the modals. Backend payloads are intentionally
// permissive — fields are optional and the formatting helpers in lib/format.ts
// coerce loose values defensively, matching the original bundle's behavior.

// --- Destinations & Trust (doc 03 §3.1) ---
export interface SelfGrantSuggestion {
  kind: string; // "destination" | "identity" | "host"
  value: string;
}

export interface SeenDestination {
  destination?: string;
  trust?: string;
  count?: number;
  recipient_identity?: string;
  suggest?: SelfGrantSuggestion | null;
}

export interface SelfAllowlist {
  destinations?: string[];
  identities?: string[];
  hosts?: string[];
}

export interface TrustedRecipient {
  kind?: string; // "identity" | "command"
  value?: string;
  identity?: string; // legacy mirror for identity entries
  classes?: string[];
  note?: string;
}

export interface TrustedCommandSuggestion {
  value: string;
  label?: string;
  kind?: string;
  wildcard?: boolean;
  skill?: string;
  source?: string; // "recent" | "skills"
}

export interface OutwardSharing {
  builtin?: string[];
  extra?: string[];
  suggestions?: string[];
}

export interface DestinationsSummary {
  tally?: Record<string, number>;
  seen?: SeenDestination[];
  self?: SelfAllowlist;
  trusted_recipients?: TrustedRecipient[];
  outward_sharing?: OutwardSharing;
  self_grants_present?: boolean;
  env_overrides?: string[];
}

export interface Rule {
  rule_id?: string;
  id?: string;
  enabled?: boolean;
  effect?: string;
  action_family?: string;
  destination?: string;
  purpose?: string;
  recipient_identity?: string;
  tool_name?: string;
  data_classes?: string[];
  expires_at?: number;
  owner_hash?: string;
  cron_job_id?: string;
  cron_job_name?: string;
  scope?: string;
}

export interface ReadingTool {
  id?: string;
  match?: string;
  source?: string;
  taints?: string[];
  note?: string;
  enabled?: boolean;
}

export interface SharingTool {
  id?: string;
  match?: string;
  egress?: string;
  destination?: string;
  note?: string;
  enabled?: boolean;
}

export interface ToolInventoryRow {
  key?: string;
  row_type?: string;
  depth?: number;
  tool_name?: string;
  match?: string;
  group?: string;
  child_count?: number;
  call_count?: number;
  result_count?: number;
  seen_count?: number;
  first_seen?: number;
  last_seen?: number;
  observed_read_families?: string[];
  observed_egress_families?: string[];
  observed_destinations?: string[];
  mcp_server_prefix?: string;
  policy?: ReadingTool | SharingTool | null;
  policy_state?: string;
  policy_match?: string;
}

export interface SourceSuggestion {
  server: string;
  hits?: number;
  last_ts?: number;
}

export interface RecentBlock {
  id?: string;
  activity_id?: string;
  approval_id?: string;
  dismiss_id?: string;
  pending?: boolean;
  covered_by_rule?: boolean;
  covered_rule_id?: string;
  covered_rule_source?: string;
  historical_approval_id?: string;
  approval_status?: string;
  expires_at?: number;
  decision?: string;
  action_family?: string;
  destination?: string;
  destination_trust?: string;
  decision_step?: string;
  tool_name?: string;
  module?: string;
  data_classes?: string[] | string;
  purpose?: string;
  recipient_identity?: string;
  created_at?: number;
  reason?: string;
  why_now?: string;
  flow_boundary_label?: string;
}

export interface ActivityRow {
  id?: string;
  decision?: string;
  icon?: string;
  direction?: string;
  time?: string;
  time_short?: string;
  ts?: number;
  tool_name?: string;
  tool?: string;
  action_family?: string;
  destination?: string;
  destination_trust?: string;
  decision_step?: string;
  purpose?: string;
  recipient_identity?: string;
  data_classes?: string;
  action_detail?: string;
  reason?: string;
  reason_short?: string;
  why_now?: WhyNow | string;
  flow_boundary_label?: string;
  turn_id?: string;
  user_prompt?: string;
  latency_us?: number;
  latency_ms?: number;
  latency_hook?: string;
  latency_llm_invoked?: boolean;
}

export interface WhyNow {
  summary?: string;
  bullets?: string[];
}

export interface CronJob {
  id: string;
  name: string;
  active?: boolean;
}

export interface SecurityRule {
  id: string;
  label?: string;
  description?: string;
  enabled?: boolean;
}

export interface LanguagePack {
  id: string;
  name?: string;
  enabled?: boolean;
  required?: boolean;
}

export interface RiskBanner {
  id?: string;
  severity?: string;
  message?: string;
}

export interface AttentionDismissal {
  dismiss_key?: string;
  kind?: string;
  item_id?: string;
  created_at?: number;
  expires_at?: number;
}

export interface Suggestions {
  destinations?: string[];
  tool_names?: string[];
  purposes?: string[];
  recipient_identities?: string[];
}

export interface Policy {
  destination_trust?: DestinationsSummary;
  rules?: Rule[];
  recent_blocks?: RecentBlock[];
  risk_banners?: RiskBanner[];
  reading_tools?: ReadingTool[];
  sharing_tools?: SharingTool[];
  reading_tool_inventory?: ToolInventoryRow[];
  sharing_tool_inventory?: ToolInventoryRow[];
  security_rules?: SecurityRule[];
  language_packs?: LanguagePack[];
  all_privacy_classes?: string[];
  cron_jobs?: CronJob[];
  suggestions?: Suggestions;
  destination_suggestions?: string[];
  tool_name_suggestions?: string[];
  purpose_suggestions?: string[];
  recipient_identity_suggestions?: string[];
  sharing_tool_egress_options?: string[];
  egress_safety?: string;
  taint_classification?: string;
  llm_source_classification?: boolean;
  llm_source_classifier_model?: string;
  llm_source_classifier_model_options?: string[];
  llm_user_context?: boolean;
  llm_cron_context?: boolean;
  persist_prompts?: boolean;
  llm_verifier_model?: string;
  llm_verifier_model_options?: string[];
  activity_max_rows?: number;
  activity_retention_days?: number;
  activity_group_seconds?: number;
  attention_dismissals?: AttentionDismissal[];
}

export interface HistoryResponse {
  data?: ActivityRow[];
  turns?: ActivityTurn[];
  recordsFiltered?: number;
  recordsTotal?: number;
}

// A turn: one user prompt and all the checks it drove. turn_id is "" for legacy
// (pre-feature) singleton rows; user_prompt is present only when persistence is on.
export interface ActivityTurn {
  turn_id?: string;
  user_prompt?: string;
  ts?: number;
  is_cron?: boolean;
  total_latency_us?: number;
  total_latency_ms?: number;
  rows?: ActivityRow[];
}

// --- Activity pending approvals (doc 02 §Tab1) ---
// A context-derived way to permit a block (doc 06). Rule rows (structural=false) create
// an allow rule; structural rows widen what counts as yours/trusted and need the admin
// confirm. `value` is the concrete recipient/host/command/connector the option would add.
export interface PermitOption {
  method: string;
  label: string;
  detail?: string;
  value?: string;
  kind?: string;
  structural?: boolean;
  data_classes?: string[];
  group?: string;
}

export interface PendingApproval {
  id?: string;
  tool_name?: string;
  action_family?: string;
  destination?: string;
  destination_trust?: string;
  decision_step?: string;
  purpose?: string;
  recipient_identity?: string;
  data_classes?: string[];
  reason?: string;
  why_now?: WhyNow | string;
  flow_boundary_label?: string;
  created_at?: number;
  expires_at?: number;
  covered_by_rule?: boolean;
  covered_rule_id?: string;
  covered_rule_source?: string;
  permit_options?: PermitOption[];
}

// --- Pure-function widget payloads (doc 02 §Tab2/§Tab3) ---
export interface DestinationResolution {
  value?: string;
  kind?: string;
  id?: string;
  trust?: string;
}

export interface SendPreview {
  action_family?: string;
  destination?: string;
  data_classes?: string[];
  destination_trust?: string;
  decision?: string;
  decision_step?: string;
}

export interface ImpactRow {
  id?: string;
  decision?: string;
  action_family?: string;
  destination?: string;
  destination_trust?: string;
  data_classes?: string | string[];
  purpose?: string;
  recipient_identity?: string;
  created_at?: number;
}

export interface ImpactPreview {
  effect?: string;
  verb?: string;
  matched_count?: number;
  considered?: number;
  matched?: ImpactRow[];
}

// Local form state for the rule modal.
export interface RuleForm {
  id: string;
  enabled: boolean;
  effect: string;
  action_family: string;
  destination: string;
  purpose: string;
  recipient_identity: string;
  tool_name: string;
  data_classes: string[];
  expiry: "forever" | "5m" | "1h" | "custom";
  expires_at: number | string;
  owner_hash: string;
  cron_job_id: string;
  cron_job_name: string;
}

export interface RuleMatch {
  tool_name: string;
  action_family: string;
  destination: string;
  purpose: string;
  recipient_identity: string;
  data_classes: string[];
}

export interface RuleScope {
  owner_hash: string;
  cron_job_id: string;
  cron_job_name: string;
}

export interface RulePayload {
  effect: string;
  match: RuleMatch;
  scope: RuleScope;
  expires_at: number;
  confirm?: string;
}

// Local form state for Reading/Sharing tool-classification modals.
export interface OverrideForm {
  id: string;
  match: string;
  egress: string;
  source: string;
  destination: string;
  taints: string[];
  note: string;
  enabled: boolean;
  isEdit: boolean;
}

export type ToastVariant = "success" | "error";

export interface Toast {
  id: string;
  message: string;
  variant: ToastVariant;
}

export interface PerfStats {
  count: number;
  avg_ms: number;
  p50_ms: number;
  p95_ms: number;
  max_ms: number;
  total_ms: number;
}

export interface PerfHook extends PerfStats {
  hook: string;
  label: string;
}

export interface PerfSample {
  ts: number;
  hook: string;
  tool_name: string;
  duration_ms: number;
  llm_invoked: boolean;
  blocked: boolean;
}

export interface Performance {
  overall: PerfStats;
  by_hook: PerfHook[];
  llm: PerfStats;
  deterministic: PerfStats;
  samples: PerfSample[];
  window_size: number;
}
