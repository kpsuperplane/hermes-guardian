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
  identity?: string;
  classes?: string[];
  note?: string;
}

export interface OutwardSharing {
  builtin?: string[];
  extra?: string[];
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
  remaining_invocations?: number;
  owner_hash?: string;
  session_id?: string;
  cron_job_id?: string;
  cron_job_name?: string;
  scope?: string;
}

export interface ToolOverride {
  id?: string;
  match?: string;
  egress?: string;
  destination?: string;
  taints?: string[];
  note?: string;
  enabled?: boolean;
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
}

export interface ActivityRow {
  id?: string;
  decision?: string;
  time?: string;
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
  reason?: string;
  reason_short?: string;
  turn_id?: string;
  user_prompt?: string;
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
  tool_overrides?: ToolOverride[];
  security_rules?: SecurityRule[];
  language_packs?: LanguagePack[];
  all_privacy_classes?: string[];
  cron_jobs?: CronJob[];
  suggestions?: Suggestions;
  destination_suggestions?: string[];
  tool_name_suggestions?: string[];
  purpose_suggestions?: string[];
  recipient_identity_suggestions?: string[];
  tool_override_egress_options?: string[];
  privacy_mode?: string;
  privacy_policy?: string;
  unknown_tools?: string;
  llm_user_context?: boolean;
  llm_cron_context?: boolean;
  persist_prompts?: boolean;
  llm_verifier_model?: string;
  llm_verifier_model_options?: string[];
  activity_max_rows?: number;
  activity_retention_days?: number;
  activity_group_seconds?: number;
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
  rows?: ActivityRow[];
}

// --- Activity pending approvals (doc 02 §Tab1) ---
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
  created_at?: number;
  expires_at?: number;
  covered_by_rule?: boolean;
  covered_rule_id?: string;
  covered_rule_source?: string;
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
  lifetime: "always" | "once" | "custom";
  remaining_invocations: number | string;
  owner_hash: string;
  session_id: string;
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
  session_id: string;
  cron_job_id: string;
  cron_job_name: string;
}

export interface RulePayload {
  effect: string;
  match: RuleMatch;
  scope: RuleScope;
  remaining_invocations: number;
  confirm?: string;
}

// Local form state for the tool-override modal.
export interface OverrideForm {
  id: string;
  match: string;
  egress: string;
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
