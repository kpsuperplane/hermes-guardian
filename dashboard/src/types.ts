// Shapes returned by the Guardian backend (dashboard/plugin_api.py) and the
// local form state used by the modals. Backend payloads are intentionally
// permissive — fields are optional and the formatting helpers in lib/format.ts
// coerce loose values defensively, matching the original bundle's behavior.

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
  purpose?: string;
  recipient_identity?: string;
  data_classes?: string;
  reason?: string;
  reason_short?: string;
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
  activity_max_rows?: number;
  activity_retention_days?: number;
  activity_group_seconds?: number;
}

export interface HistoryResponse {
  data?: ActivityRow[];
  recordsFiltered?: number;
  recordsTotal?: number;
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
