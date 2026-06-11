import type { OverrideForm, RuleForm } from "@/types";

export const ACTIONS = [
  "*",
  "browser_console",
  "browser_read",
  "browser_type",
  "cron_write",
  "final_response",
  "local_write",
  "mcp_read_query",
  "mcp_unknown",
  "mcp_write",
  "message_send",
  "terminal_exec",
  "tool_unknown",
  "web_api",
  "web_read",
];

export const TOOL_EGRESS_OPTIONS = [
  "",
  "ignore",
  "gate",
  "message_send",
  "web_api",
  "mcp_write",
  "mcp_read_query",
  "local_write",
  "terminal_exec",
  "model_api",
  "tool_write",
  "delegate_task",
  "computer_use",
  "kanban_write",
  "cron_write",
  "homeassistant_write",
];

export const DEFAULT_PRIVACY_CLASSES = [
  "browser_private_input",
  "calendar",
  "contacts",
  "documents",
  "email",
  "local_system",
  "memory",
];

export const HISTORY_PAGE_SIZES = [25, 50, 100];

export const DEFAULT_FORM: RuleForm = {
  id: "",
  enabled: true,
  effect: "allow",
  action_family: "*",
  destination: "",
  purpose: "",
  recipient_identity: "",
  tool_name: "",
  data_classes: ["*"],
  lifetime: "always",
  remaining_invocations: 5,
  owner_hash: "",
  session_id: "",
  cron_job_id: "",
  cron_job_name: "",
};

export const DEFAULT_OVERRIDE_FORM: OverrideForm = {
  id: "",
  match: "",
  egress: "",
  source: "",
  destination: "",
  taints: [],
  note: "",
  enabled: true,
  isEdit: false,
};
