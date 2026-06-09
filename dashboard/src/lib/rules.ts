import { text } from "@/lib/format";
import type { Rule, RuleForm, RulePayload } from "@/types";

export function ruleToForm(rule: Rule): RuleForm {
  const remaining = Number(rule.remaining_invocations);
  let lifetime: RuleForm["lifetime"] = "always";
  let custom = 5;
  if (Number.isFinite(remaining) && remaining === 1) {
    lifetime = "once";
    custom = 1;
  } else if (Number.isFinite(remaining) && remaining > 1) {
    lifetime = "custom";
    custom = Math.trunc(remaining);
  }
  return {
    id: text(rule.rule_id || rule.id),
    enabled: rule.enabled !== false,
    effect: text(rule.effect, "allow"),
    action_family: text(rule.action_family, "*"),
    destination: text(rule.destination) === "*" ? "" : text(rule.destination),
    purpose: text(rule.purpose) === "*" ? "" : text(rule.purpose),
    recipient_identity:
      text(rule.recipient_identity) === "*" ? "" : text(rule.recipient_identity),
    tool_name: text(rule.tool_name) === "*" ? "" : text(rule.tool_name),
    data_classes:
      Array.isArray(rule.data_classes) && rule.data_classes.length
        ? rule.data_classes.slice()
        : ["*"],
    lifetime,
    remaining_invocations: custom,
    owner_hash: text(rule.owner_hash) === "*" ? "" : text(rule.owner_hash),
    session_id: text(rule.session_id),
    cron_job_id: text(rule.cron_job_id),
    cron_job_name: text(rule.cron_job_name),
  };
}

export function formToPayload(form: RuleForm): RulePayload {
  let remaining = -1;
  if (form.lifetime === "once") remaining = 1;
  if (form.lifetime === "custom") {
    remaining = Math.max(1, Math.trunc(Number(form.remaining_invocations) || 1));
  }
  const classes = form.data_classes && form.data_classes.length ? form.data_classes : ["*"];
  return {
    effect: form.effect,
    match: {
      tool_name: text(form.tool_name, "*"),
      action_family: text(form.action_family, "*"),
      destination: text(form.destination, "*"),
      purpose: text(form.purpose, "*"),
      recipient_identity: text(form.recipient_identity, "*"),
      data_classes: classes.indexOf("*") >= 0 ? ["*"] : classes,
    },
    scope: {
      owner_hash: text(form.owner_hash, "*"),
      session_id: text(form.session_id),
      cron_job_id: text(form.cron_job_id),
      cron_job_name: text(form.cron_job_name),
    },
    remaining_invocations: remaining,
  };
}

export function payloadIsWildcardAllow(payload: RulePayload): boolean {
  const match = payload && payload.match ? payload.match : ({} as RulePayload["match"]);
  const classes = Array.isArray(match.data_classes) ? match.data_classes : [];
  return (
    payload.effect === "allow" &&
    text(match.tool_name, "*") === "*" &&
    text(match.action_family, "*") === "*" &&
    text(match.destination, "*") === "*" &&
    text(match.purpose, "*") === "*" &&
    text(match.recipient_identity, "*") === "*" &&
    classes.indexOf("*") >= 0
  );
}
