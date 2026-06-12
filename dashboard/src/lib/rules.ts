import { text } from "@/lib/format";
import type { Rule, RuleForm, RulePayload } from "@/types";

export function ruleToForm(rule: Rule): RuleForm {
  const expires = Number(rule.expires_at || 0);
  const expiry: RuleForm["expiry"] = Number.isFinite(expires) && expires > 0 ? "custom" : "forever";
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
    expiry,
    expires_at: expiry === "custom" ? Math.trunc(expires) : "",
    owner_hash: text(rule.owner_hash) === "*" ? "" : text(rule.owner_hash),
    cron_job_id: text(rule.cron_job_id),
    cron_job_name: text(rule.cron_job_name),
  };
}

export function formToPayload(form: RuleForm): RulePayload {
  const now = Math.floor(Date.now() / 1000);
  let expiresAt = 0;
  if (form.expiry === "5m") expiresAt = now + 300;
  if (form.expiry === "1h") expiresAt = now + 3600;
  if (form.expiry === "custom") {
    expiresAt = Math.max(1, Math.trunc(Number(form.expires_at) || 0));
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
      cron_job_id: text(form.cron_job_id),
      cron_job_name: text(form.cron_job_name),
    },
    expires_at: expiresAt,
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
