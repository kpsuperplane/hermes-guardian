import type { Rule } from "@/types";

export function text(value: unknown, fallback?: string): string {
  const out = value == null ? "" : String(value);
  return out || (fallback || "");
}

export function displayText(value: unknown, fallback?: string): string {
  const out = text(value, "");
  return out === "*" ? (fallback || "Any") : out || (fallback || "Any");
}

export function classesText(classes: unknown): string {
  return Array.isArray(classes) && classes.length ? classes.join(", ") : "none";
}

export function timeText(seconds: unknown): string {
  const value = Number(seconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "n/a";
  return new Date(value * 1000).toLocaleString();
}

export function dateTimeNoYearText(seconds: unknown): string {
  const value = Number(seconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "n/a";
  return new Date(value * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

export function activityTimeNoYearText(value: unknown, fallbackSeconds: unknown): string {
  const out = text(value).replace(/([A-Z][a-z]{2} \d{1,2}), \d{4} /g, "$1, ");
  return out || dateTimeNoYearText(fallbackSeconds);
}

export function latencyText(milliseconds: unknown): string {
  const value = Number(milliseconds || 0);
  if (!Number.isFinite(value) || value <= 0) return "";
  if (value < 1) return "<1 ms";
  if (value < 1000) return Math.round(value) + " ms";
  if (value < 10000) return (Math.round(value / 100) / 10).toFixed(1) + " s";
  return Math.round(value / 1000) + " s";
}

// Turn an engine decision_step label (doc 03 §3.2, e.g. "step6_approve_external",
// "step3_intra_boundary_self", "step5_deny_rule:r12") into a one-line explanation.
// The label is engine-produced; this only formats it, and falls back to a de-snaked
// version of the raw label so a future step never renders blank.
export function decisionStepText(step: unknown): string {
  const raw = text(step);
  if (!raw) return "";
  const base = raw.split(":")[0];
  if (base === "step1_read") return "read — taints the session, never an egress";
  if (base.indexOf("step3_intra_boundary_") === 0) {
    const where = base.slice("step3_intra_boundary_".length).replace(/_/g, " ");
    return "stays with you (" + (where || "owned") + ") → allowed";
  }
  if (base === "step4_no_private_taint") return "no private data in scope → allowed";
  if (base === "step5_allow_rule") return "matched an allow rule → allowed";
  if (base === "step5_deny_rule") return "matched a deny rule → blocked";
  if (base === "step6_approve_external") {
    return "external destination + private data, no matching rule → approval required";
  }
  if (base === "step6_approve_unknown_as_external") {
    return "unconfirmed destination (treated as external) + private data → approval required";
  }
  return base.replace(/^step\d+_/, "").replace(/_/g, " ");
}

export function ruleScopeText(rule: Rule): string {
  const cronName = text(rule.cron_job_name);
  const cronId = text(rule.cron_job_id);
  if (cronName || cronId) return "[Cron] " + (cronName || cronId);
  const owner = text(rule.owner_hash);
  const scope = text(rule.scope).toLowerCase();
  if (!owner || owner === "*" || scope === "all owners" || scope === "global") {
    return "Runs everywhere";
  }
  if (scope.indexOf("cron job ") === 0) {
    return "[Cron] " + scope.slice("cron job ".length).replace(/\s+\([^)]+\)$/, "");
  }
  return "Owner scoped";
}

export function expiryPillText(rule: Rule): string {
  const expiresAt = Number(rule.expires_at || 0);
  if (!Number.isFinite(expiresAt) || expiresAt <= 0) return "";
  return expiresAt <= Math.floor(Date.now() / 1000)
    ? "expired"
    : "expires " + timeText(expiresAt);
}
