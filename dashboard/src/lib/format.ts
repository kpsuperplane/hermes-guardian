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

export function ruleScopeText(rule: Rule): string {
  const cronName = text(rule.cron_job_name);
  const cronId = text(rule.cron_job_id);
  if (cronName || cronId) return "[Cron] " + (cronName || cronId);
  if (text(rule.session_id)) return "Session scoped";
  const owner = text(rule.owner_hash);
  const scope = text(rule.scope).toLowerCase();
  if (!owner || owner === "*" || scope === "all owners" || scope === "global") {
    return "Runs everywhere";
  }
  if (scope === "session") return "Session scoped";
  if (scope.indexOf("cron job ") === 0) {
    return "[Cron] " + scope.slice("cron job ".length).replace(/\s+\([^)]+\)$/, "");
  }
  return "Owner scoped";
}

export function remainingPillText(rule: Rule): string {
  const remaining = Number(rule.remaining_invocations);
  if (!Number.isFinite(remaining) || remaining < 0) return "";
  return remaining === 1
    ? "1 invocation left"
    : Math.trunc(remaining) + " invocations left";
}
