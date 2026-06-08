"""Dashboard and activity presentation helpers for Hermes Guardian."""

from __future__ import annotations

import html
import time
from datetime import datetime
from typing import Any, Callable
from zoneinfo import ZoneInfo


def activity_display_tool(row: dict[str, Any]) -> str:
    tool = str(row.get("tool_name") or row.get("action_family") or "").strip()
    if row.get("decision") == "tainted" and tool.lower() in {"terminal", "execute_code", "code_execution", "shell"}:
        return f"{tool} result"
    return tool


def clip_text(value: Any, limit: int = 120, *, ellipsis: str = "...", fallback: str = "") -> str:
    text = str(value or "").strip() or fallback
    if len(text) <= limit:
        return text
    suffix = ellipsis or ""
    return text[: max(0, limit - len(suffix))].rstrip() + suffix


def friendly_activity_timestamp(ts: Any, tz: ZoneInfo | None) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts or 0), tz=tz)
    except Exception:
        dt = datetime.fromtimestamp(0, tz=tz)
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    hour = dt.hour % 12 or 12
    am_pm = "AM" if dt.hour < 12 else "PM"
    zone = dt.tzname() or time.tzname[0] or "local"
    return f"{months[dt.month - 1]} {dt.day}, {dt.year} {hour}:{dt.minute:02d} {am_pm} {zone}"


def activity_time_text(row: dict[str, Any], tz: ZoneInfo | None) -> str:
    count = int(row.get("count") or 1)
    if count <= 1:
        return friendly_activity_timestamp(row.get("ts"), tz)
    first_ts = int(row.get("first_ts") or row.get("ts") or 0)
    latest_ts = int(row.get("ts") or 0)
    if first_ts == latest_ts:
        return friendly_activity_timestamp(latest_ts, tz)
    first_text = friendly_activity_timestamp(first_ts, tz)
    latest_text = friendly_activity_timestamp(latest_ts, tz)
    if first_text == latest_text:
        return latest_text
    return f"{first_text} - {latest_text}"


def activity_display_reason(
    row: dict[str, Any],
    *,
    all_privacy_classes: set[str],
    taint_reason_for_tool_result: Callable[[str, set[str]], str],
) -> str:
    reason = str(row.get("reason") or "").strip()
    if reason == "private source result" and row.get("decision") == "tainted":
        classes = {
            cls.strip()
            for cls in str(row.get("data_classes") or "").split(",")
            if cls.strip() in all_privacy_classes
        }
        return taint_reason_for_tool_result(str(row.get("tool_name") or ""), classes)
    return reason


def activity_status_icon(decision: str) -> str:
    status_icons = {
        "allowed": "✅",
        "auto_approved": "✅",
        "blocked": "❌",
        "denied": "❌",
        "manual_approved": "✅",
        "mode_off_allowed": "✅",
        "privacy_off_allowed": "✅",
        "read": "🌐",
        "security_blocked": "❌",
        "security_suppressed": "❌",
        "tainted": "📥",
    }
    return status_icons.get(str(decision or "").strip(), "•")


def activity_reason_prefix(decision: str) -> str:
    if decision == "read":
        return "Read"
    if decision in {"allowed", "auto_approved", "manual_approved", "mode_off_allowed", "privacy_off_allowed"}:
        return "Allowed"
    if decision == "denied":
        return "Denied"
    if decision in {"blocked", "security_blocked", "security_suppressed"}:
        return "Blocked"
    return ""


def activity_reason_line_text(
    row: dict[str, Any],
    *,
    marker: str,
    display_reason: str,
    limit: int = 72,
    marker_limit: int = 72,
) -> str:
    decision = str(row.get("decision") or "").strip()
    if decision == "tainted":
        return ""
    reason = clip_text(display_reason, limit, ellipsis="...", fallback="")
    if not reason:
        return ""
    suffix = f" (`{clip_text(marker, marker_limit, ellipsis='...', fallback='')}`)" if marker else ""
    prefix = activity_reason_prefix(decision)
    return f"{prefix}: {reason}{suffix}" if prefix else f"{reason}{suffix}"


def activity_taints_text(row: dict[str, Any], *, code: bool = False, html_code: bool = False) -> str:
    raw_classes = str(row.get("data_classes") or "").strip()
    classes = clip_text(raw_classes, 120, fallback="") if raw_classes else ""
    if not classes or classes in {"none", "n/a"}:
        return "🏷️ No taints"
    if html_code:
        return f"🏷️ <code>{html.escape(classes, quote=True)}</code>"
    if code:
        return f"🏷️ `{classes}`"
    return f"🏷️ {classes}"


def dashboard_html(
    policy: dict[str, Any],
    *,
    jquery_version: str,
    datatables_version: str,
    all_privacy_classes: set[str],
) -> str:
    def esc(value: Any) -> str:
        return html.escape(str(value or ""), quote=True)

    def rule_classes_html(classes: list[str]) -> str:
        safe_classes = sorted(str(cls) for cls in classes if str(cls))
        if set(safe_classes) == all_privacy_classes:
            title = esc(", ".join(safe_classes))
            return f'<span class="rule-chip" title="{title}">all data classes</span>'
        if not safe_classes:
            return '<span class="rule-chip muted">no data classes</span>'
        return "".join(
            f'<span class="rule-chip">{esc(cls)}</span>'
            for cls in safe_classes
        )

    def rule_item_html(rule: dict[str, Any]) -> str:
        rule_id = str(rule.get("rule_id") or "")
        source = str(rule.get("source") or "persistent")
        delete_button = ""
        if source == "persistent" and rule_id:
            item_attrs = f' data-rule-id="{esc(rule_id)}"'
            delete_button = (
                f'<button type="button" class="rule-delete" data-rule-delete '
                f'data-rule-id="{esc(rule_id)}">Delete</button>'
            )
        else:
            item_attrs = ""
        return (
            f'<li class="rule-item"{item_attrs}>'
            f'<div class="rule-main">'
            f'<span class="rule-source">{esc(source)}</span>'
            f'<span>{esc(rule["action_family"])} -> {esc(rule["destination"])}</span>'
            f'<span class="rule-scope">{esc(rule.get("scope", ""))}</span>'
            f'{delete_button}</div>'
            f'<div class="rule-classes">{rule_classes_html(rule["data_classes"])}</div></li>'
        )

    rules = policy["rules"]
    rule_items = "".join(rule_item_html(rule) for rule in rules) or "<li>No allow rules.</li>"

    def block_time(value: Any) -> str:
        try:
            ts = int(float(value or 0))
        except Exception:
            ts = 0
        if ts <= 0:
            return "n/a"
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")

    def block_detail(label: str, value: Any) -> str:
        return f"<dt>{esc(label)}</dt><dd>{esc(value) if str(value or '').strip() else 'n/a'}</dd>"

    recent_blocks = policy.get("recent_blocks") or []
    recent_block_items = "".join(
        f'<li class="block-item" data-approval-id="{esc(block.get("id", ""))}">'
        f'<div class="block-main">'
        f'<div><span class="block-action">{esc(block.get("action_family", ""))} -&gt; '
        f'{esc(block.get("destination", ""))}</span> '
        f'<code>{esc(block.get("id", ""))}</code></div>'
        f'<div class="block-actions">'
        f'<button type="button" data-approval-action="approve-once" data-approval-id="{esc(block.get("id", ""))}">Approve once</button>'
        f'<button type="button" data-approval-action="approve-always" data-approval-id="{esc(block.get("id", ""))}">Approve always</button>'
        f'<button type="button" data-approval-action="dismiss" data-approval-id="{esc(block.get("id", ""))}">Dismiss</button>'
        f'</div></div>'
        f'<dl class="block-details">'
        f'{block_detail("Tool", block.get("tool_name", ""))}'
        f'{block_detail("Taints", ", ".join(block.get("data_classes") or []))}'
        f'{block_detail("Reason", block.get("reason", ""))}'
        f'{block_detail("Action detail", block.get("action_detail", ""))}'
        f'{block_detail("Scope", block.get("scope", ""))}'
        f'{block_detail("Created", block_time(block.get("created_at")))}'
        f'{block_detail("Expires", block_time(block.get("expires_at")))}'
        f'</dl></li>'
        for block in recent_blocks
    ) or '<li class="muted-list-item">No recent unresolved blocks.</li>'
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hermes Guardian</title>
  <link rel="stylesheet" href="/assets/datatables/{datatables_version}/dataTables.dataTables.min.css">
  <style>
    :root {{
      color-scheme: light dark;
      font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
      --bg: #ffffff;
      --text: #37352f;
      --muted: #787774;
      --line: #e9e9e7;
      --soft-line: #f1f1ef;
      --surface: #f7f6f3;
      --surface-hover: #e9e9e7;
      --control: #f1f1ef;
      --code: #9f2f2f;
      --focus: #2383e2;
      --disabled: #8f8d89;
    }}
    html, body {{ overflow-x: hidden; }}
    body {{ margin: 0; background: var(--bg); color: var(--text); font-size: 16px; line-height: 1.5; }}
    .skip-link {{ position: absolute; left: 16px; top: 10px; z-index: 10; transform: translateY(-150%); border-radius: 3px; background: var(--text); color: var(--bg); padding: 8px 10px; font-size: 13px; font-weight: 600; text-decoration: none; }}
    .skip-link:focus {{ transform: translateY(0); }}
    button:focus-visible, input:focus-visible, select:focus-visible, a:focus-visible, #activity-table td.dt-control:focus-visible {{ outline: 2px solid var(--focus); outline-offset: 2px; }}
    .page-header {{ max-width: 1120px; margin: 0 auto; padding: 52px 32px 10px; background: transparent; color: inherit; }}
    main {{ padding: 0 32px 44px; max-width: 1120px; margin: 0 auto; }}
    h1 {{ margin: 0; font-size: 40px; line-height: 1.2; font-weight: 700; letter-spacing: 0; }}
    h2 {{ font-size: 17px; line-height: 1.3; margin: 0 0 12px; color: var(--text); font-weight: 650; }}
    .sub {{ margin-top: 8px; color: var(--muted); font-size: 13px; line-height: 1.45; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px; margin: 26px 0 22px; }}
    section {{ background: transparent; border: 0; border-radius: 0; padding: 0; }}
    .section-disclosure > summary {{ display: flex; align-items: center; gap: 8px; min-height: 30px; list-style: none; cursor: pointer; }}
    .section-disclosure > summary::-webkit-details-marker {{ display: none; }}
    .section-disclosure > summary::before {{ content: "+"; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border-radius: 3px; background: var(--control); color: var(--muted); font-size: 13px; font-weight: 600; flex: 0 0 auto; }}
    .section-disclosure[open] > summary::before {{ content: "-"; }}
    .section-disclosure > summary h2 {{ margin: 0; }}
    .section-disclosure[open] > summary {{ margin-bottom: 12px; }}
    dl {{ display: grid; grid-template-columns: 118px 1fr; gap: 7px 12px; margin: 0; font-size: 13px; line-height: 1.4; }}
    dt {{ color: var(--muted); }}
    dd {{ margin: 0; font-weight: 500; }}
    ul {{ margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.45; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; background: var(--surface); border-radius: 3px; padding: 1px 4px; color: var(--code); }}
    .rule-item {{ margin: 0 0 10px; min-width: 0; }}
    .rule-main {{ display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: baseline; min-width: 0; overflow-wrap: anywhere; }}
    .rule-classes {{ display: flex; flex-wrap: wrap; gap: 5px; margin-top: 6px; min-width: 0; }}
    .rule-source {{ display: inline-flex; border-radius: 3px; padding: 1px 5px; background: var(--control); color: #5f5e59; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0; }}
    .rule-scope {{ color: var(--muted); font-size: 12px; }}
    .rule-chip {{ display: inline-flex; max-width: 100%; border-radius: 3px; padding: 1px 5px; background: var(--surface); color: #4b4a45; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }}
    .rule-chip.muted {{ color: var(--muted); }}
    .rule-delete {{ min-height: 26px; border: 0; border-radius: 3px; background: var(--control); color: var(--text); font: inherit; font-size: 12px; font-weight: 500; padding: 3px 7px; cursor: pointer; }}
    .rule-delete:hover {{ background: var(--surface-hover); }}
    .rule-delete:disabled {{ cursor: wait; opacity: 0.65; }}
    .recent-blocks-section {{ margin-bottom: 24px; }}
    .recent-blocks-section h2 {{ display: inline-flex; align-items: center; gap: 8px; }}
    .block-list {{ display: grid; gap: 12px; padding: 0; list-style: none; }}
    .block-item {{ border: 0; border-radius: 0; padding: 0; min-width: 0; }}
    .block-main {{ display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; min-width: 0; }}
    .block-action {{ font-weight: 600; overflow-wrap: anywhere; }}
    .block-actions {{ display: flex; flex-wrap: wrap; gap: 6px; justify-content: flex-end; flex: 0 0 auto; }}
    .block-actions button {{ min-height: 30px; border: 0; border-radius: 3px; background: var(--control); color: var(--text); font: inherit; font-size: 12px; font-weight: 500; padding: 5px 8px; cursor: pointer; }}
    .block-actions button:hover {{ background: var(--surface-hover); }}
    .block-actions button:disabled {{ cursor: wait; opacity: 0.65; }}
    .block-details {{ display: grid; grid-template-columns: 118px minmax(0, 1fr); gap: 5px 12px; margin-top: 9px; font-size: 12px; line-height: 1.4; }}
    .block-details dd {{ font-weight: 400; min-width: 0; overflow-wrap: anywhere; word-break: break-word; }}
    .muted-list-item, .block-status, .rules-status {{ color: var(--muted); font-size: 13px; }}
    .muted-list-item {{ padding: 10px 0; }}
    .block-status {{ margin: 8px 0 0; min-height: 18px; }}
    .table-wrap {{ background: transparent; border: 1px solid var(--line); border-radius: 3px; padding: 0; overflow-x: auto; }}
    .table-wrap .dt-container {{ min-width: 860px; padding: 10px 12px 12px; }}
    .dt-layout-row {{ display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px 14px; margin: 0 0 10px; }}
    .dt-layout-row:last-child {{ margin: 10px 0 0; }}
    .dt-layout-cell {{ min-width: 0; }}
    .dt-search, .dt-length, .dt-info, .dt-paging {{ color: var(--muted); font-size: 12px; }}
    .dt-search input, .dt-length select {{ max-width: 100%; border: 1px solid #e1e1df; border-radius: 3px; background: var(--bg); color: var(--text); font: inherit; padding: 4px 7px; }}
    .dt-paging button {{ border: 0; border-radius: 3px; background: transparent; color: var(--text); font: inherit; padding: 4px 7px; }}
    .dt-paging button:hover:not(:disabled) {{ background: var(--control); }}
    .dt-paging button:disabled {{ color: var(--disabled); }}
    #activity-table {{ width: 100%; min-width: 836px; font-size: 13px; }}
    #activity-table td, #activity-table th {{ vertical-align: top; }}
    #activity-table thead th {{ color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--line); }}
    #activity-table tbody td {{ border-top: 1px solid var(--soft-line); }}
    #activity-table td.dt-control {{ width: 26px; text-align: center; cursor: pointer; color: var(--muted); font-weight: 700; }}
    #activity-table td.dt-control::before {{ content: "+"; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border: 1px solid #d9d9d6; border-radius: 3px; }}
    #activity-table tr.dt-hasChild td.dt-control::before {{ content: "-"; }}
    .dt-detail {{ display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 7px 12px; padding: 11px 12px 12px 38px; font-size: 13px; line-height: 1.4; background: #fbfbfa; border-left: 3px solid var(--line); }}
    .dt-detail dt {{ color: var(--muted); font-weight: 600; }}
    .dt-detail dd {{ margin: 0; min-width: 0; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-all; font-weight: 400; }}
    .dt-pill {{ display: inline-flex; align-items: center; border-radius: 3px; padding: 1px 5px; background: var(--surface); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }}
    .empty {{ background: transparent; border: 1px solid var(--line); border-radius: 3px; padding: 16px; color: var(--muted); }}
    @media (prefers-reduced-motion: reduce) {{
      *, *::before, *::after {{ animation-duration: 0.01ms !important; animation-iteration-count: 1 !important; scroll-behavior: auto !important; transition-duration: 0.01ms !important; }}
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{ --bg: #191919; --text: #e6e6e6; --muted: #9b9b9b; --line: #333333; --soft-line: #2a2a2a; --surface: #2f2f2f; --surface-hover: #3a3a3a; --control: #2f2f2f; --code: #ff8f8f; --disabled: #777777; }}
      .page-header {{ background: transparent; color: inherit; }}
      .rule-source {{ color: #bdbdbd; }}
      #activity-table td.dt-control::before {{ border-color: #4a4a4a; }}
      .dt-search input, .dt-length select {{ background: #202020; border-color: var(--line); }}
      .dt-detail {{ background: #202020; }}
    }}
    @media (max-width: 720px) {{
      .page-header {{ padding: 34px 20px 8px; }}
      main {{ padding: 0 20px 32px; }}
      h1 {{ font-size: 32px; }}
      h2 {{ font-size: 16px; }}
      section {{ padding: 0; border: 0; border-radius: 0; }}
      .grid {{ display: block; margin: 22px 0 18px; }}
      .grid section + section {{ margin-top: 14px; }}
      .section-disclosure > summary {{ min-height: 36px; }}
      .section-disclosure[open] > summary {{ margin-bottom: 8px; }}
      .policy-section dl {{ gap: 4px; font-size: 12px; line-height: 1.3; }}
      .rule-delete {{ min-height: 36px; padding: 7px 10px; }}
      .block-main {{ display: grid; }}
      .block-actions {{ justify-content: flex-start; }}
      .block-actions button, .dt-paging button, .dt-search input, .dt-length select {{ min-height: 44px; }}
      .block-actions button {{ padding: 8px 10px; }}
      .dt-paging button {{ padding-left: 10px; padding-right: 10px; }}
      .table-wrap {{ margin-left: -20px; margin-right: -20px; border-left: 0; border-right: 0; border-radius: 0; }}
      .table-wrap .dt-container {{ min-width: 820px; padding-left: 20px; padding-right: 20px; }}
      dl, .block-details, .dt-detail {{ grid-template-columns: 1fr; }}
      .dt-detail {{ gap: 3px; padding: 8px 10px 9px 28px; font-size: 11px; line-height: 1.3; }}
      .dt-detail dt {{ font-size: 10px; }}
    }}
  </style>
</head>
<body>
  <a class="skip-link" href="#activity-feed">Skip to activity feed</a>
  <div class="page-header">
    <h1>Hermes Guardian</h1>
    <div class="sub">Sanitized permission activity only. Raw tool args and private content are not logged.</div>
  </div>
  <main>
    <div class="grid">
      <section class="policy-section">
        <details class="section-disclosure" data-collapse-mobile open>
          <summary><h2>Policy</h2></summary>
          <dl>
            <dt>Privacy policy</dt><dd>{esc(policy['privacy_policy'])}</dd>
            <dt>Allowlist env</dt><dd>{'set' if policy['allowlist_env_set'] else 'not set'}</dd>
            <dt>Max rows</dt><dd>{esc(policy['activity_max_rows'])}</dd>
            <dt>Retention</dt><dd>{esc(policy['activity_retention_days'])} days</dd>
            <dt>Grouping</dt><dd>{esc(policy['activity_group_seconds'])} seconds</dd>
            <dt>Activity DB</dt><dd><code>{esc(policy['activity_db'])}</code></dd>
          </dl>
        </details>
      </section>
      <section>
        <h2>Allow Rules</h2>
        <ul id="rules-list">{rule_items}</ul>
        <div id="rules-status" class="rules-status" aria-live="polite"></div>
      </section>
    </div>
    <section class="recent-blocks-section">
      <h2>Recent Blocks</h2>
      <ul id="recent-blocks-list" class="block-list">{recent_block_items}</ul>
      <div id="recent-blocks-status" class="block-status" aria-live="polite"></div>
    </section>
    <h2 id="activity-feed">Activity Feed</h2>
    <div class="table-wrap">
      <table id="activity-table">
        <thead>
          <tr>
            <th></th>
            <th>Status</th>
            <th>Time</th>
            <th>Tool</th>
            <th>Action</th>
            <th>Destination</th>
            <th>Taints</th>
            <th>Reason</th>
          </tr>
        </thead>
      </table>
    </div>
  </main>
  <script src="/assets/jquery/{jquery_version}/jquery.min.js"></script>
  <script src="/assets/datatables/{datatables_version}/dataTables.min.js"></script>
  <script>
    const escapeText = (value) => value == null ? "" : String(value);
    const escapeHtml = (value) => escapeText(value)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
    const renderText = (data, type) => type === "display" ? escapeHtml(data) : data;
    const renderStatus = (_data, type, row) => {{
      if (type !== "display") return row.decision || "";
      return `${{escapeHtml(row.icon)}} ${{escapeHtml(row.decision)}}`;
    }};
    const addDetail = (dl, label, value) => {{
      const dt = document.createElement("dt");
      dt.textContent = label;
      const dd = document.createElement("dd");
      dd.textContent = value == null || value === "" ? "n/a" : String(value);
      dl.append(dt, dd);
    }};
    const rulesList = document.getElementById("rules-list");
    const rulesStatus = document.getElementById("rules-status");
    const recentBlocksList = document.getElementById("recent-blocks-list");
    const recentBlocksStatus = document.getElementById("recent-blocks-status");
    const collapseMobileSections = () => {{
      if (!window.matchMedia("(max-width: 720px)").matches) return;
      document.querySelectorAll("[data-collapse-mobile]").forEach((section) => {{
        section.removeAttribute("open");
      }});
    }};
    collapseMobileSections();
    const timestampText = (seconds) => {{
      const value = Number(seconds || 0);
      if (!Number.isFinite(value) || value <= 0) return "n/a";
      return new Date(value * 1000).toLocaleString();
    }};
    const classText = (classes) => Array.isArray(classes) && classes.length ? classes.join(", ") : "none";
    const renderRecentBlocks = (blocks) => {{
      if (!recentBlocksList) return;
      recentBlocksList.textContent = "";
      if (!Array.isArray(blocks) || blocks.length === 0) {{
        const empty = document.createElement("li");
        empty.className = "muted-list-item";
        empty.textContent = "No recent unresolved blocks.";
        recentBlocksList.append(empty);
        return;
      }}
      for (const block of blocks) {{
        const item = document.createElement("li");
        item.className = "block-item";
        item.dataset.approvalId = block.id || "";
        const main = document.createElement("div");
        main.className = "block-main";
        const titleWrap = document.createElement("div");
        const title = document.createElement("span");
        title.className = "block-action";
        title.textContent = `${{block.action_family || ""}} -> ${{block.destination || ""}}`;
        const code = document.createElement("code");
        code.textContent = block.id || "";
        titleWrap.append(title, " ", code);
        const actions = document.createElement("div");
        actions.className = "block-actions";
        for (const [label, action] of [["Approve once", "approve-once"], ["Approve always", "approve-always"], ["Dismiss", "dismiss"]]) {{
          const button = document.createElement("button");
          button.type = "button";
          button.dataset.approvalAction = action;
          button.dataset.approvalId = block.id || "";
          button.textContent = label;
          actions.append(button);
        }}
        main.append(titleWrap, actions);
        const details = document.createElement("dl");
        details.className = "block-details";
        addDetail(details, "Tool", block.tool_name);
        addDetail(details, "Taints", classText(block.data_classes));
        addDetail(details, "Reason", block.reason);
        addDetail(details, "Action detail", block.action_detail);
        addDetail(details, "Scope", block.scope);
        addDetail(details, "Created", timestampText(block.created_at));
        addDetail(details, "Expires", timestampText(block.expires_at));
        item.append(main, details);
        recentBlocksList.append(item);
      }}
    }};
    const setRecentBlockStatus = (message) => {{
      if (recentBlocksStatus) recentBlocksStatus.textContent = message || "";
    }};
    const setRulesStatus = (message) => {{
      if (rulesStatus) rulesStatus.textContent = message || "";
    }};
    const deleteRule = async (ruleId) => {{
      const response = await fetch(`/api/rules/${{encodeURIComponent(ruleId)}}`, {{
        method: "DELETE",
      }});
      const payload = await response.json().catch(() => ({{ ok: false, message: "Rule delete failed." }}));
      setRulesStatus(payload.message || (response.ok ? "Deleted." : "Rule delete failed."));
      if (!response.ok || !payload.ok) return false;
      const item = rulesList
        ? Array.from(rulesList.querySelectorAll("[data-rule-id]")).find((node) => node.dataset.ruleId === ruleId)
        : null;
      if (item) item.remove();
      if (rulesList && !rulesList.querySelector(".rule-item")) {{
        const empty = document.createElement("li");
        empty.textContent = "No allow rules.";
        rulesList.append(empty);
      }}
      return true;
    }};
    const refreshPolicy = async () => {{
      const response = await fetch("/api/policy", {{ cache: "no-store" }});
      const policy = await response.json();
      renderRecentBlocks(policy.recent_blocks || []);
      return policy;
    }};
    const postApprovalAction = async (approvalId, action) => {{
      const isDismiss = action === "dismiss";
      const scope = action === "approve-always" ? "always" : "once";
      const path = isDismiss
        ? `/api/approvals/${{encodeURIComponent(approvalId)}}/dismiss`
        : `/api/approvals/${{encodeURIComponent(approvalId)}}/approve`;
      const response = await fetch(path, {{
        method: "POST",
        headers: {{ "Content-Type": "application/json" }},
        body: JSON.stringify(isDismiss ? {{}} : {{ scope }}),
      }});
      const payload = await response.json().catch(() => ({{ ok: false, message: "Approval action failed." }}));
      if (payload.policy) renderRecentBlocks(payload.policy.recent_blocks || []);
      if (typeof activityTable !== "undefined") activityTable.ajax.reload(null, false);
      setRecentBlockStatus(payload.message || (response.ok ? "Updated." : "Approval action failed."));
    }};
    const detailNode = (data) => {{
      const dl = document.createElement("dl");
      dl.className = "dt-detail";
      addDetail(dl, "Reason", data.reason);
      addDetail(dl, "Action detail", data.action_detail);
      addDetail(dl, "Policy", data.mode);
      addDetail(dl, "Session", data.session_hash);
      addDetail(dl, "Owner", data.owner_hash);
      addDetail(dl, "Approval", data.approval_id);
      addDetail(dl, "Rule", [data.rule_source, data.rule_id].filter(Boolean).join(" "));
      addDetail(dl, "Row", `#${{data.id}} @ ${{data.ts}}`);
      return dl;
    }};
    const activityTable = new DataTable("#activity-table", {{
      ajax: "/api/activity/datatables",
      processing: true,
      serverSide: true,
      pageLength: 25,
      lengthMenu: [25, 50, 100],
      order: [[2, "desc"]],
      columns: [
        {{ data: null, defaultContent: "", orderable: false, searchable: false, className: "dt-control" }},
        {{ data: "decision", name: "decision", render: renderStatus }},
        {{ data: "time", name: "ts", render: renderText }},
        {{ data: "tool", name: "tool_name", render: renderText }},
        {{ data: "action_family", name: "action_family", render: renderText }},
        {{ data: "destination", name: "destination", render: renderText }},
        {{ data: "data_classes", name: "data_classes", render: (data, type) => type === "display" && data ? `<span class="dt-pill">${{escapeHtml(data)}}</span>` : data }},
        {{ data: "reason_short", name: "reason", render: renderText }},
      ],
    }});
    activityTable.on("draw", () => {{
      document.querySelectorAll("#activity-table tbody td.dt-control").forEach((cell) => {{
        cell.tabIndex = 0;
        cell.setAttribute("role", "button");
        cell.setAttribute("aria-label", "Toggle activity details");
      }});
    }});
    const toggleDetailRow = (controlCell) => {{
      const tr = controlCell.closest("tr");
      const row = activityTable.row(tr);
      if (row.child.isShown()) {{
        row.child.hide();
        tr.classList.remove("dt-hasChild");
        controlCell.setAttribute("aria-expanded", "false");
      }} else {{
        row.child(detailNode(row.data())).show();
        tr.classList.add("dt-hasChild");
        controlCell.setAttribute("aria-expanded", "true");
      }}
    }};
    activityTable.on("click", "tbody td.dt-control", function () {{
      toggleDetailRow(this);
    }});
    activityTable.on("keydown", "tbody td.dt-control", function (event) {{
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      toggleDetailRow(this);
    }});
    document.addEventListener("click", async (event) => {{
      const ruleButton = event.target.closest("[data-rule-delete]");
      if (ruleButton) {{
        const ruleId = ruleButton.dataset.ruleId || "";
        if (!ruleId) return;
        if (!window.confirm("Delete this persistent Guardian allow rule?")) return;
        const originalText = ruleButton.textContent;
        ruleButton.disabled = true;
        ruleButton.textContent = "Deleting...";
        setRulesStatus("");
        try {{
          const ok = await deleteRule(ruleId);
          if (!ok) {{
            ruleButton.disabled = false;
            ruleButton.textContent = originalText;
          }}
        }} catch (error) {{
          setRulesStatus(error && error.message ? error.message : "Rule delete failed.");
          ruleButton.disabled = false;
          ruleButton.textContent = originalText;
        }}
        return;
      }}
      const button = event.target.closest("[data-approval-action]");
      if (!button) return;
      const approvalId = button.dataset.approvalId || "";
      const action = button.dataset.approvalAction || "";
      if (!approvalId || !action) return;
      const originalText = button.textContent;
      button.disabled = true;
      button.textContent = "Working...";
      setRecentBlockStatus("");
      try {{
        await postApprovalAction(approvalId, action);
      }} catch (error) {{
        setRecentBlockStatus(error && error.message ? error.message : "Approval action failed.");
      }} finally {{
        button.disabled = false;
        button.textContent = originalText;
      }}
    }});
  </script>
</body>
</html>"""
