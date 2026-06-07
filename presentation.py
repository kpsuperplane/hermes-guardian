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

    rules = policy["rules"]
    rule_items = "".join(
        f'<li class="rule-item"><div class="rule-main">'
        f'<span class="rule-source">{esc(rule["source"])}</span>'
        f'<span>{esc(rule["action_family"])} -> {esc(rule["destination"])}</span></div>'
        f'<div class="rule-classes">{rule_classes_html(rule["data_classes"])}</div></li>'
        for rule in rules
    ) or "<li>No allow rules.</li>"
    sessions = policy["sessions"]
    session_items = "".join(
        f"<li><code>{esc(session['session_hash'])}</code> "
        f"{esc(','.join(session['taint']) or 'no taint')} "
        f"{esc(session['browser_host'])}</li>"
        for session in sessions
    ) or "<li>No tracked sessions.</li>"

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hermes Guardian</title>
  <link rel="stylesheet" href="/assets/datatables/{datatables_version}/dataTables.dataTables.min.css">
  <style>
    :root {{ color-scheme: light dark; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
    body {{ margin: 0; background: #f7f7f5; color: #1d1d1b; }}
    header {{ background: #22312d; color: white; padding: 18px 24px; }}
    main {{ padding: 20px 24px 32px; max-width: 1280px; margin: 0 auto; }}
    h1 {{ margin: 0; font-size: 22px; font-weight: 700; }}
    h2 {{ font-size: 16px; margin: 0 0 10px; }}
    .sub {{ margin-top: 4px; color: #d7e5de; font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 14px; margin-bottom: 18px; }}
    section {{ background: white; border: 1px solid #deded9; border-radius: 8px; padding: 14px; }}
    dl {{ display: grid; grid-template-columns: 110px 1fr; gap: 6px 10px; margin: 0; font-size: 13px; }}
    dt {{ color: #5f625d; }}
    dd {{ margin: 0; font-weight: 600; }}
    ul {{ margin: 0; padding-left: 18px; font-size: 13px; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }}
    .rule-item {{ margin: 0 0 8px; min-width: 0; }}
    .rule-main {{ display: flex; flex-wrap: wrap; gap: 4px 8px; align-items: baseline; min-width: 0; overflow-wrap: anywhere; }}
    .rule-classes {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 5px; min-width: 0; }}
    .rule-source {{ display: inline-flex; border-radius: 4px; padding: 1px 5px; background: #e5ebe7; color: #4d5b53; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0; }}
    .rule-chip {{ display: inline-flex; max-width: 100%; border-radius: 4px; padding: 1px 5px; background: #edf1ed; color: #38413b; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; overflow-wrap: anywhere; }}
    .rule-chip.muted {{ color: #6c716b; }}
    .table-wrap {{ background: white; border: 1px solid #deded9; border-radius: 8px; padding: 10px; overflow-x: auto; }}
    #activity-table {{ width: 100%; font-size: 13px; }}
    #activity-table td, #activity-table th {{ vertical-align: top; }}
    #activity-table td.dt-control {{ width: 26px; text-align: center; cursor: pointer; color: #3f6256; font-weight: 800; }}
    #activity-table td.dt-control::before {{ content: "+"; display: inline-flex; align-items: center; justify-content: center; width: 18px; height: 18px; border: 1px solid #9aa19a; border-radius: 50%; }}
    #activity-table tr.dt-hasChild td.dt-control::before {{ content: "-"; }}
    .dt-detail {{ display: grid; grid-template-columns: 120px minmax(0, 1fr); gap: 7px 12px; padding: 10px 12px 12px 38px; font-size: 13px; line-height: 1.35; background: #f8faf8; border-left: 4px solid #9aa19a; }}
    .dt-detail dt {{ color: #5f625d; font-weight: 700; }}
    .dt-detail dd {{ margin: 0; min-width: 0; white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-all; font-weight: 500; }}
    .dt-pill {{ display: inline-flex; align-items: center; border-radius: 4px; padding: 1px 5px; background: #edf1ed; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }}
    .empty {{ background: white; border: 1px solid #deded9; border-radius: 8px; padding: 16px; color: #5f625d; }}
    @media (prefers-color-scheme: dark) {{
      body {{ background: #151715; color: #eeeeea; }}
      header {{ background: #111d1a; }}
      section, .table-wrap, .empty {{ background: #1d211e; border-color: #383d38; }}
      dt {{ color: #a7ada5; }}
      .empty {{ color: #a7ada5; }}
      #activity-table td.dt-control {{ color: #9cc7b8; }}
      .dt-detail {{ background: #191d1a; }}
      .dt-detail dt {{ color: #a7ada5; }}
      .dt-pill {{ background: #2a302c; }}
      .rule-source {{ background: #26312b; color: #b8c8bf; }}
      .rule-chip {{ background: #2a302c; color: #dce5df; }}
      .rule-chip.muted {{ color: #a7ada5; }}
    }}
  </style>
</head>
<body>
  <header>
    <h1>Hermes Guardian</h1>
    <div class="sub">Sanitized permission activity only. Raw tool args and private content are not logged.</div>
  </header>
  <main>
    <div class="grid">
      <section>
        <h2>Policy</h2>
        <dl>
          <dt>Privacy policy</dt><dd>{esc(policy['privacy_policy'])}</dd>
          <dt>Allowlist env</dt><dd>{'set' if policy['allowlist_env_set'] else 'not set'}</dd>
          <dt>Max rows</dt><dd>{esc(policy['activity_max_rows'])}</dd>
          <dt>Retention</dt><dd>{esc(policy['activity_retention_days'])} days</dd>
          <dt>Grouping</dt><dd>{esc(policy['activity_group_seconds'])} seconds</dd>
          <dt>Activity DB</dt><dd><code>{esc(policy['activity_db'])}</code></dd>
        </dl>
      </section>
      <section>
        <h2>Allow Rules</h2>
        <ul>{rule_items}</ul>
      </section>
      <section>
        <h2>Tracked Sessions</h2>
        <ul>{session_items}</ul>
      </section>
    </div>
    <h2>Activity Feed</h2>
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
    activityTable.on("click", "tbody td.dt-control", function (event) {{
      const tr = event.target.closest("tr");
      const row = activityTable.row(tr);
      if (row.child.isShown()) {{
        row.child.hide();
        tr.classList.remove("dt-hasChild");
      }} else {{
        row.child(detailNode(row.data())).show();
        tr.classList.add("dt-hasChild");
      }}
    }});
  </script>
</body>
</html>"""
