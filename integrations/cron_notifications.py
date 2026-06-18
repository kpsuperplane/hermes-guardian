"""Cron failure notifications via the standalone Hermes send CLI."""

from __future__ import annotations

import asyncio
import json
import re
import subprocess
import threading
from pathlib import Path
from typing import Any

from .. import core
from .. import state
from ..privacy import tool_policy


_CRON_SESSION_RE = re.compile(r"^cron_([0-9a-f]{12})_\d{8}_\d{6}$", re.I)
_TELEGRAM_RICH_TEXT_LIMIT = 32768


class _TelegramRichSendUncertain(Exception):
    """Raised when a rich Telegram send may have reached Telegram."""


def _cron_job_id_from_session(session_id: str | None) -> str:
    match = _CRON_SESSION_RE.match(tool_policy._normalize_session_id(session_id))
    return match.group(1) if match else ""


def _hermes_cli_path() -> str:
    return state._env(core._HERMES_CLI_ENV, "/root/.local/bin/hermes").strip() or "hermes"


def _cron_job_record(job_id: str) -> dict[str, Any]:
    if not job_id:
        return {}
    try:
        jobs_path = Path.home() / ".hermes" / "cron" / "jobs.json"
        data = json.loads(jobs_path.read_text(encoding="utf-8"))
        for job in data.get("jobs", []):
            if isinstance(job, dict) and str(job.get("id") or "") == job_id:
                return job
    except Exception:
        return {}
    return {}


def _cron_job_name(job_id: str) -> str:
    job = _cron_job_record(job_id)
    name = job.get("name") or job.get("prompt") or ""
    if not name and job_id:
        try:
            output_dir = Path.home() / ".hermes" / "cron" / "output" / job_id
            for output_path in sorted(output_dir.glob("*.md"), reverse=True):
                first_line = output_path.read_text(encoding="utf-8", errors="replace").splitlines()[0]
                match = re.match(r"#\s+Cron Job:\s+(.+?)\s*$", first_line)
                if match:
                    name = match.group(1)
                    break
        except Exception:
            name = ""
    return core._presentation.clip_text(
        name,
        100,
        ellipsis="...",
        fallback="",
    )


def _safe_notify_targets(raw_targets: Any) -> list[str]:
    if isinstance(raw_targets, str):
        candidates = [raw_targets]
    elif isinstance(raw_targets, list):
        candidates = [str(target) for target in raw_targets]
    else:
        candidates = []

    targets: list[str] = []
    for target in candidates:
        value = target.strip()
        if not value or value.lower() in {"local", "log", "none", "off"}:
            continue
        if re.fullmatch(r"[A-Za-z0-9_.:@#/+~-]{1,200}", value):
            targets.append(value)
    return targets


def _cron_notify_targets(job_id: str) -> list[str]:
    raw = state._env(core._CRON_NOTIFY_TO_ENV, core._DEFAULT_CRON_NOTIFY_TO).strip()
    if raw.lower() in {"", "0", "false", "no", "off", "none"}:
        return []
    if raw.lower() in {"origin", "deliver", "delivery", "job"}:
        job = _cron_job_record(job_id)
        return _safe_notify_targets(job.get("deliver") if job else None)
    return _safe_notify_targets([target for target in re.split(r"[;\n]+", raw) if target.strip()])


def _cron_notification_message(
    *,
    session_id: str | None,
    tool_name: str,
    decision: str,
    action_family: str = "",
    destination: str = "",
    data_classes: set[str] | list[str] | tuple[str, ...] | None = None,
    reason: str = "",
    approval_id: str = "",
    action_detail: str = "",
    destination_trust: str = "",
    decision_step: str = "",
) -> str:
    job_id = _cron_job_id_from_session(session_id)
    job_name = _cron_job_name(job_id)
    classes = sorted(str(cls) for cls in (data_classes or []) if str(cls) in core._ALL_PRIVACY_CLASSES)
    action = str(action_family or tool_name or "unknown").strip()

    lines = [
        "Hermes Guardian blocked a cron job action.",
        "",
    ]
    if job_name:
        lines.append(f"Job: {job_name}")
    if job_id:
        lines.append(f"Job ID: {job_id}")
    lines.append(f"Action: {action}")
    if destination:
        lines.append(
            "Destination: "
            + core._presentation.clip_text(destination, 120, ellipsis="...", fallback="")
        )
    trust_label = str(destination_trust or "").strip()
    if trust_label:
        lines.append(f"Destination trust: {trust_label}")
    step_label = str(decision_step or "").strip()
    if step_label:
        lines.append(f"Decision step: {step_label}")
    if classes:
        lines.append(f"Data classes: {', '.join(classes)}")
    detail = core._presentation.clip_text(action_detail, 500, ellipsis="...", fallback="")
    if detail:
        lines.append(f"Action detail: {detail}")
    if reason:
        lines.append(
            "Reason: "
            + core._presentation.clip_text(reason, 180, ellipsis="...", fallback="")
        )
    if approval_id:
        lines.extend([
            "",
            f"/guardian approve {approval_id} forever",
        ])
    else:
        lines.append("Approval: no approval ID was generated for this block.")
    return "\n".join(lines)


def _cron_md_inline(value: Any, *, fallback: str = "") -> str:
    text = str(value or "").strip() or fallback
    return text.replace("\n", " ").replace("|", "\\|").replace("`", "'")


def _cron_md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(_cron_md_inline(header) for header in headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(_cron_md_inline(cell, fallback="n/a") for cell in row) + " |")
    return "\n".join(lines)


def _cron_md_details(summary: str, body_lines: list[str]) -> str:
    body = "\n".join(line for line in body_lines if str(line).strip())
    if not body:
        return ""
    return f"<details>\n<summary>{_cron_md_inline(summary)}</summary>\n\n{body}\n</details>"


def _cron_notification_rich_message(message: str) -> str:
    values: dict[str, str] = {}
    approval_command = ""
    for line in str(message or "").splitlines():
        if line.startswith("/guardian approve "):
            approval_command = re.sub(r"\s+", " ", line.strip())
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        values[key.strip().lower()] = value.strip()
    rows = [
        ["Job", values.get("job") or "n/a"],
        ["Job ID", values.get("job id") or "n/a"],
        ["Action", values.get("action") or "unknown"],
        ["Destination", values.get("destination") or "n/a"],
        ["Destination trust", values.get("destination trust") or "unknown"],
        ["Data classes", values.get("data classes") or "none"],
    ]
    details = []
    if values.get("decision step"):
        details.append(f"- Decision step: `{_cron_md_inline(values['decision step'])}`")
    if values.get("action detail"):
        details.append(f"- Action detail: `{_cron_md_inline(values['action detail'])}`")
    if values.get("reason"):
        details.append(f"- Reason: {_cron_md_inline(values['reason'])}")
    if approval_command:
        details.append(f"- Approval command: `{_cron_md_inline(approval_command)}`")
    rich = "\n\n".join([
        "## Hermes Guardian Cron Block",
        _cron_md_table(["Field", "Value"], rows),
        _cron_md_details("Review details", details),
    ]).strip()
    if len(rich.encode("utf-8")) > _TELEGRAM_RICH_TEXT_LIMIT:
        return ""
    return rich


def _cron_notification_approval_command(message: str) -> str:
    match = re.search(
        r"(?m)^(/guardian\s+approve\s+[0-9]{4}\s+forever)\s*$",
        str(message or ""),
    )
    return re.sub(r"\s+", " ", match.group(1).strip()) if match else ""


def _telegram_target_parts(target: str) -> tuple[str, str] | None:
    parts = str(target or "").strip().split(":")
    if not parts or parts[0].lower() != "telegram":
        return None
    chat_id = parts[1].strip() if len(parts) > 1 else ""
    thread_id = parts[2].strip() if len(parts) > 2 else ""
    if not chat_id:
        chat_id = state._env("TELEGRAM_HOME_CHANNEL", "").strip()
    if not thread_id:
        thread_id = (
            state._env("TELEGRAM_CRON_THREAD_ID", "").strip()
            or state._env("TELEGRAM_HOME_CHANNEL_THREAD_ID", "").strip()
        )
    if not chat_id:
        return None
    return chat_id, thread_id


def _telegram_chat_id(value: str) -> int | str:
    text = str(value or "").strip()
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    return text


def _telegram_thread_kwargs(thread_id: str) -> dict[str, int]:
    if not str(thread_id or "").strip():
        return {}
    try:
        from gateway.platforms.telegram import TelegramAdapter

        effective = TelegramAdapter._message_thread_id_for_send(str(thread_id))
    except Exception:
        effective = None if str(thread_id) == "1" else int(thread_id)
    return {"message_thread_id": int(effective)} if effective is not None else {}


def _telegram_copy_reply_markup(approval_command: str) -> Any:
    from telegram import CopyTextButton, InlineKeyboardButton, InlineKeyboardMarkup

    return InlineKeyboardMarkup([
        [
            InlineKeyboardButton("Copy approval", copy_text=CopyTextButton(approval_command)),
        ],
    ])


def _telegram_rich_failure_allows_legacy_fallback(exc: Exception) -> bool:
    text = f"{exc.__class__.__name__}: {exc}".lower()
    fallback_markers = (
        "attributeerror",
        "typeerror",
        "not found",
        "unknown method",
        "unsupported",
        "can't parse",
        "cannot parse",
        "can't find end",
        "entity",
        "rich text",
        "too many",
        "too long",
        "bad request",
    )
    uncertain_markers = (
        "timeout",
        "timed out",
        "connection",
        "network",
        "server error",
        "internal server",
        "bad gateway",
        "gateway timeout",
        "temporarily unavailable",
        "retry after",
    )
    if any(marker in text for marker in uncertain_markers):
        return False
    return any(marker in text for marker in fallback_markers)


async def _try_send_telegram_rich_message(
    bot: Any,
    *,
    chat_id: str,
    thread_id: str,
    rich_message: str,
    approval_command: str,
) -> bool:
    if not rich_message:
        return False
    method = getattr(bot, "send_rich_message", None)
    if method is None:
        return False
    base_kwargs = {
        "chat_id": _telegram_chat_id(chat_id),
        "reply_markup": _telegram_copy_reply_markup(approval_command),
        **_telegram_thread_kwargs(thread_id),
    }
    errors: list[Exception] = []
    for text_key in ("text", "message"):
        try:
            await method(**base_kwargs, **{text_key: rich_message})
            return True
        except TypeError as exc:
            errors.append(exc)
            continue
        except Exception as exc:
            if _telegram_rich_failure_allows_legacy_fallback(exc):
                return False
            raise _TelegramRichSendUncertain(str(exc)) from exc
    if errors:
        return False
    return False


async def _send_telegram_cron_notification_async(
    *,
    token: str,
    chat_id: str,
    thread_id: str,
    message: str,
    approval_command: str,
) -> None:
    from telegram import Bot

    bot_kwargs: dict[str, Any] = {}
    try:
        from gateway.platforms.base import resolve_proxy_url

        proxy_url = resolve_proxy_url("TELEGRAM_PROXY", target_hosts=["api.telegram.org"])
    except Exception:
        proxy_url = None
    if proxy_url:
        try:
            from telegram.request import HTTPXRequest

            bot_kwargs = {
                "request": HTTPXRequest(proxy=proxy_url),
                "get_updates_request": HTTPXRequest(proxy=proxy_url),
            }
        except Exception:
            bot_kwargs = {}

    bot = Bot(token=token, **bot_kwargs)
    rich_message = _cron_notification_rich_message(message)
    if await _try_send_telegram_rich_message(
        bot,
        chat_id=chat_id,
        thread_id=thread_id,
        rich_message=rich_message,
        approval_command=approval_command,
    ):
        return
    await bot.send_message(
        chat_id=_telegram_chat_id(chat_id),
        text=message,
        parse_mode=None,
        reply_markup=_telegram_copy_reply_markup(approval_command),
        disable_web_page_preview=True,
        **_telegram_thread_kwargs(thread_id),
    )


def _send_telegram_cron_notification_message(message: str, target: str, approval_command: str) -> bool:
    token = state._env("TELEGRAM_BOT_TOKEN", "").strip()
    parts = _telegram_target_parts(target)
    if not token or not parts or not approval_command:
        return False
    chat_id, thread_id = parts
    try:
        asyncio.run(
            _send_telegram_cron_notification_async(
                token=token,
                chat_id=chat_id,
                thread_id=thread_id,
                message=message,
                approval_command=approval_command,
            )
        )
        return True
    except _TelegramRichSendUncertain as exc:
        core.logger.debug(
            "%s: telegram rich cron notification outcome uncertain for %s; suppressing fallback: %s",
            core._PLUGIN_NAME,
            target,
            exc,
        )
        return True
    except Exception as exc:
        core.logger.debug(
            "%s: telegram copy-button cron notification failed for %s: %s",
            core._PLUGIN_NAME,
            target,
            exc,
        )
        return False


def _send_cron_notification_message(message: str, target: str) -> None:
    approval_command = _cron_notification_approval_command(message)
    if str(target or "").lower().startswith("telegram"):
        if _send_telegram_cron_notification_message(message, target, approval_command):
            return

    command = [_hermes_cli_path(), "send", "--to", target, "--quiet", "--file", "-"]
    subprocess.run(
        command,
        input=message,
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
        check=False,
    )


def _notify_cron_failure_if_needed(
    *,
    session_id: str | None,
    tool_name: str,
    decision: str,
    action_family: str = "",
    destination: str = "",
    data_classes: set[str] | list[str] | tuple[str, ...] | None = None,
    reason: str = "",
    approval_id: str = "",
    action_detail: str = "",
    destination_trust: str = "",
    decision_step: str = "",
) -> None:
    job_id = _cron_job_id_from_session(session_id)
    if not job_id:
        return
    # Doc 03 §4: a cron egress resolving to a `self` destination is intra-boundary —
    # it never gated, so there is nothing to notify/gate. (In practice a self flow is
    # ALLOWed and this path is not reached at all, but guard here too so any caller that
    # passes a self trust never produces routine cron FP noise.)
    if str(destination_trust or "").strip().lower() == "self":
        return
    targets = _cron_notify_targets(job_id)
    if not targets:
        return

    sid = tool_policy._normalize_session_id(session_id)
    with state._LOCK:
        if sid in state._CRON_NOTIFICATIONS_SENT:
            return
        state._CRON_NOTIFICATIONS_SENT.add(sid)

    message = _cron_notification_message(
        session_id=session_id,
        tool_name=tool_name,
        decision=decision,
        action_family=action_family,
        destination=destination,
        data_classes=data_classes,
        reason=reason,
        approval_id=approval_id,
        action_detail=action_detail,
        destination_trust=destination_trust,
        decision_step=decision_step,
    )

    def _worker() -> None:
        for target in targets:
            try:
                _send_cron_notification_message(message, target)
            except Exception as exc:
                core.logger.debug(
                    "%s: failed to send cron failure notification to %s: %s",
                    core._PLUGIN_NAME,
                    target,
                    exc,
                )

    threading.Thread(
        target=_worker,
        name="hermes-guardian-cron-notify",
        daemon=True,
    ).start()
