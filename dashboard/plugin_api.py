"""Hermes Guardian dashboard plugin API routes.

Mounted by the Hermes web dashboard at /api/plugins/hermes-guardian/.
This module is intentionally a thin adapter over the existing Guardian
dashboard action functions so the Hermes dashboard tab and slash/CLI flows share
policy mutation behavior.
"""

from __future__ import annotations

import importlib.util
import hmac
import os
import sys
from pathlib import Path
from typing import Any

try:
    from fastapi import APIRouter, HTTPException, Request
    from fastapi.responses import JSONResponse
except ModuleNotFoundError:  # pragma: no cover - exercised by import-only tests without FastAPI.
    class HTTPException(Exception):
        def __init__(self, status_code: int, detail: str):
            super().__init__(detail)
            self.status_code = status_code
            self.detail = detail

    class Request:
        headers: dict[str, str] = {}

    class JSONResponse:
        def __init__(self, content: Any, status_code: int = 200):
            self.content = content
            self.status_code = status_code

    class APIRouter:
        def get(self, *_args: Any, **_kwargs: Any):
            return lambda fn: fn

        def post(self, *_args: Any, **_kwargs: Any):
            return lambda fn: fn

        def patch(self, *_args: Any, **_kwargs: Any):
            return lambda fn: fn

        def delete(self, *_args: Any, **_kwargs: Any):
            return lambda fn: fn


router = APIRouter()


def _guardian() -> Any:
    module_name = "_hermes_guardian_dashboard_facade"
    module = sys.modules.get(module_name)
    if module is not None:
        return module
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(module_name, root / "__init__.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("failed to load Hermes Guardian plugin")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(module_name, None)
        raise
    return module


def _json_result(result: tuple[dict[str, Any], int]) -> JSONResponse:
    payload, status = result
    return JSONResponse(payload, status_code=status)


def _dashboard_mutations_enabled() -> bool:
    raw = os.environ.get("HERMES_GUARDIAN_DASHBOARD_MUTATIONS", "1").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _request_header(request: Request, name: str) -> str:
    headers = getattr(request, "headers", {}) or {}
    try:
        return str(headers.get(name) or headers.get(name.lower()) or "")
    except Exception:
        return ""


def _require_dashboard_admin(request: Request) -> None:
    if not _dashboard_mutations_enabled():
        raise HTTPException(status_code=403, detail="dashboard mutations disabled")
    token = os.environ.get("HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN", "")
    if token and not hmac.compare_digest(_request_header(request, "x-hermes-guardian-token"), token):
        raise HTTPException(status_code=403, detail="invalid guardian admin token")


def _confirmation_value(body: dict[str, Any]) -> str:
    return str(body.get("confirm") or body.get("confirmation") or "").strip().lower()


def _body_bool(body: dict[str, Any], key: str) -> bool:
    if key not in body:
        raise HTTPException(status_code=400, detail=f"{key} is required")
    value = body.get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "off", "disabled"}:
        return False
    raise HTTPException(status_code=400, detail=f"{key} must be a boolean")


def _requires_wildcard_allow_confirmation(body: dict[str, Any]) -> bool:
    if str(body.get("effect") or "").strip().lower() != "allow":
        return False
    match = body.get("match") if isinstance(body.get("match"), dict) else {}
    classes = match.get("data_classes")
    if not isinstance(classes, list):
        classes = [classes]
    return (
        str(match.get("tool_name") or "*").strip() == "*"
        and str(match.get("action_family") or "*").strip() == "*"
        and str(match.get("destination") or "*").strip() == "*"
        and str(match.get("purpose") or "*").strip() == "*"
        and str(match.get("recipient_identity") or "*").strip() == "*"
        and "*" in {str(cls).strip() for cls in classes}
    )


def _require_dashboard_confirmation(action: str, body: dict[str, Any]) -> None:
    if action == "privacy_mode" and str(body.get("mode") or "").strip().lower() == "off":
        if _confirmation_value(body) != "privacy-off":
            raise HTTPException(status_code=400, detail="privacy mode off requires confirmation")
    if action in {"create_rule", "update_rule"} and "move" not in body:
        if _requires_wildcard_allow_confirmation(body) and _confirmation_value(body) != "wildcard-allow":
            raise HTTPException(status_code=400, detail="wildcard allow rule requires confirmation")
    if action == "unknown_tools" and str(body.get("mode") or "").strip().lower() == "allow":
        if _confirmation_value(body) != "unknown-tools-allow":
            raise HTTPException(status_code=400, detail="unknown-tools allow mode requires confirmation")
    if action == "tool_override" and str(body.get("egress") or "").strip().lower() == "ignore":
        if _confirmation_value(body) != "tool-ignore":
            raise HTTPException(status_code=400, detail="ignore tool override requires confirmation")
    if action == "llm_cron_context" and _body_bool(body, "enabled"):
        if _confirmation_value(body) != "cron-context-on":
            raise HTTPException(status_code=400, detail="enabling cron context requires confirmation")


def _json_mutation_result(request: Request, action: str, result: tuple[dict[str, Any], int]) -> JSONResponse:
    payload, status = result
    try:
        _guardian()._emit_activity(
            "allowed" if bool(payload.get("ok")) else "blocked",
            tool_name="dashboard",
            action_family="dashboard_mutation",
            destination=action,
            reason=str(payload.get("message") or ""),
        )
    except Exception:
        pass
    return JSONResponse(payload, status_code=status)


@router.get("/policy")
async def policy() -> dict[str, Any]:
    return _guardian()._policy_snapshot()


@router.get("/activity")
async def activity(limit: int = 200) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 1000))
    return {"activity": _guardian()._grouped_activity_rows({}, limit=safe_limit)}


@router.get("/activity/datatables")
async def activity_datatables(request: Request) -> dict[str, Any]:
    return _guardian()._activity_datatables_payload(dict(request.query_params))


@router.post("/privacy/mode")
async def set_privacy_mode(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("privacy_mode", body)
    return _json_mutation_result(request, "privacy_mode", _guardian()._dashboard_privacy_mode_action(str(body.get("mode") or "")))


@router.patch("/security/rules/{rule_id}")
async def update_security_rule(request: Request, rule_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        request,
        "security_rule",
        _guardian()._dashboard_security_rule_action(rule_id, _body_bool(body, "enabled")),
    )


@router.patch("/language-packs/{pack_id}")
async def update_language_pack(request: Request, pack_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        request,
        "language_pack",
        _guardian()._dashboard_language_pack_action(pack_id, _body_bool(body, "enabled")),
    )


@router.post("/rules")
async def create_rule(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("create_rule", body)
    return _json_mutation_result(request, "create_rule", _guardian()._dashboard_rule_create_action(body))


@router.patch("/rules/{rule_id}")
async def update_rule(request: Request, rule_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("update_rule", body)
    return _json_mutation_result(request, "update_rule", _guardian()._dashboard_rule_update_action(rule_id, body))


@router.delete("/rules/{rule_id}")
async def delete_rule(request: Request, rule_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(request, "delete_rule", _guardian()._dashboard_rule_delete_action(rule_id))


@router.post("/approvals/{approval_id}/approve")
async def approve(request: Request, approval_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(request, "approve", _guardian()._dashboard_approval_action(approval_id, "approve", str(body.get("scope") or "")))


@router.post("/approvals/{approval_id}/dismiss")
async def dismiss(request: Request, approval_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(request, "dismiss", _guardian()._dashboard_approval_action(approval_id, "dismiss", ""))


@router.post("/privacy/unknown-tools")
async def set_unknown_tools(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("unknown_tools", body)
    return _json_mutation_result(
        request,
        "unknown_tools",
        _guardian()._dashboard_unknown_tools_mode_action(str(body.get("mode") or "")),
    )


@router.post("/privacy/user-context")
async def set_user_context(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        request,
        "llm_user_context",
        _guardian()._dashboard_llm_user_context_action(_body_bool(body, "enabled")),
    )


@router.post("/privacy/cron-context")
async def set_cron_context(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("llm_cron_context", body)
    return _json_mutation_result(
        request,
        "llm_cron_context",
        _guardian()._dashboard_llm_cron_context_action(_body_bool(body, "enabled")),
    )


@router.post("/tools")
async def create_tool_override(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("tool_override", body)
    return _json_mutation_result(
        request,
        "tool_override",
        _guardian()._dashboard_tool_override_create_action(body),
    )


@router.patch("/tools/{override_id}")
async def update_tool_override(request: Request, override_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("tool_override", body)
    return _json_mutation_result(
        request,
        "tool_override",
        _guardian()._dashboard_tool_override_update_action(override_id, body),
    )


@router.delete("/tools/{override_id}")
async def delete_tool_override(request: Request, override_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        request,
        "delete_tool_override",
        _guardian()._dashboard_tool_override_delete_action(override_id),
    )
