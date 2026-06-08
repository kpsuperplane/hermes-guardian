"""Hermes Guardian dashboard plugin API routes.

Mounted by the Hermes web dashboard at /api/plugins/hermes-guardian/.
This module is intentionally a thin adapter over the existing Guardian
dashboard action functions so the Hermes dashboard tab and slash/CLI flows share
policy mutation behavior.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse


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
    spec.loader.exec_module(module)
    return module


def _json_result(result: tuple[dict[str, Any], int]) -> JSONResponse:
    payload, status = result
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
async def set_privacy_mode(body: dict[str, Any]) -> JSONResponse:
    return _json_result(_guardian()._dashboard_privacy_mode_action(str(body.get("mode") or "")))


@router.post("/rules")
async def create_rule(body: dict[str, Any]) -> JSONResponse:
    return _json_result(_guardian()._dashboard_rule_create_action(body))


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: str, body: dict[str, Any]) -> JSONResponse:
    return _json_result(_guardian()._dashboard_rule_update_action(rule_id, body))


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str) -> JSONResponse:
    return _json_result(_guardian()._dashboard_rule_delete_action(rule_id))


@router.post("/approvals/{approval_id}/approve")
async def approve(approval_id: str, body: dict[str, Any]) -> JSONResponse:
    return _json_result(_guardian()._dashboard_approval_action(approval_id, "approve", str(body.get("scope") or "")))


@router.post("/approvals/{approval_id}/dismiss")
async def dismiss(approval_id: str) -> JSONResponse:
    return _json_result(_guardian()._dashboard_approval_action(approval_id, "dismiss", ""))
