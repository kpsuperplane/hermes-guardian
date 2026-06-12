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
    # When no admin token is configured, the host dashboard's own authentication is the
    # gate: it mounts these routes behind authenticated local/admin access (see README
    # "Recommended Hermes Baseline"). Set HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN to also
    # require a token here when the plugin port is reachable outside that host-auth
    # boundary. The unauthenticated read routes never expose live approval IDs (see
    # `_redact_approval_ids`), so a pending egress cannot be read and self-approved over
    # an unauthenticated channel even in the no-token configuration.


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
    if action == "source_classify" and str(body.get("source") or "").strip().lower() == "reference":
        # Declaring a source as reference relaxes scanning of its reads, so confirm that
        # weakening direction (private only tightens and needs no token).
        if _confirmation_value(body) != "source-reference":
            raise HTTPException(status_code=400, detail="declaring a source as reference requires confirmation")
    if action == "llm_cron_context" and _body_bool(body, "enabled"):
        if _confirmation_value(body) != "cron-context-on":
            raise HTTPException(status_code=400, detail="enabling cron context requires confirmation")
    if action == "persist_prompts" and _body_bool(body, "enabled"):
        if _confirmation_value(body) != "persist-prompts-on":
            raise HTTPException(status_code=400, detail="enabling prompt persistence requires confirmation")
    # Destination-trust edits are security-relevant (they move what resolves to self /
    # trusted), so require an explicit confirmation token like the cron-context toggle
    # (doc 03 §3.1). Applies to self/trusted/sharing adds and removes.
    if action == "destination_trust" and _confirmation_value(body) != "destination-trust":
        raise HTTPException(status_code=400, detail="destination-trust edit requires confirmation")


def _json_mutation_result(result: tuple[dict[str, Any], int]) -> JSONResponse:
    payload, status = result
    return JSONResponse(payload, status_code=status)


# The live 4-digit approval code IS the approve credential: anyone who learns a
# pending approval's `id` can POST /approvals/{id}/approve. These read routes are
# unauthenticated, so they must not echo that code. We blank the id-bearing fields
# on the pending / recent-block rows while keeping the rest of the metadata the UI
# needs to render (action, destination, classes, expiry, trust pill, permit options).
# The dashboard UI drives approve through the admin-gated mutation route; it does
# not need the raw code echoed on this open channel.
_REDACTED_APPROVAL_ID_FIELDS = (
    "id",
    "approval_id",
    "dismiss_id",
    "historical_approval_id",
)


def _redact_approval_ids(rows: Any) -> list[dict[str, Any]]:
    redacted: list[dict[str, Any]] = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        clean = dict(row)
        for field in _REDACTED_APPROVAL_ID_FIELDS:
            if field in clean:
                clean[field] = ""
        redacted.append(clean)
    return redacted


def _redacted_policy_snapshot() -> dict[str, Any]:
    snapshot = dict(_guardian()._policy_snapshot())
    if "pending" in snapshot:
        snapshot["pending"] = _redact_approval_ids(snapshot.get("pending"))
    if "recent_blocks" in snapshot:
        snapshot["recent_blocks"] = _redact_approval_ids(snapshot.get("recent_blocks"))
    return snapshot


@router.get("/policy")
async def policy() -> dict[str, Any]:
    return _redacted_policy_snapshot()


@router.get("/performance")
async def performance() -> dict[str, Any]:
    return _guardian()._performance_summary()


@router.get("/destinations")
async def destinations() -> dict[str, Any]:
    """Read endpoint for the Destinations & Trust panel (doc 03 §3.1)."""
    return _guardian()._destination_trust_summary()


@router.get("/activity")
async def activity(limit: int = 200) -> dict[str, Any]:
    safe_limit = max(1, min(int(limit), 1000))
    return {"activity": _guardian()._grouped_activity_rows({}, limit=safe_limit)}


@router.get("/approvals")
async def approvals() -> dict[str, Any]:
    """Pending-approvals read list for the Activity tab (doc 02 §Tab1).

    Reads the already-computed "pending" slice of the policy snapshot — no new
    decision logic, no mutation.

    This route is unauthenticated, so the live 4-digit approval `id` (which is
    the approve credential) is redacted from the rows — see _redact_approval_ids.
    """
    return {"approvals": _redact_approval_ids(_guardian()._dashboard_pending_approvals())}


@router.get("/destinations/resolve")
async def resolve_destination(value: str = "") -> dict[str, Any]:
    """"Check a destination" widget (What's Yours, doc 02 §Tab2). Read-only.

    Calls the engine's pure resolve_destination_trust with a hypothetical
    destination/recipient; computes only, changes nothing (no guard needed).
    """
    return _guardian()._dashboard_resolve_destination(str(value or ""))


@router.get("/sharing/preview")
async def sharing_preview(action: str = "", destination: str = "", classes: str = "") -> dict[str, Any]:
    """"Preview a send" widget (Sharing, doc 02 §Tab3). Read-only.

    Runs the pure decide_with_step on a hypothetical capability; no mutation.
    """
    class_list = [tok for tok in str(classes or "").split(",") if tok.strip()]
    return _guardian()._dashboard_preview_send(str(action or ""), str(destination or ""), class_list)


@router.post("/sharing/impact")
async def sharing_impact(body: dict[str, Any]) -> dict[str, Any]:
    """"Impact preview" (Sharing, doc 02 §Tab3). Read-only over-permissiveness guard.

    Replays recent stored activity against a candidate rule and reports the rows
    whose outcome it would change. Computes only — no mutation, so no admin guard.
    """
    candidate = body if isinstance(body, dict) else {}
    return _guardian()._dashboard_sharing_impact(candidate)


@router.get("/activity/datatables")
async def activity_datatables(request: Request) -> dict[str, Any]:
    return _guardian()._activity_datatables_payload(dict(request.query_params))


@router.get("/activity/turns")
async def activity_turns(request: Request) -> dict[str, Any]:
    return _guardian()._activity_turns_payload(dict(request.query_params))


@router.post("/privacy/mode")
async def set_privacy_mode(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("privacy_mode", body)
    return _json_mutation_result(_guardian()._dashboard_privacy_mode_action(str(body.get("mode") or "")))


@router.patch("/security/rules/{rule_id}")
async def update_security_rule(request: Request, rule_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        _guardian()._dashboard_security_rule_action(rule_id, _body_bool(body, "enabled")),
    )


@router.patch("/language-packs/{pack_id}")
async def update_language_pack(request: Request, pack_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        _guardian()._dashboard_language_pack_action(pack_id, _body_bool(body, "enabled")),
    )


@router.post("/rules")
async def create_rule(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("create_rule", body)
    return _json_mutation_result(_guardian()._dashboard_rule_create_action(body))


@router.patch("/rules/{rule_id}")
async def update_rule(request: Request, rule_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("update_rule", body)
    return _json_mutation_result(_guardian()._dashboard_rule_update_action(rule_id, body))


@router.delete("/rules/{rule_id}")
async def delete_rule(request: Request, rule_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(_guardian()._dashboard_rule_delete_action(rule_id))


@router.post("/approvals/{approval_id}/approve")
async def approve(request: Request, approval_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    # `method` is the permit method (rule_5m, rule_forever, self_host, trusted_identity, …).
    # Structural methods widen the trust boundary,
    # so they need the same destination-trust confirmation the /destinations/* edits do.
    method = str(body.get("method") or body.get("scope") or "")
    if _guardian()._dashboard_permit_method_is_structural(method):
        _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_approval_action(approval_id, "approve", method))


@router.post("/approvals/{approval_id}/dismiss")
async def dismiss(request: Request, approval_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(_guardian()._dashboard_approval_action(approval_id, "dismiss", ""))


@router.post("/privacy/clear-taint")
async def clear_taint(request: Request) -> JSONResponse:
    """Clear session taint for the dashboard owner (doc 02 §Tab1).

    Guarded like every other mutator (admin token); routes through the same
    _guardian_clear_taint handler the /guardian clear-taint slash command uses.
    """
    _require_dashboard_admin(request)
    return _json_mutation_result(_guardian()._dashboard_clear_taint_action())


@router.post("/privacy/unknown-tools")
async def set_unknown_tools(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("unknown_tools", body)
    return _json_mutation_result(
        _guardian()._dashboard_unknown_tools_mode_action(str(body.get("mode") or "")),
    )


@router.post("/privacy/user-context")
async def set_user_context(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        _guardian()._dashboard_llm_user_context_action(_body_bool(body, "enabled")),
    )


@router.post("/privacy/cron-context")
async def set_cron_context(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("llm_cron_context", body)
    return _json_mutation_result(
        _guardian()._dashboard_llm_cron_context_action(_body_bool(body, "enabled")),
    )


@router.post("/privacy/verifier-model")
async def set_verifier_model(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        _guardian()._dashboard_llm_verifier_model_action(str(body.get("model") or "")),
    )


@router.post("/protection/persist-prompts")
async def set_persist_prompts(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("persist_prompts", body)
    return _json_mutation_result(
        _guardian()._dashboard_persist_prompts_action(_body_bool(body, "enabled")),
    )


@router.post("/tools")
async def create_tool_override(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("tool_override", body)
    return _json_mutation_result(
        _guardian()._dashboard_tool_override_create_action(body),
    )


@router.patch("/tools/{override_id}")
async def update_tool_override(request: Request, override_id: str, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("tool_override", body)
    return _json_mutation_result(
        _guardian()._dashboard_tool_override_update_action(override_id, body),
    )


@router.delete("/tools/{override_id}")
async def delete_tool_override(request: Request, override_id: str) -> JSONResponse:
    _require_dashboard_admin(request)
    return _json_mutation_result(
        _guardian()._dashboard_tool_override_delete_action(override_id),
    )


@router.get("/tools/source-suggestions")
async def source_classification_suggestions() -> dict[str, Any]:
    return _guardian()._dashboard_source_suggestions()


@router.post("/tools/source")
async def classify_source(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("source_classify", body)
    return _json_mutation_result(_guardian()._dashboard_source_classify_action(body))


# --- Destinations & Trust panel (doc 03 §3.1) --------------------------------
# All destination-trust mutations are admin-token + confirmation guarded
# (_require_dashboard_confirmation("destination_trust", ...)).
@router.post("/destinations/self")
async def add_self_destination(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_self_add_action(body))


@router.post("/destinations/self/remove")
async def remove_self_destination(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_self_remove_action(body))


@router.post("/destinations/trusted")
async def add_trusted_recipient(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_trusted_add_action(body))


@router.post("/destinations/trusted/remove")
async def remove_trusted_recipient(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_trusted_remove_action(body))


@router.get("/destinations/suggestions")
async def trusted_command_suggestions() -> dict[str, Any]:
    return _guardian()._dashboard_trusted_suggestions()


@router.post("/destinations/sharing")
async def add_sharing_subtype(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_sharing_add_action(body))


@router.post("/destinations/sharing/remove")
async def remove_sharing_subtype(request: Request, body: dict[str, Any]) -> JSONResponse:
    _require_dashboard_admin(request)
    _require_dashboard_confirmation("destination_trust", body)
    return _json_mutation_result(_guardian()._dashboard_sharing_remove_action(body))
