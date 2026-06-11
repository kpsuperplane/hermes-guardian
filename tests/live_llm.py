"""Live backend-agnostic double for Guardian's LLM security verifier.

At runtime the verifier (``privacy/llm.py::_llm_security_verdict``) calls
``_PLUGIN_LLM.complete_structured(**kwargs)`` on the facade the Hermes host
injects via ``ctx.llm``. The unit suite replaces that with ``FakeSecurityLlm``
(canned verdicts). This adapter implements the SAME surface but routes the call
to a real model, so the live tests exercise the verifier's actual judgment end to
end.

Two backends are supported, selected from the environment:

- **Google AI Studio** (``GEMINI_API_KEY`` / ``GOOGLE_API_KEY``) — uses the *native*
  ``generateContent`` API with ``responseSchema`` structured output. (The native
  API is what enforces the schema for Gemma; Google's OpenAI-compat layer mangles
  ``json_schema`` for Gemma.) Free tier includes Gemma and Gemini Flash.
- **OpenRouter** (``OPENROUTER_API_KEY``) — uses the OpenAI-compatible
  ``/chat/completions`` API with ``response_format`` json_schema, plus
  ``provider.require_parameters`` so routing only lands on a provider that enforces
  the schema.

Either way ``GUARDIAN_LLM_TEST_MODEL`` names the model. The live suite is opt-in
(``--run-llm`` / ``GUARDIAN_RUN_LLM``); once opted in, a missing backend key FAILS
the run (see ``live_llm_or_fail``) rather than skipping, so an unconfigured
environment can't masquerade as a pass. Standard-library only (``urllib``), matching
the plugin's no-runtime-dependency policy; imported solely by
``test_llm_verifier_live.py``.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

# Status codes meaning "this request's structured-output schema cannot be honored"
# rather than a transient error. 404 only counts on OpenRouter (require_parameters:
# no provider can satisfy the schema); on a direct backend 404 is model-not-found,
# so it is added per backend below.
_SCHEMA_REJECTED_BASE = {400, 415, 422, 501}
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.IGNORECASE | re.DOTALL)
# Schema keywords Google's responseSchema (an OpenAPI 3.0 subset) does not accept;
# stripped before sending so the verifier's strict json-schema still drives output.
_GEMINI_UNSUPPORTED_SCHEMA_KEYS = frozenset({
    "additionalProperties", "maxLength", "minLength", "pattern",
    "$schema", "title", "default", "const", "examples",
})
# Read-timeout floor for live calls, in seconds. Larger than the verifier's
# production 20s because free-tier models can be slow; override via env.
_DEFAULT_TEST_TIMEOUT = 60.0


def _test_timeout() -> float:
    try:
        return float(os.environ.get("GUARDIAN_LLM_TEST_TIMEOUT", _DEFAULT_TEST_TIMEOUT))
    except (TypeError, ValueError):
        return _DEFAULT_TEST_TIMEOUT


# Minimum spacing between live API calls, in seconds. Not a retry — just paces the
# suite so back-to-back calls don't trip free-tier burst rejection. Override via env.
_DEFAULT_REQUEST_SPACING = 3.0
_last_request_monotonic: float | None = None


def _request_spacing() -> float:
    try:
        return max(0.0, float(os.environ.get("GUARDIAN_LLM_TEST_SPACING", _DEFAULT_REQUEST_SPACING)))
    except (TypeError, ValueError):
        return _DEFAULT_REQUEST_SPACING


def _space_requests() -> None:
    """Sleep so consecutive live calls start at least the spacing interval apart."""
    global _last_request_monotonic
    spacing = _request_spacing()
    if _last_request_monotonic is not None and spacing > 0:
        wait = spacing - (time.monotonic() - _last_request_monotonic)
        if wait > 0:
            time.sleep(wait)
    _last_request_monotonic = time.monotonic()

class StructuredOutputUnsupported(RuntimeError):
    """Raised when the backend cannot enforce the structured-output schema.

    The Guardian verifier requires schema-conformant verdicts (exact field names and
    enum values); a model/provider that drops the schema produces output the verifier
    must reject and fail closed on. Surfacing this distinctly lets the live tests fail
    with an actionable reason instead of an opaque fail-closed.
    """


@dataclass(frozen=True)
class _Backend:
    label: str
    mode: str  # "gemini" (native generateContent) or "openai" (chat/completions)
    base_url: str
    api_key: str
    require_parameters: bool
    suggestion: str


def _first_json_object(text: str) -> str | None:
    """Return the first balanced ``{...}`` substring, ignoring braces in strings."""
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _extract_verdict(content: Any) -> dict[str, Any] | None:
    """Best-effort decode of a verdict object from model content.

    Tolerates models that wrap the JSON in ``<think>`` blocks, markdown code fences,
    or surrounding prose, so a capable-but-chatty model is not treated as a
    fail-closed verifier. Returns ``None`` only when no JSON object is found.
    """
    if not isinstance(content, str):
        return content if isinstance(content, dict) else None
    text = _THINK_BLOCK_RE.sub("", content).strip()
    candidates: list[str] = []
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence:
        candidates.append(fence.group(1))
    candidates.append(text)
    embedded = _first_json_object(text)
    if embedded:
        candidates.append(embedded)
    for candidate in candidates:
        try:
            value = json.loads(candidate)
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict):
            return value
    return None


def _gemini_thinking_budget(model: str) -> int | None:
    """Thinking budget to send for a Gemini model, or None to omit thinkingConfig.

    Gemini 2.5+ models reason by default and would exhaust the verifier's small output
    budget on thinking tokens before emitting the verdict, so disable thinking
    (budget 0). Older Gemini and Gemma models reject thinkingConfig outright, so the
    field must be omitted for them.
    """
    name = model.lower()
    if "gemini-2.5" in name or "gemini-3" in name:
        return 0
    return None


def _to_gemini_schema(schema: Any) -> Any:
    """Strip keywords Google's responseSchema rejects (e.g. additionalProperties)."""
    if isinstance(schema, dict):
        out: dict[str, Any] = {}
        for key, value in schema.items():
            if key in _GEMINI_UNSUPPORTED_SCHEMA_KEYS:
                continue
            if key == "properties" and isinstance(value, dict):
                out[key] = {k: _to_gemini_schema(v) for k, v in value.items()}
            else:
                out[key] = _to_gemini_schema(value)
        return out
    if isinstance(schema, list):
        return [_to_gemini_schema(item) for item in schema]
    return schema


class LiveSecurityLlm:
    """Real-model verifier facade exposing ``complete_structured(**kwargs)``.

    The kwargs mirror what ``_llm_security_verdict`` passes: ``instructions``
    (system prompt), ``input`` (``[{"type": "text", "text": ...}]``),
    ``json_schema``, ``schema_name``, ``temperature``, ``max_tokens``,
    ``timeout``, and an optional ``model`` override. The return value mirrors the
    host facade: an object with ``.parsed`` (the decoded verdict dict, or ``None``)
    and ``.text`` (the raw model content), which the verifier then validates.
    """

    def __init__(self, *, model: str, backend: _Backend) -> None:
        self.model = model
        self.backend = backend
        self.calls: list[dict[str, Any]] = []
        # Most recent raw content and decoded verdict, so live tests can assert the
        # model genuinely judged rather than the verifier failing closed.
        self.last_text: str = ""
        self.last_parsed: dict[str, Any] | None = None
        self._schema_rejected = set(_SCHEMA_REJECTED_BASE)
        if backend.require_parameters:
            self._schema_rejected.add(404)

    def complete_structured(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        instructions = str(kwargs.get("instructions") or "")
        input_items = kwargs.get("input") or []
        user_text = ""
        if input_items and isinstance(input_items[0], dict):
            user_text = str(input_items[0].get("text") or "")
        schema = kwargs.get("json_schema") or {}
        schema_name = str(kwargs.get("schema_name") or "verdict")
        model = str(kwargs.get("model") or self.model)
        temperature = kwargs.get("temperature", 0)
        max_tokens = int(kwargs.get("max_tokens") or 240)
        # The verifier passes its production read timeout (20s); free-tier models can
        # exceed it, so use a longer floor for the live tests (override via
        # GUARDIAN_LLM_TEST_TIMEOUT). We take the max so a larger verifier value, if it
        # ever appears, is still honored.
        timeout = max(float(kwargs.get("timeout") or 0), _test_timeout())

        if self.backend.mode == "gemini":
            content = self._gemini(instructions, user_text, schema, model, temperature, max_tokens, timeout)
        else:
            content = self._openai(instructions, user_text, schema, schema_name, model, temperature, max_tokens, timeout)

        text = content if isinstance(content, str) else (json.dumps(content) if content is not None else "")
        parsed = _extract_verdict(content)
        self.last_text = text
        self.last_parsed = parsed
        return SimpleNamespace(parsed=parsed, text=text)

    def _openai(self, instructions, user_text, schema, schema_name, model, temperature, max_tokens, timeout) -> Any:
        body: dict[str, Any] = {
            "model": model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": instructions},
                {"role": "user", "content": user_text},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            },
        }
        if self.backend.require_parameters:
            # Force routing to a provider that genuinely enforces the schema, so an
            # incompatible model returns a clean 404 we turn into an actionable failure
            # rather than silently non-conforming JSON.
            body["provider"] = {"require_parameters": True}
        payload = self._send(
            f"{self.backend.base_url}/chat/completions",
            {"Authorization": f"Bearer {self.backend.api_key}", "Content-Type": "application/json"},
            body,
            timeout,
            model,
        )
        return (payload["choices"][0]["message"] or {}).get("content")

    def _gemini(self, instructions, user_text, schema, model, temperature, max_tokens, timeout) -> Any:
        generation_config: dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
            "responseMimeType": "application/json",
            "responseSchema": _to_gemini_schema(schema),
        }
        budget = _gemini_thinking_budget(model)
        if budget is not None:
            # Thinking-capable Gemini models (2.5+) reason by default and burn the
            # verifier's small output budget before emitting any JSON. Disable thinking
            # so they return the structured verdict directly. Older Gemini and Gemma
            # models reject thinkingConfig (HTTP 400), so this is applied selectively.
            generation_config["thinkingConfig"] = {"thinkingBudget": budget}
        body: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": user_text}]}],
            "generationConfig": generation_config,
        }
        if instructions:
            body["systemInstruction"] = {"parts": [{"text": instructions}]}
        payload = self._send(
            f"{self.backend.base_url}/models/{model}:generateContent",
            {"x-goog-api-key": self.backend.api_key, "Content-Type": "application/json"},
            body,
            timeout,
            model,
        )
        candidates = payload.get("candidates") or []
        if not candidates:
            return None
        parts = ((candidates[0].get("content") or {}).get("parts")) or []
        joined = "".join(str(p.get("text") or "") for p in parts if isinstance(p, dict))
        return joined or None

    def _send(self, url: str, headers: dict[str, str], body: dict[str, Any], timeout: float, model: str) -> dict[str, Any]:
        # Pace the calls (not a retry): keep consecutive requests a few seconds apart
        # so the suite doesn't burst the free tier. A schema rejection still becomes an
        # actionable StructuredOutputUnsupported, and any other API error (429, 5xx,
        # etc.) propagates and fails the test rather than being silently absorbed.
        _space_requests()
        request = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"), method="POST", headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in self._schema_rejected:
                raise StructuredOutputUnsupported(
                    f"{self.backend.label} rejected the structured-output schema "
                    f"for model {model!r} (HTTP {exc.code})"
                ) from exc
            raise


def _select_backend() -> _Backend | None:
    google_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if google_key:
        return _Backend(
            label="Google AI Studio",
            mode="gemini",
            base_url=os.environ.get(
                "GOOGLE_AI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta"
            ).rstrip("/"),
            api_key=google_key,
            require_parameters=False,
            suggestion="a free structured-output model such as gemini-2.5-flash or gemma-4-31b-it",
        )
    openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    if openrouter_key:
        return _Backend(
            label="OpenRouter",
            mode="openai",
            base_url=os.environ.get("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/"),
            api_key=openrouter_key,
            require_parameters=True,
            suggestion="a model whose supported_parameters include 'structured_outputs', e.g. openai/gpt-4o-mini",
        )
    return None


def live_models() -> list[str]:
    """Models to test, from ``GUARDIAN_LLM_TEST_MODEL`` (comma-separated for many)."""
    raw = os.environ.get("GUARDIAN_LLM_TEST_MODEL") or ""
    return [m.strip() for m in raw.split(",") if m.strip()]


def live_llm_or_fail(model: str | None = None) -> LiveSecurityLlm:
    """Return a live adapter for ``model``, or FAIL if no backend is configured.

    Configuration comes from the environment (set as CI secrets / repo variables):
    ``GUARDIAN_LLM_TEST_MODEL`` (one model, or a comma-separated list) plus one
    backend key — ``GEMINI_API_KEY`` / ``GOOGLE_API_KEY`` (Google AI Studio) or
    ``OPENROUTER_API_KEY`` (OpenRouter). Google is preferred when both are present.
    Pass ``model`` to pick one from a multi-model list; defaults to the first.

    Reaching this call means the live suite was explicitly opted into (``--run-llm``
    / ``GUARDIAN_RUN_LLM`` — otherwise the conftest hook deselects every ``llm`` test
    before the body runs). So missing credentials are a configuration ERROR, not a
    reason to silently pass: the verifier never gets exercised, and a green skip would
    hide that. Fail loudly with the env vars to set instead.
    """
    backend = _select_backend()
    chosen = model or (live_models()[0] if live_models() else None)
    if backend is None or not chosen:
        pytest.fail(
            "live LLM verifier tests were requested (--run-llm / GUARDIAN_RUN_LLM) but "
            "no backend is configured. Set GUARDIAN_LLM_TEST_MODEL plus one of "
            "GEMINI_API_KEY / GOOGLE_API_KEY (Google AI Studio) or OPENROUTER_API_KEY "
            "(OpenRouter). Locally, a gitignored repo-root .env works; in CI set them as "
            "repository secrets/variables.",
            pytrace=False,
        )
    return LiveSecurityLlm(model=chosen, backend=backend)
