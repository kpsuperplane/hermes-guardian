"""Local adversarial corpus benchmark for Hermes Guardian.

The benchmark drives real Guardian hooks and scanner helpers against a checked-in
JSON corpus while redirecting rules, approvals, and activity storage into a
temporary directory. It intentionally has no third-party dependencies.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any


CORPUS_PATH = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "adversarial_corpus.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _load_plugin(temp_dir: Path):
    plugin_path = _repo_root() / "__init__.py"
    module_name = f"hermes_guardian_adversarial_{os.getpid()}_{id(temp_dir)}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    overrides = {
        "_PERSISTENT_RULES_PATH": temp_dir / "guardian-rules.json",
        "_PERSISTENT_RULES_CACHE": module._default_privacy_config(),
        "_PERSISTENT_RULES_MTIME": None,
        "_PERSISTENT_RULES_ERROR": False,
        "_ACTIVITY_DB_PATH": temp_dir / "activity.sqlite3",
        "_ACTIVITY_DB_INITIALIZED": False,
        "_GUARDIAN_HMAC_KEY_PATH": temp_dir / ".guardian-hmac-key",
        "_LAST_ACTIVITY_PRUNE": 0.0,
    }
    # Single source of truth: rebind on the `state` module so the engine observes it.
    for key, value in overrides.items():
        setattr(module.state, key, value)
    module._apply_language_pack_config(module.state._PERSISTENT_RULES_CACHE)
    return module


def _json_result(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _load_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        corpus = json.load(handle)
    if int(corpus.get("version") or 0) != 1:
        raise ValueError(f"unsupported adversarial corpus version in {path}")
    if not isinstance(corpus.get("cases"), list):
        raise ValueError(f"adversarial corpus has no cases list: {path}")
    return corpus


def _bind_case_owner(plugin: Any, session_id: str) -> None:
    plugin._on_pre_llm_call(
        session_id=session_id,
        platform="telegram",
        sender_id="adversarial-owner",
    )


def _latest_activity(plugin: Any, session_id: str, tool_name: str) -> dict[str, Any]:
    try:
        plugin._ensure_activity_db()
        with plugin._activity_connect() as conn:
            row = conn.execute(
                """
                SELECT decision, tool_name, action_family, destination, data_classes,
                       reason, action_detail
                FROM activity
                WHERE session_hash = ? AND tool_name = ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (plugin._short_hash(plugin._normalize_session_id(session_id)), str(tool_name or "")[:120]),
            ).fetchone()
    except sqlite3.Error:
        return {}
    return dict(row) if row else {}


def _sensitive_reason_for_case(plugin: Any, case: dict[str, Any]) -> str | None:
    if case.get("surface") == "scanner":
        return plugin._sensitive_reason(case.get("text", ""))
    if "expected_security_reason" in case:
        if "args" in case:
            return plugin._sensitive_reason(case.get("args"))
        if "result" in case:
            return plugin._sensitive_reason(case.get("result"))
    return None


def _run_hook_case(plugin: Any, case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"adv_{case['id']}"
    _bind_case_owner(plugin, session_id)
    taint = set(str(cls) for cls in case.get("taint") or [])
    if taint:
        plugin._taint_session(session_id, taint)

    result = plugin._on_pre_tool_call(
        str(case.get("tool_name") or ""),
        case.get("args"),
        session_id=session_id,
    )
    prevented = result is not None
    activity = _latest_activity(plugin, session_id, str(case.get("tool_name") or ""))
    return {
        "id": case["id"],
        "surface": "hook",
        "gating": bool(case.get("gating", True)),
        "known_gap": bool(case.get("known_gap")),
        "malicious": bool(case.get("malicious")),
        "expected_prevented": bool(case.get("expected_prevented")),
        "prevented": prevented,
        "decision": activity.get("decision", "blocked" if prevented else "allowed"),
        "action_family": activity.get("action_family", ""),
        "destination": activity.get("destination", ""),
        "security_reason": _sensitive_reason_for_case(plugin, case) or "",
    }


def _run_result_case(plugin: Any, case: dict[str, Any]) -> dict[str, Any]:
    session_id = f"adv_{case['id']}"
    _bind_case_owner(plugin, session_id)
    transformed = plugin._on_transform_tool_result(
        str(case.get("tool_name") or ""),
        _json_result(case.get("result")),
        session_id=session_id,
    )
    prevented = False
    if transformed is not None:
        try:
            parsed = json.loads(transformed)
        except (TypeError, ValueError):
            parsed = {}
        prevented = bool(
            isinstance(parsed, dict)
            and (
                parsed.get("hermes_guardian", {}).get("suppressed")
                or parsed.get("security_sensitive_filter", {}).get("suppressed")
            )
        )
    activity = _latest_activity(plugin, session_id, str(case.get("tool_name") or ""))
    return {
        "id": case["id"],
        "surface": "result",
        "gating": bool(case.get("gating", True)),
        "known_gap": bool(case.get("known_gap")),
        "malicious": bool(case.get("malicious")),
        "expected_prevented": bool(case.get("expected_prevented")),
        "prevented": prevented,
        "decision": activity.get("decision", "security_suppressed" if prevented else "allowed"),
        "action_family": activity.get("action_family", ""),
        "destination": activity.get("destination", ""),
        "security_reason": _sensitive_reason_for_case(plugin, case) or "",
    }


def _run_scanner_case(plugin: Any, case: dict[str, Any]) -> dict[str, Any]:
    reason = plugin._sensitive_reason(case.get("text", ""))
    return {
        "id": case["id"],
        "surface": "scanner",
        "gating": bool(case.get("gating", True)),
        "known_gap": bool(case.get("known_gap")),
        "malicious": bool(case.get("malicious")),
        "expected_sensitive": bool(case.get("expected_sensitive")),
        "sensitive": bool(reason),
        "security_reason": reason or "",
    }


def _run_case(plugin: Any, case: dict[str, Any]) -> dict[str, Any]:
    surface = str(case.get("surface") or "")
    if surface == "hook":
        return _run_hook_case(plugin, case)
    if surface == "result":
        return _run_result_case(plugin, case)
    if surface == "scanner":
        return _run_scanner_case(plugin, case)
    raise ValueError(f"unknown adversarial case surface {surface!r} for {case.get('id')!r}")


def _scan_sanitization(plugin: Any, sentinels: list[str]) -> list[str]:
    violations: list[str] = []
    try:
        plugin._ensure_activity_db()
        with plugin._activity_connect() as conn:
            tables = {
                "activity": conn.execute("SELECT * FROM activity").fetchall(),
                "pending_approvals": conn.execute("SELECT * FROM pending_approvals").fetchall(),
            }
    except sqlite3.Error as exc:
        return [f"activity scan failed: {exc}"]

    for table, rows in tables.items():
        for index, row in enumerate(rows):
            for key in row.keys():
                value = str(row[key] or "")
                for sentinel in sentinels:
                    if sentinel in value:
                        violations.append(f"{table}[{index}].{key} contains sentinel")
    return violations


def _count_accuracy(results: list[dict[str, Any]], cases: list[dict[str, Any]]) -> tuple[int, int]:
    by_id = {result["id"]: result for result in results}
    correct = 0
    total = 0
    for case in cases:
        if "expected_action_family" not in case:
            continue
        total += 1
        result = by_id[case["id"]]
        if (
            result.get("action_family") == case.get("expected_action_family")
            and result.get("destination") == case.get("expected_destination", "")
        ):
            correct += 1
    return correct, total


def _count_scanner_accuracy(results: list[dict[str, Any]], cases: list[dict[str, Any]]) -> tuple[int, int]:
    by_id = {result["id"]: result for result in results}
    correct = 0
    total = 0
    for case in cases:
        if case.get("surface") != "scanner" and "expected_security_reason" not in case:
            continue
        total += 1
        result = by_id[case["id"]]
        expected_sensitive = bool(case.get("expected_sensitive", "expected_security_reason" in case))
        sensitive_matches = bool(result.get("security_reason")) == expected_sensitive
        reason_matches = True
        if case.get("expected_security_reason"):
            reason_matches = result.get("security_reason") == case.get("expected_security_reason")
        if sensitive_matches and reason_matches:
            correct += 1
    return correct, total


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def run_benchmark(*, corpus_path: Path = CORPUS_PATH) -> dict[str, Any]:
    corpus = _load_corpus(corpus_path)
    cases = list(corpus["cases"])
    with tempfile.TemporaryDirectory(prefix="hermes-guardian-adversarial-") as temp_name:
        plugin = _load_plugin(Path(temp_name))
        results = [_run_case(plugin, case) for case in cases]
        sanitization_violations = _scan_sanitization(
            plugin,
            [str(value) for value in corpus.get("sentinels") or []],
        )

    by_id = {result["id"]: result for result in results}
    gating_hook_result_cases = [
        case
        for case in cases
        if case.get("gating", True)
        and not case.get("known_gap")
        and case.get("surface") in {"hook", "result"}
    ]
    malicious = [case for case in gating_hook_result_cases if case.get("malicious")]
    benign = [case for case in gating_hook_result_cases if not case.get("malicious")]
    prevented = sum(1 for case in malicious if by_id[case["id"]].get("prevented"))
    false_positives = sum(1 for case in benign if by_id[case["id"]].get("prevented"))

    classification_correct, classification_total = _count_accuracy(results, cases)
    scanner_correct, scanner_total = _count_scanner_accuracy(results, cases)
    known_gap_count = sum(1 for case in cases if case.get("known_gap"))
    failures = [
        case["id"]
        for case in gating_hook_result_cases
        if bool(by_id[case["id"]].get("prevented")) != bool(case.get("expected_prevented"))
    ]
    failures.extend(
        case["id"]
        for case in cases
        if case.get("surface") == "scanner"
        and case.get("gating", True)
        and not case.get("known_gap")
        and bool(by_id[case["id"]].get("sensitive")) != bool(case.get("expected_sensitive"))
    )

    return {
        "benchmark": "guardian_adversarial",
        "corpus_version": corpus.get("version"),
        "total_cases": len(cases),
        "gating_cases": len(gating_hook_result_cases),
        "known_gap_count": known_gap_count,
        "prevented": prevented,
        "preventable": len(malicious),
        "prevented_rate": _rate(prevented, len(malicious)),
        "false_positives": false_positives,
        "benign_controls": len(benign),
        "false_positive_rate": _rate(false_positives, len(benign)),
        "classification": {
            "correct": classification_correct,
            "total": classification_total,
            "accuracy": _rate(classification_correct, classification_total),
        },
        "security_scanner": {
            "correct": scanner_correct,
            "total": scanner_total,
            "accuracy": _rate(scanner_correct, scanner_total),
        },
        "sanitization_violations": sanitization_violations,
        "failures": sorted(set(failures)),
        "cases": [
            {
                key: result[key]
                for key in (
                    "id",
                    "surface",
                    "gating",
                    "known_gap",
                    "malicious",
                    "expected_prevented",
                    "prevented",
                    "expected_sensitive",
                    "sensitive",
                    "decision",
                    "action_family",
                    "destination",
                    "security_reason",
                )
                if key in result
            }
            for result in results
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Hermes Guardian local adversarial corpus benchmark.")
    parser.add_argument(
        "--corpus",
        type=Path,
        default=CORPUS_PATH,
        help="Path to adversarial corpus JSON.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    result = run_benchmark(corpus_path=args.corpus)
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0 if not result["failures"] and not result["sanitization_violations"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
