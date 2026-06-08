"""Optional AgentDojo adapter for Hermes Guardian.

This module deliberately keeps AgentDojo as a lazy optional import. The standard
CI path uses ``benchmarks.guardian_adversarial`` and does not install AgentDojo.
"""

from __future__ import annotations

import argparse
import importlib
import json
from typing import Any

from benchmarks.guardian_adversarial import run_benchmark


MISSING_AGENTDOJO_MESSAGE = (
    "AgentDojo is not installed. Install it in a separate local benchmark "
    "environment to adapt Hermes Guardian results to AgentDojo workflows; it is "
    "intentionally not a Hermes Guardian CI dependency."
)


def _load_agentdojo() -> Any:
    try:
        return importlib.import_module("agentdojo")
    except ImportError as exc:
        raise RuntimeError(MISSING_AGENTDOJO_MESSAGE) from exc


def run_agentdojo_adapter() -> dict[str, Any]:
    agentdojo = _load_agentdojo()
    guardian_result = run_benchmark()
    return {
        "benchmark": "agentdojo_guardian",
        "agentdojo_module": getattr(agentdojo, "__name__", "agentdojo"),
        "guardian_adversarial": {
            "prevented_rate": guardian_result["prevented_rate"],
            "false_positive_rate": guardian_result["false_positive_rate"],
            "classification_accuracy": guardian_result["classification"]["accuracy"],
            "security_scanner_accuracy": guardian_result["security_scanner"]["accuracy"],
            "known_gap_count": guardian_result["known_gap_count"],
            "sanitization_violations": guardian_result["sanitization_violations"],
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the optional AgentDojo Guardian adapter.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    args = parser.parse_args(argv)

    try:
        result = run_agentdojo_adapter()
    except RuntimeError as exc:
        print(str(exc))
        return 2
    print(json.dumps(result, indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
