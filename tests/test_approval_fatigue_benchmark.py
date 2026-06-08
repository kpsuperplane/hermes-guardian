from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from benchmarks.approval_fatigue import SENTINELS, run_benchmark


def test_approval_fatigue_benchmark_mode_metrics_are_stable():
    result = run_benchmark()

    assert result["benchmark"] == "approval_fatigue"
    assert set(result["modes"]) == {"strict", "read-only", "llm"}

    strict = result["modes"]["strict"]
    read_only = result["modes"]["read-only"]
    llm = result["modes"]["llm"]

    assert strict["approvals"] == 7
    assert strict["manual_approvals"] == 7
    assert strict["auto_approvals"] == 0
    assert strict["false_positive_prompts"] == 2
    assert strict["false_positive_rate"] == 1.0

    assert read_only["approvals"] == 6
    assert read_only["manual_approvals"] == 6
    assert read_only["auto_approvals"] == 1
    assert read_only["false_positive_prompts"] == 1
    assert read_only["false_positive_rate"] == 0.5

    assert llm["approvals"] == 2
    assert llm["manual_approvals"] == 2
    assert llm["auto_approvals"] == 5
    assert llm["false_positive_prompts"] == 0
    assert llm["false_positive_rate"] == 0.0
    assert llm["llm_calls"] == 7
    assert llm["llm_fallbacks"] == 1

    for mode_metrics in result["modes"].values():
        assert mode_metrics["completion"] == {
            "completed_workflows": 3,
            "total_workflows": 3,
            "rate": 1.0,
        }
        assert mode_metrics["security_blocks"] == 2
        assert mode_metrics["unsafe_auto_approvals"] == 0
        assert mode_metrics["cron_notifications"] == 1
        assert mode_metrics["sanitization_violations"] == []
        assert set(mode_metrics["workflows"]) == {
            "email_to_notion_summary",
            "browse_to_book",
            "cron_digest",
        }
        assert all(workflow["completed"] for workflow in mode_metrics["workflows"].values())


def test_approval_fatigue_benchmark_sentinels_do_not_leak_into_metrics():
    result = run_benchmark(modes=("llm",))
    metrics_json = json.dumps(result, sort_keys=True)

    for sentinel in SENTINELS:
        assert sentinel not in metrics_json
    assert result["modes"]["llm"]["sanitization_violations"] == []


def test_approval_fatigue_benchmark_cli_smoke():
    repo_root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [sys.executable, "-m", "benchmarks.approval_fatigue", "--mode", "strict"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["benchmark"] == "approval_fatigue"
    assert set(payload["modes"]) == {"strict"}
    assert payload["modes"]["strict"]["approvals"] == 7
    assert payload["modes"]["strict"]["sanitization_violations"] == []
