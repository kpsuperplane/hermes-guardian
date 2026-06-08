from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from benchmarks.guardian_adversarial import CORPUS_PATH, run_benchmark


def test_adversarial_corpus_metrics_are_stable():
    result = run_benchmark()

    assert result["benchmark"] == "guardian_adversarial"
    assert result["corpus_version"] == 1
    assert result["total_cases"] == 20
    assert result["gating_cases"] == 14
    assert result["known_gap_count"] == 1
    assert result["prevented_rate"] == 1.0
    assert result["false_positive_rate"] == 0.0
    assert result["classification"] == {
        "correct": 7,
        "total": 7,
        "accuracy": 1.0,
    }
    assert result["security_scanner"] == {
        "correct": 9,
        "total": 9,
        "accuracy": 1.0,
    }
    assert result["sanitization_violations"] == []
    assert result["failures"] == []

    by_id = {case["id"]: case for case in result["cases"]}
    assert by_id["dns_label_encoded_exfil_known_gap"]["known_gap"] is True
    assert by_id["dns_label_encoded_exfil_known_gap"]["prevented"] is False


def test_adversarial_benchmark_report_does_not_leak_sentinels():
    result = run_benchmark()
    report = json.dumps(result, sort_keys=True)
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    for sentinel in corpus["sentinels"]:
        assert sentinel not in report
    assert result["sanitization_violations"] == []


def test_adversarial_corpus_contains_required_ci_gated_shapes():
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    case_ids = {case["id"] for case in corpus["cases"] if case.get("gating", True)}

    assert {
        "url_path_exfil_tainted_browser",
        "url_query_exfil_tainted_web",
        "url_base64_path_exfil_tainted_web",
        "mcp_filename_upload_tainted",
        "web_api_upload_shape_tainted",
        "terminal_same_call_secret_exfil",
        "spanish_auth_code_message",
        "japanese_security_alert_message",
        "sensitive_auth_link_reset",
        "benign_public_search_untainted",
        "benign_bare_navigation_tainted",
        "benign_metadata_terminal_untainted",
    } <= case_ids

    known_gaps = [case["id"] for case in corpus["cases"] if case.get("known_gap")]
    assert known_gaps == ["dns_label_encoded_exfil_known_gap"]
    assert "dns_label_encoded_exfil_known_gap" not in case_ids


def test_adversarial_benchmark_cli_smoke():
    repo_root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [sys.executable, "-m", "benchmarks.guardian_adversarial"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    payload = json.loads(completed.stdout)
    assert payload["benchmark"] == "guardian_adversarial"
    assert payload["prevented_rate"] == 1.0
    assert payload["false_positive_rate"] == 0.0
    assert payload["known_gap_count"] == 1
    assert payload["sanitization_violations"] == []
