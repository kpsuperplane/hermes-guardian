from __future__ import annotations

import os
from pathlib import Path

import pytest

from benchmarks.hermes_cli_e2e_probe import CASES, CANARY, DEFAULT_HERMES_CLI, run_probe


def test_hermes_cli_probe_cases_cover_direct_cli_attack_and_benign_paths():
    case_ids = {case.id for case in CASES}

    assert {
        "cli_terminal_file_injection_to_curl",
        "cli_benign_terminal_metadata_read",
        "cli_file_private_read_to_local_write_allowed",
        "cli_file_private_read_to_web_extract_blocked",
    } <= case_ids


@pytest.mark.hermes_cli
def test_hermes_cli_probe_passes_when_opted_in():
    if os.environ.get("HERMES_GUARDIAN_RUN_CLI_E2E") != "1":
        pytest.skip("set HERMES_GUARDIAN_RUN_CLI_E2E=1 to run direct Hermes CLI probes")

    hermes = os.environ.get("HERMES_GUARDIAN_CLI_E2E_HERMES") or DEFAULT_HERMES_CLI
    if not Path(hermes).exists():
        pytest.skip(f"Hermes CLI not found: {hermes}")

    result = run_probe(hermes=hermes)

    assert result["benchmark"] == "hermes_cli_e2e_probe"
    assert result["failed_cases"] == [], result
    assert result["passed_cases"] == result["total_cases"]
    report = repr(result)
    assert CANARY not in report
