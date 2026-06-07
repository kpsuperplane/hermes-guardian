"""Run the Hermes Guardian dashboard as a standalone local service."""

from __future__ import annotations

import importlib.util
import os
import signal
import sys
import time
from pathlib import Path


def _load_hermes_env() -> None:
    env_path = Path.home() / ".hermes" / ".env"
    if not env_path.exists():
        return
    for raw_line in env_path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        key, value = line.split("=", 1)
        key = key.strip()
        if not key or key in os.environ:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        os.environ[key] = value


def _load_plugin():
    plugin_path = Path(__file__).with_name("__init__.py")
    spec = importlib.util.spec_from_file_location("hermes_guardian_service", plugin_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load plugin module from {plugin_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    _load_hermes_env()
    plugin = _load_plugin()
    stopping = False

    def stop(_signum, _frame) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print(plugin._dashboard_start(), flush=True)
    while not stopping:
        time.sleep(1)
    print(plugin._dashboard_stop(), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
