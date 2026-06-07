"""Modularized guardian runtime module."""

from __future__ import annotations

def _dashboard_payload(filters: dict[str, str] | None = None, *, limit: int = 200) -> dict[str, Any]:
    return {
        "policy": _policy_snapshot(),
        "activity": _grouped_activity_rows(filters or {}, limit=limit),
    }


def _configured_history_timezone() -> str:
    raw = _env(_HISTORY_TIMEZONE_ENV, "").strip()
    if raw:
        return raw
    try:
        config_path = Path.home() / ".hermes" / "config.yaml"
        if config_path.exists():
            match = re.search(r"(?m)^\s*timezone:\s*['\"]?([^'\"\n#]*)", config_path.read_text())
            if match:
                return match.group(1).strip()
    except Exception:
        return ""
    return ""


def _history_timezone() -> ZoneInfo | None:
    configured = _configured_history_timezone()
    if configured:
        try:
            return ZoneInfo(configured)
        except ZoneInfoNotFoundError:
            logger.warning("%s: invalid history timezone %r; using local time", _PLUGIN_NAME, configured)
    return None

def _dashboard_host() -> str:
    host = _env(_DASHBOARD_HOST_ENV, _DEFAULT_DASHBOARD_HOST).strip()
    return host or _DEFAULT_DASHBOARD_HOST


def _dashboard_port() -> int:
    raw = _env(_DASHBOARD_PORT_ENV, str(_DEFAULT_DASHBOARD_PORT)).strip()
    try:
        port = int(raw)
    except ValueError:
        return _DEFAULT_DASHBOARD_PORT
    return port if 1 <= port <= 65535 else _DEFAULT_DASHBOARD_PORT


def _dashboard_url() -> str:
    return f"http://{_dashboard_host()}:{_dashboard_port()}"


def _activity_display_tool(row: dict[str, Any]) -> str:
    return _presentation.activity_display_tool(row)


def _clip_text(value: Any, limit: int = 120, *, ellipsis: str = "…", fallback: str = "") -> str:
    return _presentation.clip_text(value, limit, ellipsis=ellipsis, fallback=fallback)


def _friendly_activity_timestamp(ts: Any) -> str:
    return _presentation.friendly_activity_timestamp(ts, _history_timezone())


def _activity_time_text(row: dict[str, Any]) -> str:
    return _presentation.activity_time_text(row, _history_timezone())


def _activity_display_reason(row: dict[str, Any]) -> str:
    return _presentation.activity_display_reason(
        row,
        all_privacy_classes=_ALL_PRIVACY_CLASSES,
        taint_reason_for_tool_result=_taint_reason_for_tool_result,
    )


def _activity_status_icon(decision: str) -> str:
    return _presentation.activity_status_icon(decision)


def _activity_reason_prefix(decision: str) -> str:
    return _presentation.activity_reason_prefix(decision)


def _activity_reason_line_text(row: dict[str, Any], *, limit: int = 72, marker_limit: int = 72) -> str:
    return _presentation.activity_reason_line_text(
        row,
        marker=_activity_marker(row),
        display_reason=_activity_display_reason(row),
        limit=limit,
        marker_limit=marker_limit,
    )


def _activity_taints_text(row: dict[str, Any], *, code: bool = False, html_code: bool = False) -> str:
    return _presentation.activity_taints_text(row, code=code, html_code=html_code)


def _dashboard_html() -> str:
    return _presentation.dashboard_html(
        _policy_snapshot(),
        jquery_version=_JQUERY_VERSION,
        datatables_version=_DATATABLES_VERSION,
        all_privacy_classes=_ALL_PRIVACY_CLASSES,
    )

class _DashboardHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug("%s dashboard: " + format, _PLUGIN_NAME, *args)

    def _send_json(self, value: Any, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, value: str, status: int = 200) -> None:
        body = value.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_asset(self, path: str) -> bool:
        assets = {
            f"/assets/jquery/{_JQUERY_VERSION}/jquery.min.js": (
                _JQUERY_ASSET_DIR / "jquery.min.js",
                "application/javascript; charset=utf-8",
            ),
            f"/assets/datatables/{_DATATABLES_VERSION}/dataTables.min.js": (
                _DATATABLES_ASSET_DIR / "dataTables.min.js",
                "application/javascript; charset=utf-8",
            ),
            f"/assets/datatables/{_DATATABLES_VERSION}/dataTables.dataTables.min.css": (
                _DATATABLES_ASSET_DIR / "dataTables.dataTables.min.css",
                "text/css; charset=utf-8",
            ),
        }
        asset = assets.get(path)
        if asset is None:
            return False
        file_path, content_type = asset
        try:
            body = file_path.read_bytes()
        except Exception:
            self._send_json({"error": "asset not found"}, status=404)
            return True
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return True

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if self._send_asset(parsed.path):
            return
        query = {key: vals[-1] for key, vals in parse_qs(parsed.query).items() if vals}
        if parsed.path in {"/", "/index.html"}:
            self._send_html(_dashboard_html())
            return
        if parsed.path == "/api/activity":
            try:
                limit = int(query.pop("limit", "200"))
            except ValueError:
                limit = 200
            self._send_json({"activity": _grouped_activity_rows(query, limit=limit)})
            return
        if parsed.path == "/api/activity/datatables":
            self._send_json(_activity_datatables_payload(query))
            return
        if parsed.path == "/api/policy":
            self._send_json(_policy_snapshot())
            return
        if parsed.path == "/api/debug":
            try:
                self._send_json(_debug_decision(query))
            except Exception as exc:
                self._send_json({"error": str(exc)}, status=400)
            return
        self._send_json({"error": "not found"}, status=404)


def _dashboard_status() -> str:
    if _DASHBOARD_SERVER is None:
        return "Hermes Guardian dashboard is stopped."
    return f"Hermes Guardian dashboard is running at {_dashboard_url()}"


def _dashboard_start() -> str:
    global _DASHBOARD_SERVER, _DASHBOARD_THREAD
    with _LOCK:
        if _DASHBOARD_SERVER is not None:
            return _dashboard_status()
        host = _dashboard_host()
        port = _dashboard_port()
        try:
            server = http.server.ThreadingHTTPServer((host, port), _DashboardHandler)
        except Exception as exc:
            return f"Failed to start guardian dashboard on {host}:{port}: {exc}"
        thread = threading.Thread(
            target=server.serve_forever,
            name="hermes-guardian-dashboard",
            daemon=True,
        )
        thread.start()
        _DASHBOARD_SERVER = server
        _DASHBOARD_THREAD = thread
        return f"Hermes Guardian dashboard started at {_dashboard_url()}"


def _dashboard_stop() -> str:
    global _DASHBOARD_SERVER, _DASHBOARD_THREAD
    with _LOCK:
        server = _DASHBOARD_SERVER
        thread = _DASHBOARD_THREAD
        _DASHBOARD_SERVER = None
        _DASHBOARD_THREAD = None
    if server is None:
        return "Hermes Guardian dashboard is already stopped."
    server.shutdown()
    server.server_close()
    if thread is not None:
        thread.join(timeout=2.0)
    return "Hermes Guardian dashboard stopped."


