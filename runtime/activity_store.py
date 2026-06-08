"""SQLite activity persistence and retention management."""

from __future__ import annotations

def _activity_connect() -> sqlite3.Connection:
    _ACTIVITY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_ACTIVITY_DB_PATH), timeout=2.0)
    conn.row_factory = sqlite3.Row
    return conn


def _activity_max_rows() -> int:
    raw = _env(_ACTIVITY_MAX_ROWS_ENV, str(_DEFAULT_ACTIVITY_MAX_ROWS)).strip()
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_ACTIVITY_MAX_ROWS
    return max(0, value)


def _activity_retention_days() -> int:
    raw = _env(_ACTIVITY_RETENTION_DAYS_ENV, str(_DEFAULT_ACTIVITY_RETENTION_DAYS)).strip()
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_ACTIVITY_RETENTION_DAYS
    return max(0, value)


def _activity_group_seconds() -> int:
    raw = _env(_ACTIVITY_GROUP_SECONDS_ENV, str(_DEFAULT_ACTIVITY_GROUP_SECONDS)).strip()
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_ACTIVITY_GROUP_SECONDS
    return max(0, min(value, 3600))


def _ensure_activity_db() -> None:
    global _ACTIVITY_DB_INITIALIZED
    if _ACTIVITY_DB_INITIALIZED:
        return
    with _LOCK:
        if _ACTIVITY_DB_INITIALIZED:
            return
        try:
            with _activity_connect() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS activity (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        decision TEXT NOT NULL,
                        mode TEXT NOT NULL,
                        session_label TEXT NOT NULL,
                        session_hash TEXT NOT NULL,
                        owner_hash TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        action_family TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        data_classes TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        approval_id TEXT NOT NULL,
                        rule_id TEXT NOT NULL,
                        rule_source TEXT NOT NULL,
                        action_detail TEXT NOT NULL DEFAULT '',
                        module TEXT NOT NULL DEFAULT '',
                        rule_effect TEXT NOT NULL DEFAULT '',
                        rule_scope TEXT NOT NULL DEFAULT '',
                        purpose TEXT NOT NULL DEFAULT '',
                        recipient_identity TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(activity)").fetchall()
                }
                if "action_detail" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN action_detail TEXT NOT NULL DEFAULT ''")
                if "module" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN module TEXT NOT NULL DEFAULT ''")
                if "rule_effect" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN rule_effect TEXT NOT NULL DEFAULT ''")
                if "rule_scope" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN rule_scope TEXT NOT NULL DEFAULT ''")
                if "purpose" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN purpose TEXT NOT NULL DEFAULT ''")
                if "recipient_identity" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN recipient_identity TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_ts_idx ON activity(ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_decision_idx ON activity(decision)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_action_idx ON activity(action_family)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_destination_idx ON activity(destination)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_approval_idx ON activity(approval_id)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS pending_approvals (
                        id TEXT PRIMARY KEY,
                        session_id TEXT NOT NULL,
                        owner_hash TEXT NOT NULL,
                        tool_name TEXT NOT NULL,
                        action_family TEXT NOT NULL,
                        destination TEXT NOT NULL,
                        data_classes TEXT NOT NULL,
                        action_detail TEXT NOT NULL,
                        fingerprint TEXT NOT NULL,
                        created_at INTEGER NOT NULL,
                        expires_at INTEGER NOT NULL,
                        cron_job_id TEXT NOT NULL DEFAULT '',
                        cron_job_name TEXT NOT NULL DEFAULT '',
                        reason TEXT NOT NULL DEFAULT '',
                        purpose TEXT NOT NULL DEFAULT 'unknown',
                        recipient_identity TEXT NOT NULL DEFAULT 'none',
                        legacy_destination TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                pending_columns = {
                    str(row["name"])
                    for row in conn.execute("PRAGMA table_info(pending_approvals)").fetchall()
                }
                if "cron_job_id" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN cron_job_id TEXT NOT NULL DEFAULT ''")
                if "cron_job_name" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN cron_job_name TEXT NOT NULL DEFAULT ''")
                if "reason" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN reason TEXT NOT NULL DEFAULT ''")
                if "purpose" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN purpose TEXT NOT NULL DEFAULT 'unknown'")
                if "recipient_identity" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN recipient_identity TEXT NOT NULL DEFAULT 'none'")
                if "legacy_destination" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN legacy_destination TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_session_idx ON pending_approvals(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_expires_idx ON pending_approvals(expires_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_cron_job_idx ON pending_approvals(cron_job_id)")
            _ACTIVITY_DB_INITIALIZED = True
        except Exception as exc:
            logger.debug("%s: failed to initialize activity db: %s", _PLUGIN_NAME, exc)


def _emit_activity(
    decision: str,
    *,
    session_id: str | None = "",
    owner_hash: str = "",
    tool_name: str = "",
    action_family: str = "",
    destination: str = "",
    data_classes: list[str] | set[str] | tuple[str, ...] | None = None,
    reason: str = "",
    approval_id: str = "",
    rule_id: str = "",
    rule_source: str = "",
    action_detail: str = "",
    module: str = "",
    rule_effect: str = "",
    rule_scope: str = "",
    purpose: str = "",
    recipient_identity: str = "",
) -> None:
    """Persist sanitized activity metadata for dashboard/debugging."""
    if decision not in _ACTIVITY_DECISIONS:
        decision = "allowed"
    if not module:
        if decision in {"security_blocked", "security_suppressed"}:
            module = "security"
        elif decision in {"allowed", "auto_approved", "blocked", "denied", "manual_approved", "privacy_off_allowed", "tainted"}:
            module = "privacy"
    safe_classes = sorted(str(cls) for cls in (data_classes or []) if str(cls) in _ALL_PRIVACY_CLASSES)
    sid = _normalize_session_id(session_id)
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO activity (
                    ts, decision, mode, session_label, session_hash, owner_hash,
                    tool_name, action_family, destination, data_classes, reason,
                    approval_id, rule_id, rule_source, action_detail,
                    module, rule_effect, rule_scope, purpose, recipient_identity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(_now()),
                    decision,
                    _privacy_policy(),
                    _safe_session_label(sid),
                    _short_hash(sid),
                    _short_hash(owner_hash),
                    str(tool_name or "")[:120],
                    str(action_family or "")[:80],
                    str(destination or "")[:160],
                    ",".join(safe_classes),
                    str(reason or "")[:1000],
                    str(approval_id or "")[:80],
                    str(rule_id or "")[:80],
                    str(rule_source or "")[:80],
                    str(action_detail or "")[:500],
                    str(module or "")[:40],
                    str(rule_effect or "")[:40],
                    str(rule_scope or "")[:160],
                    _normalize_rule_purpose(purpose or "unknown", allow_star=False),
                    _normalize_rule_recipient_identity(recipient_identity or "none", allow_star=False),
                ),
            )
        _prune_activity_db()
    except Exception as exc:
        logger.debug("%s: failed to write activity event: %s", _PLUGIN_NAME, exc)


def _prune_activity_db(*, force: bool = False) -> dict[str, int]:
    """Bound activity DB size by age and row count.

    A value of 0 disables the corresponding limit.
    """
    global _LAST_ACTIVITY_PRUNE
    now = _now()
    if not force and now - _LAST_ACTIVITY_PRUNE < _ACTIVITY_PRUNE_INTERVAL_SECONDS:
        return {"deleted": 0, "remaining": -1}
    _LAST_ACTIVITY_PRUNE = now

    max_rows = _activity_max_rows()
    retention_days = _activity_retention_days()
    deleted = 0
    remaining = 0
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            if retention_days > 0:
                cutoff = int(now - retention_days * 86400)
                deleted += conn.execute("DELETE FROM activity WHERE ts < ?", (cutoff,)).rowcount
            if max_rows > 0:
                deleted += conn.execute(
                    """
                    DELETE FROM activity
                    WHERE id NOT IN (
                        SELECT id FROM activity ORDER BY ts DESC, id DESC LIMIT ?
                    )
                    """,
                    (max_rows,),
                ).rowcount
            remaining = int(conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0])
        if deleted:
            with _activity_connect() as conn:
                conn.isolation_level = None
                conn.execute("VACUUM")
    except Exception as exc:
        logger.debug("%s: failed to prune activity db: %s", _PLUGIN_NAME, exc)
    return {"deleted": int(deleted or 0), "remaining": remaining}
