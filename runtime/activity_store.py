"""SQLite activity persistence and retention management."""

from __future__ import annotations

def _activity_connect() -> sqlite3.Connection:
    _ACTIVITY_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_ACTIVITY_DB_PATH), timeout=2.0)
    conn.row_factory = sqlite3.Row
    # WAL lets dashboard reads (e.g. the history page) proceed against a
    # consistent snapshot while activity writes are in flight, instead of
    # blocking on the writer's lock up to the busy timeout. synchronous=NORMAL
    # is the safe/standard pairing for WAL. Both are best-effort; an old SQLite
    # or a read-only volume simply keeps the previous (rollback-journal) mode.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.Error:
        pass
    return conn


def _activity_max_rows() -> int:
    # Document `retention.max_rows` is the source of truth; the env var still overrides
    # for ops (doc 03 §1.2). _retention_setting handles the precedence + surfacing.
    value, _overridden = _retention_setting(
        "max_rows", _ACTIVITY_MAX_ROWS_ENV, _DEFAULT_ACTIVITY_MAX_ROWS
    )
    return value


def _activity_retention_days() -> int:
    value, _overridden = _retention_setting(
        "max_age_days", _ACTIVITY_RETENTION_DAYS_ENV, _DEFAULT_ACTIVITY_RETENTION_DAYS
    )
    return value


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
                        recipient_identity TEXT NOT NULL DEFAULT '',
                        destination_trust TEXT NOT NULL DEFAULT 'unknown',
                        decision_step TEXT NOT NULL DEFAULT '',
                        turn_id TEXT NOT NULL DEFAULT '',
                        user_prompt TEXT NOT NULL DEFAULT ''
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
                # Doc 03 §3.2: additive, nullable-with-default metadata columns. Existing
                # rows backfill to destination_trust='unknown' / decision_step='' (display
                # -safe; no historical migration, retention unchanged).
                if "destination_trust" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN destination_trust TEXT NOT NULL DEFAULT 'unknown'")
                if "decision_step" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN decision_step TEXT NOT NULL DEFAULT ''")
                # Turn grouping + opt-in prompt persistence: turn_id groups a user prompt's
                # actions; user_prompt holds the already-sanitized prompt only when the
                # protection.runtime.persist_prompts flag is on. Additive, display-safe
                # backfill ('') with the same retention as every other row.
                if "turn_id" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN turn_id TEXT NOT NULL DEFAULT ''")
                if "user_prompt" not in columns:
                    conn.execute("ALTER TABLE activity ADD COLUMN user_prompt TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_ts_idx ON activity(ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_decision_idx ON activity(decision)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_action_idx ON activity(action_family)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_destination_idx ON activity(destination)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_approval_idx ON activity(approval_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS activity_turn_idx ON activity(turn_id)")
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
                        legacy_destination TEXT NOT NULL DEFAULT '',
                        destination_trust TEXT NOT NULL DEFAULT 'unknown',
                        decision_step TEXT NOT NULL DEFAULT ''
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
                # destination_trust/decision_step (doc 03 §3.2) so a pending block keeps its
                # trust pill + decision step across a gateway restart, not just in memory.
                if "destination_trust" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN destination_trust TEXT NOT NULL DEFAULT 'unknown'")
                if "decision_step" not in pending_columns:
                    conn.execute("ALTER TABLE pending_approvals ADD COLUMN decision_step TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_session_idx ON pending_approvals(session_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_expires_idx ON pending_approvals(expires_at)")
                conn.execute("CREATE INDEX IF NOT EXISTS pending_approvals_cron_job_idx ON pending_approvals(cron_job_id)")
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS check_timings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ts INTEGER NOT NULL,
                        hook TEXT NOT NULL,
                        tool_name TEXT NOT NULL DEFAULT '',
                        duration_us INTEGER NOT NULL,
                        llm_invoked INTEGER NOT NULL DEFAULT 0,
                        blocked INTEGER NOT NULL DEFAULT 0
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS check_timings_ts_idx ON check_timings(ts)")
                conn.execute("CREATE INDEX IF NOT EXISTS check_timings_hook_idx ON check_timings(hook)")
                # Trusted-destinations picker (recent-blocks source): safe command prefixes
                # (program + script/subcommand only, never flag values) for terminal commands
                # that gated. Shared across the gateway/dashboard processes via this DB.
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS command_suggestions (
                        prefix TEXT PRIMARY KEY,
                        last_ts INTEGER NOT NULL,
                        hits INTEGER NOT NULL DEFAULT 1
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS command_suggestions_ts_idx ON command_suggestions(last_ts)")
            _ACTIVITY_DB_INITIALIZED = True
        except Exception as exc:
            logger.debug("%s: failed to initialize activity db: %s", _PLUGIN_NAME, exc)


# Allowed destination-trust labels persisted on a row (doc 03 §3.2). A garbage / empty
# label fails closed to "unknown" so the column is always a clean enum, never payload.
_DESTINATION_TRUST_LABELS = {
    "self",
    "trusted_recipient",
    "trusted",
    "local_system",
    "model_provider",
    "external",
    "public",
    "unknown",
}


def _normalize_destination_trust_label(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text == "trusted_recipient":
        text = "trusted"
    return text if text in _DESTINATION_TRUST_LABELS else "unknown"


def _normalize_decision_step_label(value: Any) -> str:
    # A short, charset-bounded step label (e.g. "step3_intra_boundary"); never payload.
    text = re.sub(r"[^a-z0-9_:.\- ]+", "", str(value or "").strip().lower())
    return text[:60]


def _record_command_suggestion(prefix: str) -> None:
    """Remember a safe command prefix that just gated (Trusted-destinations picker)."""
    text = str(prefix or "").strip()
    if not text:
        return
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO command_suggestions (prefix, last_ts, hits) VALUES (?, ?, 1)
                ON CONFLICT(prefix) DO UPDATE SET last_ts=excluded.last_ts, hits=hits+1
                """,
                (text[:400], int(_now())),
            )
    except Exception as exc:
        logger.debug("%s: failed to record command suggestion: %s", _PLUGIN_NAME, exc)


def _recent_command_suggestions(limit: int = 20) -> list[dict[str, Any]]:
    """Recently gated command prefixes, newest first (Trusted-destinations picker)."""
    _ensure_activity_db()
    try:
        with _activity_connect() as conn:
            rows = conn.execute(
                "SELECT prefix, last_ts, hits FROM command_suggestions ORDER BY last_ts DESC LIMIT ?",
                (max(1, min(int(limit or 20), 100)),),
            ).fetchall()
        return [
            {"prefix": str(row["prefix"]), "last_ts": int(row["last_ts"]), "hits": int(row["hits"])}
            for row in rows
        ]
    except Exception as exc:
        logger.debug("%s: failed to read command suggestions: %s", _PLUGIN_NAME, exc)
        return []


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
    destination_trust: str = "",
    decision_step: str = "",
) -> None:
    """Persist sanitized activity metadata for dashboard/debugging.

    ``destination_trust`` (an enum label: self/trusted/external/public/unknown) and
    ``decision_step`` (a decide() step label) are METADATA ONLY — no payload content
    (doc 03 §5 / invariant #5). They default to display-safe values for callers/old rows.
    """
    if decision not in _ACTIVITY_DECISIONS:
        decision = "allowed"
    if not module:
        if decision in {"security_blocked", "security_suppressed"}:
            module = "security"
        elif decision in {"allowed", "auto_approved", "blocked", "denied", "manual_approved", "privacy_off_allowed", "tainted"}:
            module = "privacy"
    safe_classes = sorted(str(cls) for cls in (data_classes or []) if str(cls) in _ALL_PRIVACY_CLASSES)
    sid = _normalize_session_id(session_id)
    # Turn grouping is always on (cheap random label). The prompt is persisted ONLY when
    # the operator opts in; both sources (owner request / cron instruction) are already
    # sanitized by _redact_command_for_llm, and we re-clamp defensively. Unauthenticated
    # senders / non-cron sessions yield "" from both, so nothing is persisted for them.
    turn_id = _current_turn_id(sid)
    user_prompt = ""
    if _persist_prompts_enabled():
        user_prompt = (_recent_user_request_for_owner(owner_hash) or _cron_instruction_for_session(sid))[:500]
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO activity (
                    ts, decision, mode, session_label, session_hash, owner_hash,
                    tool_name, action_family, destination, data_classes, reason,
                    approval_id, rule_id, rule_source, action_detail,
                    module, rule_effect, rule_scope, purpose, recipient_identity,
                    destination_trust, decision_step, turn_id, user_prompt
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    _normalize_destination_trust_label(destination_trust),
                    _normalize_decision_step_label(decision_step),
                    str(turn_id or "")[:60],
                    str(user_prompt or "")[:500],
                ),
            )
        _prune_activity_db()
    except Exception as exc:
        logger.debug("%s: failed to write activity event: %s", _PLUGIN_NAME, exc)


def _perf_begin_check() -> None:
    """Reset per-thread timing scratch state at the start of a hook check."""
    _CHECK_TIMING_STATE.llm_invoked = False


def _perf_mark_llm_invoked() -> None:
    """Flag that the current hook check invoked the LLM verifier (its main cost)."""
    _CHECK_TIMING_STATE.llm_invoked = True


def _perf_llm_invoked() -> bool:
    return bool(getattr(_CHECK_TIMING_STATE, "llm_invoked", False))


def _record_check_timing(
    hook: str,
    *,
    duration_us: int,
    tool_name: str = "",
    llm_invoked: bool = False,
    blocked: bool = False,
) -> None:
    """Persist sanitized per-check timing for the Performance dashboard."""
    try:
        _ensure_activity_db()
        with _activity_connect() as conn:
            conn.execute(
                """
                INSERT INTO check_timings (ts, hook, tool_name, duration_us, llm_invoked, blocked)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    int(_now()),
                    str(hook or "")[:60],
                    str(tool_name or "")[:120],
                    max(0, int(duration_us)),
                    1 if llm_invoked else 0,
                    1 if blocked else 0,
                ),
            )
    except Exception as exc:
        logger.debug("%s: failed to write check timing: %s", _PLUGIN_NAME, exc)


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
                conn.execute("DELETE FROM check_timings WHERE ts < ?", (cutoff,))
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
                conn.execute(
                    """
                    DELETE FROM check_timings
                    WHERE id NOT IN (
                        SELECT id FROM check_timings ORDER BY ts DESC, id DESC LIMIT ?
                    )
                    """,
                    (max_rows,),
                )
            remaining = int(conn.execute("SELECT COUNT(*) FROM activity").fetchone()[0])
        if deleted:
            # The table is bounded by row count / retention, so its file size
            # self-limits at steady state -- a full VACUUM after every prune is
            # unnecessary churn and (before WAL) was the main source of the
            # multi-second exclusive lock that stalled dashboard reads. Just
            # truncate the WAL so it doesn't grow unbounded; this does not block
            # concurrent readers the way VACUUM does.
            with _activity_connect() as conn:
                conn.isolation_level = None
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                except sqlite3.Error:
                    pass
    except Exception as exc:
        logger.debug("%s: failed to prune activity db: %s", _PLUGIN_NAME, exc)
    return {"deleted": int(deleted or 0), "remaining": remaining}
