# AGENTS.md

Guidance for coding agents working in this repository.

## Scope

This file applies to the entire `hermes-guardian` repository.

Hermes Guardian is a Python user plugin for Hermes Agent. It adds two policy
layers around Hermes-mediated activity:

- A non-approvable Security Module for credential, account-security, OTP,
  magic-link, reset-link, security-alert, and similar sensitive content.
- A Privacy Module that taints sessions after private sources are observed and
  approval-gates classified egress by action family, destination, data class,
  owner/session/cron scope, and privacy rules.

Treat this repository as security-sensitive code. Prefer small, test-backed
changes that preserve fail-closed behavior and metadata-only storage.

## Current Project Shape

The plugin is distributed as a Hermes user plugin (cloned into
`~/.hermes/plugins/hermes-guardian` and loaded by absolute path), not as a
pip-installable package, so there is no `[build-system]` and no build step.

`pyproject.toml` provides project metadata, a manifest of optional dependencies
(`dashboard`, `telegram`, `dev` extras), and pytest configuration. The core
plugin is pure standard-library Python with no runtime dependencies.
`requirements-dev.txt` pins the dev/CI dependencies (currently just `pytest`).
There is no full transitive lockfile.

CI installs `requirements-dev.txt` and runs:

```bash
python -m pytest -q
```

GitHub Actions runs the test suite on Python 3.11, 3.12, and 3.13. Optional
runtime integrations may import FastAPI or Telegram libraries, but
`dashboard/plugin_api.py` includes import-only fallbacks for tests without
FastAPI installed.

Important local/runtime files are intentionally ignored by git:

- `guardian-rules.json`: local privacy/security rule configuration.
- `activity.sqlite3` and SQLite sidecar files: sanitized activity and pending
  approval storage.
- `.guardian-hmac-key`: local HMAC key for exact-argument approval binding.
- `.unsafe-diagnostics`: opt-in unsafe diagnostic flag.
- `__pycache__/`, `.pytest_cache/`, coverage artifacts.

Do not treat ignored runtime state as source. Do not commit, rewrite, or inspect
runtime state unless the task explicitly requires it.

## Repository Map

- `plugin.yaml`: Hermes plugin manifest. Keep hook names aligned with
  `core.register`.
- `__init__.py`: Hermes-facing facade. It loads `core.py` by absolute path and
  bridges private globals/functions so tests and Hermes imports can monkeypatch
  state.
- `core.py`: composition root and shared global namespace. It defines constants,
  mutable process state, regexes, helper loaders, and `register(ctx)`.
- `hooks.py`: hook orchestration only. Security checks run before privacy checks;
  hook-level exceptions fail closed where data could leak.
- `security/`: reusable sensitive-content scanner plus core-facing wrappers.
- `privacy/`: taint tracking, tool/action classification, LLM verifier helpers,
  rule loading/mutation, approvals, and sanitized action details.
- `runtime/`: shared cross-hook context, SQLite activity storage, activity query
  shaping/grouping, and session lifecycle cleanup.
- `ui/`: `/guardian` slash command handling, CLI command setup, dashboard action
  adapters, and shared presentation formatting.
- `dashboard/`: Hermes dashboard manifest, FastAPI plugin API adapter, and
  checked-in static dashboard assets in `dashboard/dist/`.
- `integrations/`: cron failure notification support through Hermes CLI and
  optional Telegram copy-button delivery.
- `language_packs/`: declarative semantic detection packs. English and Spanish
  are bundled and enabled by default.
- `tests/`: behavior-focused pytest suite. `tests/support.py` loads the plugin
  from `__init__.py` and redirects rule/activity/HMAC state into `/tmp`.
- `README.md`: user-facing documentation and operational model.
- `theory.md`: defense theory, assumptions, limitations, and comparisons.

The `.agents/` and `.codex/` directories currently contain no repository-local
agent files.

## Loader And Namespace Rules

`core.py` deliberately exec-loads most module files into one shared global
namespace via `_load_core_logic()`. Files under `privacy/`, `runtime/`, `ui/`,
`integrations/`, and `hooks.py` often reference globals defined in `core.py` or
in modules loaded earlier. They are not normal isolated modules when executed by
the plugin.

When editing this code:

- Preserve the `_load_core_logic()` load order unless you have traced every
  cross-file dependency and updated tests.
- Do not casually add normal relative imports between exec-loaded modules.
  Prefer the existing shared-global style unless doing a deliberate loader
  refactor.
- Keep reusable standalone imports in modules that are imported normally, such
  as `security/scanner.py`, `language_packs/runtime.py`, and
  `ui/presentation.py`.
- If a function must be monkeypatched through the facade in tests, ensure
  `__init__.py` can bridge it correctly.
- Dashboard API loading must continue to work outside the plugin current working
  directory; see `tests/test_hooks_registration.py`.

## Core Security Invariants

Preserve these invariants unless the user explicitly asks for a model change and
the tests/docs are updated accordingly:

- Security-sensitive content is non-approvable. Privacy allow rules, approval
  commands, and `privacy.tools` overrides must not bypass Security Module
  blocks/suppression or intrinsic same-call hard blocks.
- Unrecognized non-MCP tools fail closed under taint by default (`unknown_tools`
  = `gate`, classified `tool_unknown`). Do not regress this to an allow fallback;
  the only opt-out is the explicit `allow` mode, which raises a risk banner.
- Hook failures that could leak private or sensitive data fail closed:
  `pre_tool_call` blocks, `transform_tool_result` suppresses, and tainted final
  output errors suppress when appropriate.
- Security checks run before privacy checks in `pre_tool_call`.
- Tool results are observed for privacy taint before Security Module result
  scrubbing, so taint is preserved even when sensitive records are suppressed.
- Persistent state stores sanitized metadata only. Never store raw email bodies,
  message text, typed browser values, document contents, file contents, full
  tokenized URLs, credentials, or raw tool arguments.
- Approval IDs are short-lived four-digit codes, but one-time approvals are
  bound to an HMAC fingerprint of the exact tool arguments.
- Session taint is intentionally coarse. Do not weaken it to content-only
  detection for known private source tools.
- Unknown or ambiguous egress surfaces should be classified conservatively,
  especially MCP tools, terminal/code execution, browser console/CDP, model
  APIs, and final responses.
- `privacy.mode=off` disables private-egress approval checks only. It must not
  disable Security Module blocking/suppression.
- `read-only` mode should auto-approve only metadata-verified low-risk actions.
  Anything uncertain falls back to manual approval.
- `llm` mode sends the verifier the real action payload (`action_arguments`) so
  it can judge content against intent. This is deliberate: the verifier is the
  same model/provider (`ctx.llm`) the agent already uses to process all of this
  content, so redacting it from the verifier protects nothing against the
  provider while crippling its judgment. The boundary still preserved is
  at-rest/storage, not model visibility: security-sensitive content is still
  stripped from the payload (`_payload_string_for_llm` — and such args are
  hard-blocked upstream anyway), credential-shaped tokens are removed, and the
  verdict rationale is sanitized (`_sanitize_rationale`) before it is shown or
  stored. Persistent state stays metadata-only regardless (see below). This
  relaxation assumes the configured verifier LLM shares the agent's trust
  boundary; the owner is responsible for which LLMs they connect.
  The one conversation-derived input
  is `user_request_context`: a sanitized excerpt of the most recent inbound
  message from an authenticated session owner (CLI or configured gateway owner),
  captured at gateway dispatch after the Security Module clears it. It is the
  user turn only (never system prompt, tool results, or model output), redacted,
  held in volatile owner-keyed state, never persisted, and treated as
  authorization evidence only — it must not override `risk_level` or absolute
  deny rules, and group/cron/unauthenticated senders must never populate it.
  Both context channels are gated by privacy booleans: `llm_user_context`
  (default on) gates the owner channel above; `llm_cron_context` (default off)
  gates a parallel `cron_context` channel that supplies a cron job's own
  sanitized stored instruction. Because cron runs unattended, a cron job may
  never self-authorize high-risk egress: a high-risk `allow` verdict on a cron
  session is always downgraded to manual approval, even with cron context on.
  Authorization is data-class-scoped, not action-only. The verifier input
  distinguishes ambient `classes_in_scope` (what the session has read) from
  per-argument `source_classes` and `exported_source_classes` (object-level
  provenance over this call's payload — what is actually being exported). These
  are sanitized class labels, never raw content. Context channels authorize only
  the data classes intrinsic to the request, so authorization cannot launder an
  export whose provenance shows content from a source the request did not call
  for (e.g. a calendar event submitted into an email subscription form).
- Final model responses are egress. Tainted responses to owner-private CLI/DM
  destinations may pass; tainted responses to group, cron, or unknown
  destinations are suppressed.
- Cron failure notifications include safe metadata only and are sent at most
  once per cron session.

## Policy And State Files

`guardian-rules.json` is organized into the five IA concepts, in `decide` order —
`whats_yours` → `sharing` → `review` → `protection`, plus `version`/meta (Activity
is pure output, so it has no config block). The on-disk **v4 schema** is the only
shape: there is no back-compat, no version detection, and the loader does NOT branch
on `version`. An old-shape file is not migrated — it fails closed to strict with a
clear log line (`"unrecognized config shape — re-author per the v4 schema"`) — and is
re-authored to the schema below.

```json
{
  "version": 4,
  "whats_yours": {
    "stores": ["store:files", "store:notes", "store:calendar", "store:drive", "draft:*"],
    "identities": [],
    "hosts": []
  },
  "sharing": {
    "trusted_recipients": [
      {"identity": "ally@example.com", "classes": ["communications"], "note": ""}
    ],
    "rules": [],
    "outward": {"extra": []}
  },
  "review": {
    "mode": "strict",
    "owner_context": true,
    "cron_context": false,
    "verifier_model": ""
  },
  "protection": {
    "security": {
      "account_security_content": true,
      "credential_content": true,
      "sensitive_links": true,
      "intrinsic_exfiltration": true,
      "private_network_reads": true
    },
    "unknown_tools": "gate",
    "tools": [
      {
        "id": "tool_ab12cd34",
        "match": "mcp_acme_*",
        "taints": ["email"],
        "egress": "ignore",
        "destination": "",
        "enabled": true,
        "note": "acme MCP server is a trusted read"
      }
    ],
    "language_packs": {"en": true},
    "retention": {"max_rows": 100, "max_age_days": 7},
    "runtime": {"dashboard_mutations": "auto"}
  }
}
```

Internally, `privacy/rules.py` keeps the SAME normalized in-memory structure the
engine has always consumed (`privacy.{mode,unknown_tools,llm_user_context,
llm_cron_context,llm_verifier_model,rules,tools}`, `self`, `trusted_recipients`,
`outward_sharing`, `security.rules`, `language_packs.enabled`, `retention`,
`dashboard`). Only the parsing front-end changed: `_normalize_privacy_config` parses
the v4 file into that internal structure, `_serialize_config_to_v4` encodes it back
out, and `_normalize_internal_config` re-normalizes the internal structure on save.
`decide`, `classify`, and `resolve_destination_trust` never notice the file reshape.
The conceptual file→internal map (doc 04 §3): `whats_yours.stores/.identities/.hosts`
→ `self.destinations/.identities/.hosts`; `sharing.trusted_recipients` →
`trusted_recipients.entries`; `sharing.rules` → `privacy.rules`;
`sharing.outward.extra` → `outward_sharing.extra` (builtin subtypes are code-owned and
never read from / written to config); `review.mode/.owner_context/.cron_context/
.verifier_model` → `privacy.mode/.llm_user_context/.llm_cron_context/
.llm_verifier_model`; `protection.security` (a `{id: bool}` toggle map)
→ `security.rules`; `protection.unknown_tools` → `privacy.unknown_tools`;
`protection.tools` → `privacy.tools`; `protection.language_packs`
(a `{id: bool}` toggle map) → `language_packs.enabled`; `protection.retention` →
`retention`; `protection.runtime` → `dashboard`.

`protection.unknown_tools` is `gate` (default) or `allow`. In `gate`, an unrecognized
tool (not a known built-in, not covered by a `privacy.tools` override) is classified
as `tool_unknown` and gated under taint, mirroring `mcp_unknown`. `allow` restores
the legacy permissive behavior and raises a runtime risk banner.

The key names below (`privacy.tools`, `privacy.llm_*`, `privacy.llm_verifier_model`)
are the INTERNAL in-memory keys the engine and mutators use; on disk they live under
the v4 `protection.tools` / `review.owner_context` / `review.cron_context` /
`review.verifier_model` keys per the file→internal map above.

`privacy.tools` is the user-managed tool override registry. Each entry has a `match`
(exact tool name or a single trailing-`*` prefix), optional `taints` (source classes
applied when the tool's result is observed), and optional `egress`: `ignore` (treat
as a safe non-sink), `gate` (force `tool_unknown` gating), or a concrete action
family. Overrides take precedence over built-in classification but are privacy-layer
only: they never bypass the Security Module or intrinsic same-call hard blocks.

`privacy.llm_user_context` (default `true`) and `privacy.llm_cron_context`
(default `false`) are booleans gating the two `llm`-mode authorization-evidence
channels. They are normalized by `_config_bool` and exposed through
`_llm_user_context_enabled` / `_llm_cron_context_enabled` and the
`_set_llm_user_context` / `_set_llm_cron_context` setters.

`privacy.llm_verifier_model` (default `""`) optionally pins the llm-mode verifier
to a faster model than the agent's, passed to `complete_structured(model=...)`.
Hermes gates per-plugin model selection, so it only takes effect when the operator
sets `plugins.entries.hermes-guardian.llm.allow_model_override: true` in
`config.yaml`. `_llm_security_verdict` is fail-safe: if the override is rejected or
the model errors, it retries once on the default model rather than failing closed.
The dashboard renders this as a dropdown: `_verifier_model_options` best-effort
reads the operator's `allowed_models` for this plugin from `$HERMES_HOME/config.yaml`
(optional PyYAML, guarded; only model strings are extracted, nothing is stored) and
the snapshot exposes them as `llm_verifier_model_options`. No grant -> no options.
Guardian also keeps a short-TTL, deny-only verdict cache (`_LLM_DENY_VERDICT_CACHE`)
keyed by session+owner+fingerprint; only denials are cached, so a stale hit can
never become a false allow.

Rule mutation helpers must preserve privacy rules, security rule settings, the
`unknown_tools` mode, the `llm_user_context` / `llm_cron_context` flags,
`llm_verifier_model`, and `tools` overrides. This is covered by
`tests/test_security_rules_config.py`, `tests/test_tool_overrides.py`,
`tests/test_llm_context_settings.py`, and `tests/test_verifier_model.py`.

`activity.sqlite3` has three logical roles:

- `activity`: sanitized audit/debug rows for dashboard, history, and tests.
- `pending_approvals`: short-lived approval records, including cron approvals
  resolvable from another process.
- `check_timings`: sanitized per-hook timing samples (hook, tool name, duration,
  `llm_invoked`, `blocked`) recorded by `_record_check_timing` from the hook
  wrappers in `hooks.py`, aggregated by `_performance_summary` for the dashboard
  Performance tab. Timing is best-effort and must never alter a check's result.
  Pruned with the same retention/row caps as `activity`.

Schema changes should be backward-compatible through `ALTER TABLE` checks in
`runtime/activity_store.py`; add migration tests when adding columns.

## Action Classification Notes

The main egress classifier lives in `privacy/tool_policy.py`.

Important classifier families include:

- `message_send`, `message_list`
- `mcp_write`, `mcp_read_query`, `mcp_unknown`
- `browser_read`, `browser_type`, `browser_click`, `browser_press`,
  `browser_dialog`, `browser_console`, `browser_cdp`
- `terminal_exec`, `local_write`, `cron_write`, `kanban_write`,
  `homeassistant_write`, `tool_write`, `computer_use`
- `web_read`, `web_api`, `model_api`, `delegate_task`
- `tool_unknown` (secure-by-default fallback for unrecognized non-MCP tools under
  taint; see `_recognized_builtin_tool` and `_unknown_tools_mode`)
- `final_response`

`_recognized_builtin_tool` separates a known built-in whose specific call is a
read/no-op (which stays allowed) from a genuinely unknown tool (gated under taint).
When you add a new built-in tool family, also add it there so its read/no-op calls
are not mistaken for unknown sinks.

When adding a new Hermes tool family:

- Decide whether it is a source, sink, both, or metadata-only.
- Add source taint rules if reading private data should taint by tool name.
- Add egress classification before generic write fallbacks if the destination
  or action family matters.
- Sanitize action detail output in `privacy/action_details.py`.
- Add activity/dashboard presentation tests if the new action appears in
  history.
- Add adversarial tests for same-call source-and-sink shapes when relevant.

## Dashboard Rules

The dashboard is integrated through `dashboard/manifest.json` at `/guardian`.
API routes are mounted under `/api/plugins/hermes-guardian/`.

`guardian.example.com` and the standalone
`hermes-guardian-dashboard.service` are retired. Do not use, restart, or debug
that standalone service for normal dashboard work. The supported UI surface is
the Hermes dashboard plugin tab served by `hermes-dashboard.service`.

Keep `dashboard/plugin_api.py` as a thin adapter:

- It should load the plugin facade by absolute path.
- It should call existing `_dashboard_*` action functions for policy changes.
- It should not implement separate policy mutation semantics.
- It should keep mutation guards:
  `HERMES_GUARDIAN_DASHBOARD_MUTATIONS=0` disables mutations, and
  `HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN` requires
  `x-hermes-guardian-token`.
- It should require explicit confirmation for the weakening actions: privacy mode
  `off` (`privacy-off`), global wildcard allow rules (`wildcard-allow`),
  `unknown_tools=allow` (`unknown-tools-allow`), `egress:ignore` tool overrides
  (`tool-ignore`), and enabling cron context (`cron-context-on`).
- Tool override, unknown-tools, and LLM-context routes (`POST /tools`,
  `PATCH /tools/{id}`, `DELETE /tools/{id}`, `POST /privacy/unknown-tools`,
  `POST /privacy/user-context`, `POST /privacy/cron-context`,
  `POST /privacy/verifier-model`) are thin adapters over the `privacy/rules.py`
  mutators, like the other `_dashboard_*` actions.

The dashboard is a React + TypeScript app. Source lives in `dashboard/src/`;
`dashboard/dist/index.js` and `dashboard/dist/style.css` are committed build
artifacts. Edit the source, then rebuild with `bun run build` (or, if `bun` is
unavailable, the equivalent `esbuild` bundle: IIFE format, `React.createElement`
JSX factory, React kept external via `window.__HERMES_PLUGIN_SDK__`). Preserve
the Hermes plugin SDK usage and the API route contract.

## Language Packs

Language packs are declarative `PACK` dictionaries. Required keys are validated
in `language_packs/runtime.py`.

When adding or changing a pack:

- Keep English available even when the environment requests other packs.
- Add or update tests in `tests/test_language_packs.py`.
- Add multilingual security coverage in `tests/test_multilingual_security.py`
  for password reset/recovery, auth-code phrases, account/security alerts,
  private field labels, browser private-context hints, redaction markers, and
  sensitive-link terms.
- Avoid regex syntax inside pack phrases; runtime compiles them as escaped
  literal phrases.

## Slash And CLI Commands

Slash command behavior lives in `ui/commands.py`.

Important user-facing commands:

Commands are grouped into the five IA concepts in `decide` order
(`activity`/`mine`/`sharing`/`review`/`protection`), with `status`/`why` on
top. The old top-level names (`self`, `rules`, the bare outward `sharing`,
`security`, `tools`, `language-packs`, `privacy`, `history`, `failures`,
`debug`) are removed, not aliased — each capability survives via the same
underlying handler under its new group.

```text
/guardian status
/guardian why <id>
/guardian activity [limit]
/guardian activity failures [limit]
/guardian approvals
/guardian approve <id> [once|session|always]
/guardian deny <id>
/guardian clear-taint
/guardian mine
/guardian mine add|remove destination|identity|host <value>
/guardian check <destination|recipient>
/guardian sharing
/guardian sharing trusted add|remove <identity> [classes=a+b] [note=<text>]
/guardian sharing rule add|delete|enable|disable|move ...
/guardian sharing outward add|remove <subtype>
/guardian sharing preview <action> <destination> <class>
/guardian review mode strict|read-only|llm|off
/guardian review owner-context on|off
/guardian review cron-context on|off
/guardian review verifier-model <model_id|default>
/guardian protection security enable|disable <rule_id>
/guardian protection tool set <match> [taints=a+b] [egress=ignore|gate|<family>] [destination=<dest>] [note=<text>]
/guardian protection tool delete <match_or_id>
/guardian protection tool enable|disable <id_or_match>
/guardian protection unknown-tools gate|allow
/guardian protection language-packs enable|disable <pack_id>
```

`/guardian deny` is an alias for `dismiss`. `hermes guardian dashboard
status|url|prune` is the CLI surface.

Owner checks matter. Non-CLI slash users can mutate global config only when
their hashed identity is in configured owner env vars. Do not loosen these
checks without tests.

## Environment Variables

Current `HERMES_GUARDIAN_*` variables include:

- `HERMES_GUARDIAN_ACTIVITY_MAX_ROWS`
- `HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS`
- `HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS`
- `HERMES_GUARDIAN_HISTORY_TIMEZONE`
- `HERMES_GUARDIAN_CRON_NOTIFY_TO`
- `HERMES_GUARDIAN_HERMES_CLI`
- `HERMES_GUARDIAN_DASHBOARD_MUTATIONS`
- `HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN`
- `HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS`
- `HERMES_GUARDIAN_LANGUAGE_PACKS`

Tests intentionally delete legacy variables such as
`HERMES_GUARDIAN_ALLOWLIST` and `HERMES_GUARDIAN_PRIVACY`. Do not reintroduce
legacy env behavior unless that is a deliberate compatibility task with tests.

Gateway owner helpers also read:

- `TELEGRAM_ALLOWED_USERS`
- `TELEGRAM_GROUP_ALLOWED_USERS`
- `DISCORD_ALLOWED_USERS`

Cron Telegram delivery may read Telegram bot/channel/thread variables through
the integration code.

## Testing Guidance

Run the full suite before finishing broad or security-sensitive changes:

```bash
python -m pytest -q
```

Use focused tests while iterating:

- Security scanning/suppression:
  `python -m pytest -q tests/test_security.py tests/test_security_rules_config.py`
- Privacy taint and egress classification:
  `python -m pytest -q tests/test_privacy_egress.py tests/test_privacy_modes.py`
- LLM/read-only/public-read behavior:
  `python -m pytest -q tests/test_llm_and_public_reads.py`
- Adversarial and fail-closed behavior:
  `python -m pytest -q tests/test_adversarial_exfiltration.py`
- Approvals and cross-process persistence:
  `python -m pytest -q tests/test_approvals.py`
- Slash commands and history formatting:
  `python -m pytest -q tests/test_commands_debug_history.py tests/test_commands_rules_failures.py`
- Dashboard policy/activity/API behavior:
  `python -m pytest -q tests/test_dashboard_policy.py tests/test_dashboard_activity.py tests/test_hooks_registration.py`
- Cron notifications:
  `python -m pytest -q tests/test_cron_notifications.py`
- Language packs:
  `python -m pytest -q tests/test_language_packs.py tests/test_multilingual_security.py`

Tests load fresh plugin modules and redirect persistent state into `/tmp`. If a
test mutates module globals, prefer using `tests/support.py` helpers rather than
sharing process-global state across tests.

## Development Practices

- Use `rg`/`rg --files` for repository search.
- Keep edits tightly scoped. This repository relies on security invariants more
  than broad refactors.
- Prefer deterministic checks before optional LLM judgment.
- Use structured JSON parsing/serialization for policy files.
- Keep action details and activity reasons sanitized and length-bounded.
- Preserve ASCII unless editing existing multilingual pack phrases.
- Add tests for every classifier, policy, storage, or dashboard API behavior
  change.
- Update `README.md` when user-facing commands, modes, env vars, security
  rules, dashboard routes, or operational semantics change.
- Update `theory.md` only when the defense model, assumptions, or limitations
  change.
- Do not restart the Hermes gateway, run `systemctl`, or modify live
  `~/.hermes` state unless the user explicitly asks.

## Common Pitfalls

- Adding a normal import that works when a file is imported directly but fails
  when `core.py` exec-loads it.
- Storing raw tool args or content in activity rows, approval records, dashboard
  payloads, or notification messages. (The `llm` verifier input is the deliberate
  exception — it receives the real payload — but its output rationale and all
  persisted state must still be sanitized.)
- Letting privacy allow rules bypass Security Module findings.
- Treating unknown MCP tools as safe reads under taint.
- Allowing URL paths, query strings, search text, browser typed text, shell
  commands, or final responses to carry tainted data without classification.
- Clearing taint on `on_session_end`; current behavior intentionally prunes
  volatile state only because Hermes may fire it at run-conversation
  boundaries.
- Forgetting to preserve security rule config when saving privacy mode/rules.
- Forking dashboard mutation logic away from slash/CLI mutation logic.
