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
- `llm` mode must send only sanitized metadata to the verifier. Raw private
  content must not enter `_llm_verdict_input`.
- Final model responses are egress. Tainted responses to owner-private CLI/DM
  destinations may pass; tainted responses to group, cron, or unknown
  destinations are suppressed.
- Cron failure notifications include safe metadata only and are sent at most
  once per cron session.

## Policy And State Files

`guardian-rules.json` uses this normalized top-level shape:

```json
{
  "version": 1,
  "privacy": {
    "mode": "strict",
    "unknown_tools": "gate",
    "rules": [],
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
    ]
  },
  "security": {
    "rules": [
      {"id": "account_security_content", "enabled": true},
      {"id": "credential_content", "enabled": true},
      {"id": "sensitive_links", "enabled": true},
      {"id": "intrinsic_exfiltration", "enabled": true},
      {"id": "private_network_reads", "enabled": true}
    ]
  }
}
```

`privacy.unknown_tools` is `gate` (default) or `allow`. In `gate`, an unrecognized
tool (not a known built-in, not covered by a `privacy.tools` override) is classified
as `tool_unknown` and gated under taint, mirroring `mcp_unknown`. `allow` restores
the legacy permissive behavior and raises a runtime risk banner.

`privacy.tools` is the user-managed tool override registry. Each entry has a `match`
(exact tool name or a single trailing-`*` prefix), optional `taints` (source classes
applied when the tool's result is observed), and optional `egress`: `ignore` (treat
as a safe non-sink), `gate` (force `tool_unknown` gating), or a concrete action
family. Overrides take precedence over built-in classification but are privacy-layer
only: they never bypass the Security Module or intrinsic same-call hard blocks.

Rule mutation helpers must preserve privacy rules, security rule settings, the
`unknown_tools` mode, and `tools` overrides. This is covered by
`tests/test_security_rules_config.py` and `tests/test_tool_overrides.py`.

`activity.sqlite3` has two logical roles:

- `activity`: sanitized audit/debug rows for dashboard, history, and tests.
- `pending_approvals`: short-lived approval records, including cron approvals
  resolvable from another process.

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

`guardian.hermes.kevinpei.com` and the standalone
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
  `unknown_tools=allow` (`unknown-tools-allow`), and `egress:ignore` tool overrides
  (`tool-ignore`).
- Tool override and unknown-tools routes (`POST /tools`, `PATCH /tools/{id}`,
  `DELETE /tools/{id}`, `POST /privacy/unknown-tools`) are thin adapters over the
  `privacy/rules.py` mutators, like the other `_dashboard_*` actions.

The static dashboard files are checked in under `dashboard/dist/`. There is no
frontend source build pipeline in this repository. If editing those files,
preserve the Hermes plugin SDK usage (`window.__HERMES_PLUGIN_SDK__`) and API
route contract.

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

```text
/guardian status
/guardian approve <id> once|session|always
/guardian dismiss <id>
/guardian clear-taint
/guardian rules
/guardian rule add|delete|enable|disable|move ...
/guardian privacy mode strict|read-only|llm|off
/guardian privacy unknown-tools gate|allow
/guardian tools
/guardian tool set <match> [taints=a+b] [egress=ignore|gate|<family>] [destination=<dest>] [note=<text>]
/guardian tool delete <match_or_id>
/guardian tool enable|disable <id_or_match>
/guardian security enable|disable <rule_id>
/guardian history [limit]
/guardian failures [limit]
/guardian debug action=<family> destination=<dest> classes=<class+class>
```

`/guardian deny` is an alias for dismiss. `hermes guardian dashboard
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
  payloads, notification messages, or LLM verifier input.
- Letting privacy allow rules bypass Security Module findings.
- Treating unknown MCP tools as safe reads under taint.
- Allowing URL paths, query strings, search text, browser typed text, shell
  commands, or final responses to carry tainted data without classification.
- Clearing taint on `on_session_end`; current behavior intentionally prunes
  volatile state only because Hermes may fire it at run-conversation
  boundaries.
- Forgetting to preserve security rule config when saving privacy mode/rules.
- Forking dashboard mutation logic away from slash/CLI mutation logic.
