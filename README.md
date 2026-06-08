# Hermes Guardian

[![Tests](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Hermes Plugin](https://img.shields.io/badge/Hermes-plugin-0f766e.svg)](https://github.com/NousResearch/hermes-agent)

Security and privacy policy controls for personal Hermes agents.

Hermes Guardian is a user plugin for
[Hermes Agent](https://github.com/NousResearch/hermes-agent). It lets an agent
read useful private context, such as email, contacts, documents, memory,
calendar events, browser state, and local system output, while controlling where
that context can leave through Hermes-mediated tools.

Guardian adds two policy layers:

- **Security Module**: non-approvable blocking and suppression for credentials,
  OTPs, magic links, password resets, security alerts, sensitive account links,
  and similar access-sensitive content.
- **Privacy Module**: session taint, egress classification, privacy modes,
  optional declassification rules, and metadata-only activity history for
  private data flows.

## Features

- Blocks or suppresses credentials, OTPs, reset links, magic links, account
  verification links, security alerts, private keys, bearer tokens, JWTs,
  cookies, and known upstream redaction placeholders.
- Taints sessions after private sources are read, including email, contacts,
  memory, documents, calendar, local system output, and private browser input.
- Classifies common Hermes egress families such as messaging, MCP writes,
  browser typing/submission, terminal execution, local writes, cron writes,
  web/API calls, model APIs, delegated tasks, and final responses.
- Uses `strict`, `read-only`, and `llm` privacy modes as the core egress policy
  engine, with `llm` as the default.
- Supports optional allow/deny rules for explicit user customization and
  declassification.
- Stores sanitized activity rows and pending approvals in local SQLite.
- Binds one-time approvals to an HMAC fingerprint of the exact tool arguments.
- Provides slash commands, CLI maintenance commands, and a Hermes dashboard tab.
- Sends sanitized cron failure notifications at most once per cron run.
- Uses declarative multilingual language packs for semantic security detection.

## Quickstart

Clone the plugin into the Hermes user plugin directory:

```bash
mkdir -p ~/.hermes/plugins
git clone git@github.com:kpsuperplane/hermes-guardian.git ~/.hermes/plugins/hermes-guardian
```

Enable it in `~/.hermes/config.yaml`:

```yaml
plugins:
  enabled:
    - hermes-guardian
```

Restart the Hermes gateway:

```bash
systemctl restart hermes-gateway.service
```

Verify Hermes can see the plugin:

```bash
hermes plugins list --plain --no-bundled
```

Expected result:

```text
enabled      git      3.0.0    hermes-guardian
```

Guardian registers a `/guardian` slash command and an integrated dashboard tab
at `/guardian`.

## Why Guardian?

Modern agents need private context to be useful. They also have many outbound
surfaces: messages, MCP writes, browser forms, URLs, search queries, terminal
commands, code execution, model APIs, cron jobs, and final responses.

Guardian treats those surfaces as egress. Once a session has observed private
data, the active privacy mode evaluates classified outbound actions before they
run. Some actions are auto-approved, some are blocked immediately, and some
fall back to manual approval. Security-sensitive content is stricter: it is
blocked or suppressed outright, even if privacy mode is off.

Use Guardian when you want:

- Private data available for reasoning, not blindly stripped from context.
- Strong default egress behavior without needing to write custom rules first.
- Optional declassification rules by action family, destination, data class,
  owner, session, and cron scope.
- Mobile-friendly approvals for blocked actions.
- Fail-closed behavior when private data could leak.
- Sanitized dashboard and history views that do not store raw private content.
- A plugin-only layer that works through documented Hermes hooks.

Guardian is not a sandbox. It complements Hermes process isolation, credential
scoping, SSRF protection, gateway authorization, and dangerous-command controls.

## How It Works

Guardian's core policy is intentionally small:

> For Hermes-mediated actions that Guardian classifies as outbound egress, if
> the current session has observed private data, the active privacy mode decides
> whether the action can run, needs approval, or must be blocked.

The flow looks like this:

```text
Private source observed
        |
        v
Session tainted with data classes
        |
        v
Outbound tool call or final response classified
        |
        v
Security-sensitive? ---- yes ----> block or suppress
        |
        no
        |
        v
Privacy mode engine evaluates action
        |
        |  optional user rules can narrow or override known routes
        v
Auto-allow, hard-block, or request approval
```

Security checks run before privacy checks. Privacy allow rules and approval
commands cannot bypass Security Module blocks. Privacy rules are customization
hooks on top of the mode engine, not a requirement for Guardian to protect a
session.

## Privacy Modes

Privacy mode is the foundation of the Privacy Module. It controls how
private-context egress is handled by default:

| Mode | Behavior |
| --- | --- |
| `strict` | Require manual approval for tainted egress by default. Optional allow rules can preapprove known routes. |
| `read-only` | Auto-approve only metadata-verified low-risk reads; ask for approval otherwise. Optional rules can further narrow or preapprove routes. |
| `llm` | Run deterministic hard blocks first, then ask a sanitized LLM verifier for low-risk judgment. Optional rules can override known routes. |
| `off` | Disable private-egress approval checks. Security-sensitive content is still blocked. |

The default mode is `llm`.

Set the mode from a Hermes gateway:

```text
/guardian privacy mode llm
```

Or edit `guardian-rules.json`:

```json
{
  "version": 1,
  "privacy": {
    "mode": "llm",
    "rules": []
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

Rule mutation helpers preserve both privacy rules and security rule settings.

## Approvals

When Guardian blocks egress, it returns a short-lived four-digit approval ID:

```text
Hermes Guardian blocked this egress.

Approval ID: 4827
Action: browser_type
Destination: example.com
Data classes: email, contacts

Kevin can approve with:
/guardian approve 4827 once
/guardian approve 4827 session
/guardian approve 4827 always
or dismiss with:
/guardian dismiss 4827
```

Approval scopes:

| Scope | Behavior |
| --- | --- |
| `once` | Creates a matching allow rule with `remaining_invocations=1`, bound to the exact tool arguments by HMAC. |
| `session` | Creates a volatile allow rule for the active session/process state. |
| `always` | Persists a narrow allow rule with `remaining_invocations=-1`. Cron approvals are scoped to the cron job. |

Blocked tool calls are not paused and resumed. After approval, the agent must
retry the action.

There is no global "allow everything" approval.

## Privacy Rules

Privacy rules are optional custom policy. Use them when the default privacy
mode is too broad or too conservative for a known workflow.

Rules are ordered allow/deny overrides evaluated before the mode fallback for a
matching action. They match egress by tool, action family, destination, data
class, owner, session, and cron scope.

Example persistent allow rule:

```json
{
  "id": "rule_notion",
  "effect": "allow",
  "enabled": true,
  "match": {
    "tool_name": "*",
    "action_family": "mcp_write",
    "destination": "mcp:notion",
    "data_classes": ["*"]
  },
  "scope": {
    "owner_hash": "*",
    "session_id": "",
    "cron_job_id": "",
    "cron_job_name": ""
  },
  "remaining_invocations": -1,
  "created_at": 1780775040
}
```

Keep persistent rules narrow. A good rule should mean:

> This owner/session/cron context may send this class of private data through
> this action family to this destination.

Deny rules are useful for hard policy choices that should block even when the
current privacy mode would otherwise ask for approval.

## Security Rules

High-level Security Module protections are enabled by default:

| Rule ID | Blocks |
| --- | --- |
| `account_security_content` | Password reset/recovery, auth codes, magic links, account verification, security alerts, and similar semantic account-security content. |
| `credential_content` | Private keys, OAuth/session/cloud/API tokens, bearer tokens, JWTs, cookies, and `.env`-style secret assignments. |
| `sensitive_links` | Reset, recovery, verification, confirmation, magic-link, OTP, and 2FA URLs. |
| `intrinsic_exfiltration` | Same-call local/browser secret reads combined with network sinks before session taint exists. |
| `private_network_reads` | Terminal remote-read shortcuts targeting localhost, private IPs, link-local/metadata hosts, or `.local` hosts. |

Toggle rules with:

```text
/guardian security
/guardian security disable sensitive_links
/guardian security enable sensitive_links
```

Disabling a security rule weakens non-approvable hardening. Privacy checks still
apply to classified private egress, but the disabled security category no
longer categorically blocks matching content or action shapes.

## Data Classes

Guardian tracks private context with these data classes:

| Class | Examples |
| --- | --- |
| `email` | Email bodies, subjects, snippets, senders, and message lists. |
| `contacts` | Dex/contact data, names, email addresses, phone numbers, and contact metadata. |
| `memory` | Hermes memory, Mnemosyne, and session-search results. |
| `documents` | Notion, Drive, files, document bodies, and document metadata. |
| `calendar` | Meetings, attendees, schedule details, and event data. |
| `local_system` | Content-bearing terminal or code output and local runtime details. |
| `browser_private_input` | Private or user-derived text typed into a browser page. |

Source-based taint wins over content detection for known private sources. For
example, reading email taints the session as `email` even if the returned email
text contains no obvious PII pattern.

## Egress Surfaces

These action families normally require approval when private data is in scope:

- Messaging and send tools.
- MCP write-like tools, and unknown MCP tools under taint.
- MCP read/search/query tools when arguments send query text or request bodies
  to a remote MCP service.
- Browser typing, submission, dialogs, and raw CDP calls.
- Terminal, shell, code execution, browser console, and computer-use actions.
- Local writes, cron writes, kanban writes, and Home Assistant writes.
- Web/search/navigation/API calls whose arguments can carry private data.
- Model/media tools that may send context to another model or generation
  service.
- Final responses to group, cron, or unknown destinations.

Read-only browsing and search are allowed only when arguments do not send
private-looking or tainted session-derived text outward. Content returned from
those tools may still taint the session.

## Browser And Terminal Behavior

Guardian tracks browser host state from navigation and result metadata when
available:

- `browser_type` is blocked under taint unless the host/action/classes are
  approved.
- `browser_click`, `browser_press`, and `browser_dialog` are blocked after
  private text was typed into the current host or when result metadata indicates
  a private/authenticated page context.
- URL query strings are not persisted in approval records or allow rules.

Terminal and code execution are conservative because they can read local state
and exfiltrate data in the same call. In `read-only` mode, Guardian only
auto-approves a small metadata-verified set:

```text
pwd, date, whoami, id, uname, hostname, ls, wc, stat, du, df, test, true, false
```

Commands with network tools, URLs, redirects, pipes, command chaining,
substitution, script runtimes, or content-bearing reads such as `cat`, `grep`,
`rg`, `find`, `sed`, `awk`, `jq`, or `sqlite3` are not auto-approved by
`read-only`.

## Slash Commands

Use these from a Hermes gateway interface:

```text
/guardian status
/guardian approve <id> once|session|always
/guardian dismiss <id>
/guardian deny <id>
/guardian clear-taint
/guardian rules
/guardian rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>]
/guardian rule delete <rule_id>
/guardian rule enable|disable <rule_id>
/guardian rule move <rule_id> before|after <other_rule_id>
/guardian privacy mode strict|read-only|llm|off
/guardian security
/guardian security enable|disable <rule_id>
/guardian language-packs
/guardian language-packs enable|disable <pack_id>
/guardian history [limit]
/guardian failures [limit]
/guardian failed [limit]
/guardian debug action=<family> destination=<dest> classes=<class+class> [tool=<tool_name>]
```

Helpful commands:

```text
/guardian status
/guardian history 20
/guardian failures
/guardian debug action=mcp_write destination=mcp:notion classes=email
```

`/guardian deny` is an alias for dismiss. `/guardian failed` is an alias for
`/guardian failures`.

## Dashboard

Guardian appears in the main Hermes dashboard at `/guardian` via
`dashboard/manifest.json`.

Dashboard tabs:

- **Settings**: edit privacy mode, toggle Security Module rules, and manage
  language packs.
- **Rules**: create, edit, delete, enable/disable, and reorder privacy rules.
- **Recent Blocks**: inspect privacy/security blocks, approve pending actions,
  and dismiss approvals.
- **History**: browse paginated sanitized activity rows.

Hermes mounts the dashboard API under `/api/plugins/hermes-guardian/`:

```text
GET /api/plugins/hermes-guardian/policy
GET /api/plugins/hermes-guardian/activity
GET /api/plugins/hermes-guardian/activity/datatables
POST /api/plugins/hermes-guardian/privacy/mode
PATCH /api/plugins/hermes-guardian/security/rules/{rule_id}
PATCH /api/plugins/hermes-guardian/language-packs/{pack_id}
POST /api/plugins/hermes-guardian/rules
PATCH /api/plugins/hermes-guardian/rules/{rule_id}
DELETE /api/plugins/hermes-guardian/rules/{rule_id}
POST /api/plugins/hermes-guardian/approvals/{approval_id}/approve
POST /api/plugins/hermes-guardian/approvals/{approval_id}/dismiss
```

Mutation routes can be disabled with:

```bash
HERMES_GUARDIAN_DASHBOARD_MUTATIONS=0
```

If `HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN` is set, mutation requests must
include that value in `x-hermes-guardian-token`.

The dashboard stores and displays sanitized metadata only. It does not store
raw tool arguments, email bodies, typed text, tokenized URLs, file contents, or
message content.

## Language Packs

Guardian uses declarative language packs for semantic security terms, auth-code
labels, private-field labels, browser private-context hints, redaction markers,
and sensitive-link terms.

English is required and always enabled. Bundled pack IDs:

```text
en, zh, hi, es, fr, ar, bn, pt, ru, ur, id, de, ja, pcm, mr, te, tr, ta, vi, tl, ko, fa
```

Configure packs in `guardian-rules.json`, from the dashboard, or with:

```text
/guardian language-packs
/guardian language-packs disable es
/guardian language-packs enable es
```

You can also set:

```bash
HERMES_GUARDIAN_LANGUAGE_PACKS=en,es
```

Use `HERMES_GUARDIAN_LANGUAGE_PACKS=all` to enable every bundled pack.
Structural protections such as source-based taint, credential-format scanning,
tainted URL/search/MCP checks, and final-response mediation remain
language-independent.

## Activity And State

Persistent files live in the plugin directory and are ignored by git:

| File | Purpose |
| --- | --- |
| `guardian-rules.json` | Privacy mode, privacy allow/deny rules, security-rule toggles, and language-pack selection. |
| `activity.sqlite3` | Sanitized activity history and pending approvals. |
| `.guardian-hmac-key` | Local key for exact-argument one-time approval binding. |
| `.unsafe-diagnostics` | Opt-in unsafe diagnostics flag for development only. |

Activity retention settings:

```bash
HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=10000
HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=30
HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
```

Set a retention value to `0` to disable that specific limit. Set
`HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=0` to disable display grouping.

Persistent state stores metadata only. If rules or activity state cannot be
read or written, security-sensitive filtering still runs and private egress
from tainted sessions fails closed.

## Cron Notifications

When Guardian blocks a command inside a cron session such as
`cron_<job_id>_<timestamp>`, it can send one sanitized notification for that run
using `hermes send`.

```bash
HERMES_GUARDIAN_CRON_NOTIFY_TO=origin
HERMES_GUARDIAN_HERMES_CLI=/root/.local/bin/hermes
```

Defaults:

- `HERMES_GUARDIAN_CRON_NOTIFY_TO=origin`
- `HERMES_GUARDIAN_HERMES_CLI=/root/.local/bin/hermes`

`origin` means the cron job's own delivery target. Set
`HERMES_GUARDIAN_CRON_NOTIFY_TO=off` to disable cron notifications.

Notifications include safe metadata only: job name/id, action, destination,
data classes, reason, and an approval command when available.

## Architecture

The implementation is split by responsibility:

| Path | Responsibility |
| --- | --- |
| `core.py` | Composition root, shared global namespace, constants, loader, and `register(ctx)`. |
| `hooks.py` | Hook orchestration. Security checks run before privacy checks. |
| `security/` | Sensitive-content scanner and core-facing wrappers. |
| `privacy/` | Taint tracking, egress classification, rules, approvals, action details, and LLM verifier helpers. |
| `runtime/` | Shared context, SQLite storage, activity shaping/grouping, and lifecycle cleanup. |
| `ui/` | Slash commands, CLI command setup, dashboard action adapters, and presentation helpers. |
| `dashboard/` | Hermes dashboard manifest, FastAPI plugin API adapter, and checked-in static assets. |
| `integrations/` | Cron failure notification support. |
| `language_packs/` | Declarative semantic detection packs. |
| `tests/` | Behavior-focused pytest suite. |

`core.py` exec-loads most modules into one shared global namespace. Avoid adding
normal relative imports between exec-loaded modules unless doing a deliberate
loader refactor.

Guardian registers these Hermes hooks:

```text
pre_tool_call
transform_tool_result
pre_gateway_dispatch
transform_llm_output
pre_llm_call
on_session_reset
on_session_end
```

## Recommended Hermes Baseline

Guardian is strongest when Hermes supplies the lower-level boundary:

- Use whole-process isolation when feasible.
- Prefer Docker, Modal, Daytona, SSH, Singularity, or another sandboxed
  terminal backend over host-local execution.
- Mount only the directories the task requires.
- Do not mount `$HOME` wholesale.
- Do not pass API keys, OAuth tokens, SSH keys, browser profiles, or `.env`
  files unless the workflow requires them.
- Keep Hermes dangerous-command approvals enabled.
- Keep private URL and SSRF protections enabled unless you intentionally trust
  LAN, Tailscale, or internal targets.
- Use gateway allowlists and DM pairing.
- Constrain MCP server environment variables to the minimum credentials each
  server needs.
- Expose the Guardian dashboard only behind authenticated local/admin access.

Guardian can surface policy mistakes, but it cannot make an unsafe Hermes
runtime safe by itself.

## Development

There is no package manager lockfile or build system in this repository. The
plugin is primarily standard-library Python. Optional runtime integrations may
import FastAPI or Telegram libraries, but tests run without those dependencies.

Run the full test suite:

```bash
python -m pytest -q
```

Run focused suites while iterating:

```bash
python -m pytest -q tests/test_security.py tests/test_security_rules_config.py
python -m pytest -q tests/test_privacy_egress.py tests/test_privacy_modes.py
python -m pytest -q tests/test_dashboard_policy.py tests/test_dashboard_activity.py
python -m pytest -q tests/test_language_packs.py tests/test_multilingual_security.py
```

GitHub Actions runs `python -m pytest -q` on Python 3.11 and 3.12.

## Updating

Because Guardian is a user plugin under `~/.hermes/plugins`, normal Hermes
updates should not overwrite it.

```bash
cd ~/.hermes/plugins/hermes-guardian
git pull
python -m pytest -q
systemctl restart hermes-gateway.service
```

## Limitations

- Guardian is not a sandbox and does not replace OS, container, network, or
  Hermes runtime isolation.
- It protects Hermes-mediated tool calls and selected model/output surfaces.
  Data that bypasses Hermes hooks is out of scope.
- Blocked tool calls are not paused and resumed; the agent must retry after
  approval.
- Session taint is intentionally coarse. It is safer than regex-only detection,
  but it is not object-level provenance.
- Tool classification is heuristic. Unknown MCP tools, browser actions, or
  future Hermes tools should be classified conservatively until reviewed.
- URL paths, URL queries, search queries, redirects, image loads, DNS, and final
  responses can all be egress channels.
- Terminal, code execution, browser console/CDP, and some MCP servers can act as
  both private-data sources and outbound sinks in one call. Sandbox and network
  policy are required for hard containment.
- `llm` mode depends on the Hermes plugin LLM facade. If the verifier is
  unavailable or malformed, Guardian falls back to manual approval.
- Deterministic checks intentionally favor false positives over silent
  exfiltration.

## Further Reading

- [`theory.md`](./theory.md): Guardian's defense theory, assumptions, and
  comparisons.
- [Hermes security guide](https://hermes-agent.nousresearch.com/docs/user-guide/security)
- [Hermes security policy](https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md)
