# Hermes Guardian

[![Tests](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Hermes Plugin](https://img.shields.io/badge/Hermes-plugin-0f766e.svg)](https://github.com/NousResearch/hermes-agent)

Security and privacy policy controls for personal Hermes agents.

Hermes Guardian is a user plugin for
[Hermes Agent](https://github.com/NousResearch/hermes-agent). It protects the
private content a personal agent reads — an email body, a contact list, calendar
entries, a Notion page, memory, and local system output — and controls where
that content can leave through Hermes-mediated tools.

What makes that content hard to protect is that most of it has no signature. A
credential, API key, or most PII matches a recognizable pattern, which is exactly
what scanner, DLP, and secret-detection tools key on. An email body, a friend
list, a meeting's attendees, or a document does not match any pattern — it is
private only because of *where it came from*, not because of how it is shaped.
Pattern-based tools are structurally blind to content with no signature. Guardian
protects this *provenance-private* content by its origin: once the agent reads a
private source, the session is tainted regardless of what the content looks like,
and outbound actions are gated accordingly.

Guardian adds two policy layers:

- **Security Module**: non-approvable blocking and suppression for credentials,
  OTPs, magic links, password resets, security alerts, sensitive account links,
  and similar access-sensitive content.
- **Privacy Module**: session taint, egress classification, privacy modes,
  optional declassification rules, and metadata-only activity history for
  private data flows.
  
## Why Guardian?

Modern agents need private context to be useful, and the most useful context is
also the least pattern-detectable. Credentials and secrets have signatures;
scanner and DLP tools find them by shape. But the things a personal agent
actually reads — your inbox, your contacts, your calendar, your notes — have no
signature. They are private by *provenance*: the only thing that marks an email
body as yours is that it came from your inbox. A tool that classifies by content
pattern cannot see provenance-private data at all, because there is no pattern to
match. Guardian's primary protected asset is exactly this content, tracked by
origin rather than by shape.

Among practical, local-first, default-configured personal-agent guards, treating
provenance-private personal content as the primary protected asset is
distinctive. Two honest caveats keep that claim calibrated:

- The goal is not conceptually new. Guardian descends from a privacy-research
  lineage — GAAP, RTBAS, and contextual integrity — that already targets
  personal-data confidentiality. Guardian is the deployable, default
  instantiation of that goal for an existing agent runtime, not a new idea about
  what to protect.
- Other tools *can* express non-credential data-flow rules. Invariant
  Guardrails, for instance, can encode exactly the email `get_inbox -> send_email`
  shape — but it requires user-authored flow rules and runs as an enterprise
  proxy with a telemetry path. Guardian applies that kind of protection by
  default, by provenance, and locally.

Agents also have many outbound surfaces: messages, MCP writes, browser forms,
URLs, search queries, terminal commands, code execution, model APIs, cron jobs,
and final responses.

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

## Features

- Block or suppress credentials, OTPs, reset links, magic links, account
  verification links, security alerts, private keys, bearer tokens, JWTs,
  cookies, and known upstream redaction placeholders.
- Taint sessions after private sources are read, including email, contacts,
  memory, documents, calendar, local system output, and private browser input.
- Classify common Hermes egress families such as messaging, MCP writes, browser
  typing/submission, terminal execution, local writes, cron writes, web/API
  calls, model APIs, delegated tasks, and final responses.
- Store sanitized activity rows and pending approvals in local SQLite.
- Bind one-time approvals to an HMAC fingerprint of the exact tool arguments.
- Provide slash commands, CLI maintenance commands, and a Hermes dashboard tab.
- Send sanitized cron failure notifications at most once per cron run.
- Use declarative multilingual language packs for semantic security detection.

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
matching action. They match egress by tool, action family, destination,
optional purpose, optional pseudonymous recipient identity, data class, owner,
session, and cron scope. `purpose` defaults to the safe token `unknown` on
actions and to wildcard `*` on rules. `recipient_identity` defaults to `none`
on actions and wildcard `*` on rules.

For message sends, Guardian now classifies the route as
`action_family=message_send` and `destination=messaging`, with the concrete
recipient represented as a stable `recipient_<hash>` value. Existing legacy
rules that used the recipient string as `destination` still match live
message-send calls, but new approvals and rules prefer the route plus hashed
recipient form.

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
    "purpose": "*",
    "recipient_identity": "*",
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
| `intrinsic_exfiltration` | Same-call local, code, browser console/CDP, or obvious MCP private-source reads combined with network/share sinks before session taint exists. |
| `private_network_reads` | Terminal remote-read shortcuts targeting localhost, private IPs, link-local/metadata hosts, or `.local` hosts. |

Toggle rules with:

```text
/guardian security
/guardian security disable sensitive_links
/guardian security enable sensitive_links
```

The intrinsic exfiltration rule is structural and metadata-only: blocked rows
record the action family, destination host or network class, data classes, and
reason, not raw commands, browser expressions, URL paths/queries, or MCP
payloads. It covers shapes such as local secret reads sent through
`requests.post`, GET query construction from local files, browser DOM/cookie
reads sent with `fetch` or `sendBeacon`, CDP `Runtime.evaluate` exfiltration,
and MCP private-source tools paired with webhook/share sinks.

Disabling a security rule weakens non-approvable hardening. Privacy checks still
apply to classified private egress, but the disabled security category no
longer categorically blocks matching content or action shapes. `/guardian
status` and the dashboard policy snapshot surface a risk banner when
`intrinsic_exfiltration` is disabled.

## Data Classes

Guardian's data classes are categories of *provenance-private* content — content
that is private because of where it came from, not because it matches a sensitive
pattern. This is why the classes are email, contacts, calendar, and documents
rather than credential or secret formats: Guardian protects a different asset
than a secret scanner does. (Access-sensitive material that *does* have a
signature — credentials, OTPs, tokens — is handled separately and more strictly
by the Security Module.)

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

Guardian also keeps volatile, metadata-only provenance for some copied text
inside the active session. It indexes non-security-sensitive, medium-length
phrases from tainting tool results as keyed HMAC fingerprints with source data
classes. If later tool arguments or a final response structurally contain a
matching copied phrase, Guardian can narrow the data classes in scope to the
matched source classes plus any private-looking argument classes. If there is no
match, if the text is too short, if it is paraphrased, or if provenance is
missing, Guardian falls back to the full session taint. Raw source text is not
stored in provenance, activity rows, approval records, or LLM verifier input,
and security-sensitive strings are not indexed.

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
- Unrecognized tools (custom or third-party) under taint, unless declared safe by
  a tool override (see [Tool Classification And Overrides](#tool-classification-and-overrides)).
- Final responses to group, cron, or unknown destinations.

Read-only browsing and search are allowed only when arguments do not send
private-looking or tainted session-derived text outward. Content returned from
those tools may still taint the session.

## Tool Classification And Overrides

Guardian recognizes Hermes built-in tools and classifies their calls. Any tool it
does **not** recognize — a third-party MCP tool, a custom integration, or a tool
Guardian simply has no rule for — is treated as a potential sink and gated under
taint, exactly like unknown MCP tools. This is the `unknown_tools` mode:

- `gate` (default): unrecognized tools require approval once private data is in
  scope. Untainted sessions are unaffected.
- `allow`: restores the older permissive behavior (unrecognized non-MCP tools are
  not gated). This is a footgun and surfaces a risk banner in `/guardian status`
  and the dashboard.

```text
/guardian privacy unknown-tools gate|allow
```

When the default is too strict for a tool you trust, declare it with a **tool
override** instead of weakening the global mode. Overrides let you tell Guardian
what a tool actually does, and Guardian trusts your declaration:

```text
# An MCP server you trust: its reads carry email, and it is not a sink.
/guardian tool set mcp_acme_* taints=email egress=ignore note="trusted acme server"

# A custom tool that really sends messages: classify it so it gates correctly.
/guardian tool set send_widget egress=message_send

# A custom tool that is just a safe read:
/guardian tool set lookup_widget egress=ignore

# Force an unrecognized tool to require approval under taint:
/guardian tool set risky_tool egress=gate

/guardian tools                       # list overrides + current unknown-tools mode
/guardian tool enable|disable <id>
/guardian tool delete <match_or_id>
```

Override fields:

- `match`: exact tool name, or a single trailing-`*` prefix (e.g. `mcp_acme_*`) to
  cover every tool from one MCP server.
- `taints`: data classes applied when the tool's result is observed (the "this tool
  reads my email" case). Independent of egress.
- `egress`: `ignore` (safe non-sink, allowed under taint), `gate` (force approval
  under taint), or a concrete action family such as `message_send` or `web_api`.

Overrides are a privacy-layer convenience. They never bypass the Security Module
(credentials, OTPs, sensitive links) or the intrinsic same-call exfiltration hard
blocks, which always run first. Editing overrides requires CLI or configured-owner
privileges, and the dashboard requires explicit confirmation for the weakening
`egress=ignore` and `unknown-tools=allow` actions.

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
/guardian rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>] [purpose=<token|*>] [recipient=<id|raw|*>]
/guardian rule delete <rule_id>
/guardian rule enable|disable <rule_id>
/guardian rule move <rule_id> before|after <other_rule_id>
/guardian privacy mode strict|read-only|llm|off
/guardian privacy unknown-tools gate|allow
/guardian tools
/guardian tool set <match> [taints=class+class] [egress=ignore|gate|<family>] [destination=<dest>] [note=<text>]
/guardian tool delete <match_or_id>
/guardian tool enable|disable <id_or_match>
/guardian security
/guardian security enable|disable <rule_id>
/guardian language-packs
/guardian language-packs enable|disable <pack_id>
/guardian history [limit]
/guardian failures [limit]
/guardian failed [limit]
/guardian debug action=<family> destination=<dest> classes=<class+class> [tool=<tool_name>] [purpose=<token>] [recipient=<id|raw>]
```

Helpful commands:

```text
/guardian status
/guardian history 20
/guardian failures
/guardian debug action=mcp_write destination=mcp:notion classes=email
/guardian debug action=message_send destination=messaging classes=email purpose=support recipient=recipient_...
```

`/guardian deny` is an alias for dismiss. `/guardian failed` is an alias for
`/guardian failures`.

## Dashboard

Guardian appears in the main Hermes dashboard at `/guardian` via
`dashboard/manifest.json`.

Dashboard tabs:

- **Settings**: edit privacy mode, set the unknown-tools mode, manage tool
  overrides, toggle Security Module rules, and manage language packs.
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
POST /api/plugins/hermes-guardian/privacy/unknown-tools
PATCH /api/plugins/hermes-guardian/security/rules/{rule_id}
PATCH /api/plugins/hermes-guardian/language-packs/{pack_id}
POST /api/plugins/hermes-guardian/rules
PATCH /api/plugins/hermes-guardian/rules/{rule_id}
DELETE /api/plugins/hermes-guardian/rules/{rule_id}
POST /api/plugins/hermes-guardian/tools
PATCH /api/plugins/hermes-guardian/tools/{override_id}
DELETE /api/plugins/hermes-guardian/tools/{override_id}
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
message content. Recipient context is displayed as a stable pseudonymous
`recipient_<hash>` identity rather than the raw recipient value.

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

`core.py` exec-loads most modules into one shared global namespace. The ordered
module list is `_CORE_LOGIC_MODULES`; update that tuple and
`tests/test_loader_contract.py` together when changing loader order or adding
exec-loaded files. Avoid adding normal relative imports between exec-loaded
modules unless doing a deliberate loader refactor. Duplicate top-level
definitions in exec-loaded modules must be intentional and listed in
`_CORE_LOGIC_ALLOWED_REBINDS`.

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

Guardian is distributed as a Hermes user plugin (loaded by path), not as a
pip-installable package, so there is no build step. Project metadata and the
optional-dependency manifest live in `pyproject.toml`; the core plugin is pure
standard-library Python with no runtime dependencies.

Install the pinned dev/CI dependencies (currently just `pytest`):

```bash
pip install -r requirements-dev.txt
```

Optional integrations are declared as extras and imported lazily, so tests run
without them. Install one only to exercise that integration locally:

```bash
pip install fastapi            # dashboard plugin API routes
pip install python-telegram-bot  # Telegram cron notifications
```

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
python -m pytest -q tests/test_loader_contract.py tests/test_hooks_registration.py
python -m pytest -q tests/test_approval_fatigue_benchmark.py
python -m pytest -q tests/test_adversarial_corpus.py
```

Run the additive approval-fatigue benchmark:

```bash
python -m benchmarks.approval_fatigue --pretty
```

The benchmark loads the plugin facade into temporary Guardian state, drives the
real hooks through synthetic email-to-Notion, browsing/booking, and cron digest
workflows, and compares `strict`, `read-only`, and `llm` mode metrics. It uses a
deterministic fake LLM and reports approvals, false-positive prompt rate,
auto/manual approvals, security blocks, unsafe auto approvals, completion, LLM
calls/fallbacks, cron notifications, and sanitization violations.

Run the additive adversarial corpus benchmark:

```bash
python -m benchmarks.guardian_adversarial --pretty
```

The adversarial benchmark loads the plugin facade into temporary Guardian state
and exercises hook, classifier, scanner, and result-suppression cases from
`tests/fixtures/adversarial_corpus.json`. It reports prevented rate,
false-positive rate, classification accuracy, security scanner accuracy,
sanitization violations, and known-gap count. CI gates URL path/query/base64
exfiltration, filename/upload shapes, supported same-call terminal exfiltration,
multilingual auth-code/security phrasing, sensitive auth links, and benign
controls. DNS-label-only exfiltration is tracked as a non-gating known gap.

### AgentDojo adapter (optional, local research)

[AgentDojo](https://github.com/ethz-spylab/agentdojo) is the common
prompt-injection-against-tool-use benchmark used by LlamaFirewall and Invariant.
The optional adapter drives Guardian's real Security + Privacy hooks over
AgentDojo's ground-truth tool-call traces and reports Guardian-specific
egress-monitor metrics. AgentDojo is intentionally a lazy optional import and is
not installed by CI or required for normal Guardian development:

```bash
python3 -m venv .venv-agentdojo
.venv-agentdojo/bin/pip install --break-system-packages agentdojo
.venv-agentdojo/bin/python -m benchmarks.agentdojo_guardian --summary
.venv-agentdojo/bin/python -m benchmarks.agentdojo_guardian --pretty --out agentdojo_metrics.json
```

If AgentDojo is not installed the adapter prints install instructions and exits
non-zero **without fabricating numbers**.

**What it measures.** Guardian is an *egress monitor*, not an agent. The adapter
does not run AgentDojo's agent pipeline or any LLM and cannot score end-to-end
task success. For each task it takes the canonical `ground_truth` tool-call
sequence and asks whether Guardian's deterministic gate fires on any egress call:

- `prevented_rate` — fraction of *injection* (attack) tasks whose attacker
  tool-call sequence Guardian gates.
- `false_positive_rate` — fraction of *user* (utility) tasks whose benign
  sequence Guardian gates. Guardian's gate is a human-approval prompt, so a
  benign gate is friction (a prompt the operator approves), not a hard failure.

Current results (AgentDojo `v1.2.1`, `strict` mode, deterministic verifier):

| Suite | prevented_rate | false_positive_rate |
|---|---|---|
| banking | 1.00 (9/9) | 0.75 (12/16) |
| slack | 0.80 (4/5) | 0.95 (20/21) |
| travel | 1.00 (6/6) | 0.30 (6/20) |
| workspace | 1.00 (6/6) | 0.62 (25/40) |
| **overall** | **0.962 (25/26)** | **0.649 (63/97)** |

Nine injection tasks have no ground-truth trace and are reported as
unmeasurable, not scored. The one un-prevented injection (`slack
injection_task_3`) only navigates to an attacker URL — a read, not an egress —
so it is outside an egress monitor's scope by construction. The high benign
false-positive rate is expected and honest: Guardian gates *all* tainted egress
(payments, messages, file writes) for human approval and cannot autonomously
tell a legitimate payment from an attacker payment — that decision is the
operator's. Read-only utility tasks (most of `travel`) pass clean, which is why
its FP rate is far lower.

**Modeling assumptions** (all emitted in the metrics JSON and bounding the
numbers): (1) AgentDojo's tools are unknown to Guardian, so the adapter supplies
an explicit, auditable source/sink mapping via Guardian's `privacy.tools`
override registry — without it the run would only measure "AgentDojo's vocabulary
is unknown to Guardian"; (2) every session is tainted, reflecting AgentDojo's
threat model in which the agent has read attacker-controlled content before
acting; (3) runs use `strict` mode with the deterministic verifier.

> **Caveat — no real-LLM judgment, and limited comparability.** These figures
> use Guardian's *deterministic* gating only; no number here reflects real-model
> (`llm` mode) judgment. Only label a Guardian number as a real-model result if
> it was produced with an actual verifier, not the deterministic benchmark path.
> The numbers are also **not directly comparable** to LlamaFirewall or Invariant
> AgentDojo scores: those tools measure *attack success / utility under a live
> agent rollout*, whereas Guardian measures *whether its egress gate fires on the
> canonical ground-truth trace*. The denominators, the unit of evaluation, and
> the meaning of "prevented" all differ.

GitHub Actions runs `python -m pytest -q` on Python 3.11, 3.12, and 3.13.

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
- Session taint is intentionally coarse. Volatile provenance can narrow copied
  phrase classes, but it is not a complete dependency proof and never makes
  missing provenance safe.
- Tool classification is heuristic. Unrecognized tools (unknown MCP tools, custom
  integrations, future Hermes tools) are gated conservatively under taint by
  default; declare trusted ones with tool overrides rather than disabling the
  secure default. A tool whose name matches a private-source pattern but is also a
  non-standard sink may still be treated as a recognized read — review and add an
  `egress=gate` override if needed.
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

## License

Hermes Guardian is released under the [BSD 3-Clause License](./LICENSE).
