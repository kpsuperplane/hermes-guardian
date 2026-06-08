# Hermes Guardian

Hermes Guardian is a user plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that adds privacy-aware egress guardrails around security-sensitive content and
private data flows.

It is designed for people who want their Hermes agent to read useful private
context such as email, contacts, documents, memory, calendar entries, and local
system output, while preventing that context from being sent outward through
Hermes-mediated tools unless the action is explicitly allowed.

Hermes Guardian is not a sandbox, not a complete information-flow-control
system, and not a proof of noninterference. It is designed to complement Hermes
Agent's built-in sandboxing, credential scoping, SSRF protection, gateway
authorization, and dangerous-command controls. For untrusted input surfaces,
run Hermes with OS/container/network isolation and use Guardian as the semantic
egress/declassification layer above that boundary.

<img width="2434" height="1892" alt="CleanShot 2026-06-06 at 20 24 01@2x" src="https://github.com/user-attachments/assets/fafaa94a-dc19-4211-9240-aa5dcda01d78" />

## Security Model At A Glance

Guardian's core security claim is intentionally narrow:

> For Hermes-mediated tool calls that Guardian classifies as outbound egress,
> if the current session has observed private data and no matching allow rule or
> approval exists, Guardian blocks the tool call before execution.

That is a useful policy invariant, but it depends on several assumptions:

- Relevant actions pass through Hermes plugin hooks.
- Guardian correctly classifies the tool call as a sink.
- Guardian hook failures fail closed.
- High-risk runtimes such as terminal, code execution, browser console/CDP, and
  MCP servers are contained by Hermes/OS/network configuration.
- The user treats approval rules as declassification decisions, not generic
  trust grants.

Guardian should be deployed as one layer in a defense-in-depth stack:

```text
Hermes OS/container/network containment
+ Hermes env/MCP credential filtering
+ Hermes SSRF/private-network protection
+ Hermes gateway authorization
+ Hermes dangerous-command approval and hardline blocks
+ Guardian taint, egress policy, approvals, and metadata-only audit
```

The model is simple: Hermes limits what the agent and tools can reach; Guardian
limits where private information can flow after the agent has legitimately seen
it.


## What It Does

Hermes Guardian has two protection modules:

1. The Security Module blocks or filters security/access-sensitive content
   categorically.
2. The Privacy Module approval-gates private-context egress by destination,
   action type, data class, and user privacy rules.

Security-sensitive content is never approval-gated. It is blocked or suppressed
outright. This includes password resets, OTPs, 2FA codes, magic links, account
verification links, login/security alerts, security key changes, credential
material, and known upstream redaction placeholders such as
`[sensitive email subject redacted]`.

Private context is handled differently. The model can still use normal private
context when the user asks for it, but once a session has seen private data,
outbound actions are checked before they execute. If a tool call would send or
expose that private context to a destination that has not been approved, Hermes
Guardian blocks the call and creates a short-lived approval ID.

The Privacy Module mode controls how private-context egress is handled when no
user privacy rule matches:

- `strict`: require manual approval unless an allow rule matches.
- `read-only`: automatically allow a small set of metadata-verified low-risk
  local reads, and require approval for everything else.
- `llm`: run a deterministic malicious-action blocklist first, then delegate
  low-risk judgment to a sanitized LLM verifier.
- `off`: disable private-egress approval checks while still blocking
  security/access-sensitive content.

Blocked tool calls are not paused or resumed. After approval, the agent must
retry the action.

## Design Goals

- Plugin-only: no Hermes internals, adapter patches, or private approval queues.
- Defense-in-depth: complement Hermes isolation and runtime hardening rather
  than replacing them.
- Flow control over prompt detection: assume untrusted text may influence the
  model, then control outbound data flows.
- Deterministic first: source names, tool names, structured fields, and regexes
  before optional LLM judgment.
- Fail closed for security-sensitive content, storage failures, and policy
  uncertainty.
- Keep normal private data available for useful reasoning, but control where it
  leaves.
- Store only safe metadata for approvals, rules, history, and diagnostics.
- Stay resilient across Hermes updates by living under `~/.hermes/plugins`.



## How Guardian Complements Hermes Built-in Security

Hermes and Guardian operate at different layers.

| Layer | Hermes built-in role | Guardian role |
|---|---|---|
| OS/process containment | Docker, remote backends, and whole-process wrapping limit filesystem/process/network reach. | Assumes this is the hard boundary; does not replace it. |
| Credential exposure | Env filtering, Docker env allowlists, MCP env filtering, and credential-file passthrough controls reduce accidental secret availability. | Treats private tool results and explicitly forwarded credentials as sensitive sources. |
| Network target safety | SSRF/private-network/cloud-metadata protections and website blocklists constrain what URL-capable tools may reach. | Gates public destinations when tainted data may be embedded in URLs, searches, messages, or tool payloads. |
| Gateway access | Platform allowlists and DM pairing control who can talk to the agent. | Uses owner/session/cron scope for approvals and persistent declassification rules. |
| Command safety | Dangerous-command approval and hardline blocks stop destructive shell behavior. | Adds privacy-aware checks for non-destructive commands that may leak data. |
| Prompt-injection hygiene | Context/skill/memory scanners reduce obvious malicious instructions before ingestion. | Assumes scanners can fail and enforces flow policy after private data enters context. |

Recommended reading:

- Hermes security guide: <https://hermes-agent.nousresearch.com/docs/user-guide/security>
- Hermes security policy: <https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md>
- Guardian theory document: [`theory.md`](./theory.md)

## Architecture

The implementation is split by responsibility:

- `security/`: Security Module scanner and hook-surface filtering.
- `privacy/`: Privacy Module taint, egress classification, rules, approvals,
  action details, and LLM mode.
- `runtime/`: shared sanitized context, activity storage, activity rows, and
  lifecycle state.
- `ui/`: slash commands, Hermes dashboard action adapters, and presentation
  helpers.
- `dashboard/`: Hermes dashboard manifest, static tab assets, and FastAPI
  plugin API routes.
- `integrations/`: cron failure notifications.
- `tests/`: focused pytest files split by behavior area, with shared helpers in
  `tests/support.py` and environment cleanup in `tests/conftest.py`.

`core.py` is the composition root, and `hooks.py` only orchestrates module
calls in hook order.

## Install

Clone or copy the plugin into the Hermes user plugin directory:

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

Restart the Hermes gateway after enabling or changing plugin configuration:

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

## Configuration

Privacy configuration is stored in `guardian-rules.json` inside the plugin
directory. It can be edited directly as JSON, through `/guardian` slash
commands, or through the integrated dashboard. Dashboard runtime options,
activity retention, timezone, and cron notification settings are configured with
environment variables.

### Privacy Config

```json
{
  "version": 1,
  "privacy": {
    "mode": "strict",
    "rules": []
  }
}
```

Supported `privacy.mode` values:

- `strict`: default. Private egress from tainted sessions requires manual
  approval unless an allow rule matches.
- `read-only`: allows only actions that Hermes Guardian can verify as low-risk
  from safe metadata. Everything else falls back to manual approval.
- `llm`: runs a deterministic malicious-action blocklist first, then asks the
  Hermes plugin LLM for a Codex Guardian-style structured verdict using
  sanitized action metadata only.
- `off`: disables private-egress approval checks. Security/access-sensitive
  content is still blocked.

Security/access-sensitive content is always blocked regardless of this setting.

### Privacy Rules

Privacy rules are ordered user rules evaluated before the default privacy mode.
Rules can explicitly `allow` or `deny` matching egress. Deny rules are useful
for hard policy choices that should block even when the current privacy mode
would otherwise ask for approval.

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

`remaining_invocations=-1` means infinite. Positive values count down on each
match and the rule is deleted at `0`. Security Module blocks and filters remain
non-approvable and cannot be bypassed by privacy allow rules.

Approval-created rules use the same schema. `approve once` creates a
session-scoped allow rule with `remaining_invocations=1`; the rule is visible in
the dashboard and deleted after the matching retry consumes it. `approve always`
creates a persistent allow rule with `remaining_invocations=-1`; cron approvals
also store the cron job id/name so the rule applies only to future runs of that
job.

### Dashboard

Hermes Guardian registers a tab in the main Hermes dashboard at `/guardian` via
`dashboard/manifest.json`.

Dashboard tabs:

- Settings: edit `privacy.mode`.
- Rules: create, edit, delete, enable/disable, and reorder privacy allow/deny
  rules. The rule modal uses guided fields, data-class selection, invocation
  lifetime controls, and cron-job name selection.
- Recent Blocks: inspect recent privacy/security blocks, approve or dismiss
  pending approvals, and avoid duplicate approvals. If a pending block is
  already covered by a newly created allow rule, the approval buttons are
  shown as a disabled "Already covered by rule" button.
- History: paginated activity feed. Tool, action, and destination are combined
  into one route column so time and reason have more room.

Dashboard actions return toast notifications rather than persistent inline save
messages.

Dashboard mutation routes are defense-in-depth guarded. Set
`HERMES_GUARDIAN_DASHBOARD_MUTATIONS=0` to disable HTTP mutations, or set
`HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN` and send it in
`x-hermes-guardian-token` for mutation requests. The dashboard UI also requires
explicit confirmation before switching privacy mode to `off` or creating a
global wildcard allow rule.

### Activity Retention

```bash
HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=10000
HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=30
HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60
```

Defaults:

- `HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=10000`
- `HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=30`
- `HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60`

Set a retention value to `0` to disable that specific limit. Set
`HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=0` to disable display grouping.

Grouping affects only `/api/activity`, `/guardian history`, and `/guardian
failures`. The dashboard History tab uses paginated raw activity rows.
The underlying audit rows remain exact until retention pruning deletes them.

### History Timezone

```bash
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
```

If unset, Hermes Guardian tries to read `timezone:` from `~/.hermes/config.yaml`.
If neither is available, it uses the process local timezone.

### Cron Failure Notifications

```bash
HERMES_GUARDIAN_CRON_NOTIFY_TO=origin
HERMES_GUARDIAN_HERMES_CLI=/root/.local/bin/hermes
```

Defaults:

- `HERMES_GUARDIAN_CRON_NOTIFY_TO=origin`
- `HERMES_GUARDIAN_HERMES_CLI=/root/.local/bin/hermes`

When Guardian blocks a command inside a cron session such as
`cron_<job_id>_<timestamp>`, it sends one sanitized notification for that run
using `hermes send --to <target>`. By default, `origin` means the cron job's
own `deliver` target(s), so the warning goes to the same output channel as the
job result. The target can also be any explicit `hermes send` target, for
example `telegram`, `discord`, or `telegram:<chat_id>:<thread_id>`. Multiple
explicit targets can be separated with semicolons or newlines.

Set `HERMES_GUARDIAN_CRON_NOTIFY_TO=off` to disable these notifications.

Notifications include safe metadata only: job name/id, action, destination,
data classes, reason, and `/guardian approve <id> always` when an approval is
available. Raw tool arguments and private content are not included.

The notification text is the same on every delivery target. For Telegram,
Guardian also adds one inline copy-text button for the approval command. If
Telegram copy-button delivery is unavailable, Guardian falls back to the same
plain `hermes send` notification used for other platforms.

### Unsafe Diagnostics

```bash
HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS=1
```

This is for development only. It can log sensitive detection matches and context
snippets. Do not enable it in production or on shared systems.

## Data Classes

Hermes Guardian tracks private context using these data classes:

- `email`: email bodies, subjects, snippets, sender metadata, and message lists.
- `contacts`: Dex/contact data, names, email addresses, phone numbers, and
  related contact metadata.
- `memory`: Hermes memory, Mnemosyne, and session-search results.
- `documents`: Notion, Drive, files, document bodies, and document metadata.
- `calendar`: meetings, attendees, schedule details, and event data.
- `local_system`: local file/content-bearing terminal output, code execution
  output, and local runtime details that may contain private context.
- `browser_private_input`: private or user-derived text typed into a browser
  page.

Source-based taint wins over content detection for private sources such as
email, contacts, memory, documents, and calendar tools. For example, reading
email taints the session as `email` even if the returned email text contains no
obvious PII regex match.

`local_system` is intentionally more permissive. Hermes Guardian does not taint
a session merely because a terminal startup or metadata command returned output.
Commands such as `pwd`, `date`, `whoami`, `hostname`, `ls`, `stat`, `du`, and
`df` are treated as metadata-only for result-taint purposes. Content-bearing
commands such as `cat ~/.hermes/config.yaml`, code execution, unknown local
system results with private-content patterns, or non-metadata terminal reads can
still taint the session as `local_system`.

## Security-Sensitive Blocking

Security-sensitive content is non-approvable. Hermes Guardian blocks or
suppresses content matching categories such as:

- Password reset, password recovery, or account recovery messages.
- OTPs, one-time passcodes, 2FA/MFA codes, verification codes, and auth codes.
- Magic links.
- Account verification or confirmation links.
- Security alerts, new-login alerts, suspicious-login alerts, and unauthorized
  activity notices.
- SSH, GPG, deploy key, or public key change notices.
- Private keys, cloud/API tokens, bearer tokens, JWTs, session cookies, and
  `.env`-style secret assignments.
- Known upstream sensitive-email redaction placeholders.

For tool calls, security-sensitive arguments are blocked before execution. For
tool results and model output, matching sensitive email records are removed
entirely rather than merely redacting the subject.

## Egress Policy

When a session has private data in scope, Hermes Guardian checks classified
outbound tool calls before they execute.

These actions normally require approval when tainted private data is in scope:

- Messaging and send tools.
- MCP write-like tools with names containing verbs such as `create`, `update`,
  `delete`, `send`, `post`, `comment`, `share`, `invite`, `append`,
  `publish`, `upload`, `patch`, or `insert`.
- Unknown MCP tools under taint, unless they are confidently classified as
  read-only.
- MCP read/search/query tools under taint when their arguments send query text
  or request bodies to the remote MCP service.
- Browser typing into an unapproved host.
- Browser clicking, pressing, dialog handling, or submitting after private text
  was typed into the current host.
- Raw browser CDP calls.
- Terminal, shell, and code execution.
- Web/search/navigation/API calls whose arguments contain detected personal
  data or send URL paths, URL queries, search queries, or bodies after the
  session is tainted.
- Model/media tools that may send private prompt context to another model or
  generation service.

Read-only browsing and search are allowed only when the arguments do not send
private-looking or tainted session-derived text outward. Content returned from
those tools may still taint the session.

Final model responses are also treated as an egress surface. Tainted responses
to owner-private CLI/DM destinations are allowed and logged; tainted responses
to group, cron, or unknown destinations are suppressed with a Guardian marker.

Approval rules are declassification rules. A persistent allow rule should mean:

> This owner/session/cron context may send this class of private data through
> this action family to this destination.

Keep allow rules narrow. Prefer destination-specific rules such as
`mcp:notion` or a specific message channel over wildcard destinations.

## Browser Behavior

Hermes Guardian tracks browser host state from navigation and browser result
metadata when available.

- `browser_navigate` updates the current host and clears private-typing state
  for the new page after the navigation is allowed or when result metadata shows
  the final URL.
- `browser_type` is blocked under taint unless the host/action/classes are
  approved.
- `browser_click`, `browser_press`, and `browser_dialog` are blocked if private
  text was typed on the current host or browser result metadata indicates a
  private/authenticated page context and that host is not approved.
- `browser_cdp` requires approval under taint.
- URL query strings are not persisted in approval records or allow rules.

## Terminal And Code Behavior

Terminal and code execution are conservative because shell, Python, Node, and
similar tools can read local state and exfiltrate data in many ways.

In `strict`, terminal/code actions require approval when private data is in
scope.

Terminal result taint is a separate question. To avoid noisy startup state,
Hermes Guardian records the command shape before a local-system tool runs and
only adds `local_system` taint when the resulting command is content-bearing or
code-like. Metadata-only terminal commands do not leave persistent
`local_system` taint behind.

In `read-only`, Hermes Guardian allows a small metadata-verified set of
low-risk read commands, such as:

```text
pwd, date, whoami, id, uname, hostname, ls, wc, stat, du, df, test, true, false
```

Commands with network tools, URLs, redirects, pipes, command chaining,
substitution, script runtimes, or content-bearing reads such as `cat`, `grep`,
`rg`, `find`, `sed`, `awk`, `jq`, or `sqlite3` are not auto-approved by
`read-only`.

In `llm`, a strict deterministic blocklist runs first. If the action is not
explicitly malicious, Hermes Guardian sends sanitized metadata to the plugin LLM
for a structured decision.

Terminal URL fetches are direction-aware. A command that only reads a
user-requested URL and stages the fetched bytes in `/tmp` or `/var/tmp` is
treated as inbound remote-read activity only for public hosts, even for
paste-style hosts. Loopback, private-network, link-local, cloud metadata, and
`.local` hosts are not treated as safe public reads. The risky case is the
opposite direction: posting, uploading, copying, or sending private or local
data to paste bins, webhooks, tunnels, or other dropbox-style endpoints. Those
outbound shapes remain hard-blocked.

Fetched public-page text is also source-aware for security-sensitive matching.
If a public remote-read result contains example text like "verification code
123456", Hermes Guardian does not suppress it as Kevin's private auth code.
Private sources such as email, messages, authenticated account pages, and
sensitive URLs still receive categorical security-sensitive suppression.

Terminal/code/browser-console calls that combine local or browser secret reads
with network sinks in the same call are blocked even before session taint is
recorded. Guardian should still be paired with Hermes sandboxing and network
egress controls for those runtimes.

## LLM Privacy Mode

`privacy.mode=llm` is intended to approximate Codex-style
low-risk-action approval while keeping private content out of the verifier
prompt.

The verifier receives:

- Tool name.
- Action family.
- Normalized destination.
- Data classes in scope.
- Argument keys and shapes.
- Sanitized command/URL structure.
- Redacted indicators for content fields.

The verifier does not receive raw email bodies, typed text, document contents,
tokenized URLs, or long literal strings.

The LLM verdict schema distinguishes:

- Risk: `low`, `medium`, `high`, `critical`.
- User authorization: `explicit`, `substantive`, `weak`, `unknown`.
- Outcome: `allow` or `deny`.

Malformed output, missing LLM access, verifier errors, or `deny` outcomes fall
back to manual approval.

The decision frame is modeled after Codex Guardian policy:

- <https://github.com/openai/codex/blob/main/codex-rs/core/src/guardian/policy_template.md>
- <https://raw.githubusercontent.com/openai/codex/refs/heads/main/codex-rs/core/src/guardian/policy.md>

## Approval Flow

When egress is blocked, the model/user sees a message like:

```text
Hermes Guardian blocked this egress.

Approval ID: 4827
Action: browser_type
Destination: example.com
Action detail: browser_type to example.com
Data classes: email, contacts

Kevin can approve with:
/guardian approve 4827 once
/guardian approve 4827 session
/guardian approve 4827 always
or dismiss with:
/guardian dismiss 4827
```

Approval IDs are four-digit codes, so they are easy to type on mobile. Guardian
avoids reusing codes that are pending or that appeared in activity during the
last 7 days; codes outside that window can be reused. IDs remain short-lived
and scoped to the gateway sender identity captured for the session. Pending
approvals are stored in Guardian's SQLite activity database so cron-created
approvals can be resolved by gateway or CLI command handlers in another
process.

Approval scopes:

- `once`: create a matching privacy allow rule with `remaining_invocations=1`,
  bound to an HMAC of the exact tool arguments. Changing the payload requires a
  new approval.
- `session`: create a session-scoped volatile privacy allow rule that lasts for
  the active plugin process/session state.
- `always`: persist a narrow privacy allow rule with
  `remaining_invocations=-1`. When approved from a cron run, the persistent
  rule is also scoped to that cron job ID, so it can apply to future runs of
  the same job without approving the same action for unrelated jobs or chat
  sessions.
  Guardian displays the cron name when available and keeps the numeric job ID
  beside it for unambiguous matching.

There is no global "allow everything" approval.

## Slash Commands

Use these from a Hermes gateway interface:

```text
/guardian status
/guardian approve <id> once
/guardian approve <id> session
/guardian approve <id> always
/guardian dismiss <id>
/guardian clear-taint
/guardian rules
/guardian rule add allow|deny action=<family> destination=<dest> classes=<class+class|*>
/guardian rule delete <rule_id>
/guardian rule enable|disable <rule_id>
/guardian rule move <rule_id> before|after <other_rule_id>
/guardian privacy mode strict|read-only|llm|off
/guardian history [limit]
/guardian failures [limit]
/guardian failed [limit]
/guardian debug action=<family> destination=<dest> classes=<class+class> [tool=<tool_name>]
```

Command notes:

- `/guardian status` shows active data classes, pending approval count,
  privacy mode, and matching privacy-rule count.
- `/guardian rules` lists persistent privacy rules without raw private content.
- `/guardian rule ...` creates, deletes, toggles, and reorders privacy rules.
- `/guardian privacy mode ...` edits `guardian-rules.json`.
- `/guardian clear-taint` clears taint and session approvals for active Guardian
  sessions owned by the sender.
- `/guardian dismiss <id>` removes a pending approval without adding a rule.
  `/guardian deny <id>` remains an alias for dismiss.
- `/guardian failed` is an alias for `/guardian failures`.
- `/guardian debug ...` evaluates a hypothetical action/destination/classes
  tuple against the current privacy mode and rules.

## Dashboard

Hermes Guardian is integrated into the main Hermes dashboard at `/guardian` for
understanding decisions, editing privacy mode, and managing privacy rules.

The Guardian CLI dashboard command reports the integration status and can prune
activity history:

```bash
hermes guardian dashboard status
hermes guardian dashboard url
hermes guardian dashboard prune
```

Dashboard API routes are mounted by Hermes under
`/api/plugins/hermes-guardian/`:

```text
GET /api/plugins/hermes-guardian/policy
GET /api/plugins/hermes-guardian/activity
GET /api/plugins/hermes-guardian/activity/datatables
POST /api/plugins/hermes-guardian/privacy/mode
POST /api/plugins/hermes-guardian/rules
PATCH /api/plugins/hermes-guardian/rules/{rule_id}
DELETE /api/plugins/hermes-guardian/rules/{rule_id}
POST /api/plugins/hermes-guardian/approvals/{approval_id}/approve
POST /api/plugins/hermes-guardian/approvals/{approval_id}/dismiss
```

The `/activity/datatables` endpoint provides paginated and filterable SQLite
activity rows for the History tab.

HTTP mutation routes can be disabled with
`HERMES_GUARDIAN_DASHBOARD_MUTATIONS=0`. If
`HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN` is set, mutation requests must include
that value in `x-hermes-guardian-token`.

The dashboard shows sanitized metadata only:

- Timestamp.
- Security policy.
- Decision.
- Tool/route metadata: tool name, action family, and destination.
- Data classes.
- Approval/rule identifiers.
- Short session hashes.
- Sanitized action detail, such as a short command summary.

History rows show compact metadata by default. The History tab combines tool,
action, and destination into one column, while `/guardian history` formats the
same sanitized metadata as grouped chat output.

It does not store raw tool arguments, email bodies, typed text, tokenized URLs,
file contents, or message content.

Activity is stored in `activity.sqlite3` inside the plugin directory. This file
is ignored by git.

## History Output

Recent sanitized activity can be checked from gateway interfaces:

```text
/guardian history
/guardian history 20
/guardian failures
/guardian failures 20
```

History is capped at 25 grouped entries. `/guardian failures` is a shortcut for
command-level failures: blocked calls, denied approvals, and security-blocked
tool calls.

Example:

```text
🛡️ **Guardian history** · newest first · 2 shown

✅ **`mcp_notion_update_page`** x3
Jun 6, 2026 10:42 PM PDT
🏷️ `documents`
Action: `mcp_write to mcp:notion`
Allowed: matched allow rule (`rule_notion`)

📥 **`mcp_gmail_search`**
Jun 6, 2026 10:41 PM PDT
🏷️ `email`
```

The 📥 icon means private context entered the session. It is not a success or
failure signal by itself. It means later outbound actions may require approval.

## State Storage

In-memory state:

- Session taint.
- Pending approvals loaded from SQLite for the current process.
- Session approvals.
- Browser host and private-typing state.
- Short-lived sanitized cross-hook context, such as local-system result policy
  and public remote-read metadata.

Persistent state:

- `guardian-rules.json`: privacy mode and persistent privacy allow/deny rules.
- `activity.sqlite3`: sanitized activity history and pending approvals.
- `.guardian-hmac-key`: local key used to bind exact-argument one-time
  approvals.

Persistent state stores metadata only. It should not contain raw private
messages, email bodies, typed form values, file contents, tokenized URLs, or
credential material.

If persistent state cannot be read or written, security-sensitive filtering
still runs. Private egress from tainted sessions fails closed.

## Hooks Used

Hermes Guardian registers these documented Hermes plugin hooks:

- `pre_gateway_dispatch`
- `pre_llm_call`
- `transform_tool_result`
- `pre_tool_call`
- `transform_llm_output`
- `on_session_reset`
- `on_session_end`

It also registers the gateway slash command:

```text
/guardian
```

## Recommended Hermes Security Baseline

Guardian is strongest when Hermes supplies the lower-level boundary. For a
personal agent that reads private data, use a baseline like this:

```text
Use whole-process isolation when feasible.
Use Docker, Modal, Daytona, SSH, Singularity, or another sandboxed terminal backend instead of host-local execution.
Mount only the directories the task requires.
Do not mount $HOME wholesale.
Do not pass API keys, OAuth tokens, SSH keys, browser profiles, or `.env` files unless the workflow requires them.
Keep Hermes dangerous-command approvals enabled; avoid YOLO outside disposable sandboxes.
Keep private URL / SSRF protections enabled unless you intentionally trust LAN/Tailscale/internal targets.
Use gateway allowlists and DM pairing; do not expose a public unauthenticated gateway.
Constrain MCP server env vars to the minimum credentials each server needs.
Use Guardian `strict` for high-sensitivity sessions and `llm` only when you accept sanitized LLM judgment for low-risk actions.
Expose the Guardian dashboard only behind authenticated local/admin access.
```

Guardian can help surface policy mistakes, but it cannot make an unsafe Hermes
runtime safe by itself.

## Recommended Setup

For a personal Hermes install, a practical default is:

```json
{
  "version": 1,
  "privacy": {
    "mode": "llm",
    "rules": [
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
        "created_at": 0
      }
    ]
  }
}
```

Common environment settings:

```bash
HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=10000
HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=30
HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
HERMES_GUARDIAN_CRON_NOTIFY_TO=origin
```

Expose the dashboard only behind an authenticated tunnel or other access
control. The dashboard stores sanitized metadata only, but it can change privacy
rules and privacy mode.

## Updating

Because this is a user plugin under `~/.hermes/plugins`, normal Hermes updates
should not overwrite it.

To update the plugin:

```bash
cd ~/.hermes/plugins/hermes-guardian
git pull
python -m pytest -q
systemctl restart hermes-gateway.service
```

If you run the dashboard as a systemd service, restart that service too.

## Tests

Run the local test suite with:

```bash
python -m pytest -q
```

Run a focused area with:

```bash
python -m pytest -q tests/test_approvals.py
```

The tests cover:

- Security-sensitive email suppression.
- Security-sensitive tool argument blocking.
- Taint tracking.
- Browser, MCP write, messaging, terminal, and code egress checks.
- Manual approval flows.
- Cross-process approval persistence for cron and dashboard flows.
- Cron failure notifications.
- Slash command status, debug, history, failures, rules, and approvals.
- Privacy allow/deny rules, countdown deletion, and approval-created rules.
- `strict`, `read-only`, `llm`, and `off` privacy mode behavior.
- Dashboard policy payloads, rule CRUD, recent blocks, history pagination, and
  activity formatting/retention.

The test suite is split by behavior area:

```text
tests/test_security.py
tests/test_privacy_egress.py
tests/test_privacy_modes.py
tests/test_llm_and_public_reads.py
tests/test_dashboard_activity.py
tests/test_dashboard_policy.py
tests/test_commands_debug_history.py
tests/test_commands_rules_failures.py
tests/test_cron_notifications.py
tests/test_approvals.py
tests/test_hooks_registration.py
```

GitHub Actions is configured to run the test suite on Python 3.11.

## Limitations

- Hermes Guardian is not a sandbox. It should be paired with Hermes
  whole-process isolation, terminal-backend isolation, and/or OS/network
  controls when handling untrusted input.
- The plugin protects Hermes-mediated tool calls and selected tool/model output
  surfaces. It cannot protect data that bypasses Hermes hooks entirely.
- Guardian does not pause and resume blocked tool calls. The agent must retry
  after approval.
- Session-level taint is intentionally coarse. It is safer than regex-only
  detection, but it is not precise object-level provenance.
- Tool classification is heuristic. Unknown MCP tools, new browser actions, or
  future Hermes tools should be treated conservatively until classified.
- URL paths, URL queries, search queries, redirects, image loads, DNS, and final
  responses can all be egress channels. High-sensitivity deployments should add
  lower-level network egress allowlists/proxies.
- Terminal, code execution, browser console/CDP, and some MCP servers can act as
  both a private-data source and an outbound sink in one tool call. Sandbox and
  network policy are required for hard containment.
- `llm` mode is only as available as the Hermes plugin LLM facade. If the LLM
  verifier is unavailable or malformed, the plugin falls back to manual
  approval.
- Persistent privacy allow rules should be narrow. They are powerful
  declassification rules and should represent destinations you actually trust.
- Deterministic checks intentionally favor false positives over silent
  exfiltration.

## Further Reading

- [`theory.md`](./theory.md): Guardian's defense theory and comparison against
  industry and research systems.
- Hermes security guide: <https://hermes-agent.nousresearch.com/docs/user-guide/security>
- Hermes security policy: <https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md>
- OpenAI, “Designing AI agents to resist prompt injection”: <https://openai.com/index/designing-agents-to-resist-prompt-injection/>
- OpenAI, “Keeping your data safe when an AI agent clicks a link”: <https://openai.com/index/ai-agent-link-safety/>
- Anthropic, “making Claude Code more secure and autonomous”: <https://www.anthropic.com/engineering/claude-code-sandboxing>
- Microsoft Copilot Studio external security provider: <https://learn.microsoft.com/en-us/microsoft-copilot-studio/external-security-provider>
- CaMeL, “Defeating Prompt Injections by Design”: <https://arxiv.org/abs/2503.18813>
- RTBAS, “Defending LLM Agents Against Prompt Injection and Privacy Leakage”: <https://arxiv.org/abs/2502.08966>
- GAAP, “An AI Agent Execution Environment to Safeguard User Data”: <https://arxiv.org/abs/2604.19657>
- “AI Agents May Always Fall for Prompt Injections”: <https://arxiv.org/abs/2605.17634>
