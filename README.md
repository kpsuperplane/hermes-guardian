# Hermes Guardian

Hermes Guardian is a user plugin for [Hermes Agent](https://github.com/NousResearch/hermes-agent)
that adds deterministic protection around security-sensitive content and private
data egress.

It is designed for people who want their Hermes agent to read useful private
context such as email, contacts, documents, memory, calendar entries, and local
system output, while preventing that context from being sent outward through
tools unless the action is explicitly allowed.

## What It Does

Hermes Guardian has two protection layers:

1. Security/access-sensitive content is blocked categorically.
2. Private-context egress is approval-gated by destination, action type, and
   data class.

Security-sensitive content is never approval-gated. It is blocked or suppressed
outright. This includes password resets, OTPs, 2FA codes, magic links, account
verification links, login/security alerts, security key changes, and known
upstream redaction placeholders such as `[sensitive email subject redacted]`.

Private context is handled differently. The model can still use normal private
context when the user asks for it, but once a session has seen private data,
outbound actions are checked before they execute. If a tool call would send or
expose that private context to a destination that has not been approved, Hermes
Guardian blocks the call and creates a short-lived approval ID.

The original tool call is not paused or resumed. After approval, the agent must
retry the action.

## Design Goals

- Plugin-only: no Hermes internals, adapter patches, or private approval queues.
- Deterministic first: source names, tool names, structured fields, and regexes.
- Fail closed for sensitive content and storage failures.
- Keep private data available for useful reasoning, but control where it leaves.
- Store only safe metadata for approvals, rules, history, and diagnostics.
- Stay resilient across Hermes updates by living under `~/.hermes/plugins`.

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
enabled      git      2.0.0    hermes-guardian
```

## Configuration

Configuration is read from environment variables. On a typical Hermes install,
put these in `~/.hermes/.env` or in the environment used by the gateway service.

### Security Policy

```bash
HERMES_GUARDIAN_SECURITY=strict
```

Supported values:

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

### Static Allowlist

```bash
HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion"
```

Use this for destinations that should always be allowed without creating runtime
approval records.

Format:

```text
action_family:destination
action_family:destination#class+class
```

Entries can be separated with semicolons or newlines:

```bash
HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion;browser_type:trusted.example.com#email+contacts"
```

The first colon separates the action family from the destination, so destinations
such as `mcp:notion` work correctly. Without a `#class+class` suffix, the rule
allows all Guardian data classes for that action and destination.

Examples:

```bash
# Always allow writes to Notion for any private data class.
HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion"

# Allow browser typing to one trusted host only for email and contacts.
HERMES_GUARDIAN_ALLOWLIST="browser_type:forms.example.com#email+contacts"

# Allow multiple destinations.
HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion;message_send:mcp:slack#calendar"
```

Static allowlist rules cannot override security-sensitive blocking.

### Dashboard

```bash
HERMES_GUARDIAN_DASHBOARD_HOST=127.0.0.1
HERMES_GUARDIAN_DASHBOARD_PORT=8787
```

Defaults:

- `HERMES_GUARDIAN_DASHBOARD_HOST=127.0.0.1`
- `HERMES_GUARDIAN_DASHBOARD_PORT=8787`

Bind to `0.0.0.0` only if the host-level exposure model is safe, for example a
firewall plus Cloudflare Tunnel authentication.

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

Grouping affects only the dashboard, `/api/activity`, and `/guardian history`.
The underlying audit rows remain exact until retention pruning deletes them.

### History Timezone

```bash
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
```

If unset, Hermes Guardian tries to read `timezone:` from `~/.hermes/config.yaml`.
If neither is available, it uses the process local timezone.

### Unsafe Diagnostics

```bash
HERMES_GUARDIAN_UNSAFE_DIAGNOSTICS=1
```

This is for development only. It can log sensitive detection matches and context
snippets. Do not enable it in production or on shared systems.

### Legacy Environment Names

The old `PRIVACY_EGRESS_GUARD_*` environment variable names are still accepted
as fallback aliases so existing installs do not break during migration.

Prefer the new `HERMES_GUARDIAN_*` names for all new configuration.

## Data Classes

Hermes Guardian tracks private context using these data classes:

- `email`: email bodies, subjects, snippets, sender metadata, and message lists.
- `contacts`: Dex/contact data, names, email addresses, phone numbers, and
  related contact metadata.
- `memory`: Hermes memory, Mnemosyne, and session-search results.
- `documents`: Notion, Drive, files, document bodies, and document metadata.
- `calendar`: meetings, attendees, schedule details, and event data.
- `local_system`: terminal output, code execution output, local files, and local
  runtime details.
- `browser_private_input`: private or user-derived text typed into a browser
  page.

Source-based taint wins over content detection. For example, reading email
taints the session as `email` even if the returned email text contains no
obvious PII regex match.

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
- Known upstream sensitive-email redaction placeholders.

For tool calls, security-sensitive arguments are blocked before execution. For
tool results and model output, matching sensitive email records are removed
entirely rather than merely redacting the subject.

## Egress Policy

When a session has private data in scope, Hermes Guardian checks outbound tool
calls before they execute.

These actions normally require approval:

- Messaging and send tools.
- MCP write-like tools with names containing verbs such as `create`, `update`,
  `delete`, `send`, `post`, `comment`, `share`, `invite`, `append`, or
  `publish`.
- Browser typing into an unapproved host.
- Browser clicking or submitting after private text was typed into the current
  host.
- Raw browser CDP calls.
- Terminal, shell, and code execution.
- Web/API calls whose arguments contain detected personal data.

Read-only browsing and search are allowed when the arguments do not contain
private data. Content returned from those tools may still taint the session.

## Browser Behavior

Hermes Guardian tracks browser host state from navigation and browser result
metadata when available.

- `browser_navigate` updates the current host and clears private-typing state
  for the new page.
- `browser_type` is blocked under taint unless the host/action/classes are
  approved.
- `browser_click` is blocked if private text was typed on the current host and
  that host is not approved.
- `browser_cdp` requires approval under taint.
- URL query strings are not persisted in approval records or allow rules.

## Terminal And Code Behavior

Terminal and code execution are conservative because shell, Python, Node, and
similar tools can exfiltrate data in many ways.

In `strict`, terminal/code actions require approval when private data is in
scope.

In `read-only`, Hermes Guardian allows a small metadata-verified set of low-risk
read commands, such as:

```text
pwd, date, whoami, id, uname, hostname, ls, find, rg, grep, cat, head, tail,
wc, stat, du, df, test, true, false
```

Commands with network tools, URLs, redirects, pipes, command chaining,
substitution, or script runtimes are not auto-approved by `read-only`.

In `llm`, a strict deterministic blocklist runs first. If the action is not
explicitly malicious, Hermes Guardian sends sanitized metadata to the plugin LLM
for a structured decision.

## LLM Security Mode

`HERMES_GUARDIAN_SECURITY=llm` is intended to approximate Codex-style
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

Approval ID: peg_8f3c2a91
Action: browser_type
Destination: example.com
Action detail: browser_type to example.com
Data classes: email, contacts

Kevin can approve with:
/guardian approve peg_8f3c2a91 once
/guardian approve peg_8f3c2a91 session
/guardian approve peg_8f3c2a91 always
or deny with:
/guardian deny peg_8f3c2a91
```

Approval IDs are random, short-lived, and scoped to the gateway sender identity
captured for the session.

Approval scopes:

- `once`: allow exactly the matching next tool call once.
- `session`: allow the same destination, action family, and data classes for
  the current session.
- `always`: persist a narrow rule for the same destination, action family, and
  data classes.

There is no global "allow everything" approval.

## Slash Commands

Use these from a Hermes gateway interface:

```text
/guardian status
/guardian approve <id> once
/guardian approve <id> session
/guardian approve <id> always
/guardian deny <id>
/guardian clear-taint
/guardian rules
/guardian revoke <rule_id>
/guardian self-test
/guardian dashboard status
/guardian dashboard start
/guardian dashboard stop
/guardian dashboard url
/guardian dashboard prune
/guardian history [limit]
/guardian debug action=<family> destination=<dest> classes=<class+class> [tool=<tool_name>]
```

Command notes:

- `/guardian status` shows active data classes, pending approval count, and
  matching allow-rule count.
- `/guardian rules` lists persistent and configured allow rules without raw
  private content.
- `/guardian clear-taint` clears taint and session approvals for active Guardian
  sessions owned by the sender.
- `/guardian self-test` checks representative terminal and allowlist behavior
  without using private content.
- `/guardian debug ...` evaluates a hypothetical action/destination/classes
  tuple against the current policy and allow rules.

## Dashboard

Hermes Guardian includes a local read-only dashboard for understanding decisions
and recent activity.

Start it from the gateway:

```text
/guardian dashboard start
```

Or run it as a standalone local service:

```bash
python ~/.hermes/plugins/hermes-guardian/dashboard_server.py
```

Read-only endpoints:

```text
GET /
GET /api/activity
GET /api/activity?decision=blocked&data_class=email
GET /api/policy
GET /api/debug?action_family=mcp_write&destination=mcp:notion&data_classes=email
```

The dashboard shows sanitized metadata only:

- Timestamp.
- Security policy.
- Decision.
- Tool name.
- Action family.
- Destination.
- Data classes.
- Approval/rule identifiers.
- Short session hashes.
- Sanitized action detail, such as a short command summary.

It does not store raw tool arguments, email bodies, typed text, tokenized URLs,
file contents, or message content.

Activity is stored in `activity.sqlite3` inside the plugin directory. This file
is ignored by git.

## History Output

Recent sanitized activity can be checked from gateway interfaces:

```text
/guardian history
/guardian history 20
```

History is capped at 25 grouped entries.

Example:

```text
🛡️ **Guardian history** · newest first · 2 shown

✅ **`mcp_notion_update_page`** x3
Jun 6, 2026 10:42 PM PDT
🏷️ `documents`
Action: `mcp_write to mcp:notion`
Allowed: matched allow rule (`env`)

📥 **`mcp_gmail_search`**
Jun 6, 2026 10:41 PM PDT
🏷️ `email`
```

The 📥 icon means private context entered the session. It is not a success or
failure signal by itself. It means later outbound actions may require approval.

## State Storage

In-memory state:

- Session taint.
- Pending approvals.
- Once/session approvals.
- Browser host and private-typing state.

Persistent state:

- `guardian-rules.json`: persistent `always` allow rules.
- `activity.sqlite3`: sanitized activity history.

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

## Recommended Setup

For a personal Hermes install, a practical default is:

```bash
HERMES_GUARDIAN_SECURITY=llm
HERMES_GUARDIAN_ALLOWLIST="mcp_write:mcp:notion"
HERMES_GUARDIAN_DASHBOARD_HOST=127.0.0.1
HERMES_GUARDIAN_DASHBOARD_PORT=8787
HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=10000
HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=30
HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
```

Expose the dashboard only behind an authenticated tunnel or other access
control. The dashboard is read-only and sanitized, but it is still operational
security metadata.

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

The tests cover:

- Security-sensitive email suppression.
- Security-sensitive tool argument blocking.
- Taint tracking.
- Browser, MCP write, messaging, terminal, and code egress checks.
- Manual approval flows.
- Static allowlist behavior.
- `strict`, `read-only`, `llm`, and `off` policy behavior.
- Dashboard/activity history formatting and retention.

GitHub Actions is configured to run the test suite on Python 3.11.

## Limitations

- Hermes Guardian does not pause and resume blocked tool calls. The agent must
  retry after approval.
- The plugin cannot protect data that bypasses Hermes tools entirely.
- Deterministic checks intentionally favor false positives over silent
  exfiltration.
- `llm` mode is only as available as the Hermes plugin LLM facade. If the LLM
  verifier is unavailable or malformed, the plugin falls back to manual
  approval.
- Static allowlists should be narrow. They are powerful and should represent
  destinations you actually trust.
