# Hermes Guardian
Security and privacy policy controls for personal Hermes agents.

[![Tests](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml/badge.svg)](https://github.com/kpsuperplane/hermes-guardian/actions/workflows/tests.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Hermes Plugin](https://img.shields.io/badge/Hermes-plugin-0f766e.svg)](https://github.com/NousResearch/hermes-agent)

<img width="350" src="https://github.com/user-attachments/assets/7629a26c-5a44-4266-83e8-bd5c931b78d6" />

Hermes Guardian is a user plugin for
[Hermes Agent](https://github.com/NousResearch/hermes-agent). It protects the
private content a personal agent reads — an email body, a contact list, calendar
entries, a Notion page, memory, and local system output — and controls where
that content can leave through Hermes-mediated tools.

Guardian adds two policy layers:

- **Security Module**: non-approvable blocking and suppression for credentials,
  OTPs, magic links, password resets, security alerts, sensitive account links,
  and similar access-sensitive content.
- **Privacy Module**: session taint, egress classification, privacy modes,
  optional declassification rules, and a sanitized, largely metadata activity
  history for private data flows.

  
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
hermes-guardian
```

Guardian registers a `/guardian` slash command and an integrated dashboard tab
at `/guardian`.

## How It Works

Guardian's core policy is intentionally small. Every tool call resolves once into a
**capability** `(direction, destination, data classes)`, and a single pure decision
function reasons over it:

> A read taints the session; it never egresses. A write is a confidentiality event
> only when it crosses **outward** — toward a destination whose trust is something
> other than the data owner's own boundary. A write that stays inside the owner's
> boundary (to one of their own stores, a draft, the model provider) is allowed
> without gating, because it exposes data to no other party. A write that crosses
> outward while the session holds private data gates for approval (or, with a
> declassification rule, allows or blocks deterministically).

The flow looks like this:

```text
Private source observed
        |
        v
Session tainted with data classes
        |
        v
Tool call classified -> capability (direction, destination, data classes)
        |
        v
Security-sensitive? ---- yes ----> block or suppress   (runs first, unchanged)
        |
        no
        |
        v
decide(): read? -> allow.  Destination inside the owner's boundary? -> allow.
          Outward + private taint + no rule? -> gate for approval
          (llm mode: verifier may upgrade by reading the real payload)
        |
        v
Auto-allow, hard-block, or request approval
```

### Destination trust

Each sink's destination is resolved to a trust level **relative to the data owner**:
`self`, `trusted_recipient`, `local_system`, `model_provider`, `external`, `public`,
or `unknown`. This is what lets Guardian tell "save my inbox summary to my own Notion"
(self, allowed) from "email my inbox summary to a stranger" (external, gated) instead
of gating both. Resolution is **local** — it calls no vendor service.

The defaults are conservative and fail closed. A destination whose ownership cannot
be *proven* is `unknown`, and `unknown` is treated exactly as `external`. Mislabeling
an external destination as `self` is the *only* way this design leaks, so every
ambiguity resolves toward "not self." Out of the box you get a small, floor-safe set
of seeded self stores (your own files / memory / todo / calendar / notion / drive,
plus drafts); **send-to-self for your own messaging identities and own-infrastructure
hosts is opt-in** — you add them explicitly to the self allowlist. No operator is
forced to configure anything to retain the prior safety.

### One declarative policy document

The entire risk posture lives in one policy document (the persisted Guardian config):
privacy mode, the self allowlist (destinations / identities / hosts), declassification
rules, and tool overrides. Existing configs keep working (older versions load with the
conservative defaults injected). A wholly corrupt document falls back to `strict`, not
to anything permissive.

Security checks run before privacy checks. Privacy allow rules and approval
commands cannot bypass Security Module blocks. Privacy rules are customization
hooks on top of the decision engine, not a requirement for Guardian to protect a
session.

## Privacy Modes

Privacy mode is the foundation of the Privacy Module. It controls how
private-context egress is handled by default:

| Mode | Behavior |
| --- | --- |
| `strict` | Require manual approval for tainted egress by default. Optional allow rules can preapprove known routes. |
| `read-only` | Auto-approve only metadata-verified low-risk reads; ask for approval otherwise. Optional rules can further narrow or preapprove routes. |
| `llm` | Run deterministic hard blocks first, then ask an LLM verifier for low-risk judgment. The verifier reads the real action payload (see note below). Optional rules can override known routes. |
| `off` | Disable private-egress approval checks. Security-sensitive content is still blocked. |

The default mode is `llm`.

Set the mode from a Hermes gateway:

```text
/guardian review mode llm
```

Or edit `guardian-rules.json`. The file is organized into the five IA concepts,
in `decide` order — `whats_yours` → `sharing` → `review` → `protection` (Activity
is pure output, so it has no config block) — so reading the file is reading the
decision:

```json
{
  "version": 4,
  "whats_yours": {
    "stores": ["store:files", "store:notes", "store:calendar", "store:drive", "draft:*"],
    "identities": [],
    "hosts": []
  },
  "sharing": {
    "trusted_recipients": [],
    "rules": [],
    "outward": { "extra": [] }
  },
  "review": {
    "mode": "llm",
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
    "tools": [],
    "language_packs": { "en": true },
    "retention": { "max_rows": 100, "max_age_days": 7 },
    "runtime": { "dashboard_mutations": "auto", "persist_prompts": false }
  }
}
```

This v4 schema is the only shape: there is no back-compatibility with older files,
no version detection, and the loader does not branch on `version`. An old-shape
file is not migrated — it fails closed to strict with a clear log line, and is
re-authored to the schema above. Any block may be omitted; missing blocks fill
from safe defaults (`review.mode` defaults to `llm`, `whats_yours.stores` seeds the
single-operator stores, `sharing` is empty). Outward-sharing builtin subtypes are
code-owned and never read from config; only `sharing.outward.extra` adds to them.
Mutations from the dashboard, the slash commands, and direct edits all persist this
shape, and rule mutation helpers preserve every block.

### LLM mode details

The `llm` verifier receives a sanitized excerpt of
the most recent inbound message from an **authenticated** session owner, captured
at gateway dispatch as `user_request_context`.

This channel is deliberately narrow and fail-closed:

- It is attached only for the CLI owner or a configured gateway owner
  (`TELEGRAM_ALLOWED_USERS`, `TELEGRAM_GROUP_ALLOWED_USERS`, `DISCORD_ALLOWED_USERS`).
  Group non-owners, cron, and unauthenticated senders never populate it.
- It is the inbound user turn only — never the system prompt, prior tool results,
  or model output.
- It is captured before the model or any tool runs, and only after the Security
  Module clears the message, so reset codes and credentials are never cached.
- It is sanitized (emails, phones, tokens, and URL paths redacted), held in
  volatile owner-keyed state, expires after 15 minutes, and is never written to
  activity rows, approval records, or any persistent store.
- The verifier treats it as authorization *evidence*, not an instruction: it can
  raise `authorization_level` for actions the user actually asked for, but cannot
  override `risk_level` or the absolute deny rules.
- Authorization is scoped to the data actually being sent, not just the action.
  The verifier reads the real `action_arguments` (below) alongside the ambient
  classes the session has read, and judges the payload's content against the
  authorized intent. A request authorizes only the data classes intrinsic to it,
  so "subscribe me to this newsletter" cannot launder a calendar event into the
  form: a bare email address still auto-approves, but a calendar event in the same
  field does not, even though both ran with the calendar ambiently in scope. (This
  content/intent judgment is the verifier's, made from the real payload — there is
  no separate deterministic `exported_source_classes` provenance signal anymore;
  see Data Classes.)

The verifier also receives the **real action payload** — with security-sensitive 
content and credential-shaped tokens stripped — so it can check that content 
matches the authorized intent. At-rest storage stays metadata-only apart from 
the sanitized verdict rationale (best-effort redaction, see Limitations). 
Enabling `llm` mode assumes the verifier LLM shares the agent's trust boundary; since 
you choose which LLMs Hermes connects to, that assumption is yours to own. 
The full trust-boundary rationale is in theory's 
[Coarse declassification context](./theory.md#coarse-declassification-context).

**Verifier latency.** By default the verifier runs on the agent's own model. If
that is a large or reasoning model, each gated egress can take several seconds. A
classification verdict does not need a frontier model, so you can point the
verifier at a faster one.

Because Hermes gates per-plugin model selection, you first grant Guardian an
allowlist in `~/.hermes/config.yaml` (one-time):

```yaml
plugins:
  entries:
    hermes-guardian:
      llm:
        allow_model_override: true
        allowed_models: [gpt-5.4-mini, gpt-5.5]   # the models to offer
```

Guardian reads that allowlist and offers exactly those models as a **dropdown** in
the dashboard Settings tab (Verifier model) — no need to type model ids. You can
also set it by slash command:

```text
/guardian review verifier-model gpt-5.4-mini
/guardian review verifier-model default          # back to the Hermes default
```

Guardian is fail-safe: if the override is rejected (grant missing) or the model is
unavailable, it retries once on the default model rather than denying everything. A
smaller model is faster but less sharp on subtle content/intent calls, so prefer a
capable "mini"/"flash"-class model over the smallest. Guardian also caches *deny*
verdicts briefly per session, so a retried blocked action does not re-pay the
verifier latency (denials only — a cached deny can never become a false allow).
Watch the effect in the **Performance** tab.

Both context channels are toggleable, in the dashboard Review tab, by slash
command, or directly in `guardian-rules.json` under `review`:

```text
/guardian review owner-context on|off   # default on
/guardian review cron-context on|off    # default off
```

```json
{ "review": { "owner_context": true, "cron_context": false } }
```

`llm_user_context` (default on) gates the owner channel above. `llm_cron_context`
(default off) gates a parallel channel for cron runs: when on, the verifier also
receives `cron_context`, a sanitized excerpt of the cron job's own stored
instruction (sourced from the job record, redacted the same way). Because cron
runs unattended with no human to catch a bad auto-approval, a cron job can **never
self-authorize high-risk egress** — high-risk cron actions always fall back to
manual approval even with cron context on, and enabling it raises a runtime risk
banner. Enabling cron context from the dashboard requires explicit confirmation.

## Approvals

When Guardian blocks egress, it returns a short-lived four-digit approval ID:

```text
Hermes Guardian blocked this egress.

Approval ID: 4827
Action: browser_type
Destination: example.com
Data classes: communications, contacts

The owner can approve with:
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
| `credential_content` | Private keys, OAuth/session/cloud/API tokens, bearer tokens, JWTs, cookies, and `.env`-style secret assignments. API/service tokens are read inbound but blocked at egress — see below. |
| `sensitive_links` | Reset, recovery, verification, confirmation, magic-link, OTP, and 2FA URLs. |
| `intrinsic_exfiltration` | Same-call local, code, browser console/CDP, or obvious MCP private-source reads combined with network/share sinks before session taint exists. |
| `private_network_reads` | Terminal remote-read shortcuts targeting localhost, private IPs, link-local/metadata hosts, or `.local` hosts. |

Toggle rules with:

```text
/guardian protection security
/guardian protection security disable sensitive_links
/guardian protection security enable sensitive_links
```

The intrinsic exfiltration rule is structural and metadata-only: blocked rows
record the action family, destination host or network class, data classes, and
reason, not raw commands, browser expressions, URL paths/queries, or MCP
payloads. It covers shapes such as local secret reads sent through
`requests.post`, GET query construction from local files, browser DOM/cookie
reads sent with `fetch` or `sendBeacon`, CDP `Runtime.evaluate` exfiltration,
and MCP private-source tools paired with webhook/share sinks.

`credential_content` is asymmetric by direction. On **egress** surfaces — tool
arguments, gateway messages, and the final response — every credential shape
above is blocked or suppressed. On the **inbound** tool-result path, API/service
authentication tokens (OAuth/cloud/bearer tokens, JWTs, session cookies, and
`.env`-style `*_API_KEY=` / `*_TOKEN=` / `*_SECRET=` assignments) are read into
context rather than suppressed: integrations such as MCP servers routinely
surface their own tokens, and stripping them at read-time breaks the integration
without preventing any leak — the token is still blocked if the agent later tries
to send it anywhere. Hard secrets (private keys, AWS access keys, and
`*_PASSWORD=` / `*_PRIVATE_KEY=` assignments) stay suppressed even inbound, as
does all `account_security_content` (OTPs, reset/recovery, magic links).

Disabling a security rule weakens non-approvable hardening. Privacy checks still
apply to classified private egress, but the disabled security category no
longer categorically blocks matching content or action shapes. `/guardian
status` and the dashboard policy snapshot surface a risk banner when
`intrinsic_exfiltration` is disabled.

## Data Classes

Guardian's data classes are categories of *provenance-private* content — private by
origin, not by pattern (see [Why Guardian?](#why-guardian)). This is why they are
communications, contacts, calendar, and documents rather than credential or secret
formats; access-sensitive material that *does* have a signature (credentials, OTPs,
tokens) is handled separately and more strictly by the Security Module.

Guardian tracks private context with these data classes:

| Class | Examples |
| --- | --- |
| `communications` | Email and message bodies, subjects, snippets, senders, threads, and message lists (email/DM/chat tools, or email-record headers in content). |
| `contacts` | Dex/contact data, names, **email addresses**, phone numbers, and contact metadata. |
| `memory` | Hermes memory, Mnemosyne, and session-search results. |
| `documents` | Notion, Drive, files, document bodies, and document metadata. |
| `calendar` | Meetings, attendees, schedule details, and event data. |
| `local_system` | Content-bearing terminal or code output and local runtime details. |
| `browser_private_input` | Private or user-derived text typed into a browser page. |

Source-based taint wins over content detection for known private sources. For
example, reading email taints the session as `communications` even if the returned
email text contains no obvious PII pattern. A bare email address found in content
is an identifier and taints `contacts`, not `communications`.

Web and browser reads are confidence-gated: contact-shaped content (an address, a
phone number, an `address`/`contact` field label) only taints when the host
carries private context — the operator typed credentials there, or the page shows
logged-in/account markers. Business or public-facing addresses (`support@…`, or
any address at a non-consumer domain such as `hello@kevinpei.com`) never taint on
their own, so browsing public pages does not accrue noise taint. Structurally
unambiguous signals (an SSN, an email-record header block) still taint regardless
of context. The legacy `email` class is accepted in persisted rules and maps to
`communications`.

Egress decisions reason over the **ambient session taint**: the union of the data
classes the session has read so far and any private-looking classes intrinsic to
the outgoing payload. There is no per-payload narrowing of which classes are
"provably" leaving — that is deliberately conservative (Guardian never treats
"we couldn't detect private content in this payload" as grounds to allow an
outward flow). Narrowing happens only in `llm` mode, where the verifier reads the
real payload and judges its content against the authorized intent.

> **Provenance was retired.** Earlier versions kept a volatile, metadata-only
> *provenance* index — keyed HMAC fingerprints of copied phrases from tainting
> tool results — to deterministically catch a payload that copied private content
> verbatim out of an authorized action ("laundering"). That layer was retired in
> favor of the verifier (the destination-trust model in How It Works now handles
> intra-boundary flows, and the verifier reads the real payload in `llm` mode). The trade is
> honest and scoped: in `strict` mode the contract is already "a human reviews
> every tainted egress," so the human is the laundering catch and provenance was an
> optimization at odds with that contract; in `llm` mode the verifier reads the
> real payload and catches the laundering case semantically (including paraphrased
> copies, which exact-fingerprint provenance never caught) — but it loses the
> deterministic backstop, so an adversary who fools the verifier on a *verbatim*
> laundering payload that provenance would have caught now succeeds. This is the
> one place in the design where a protection was intentionally reduced; it is
> reversible (the mechanism can be reintroduced scoped to external destinations if
> a deterministic backstop ever becomes a requirement).

## Egress Surfaces

These action families normally require approval when private data is in scope:

- Messaging and send tools.
- MCP write-like tools, and unknown MCP tools under taint.
- MCP read/search/query tools when arguments send query text or request bodies
  to a remote MCP service.
- Browser typing, submission, dialogs, and raw CDP calls.
- Terminal, shell, code execution, computer-use actions, and browser console
  evals that are not provably side-effect-free reads (see below).
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

A `browser_console` eval is classified by what its expression does. Reading page
state — DOM nodes, form field values, page text, attributes — and returning it to
the agent is a read, not egress, recognized through a fail-closed allowlist (every
operation must be a known pure-read accessor) and not gated. An eval that writes
into the page (DOM/element properties, inserting nodes, setting attributes),
submits a form, navigates, touches a credential store (cookies, web storage), runs
dynamic code, or sends to a network sink (`fetch`/XHR/`sendBeacon`/`WebSocket`) is
treated as egress — an in-page write is itself an exfiltration channel even with no
network call. Anything the allowlist cannot prove read-only falls through to normal
gating (and, in `llm` mode, to a verifier likewise instructed to allow genuine
reads).

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
/guardian protection unknown-tools gate|allow
```

When the default is too strict for a tool you trust, declare it with a **tool
override** instead of weakening the global mode. Overrides let you tell Guardian
what a tool actually does, and Guardian trusts your declaration:

```text
# An MCP server you trust: its reads carry communications, and it is not a sink.
/guardian protection tool set mcp_acme_* taints=communications egress=ignore note="trusted acme server"

# A custom tool that really sends messages: classify it so it gates correctly.
/guardian protection tool set send_widget egress=message_send

# A custom tool that is just a safe read:
/guardian protection tool set lookup_widget egress=ignore

# Force an unrecognized tool to require approval under taint:
/guardian protection tool set risky_tool egress=gate

/guardian protection tools            # list overrides + current unknown-tools mode
/guardian protection tool enable|disable <id>
/guardian protection tool delete <match_or_id>
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

Commands are grouped into the same five concepts as the dashboard tabs, in
`decide` order, so the help output mirrors the mental model: `activity`,
`mine` (what's yours), `sharing`, `review`, `protection`. `status` and `why`
sit on top as the everyday commands.

```text
/guardian status                         what's happening right now
/guardian why <id>                       explain a specific decision

# ACTIVITY — what happened, and what needs you
/guardian activity [limit]
/guardian activity failures [limit]
/guardian approvals
/guardian approve <id> [once|session|always]
/guardian deny <id>                      (alias: dismiss)
/guardian clear-taint

# WHAT'S YOURS — where you end and the world begins
/guardian mine
/guardian mine add|remove destination|identity|host <value>
/guardian check <destination|recipient>

# SHARING — what you've authorized to leave you
/guardian sharing
/guardian sharing trusted add|remove <identity> [classes=<class+class>] [note=<text>]
/guardian sharing rule add allow|deny action=<family|*> destination=<dest|*> classes=<class+class|*> [tool=<tool_name|*>] [purpose=<token|*>] [recipient=<id|raw|*>]
/guardian sharing rule delete|enable|disable <rule_id>
/guardian sharing rule move <rule_id> before|after <other_rule_id>
/guardian sharing outward add|remove <subtype>
/guardian sharing preview <action> <destination> <class>

# REVIEW — who judges everything else
/guardian review
/guardian review mode strict|read-only|llm|off
/guardian review owner-context on|off
/guardian review cron-context on|off
/guardian review verifier-model <model_id|default>

# PROTECTION — the floor that always holds
/guardian protection
/guardian protection security enable|disable <rule_id>
/guardian protection tool set <match> [taints=class+class] [egress=ignore|gate|<family>] [destination=<dest>] [note=<text>]
/guardian protection tool delete <match_or_id>
/guardian protection tool enable|disable <id_or_match>
/guardian protection unknown-tools gate|allow
/guardian protection persist-prompts on|off
/guardian protection language-packs enable|disable <pack_id>
```

Helpful commands:

```text
/guardian status
/guardian activity 20
/guardian activity failures
/guardian check stranger@example.com
/guardian sharing preview message_send messaging communications
```

`/guardian deny` is an alias for `dismiss`. `/guardian activity failed` is an
alias for `/guardian activity failures`.

## Dashboard

Guardian appears in the main Hermes dashboard at `/guardian` via
`dashboard/manifest.json`.

Dashboard tabs follow the five-concept IA, in `decide` order — reading the nav
left-to-right is reading the decision pipeline top-to-bottom (what happened → is it
mine → is it covered by a grant → who judges the rest → the floor):

- **Activity**: the decided stream as **turn cards** — each card is one turn (one user
  prompt and the checks it drove), paginated by turn, with its checks nested inside and
  expandable to the full resolved capability (the dashboard twin of `/guardian why`).
  Plus a pinned *Pending approvals* list with same-screen Approve / Dismiss, a session
  **taint strip** with *Clear session taint*, per-check **trust pills**, and
  **deep-linked decision steps** whose clauses jump to the tab that governs them.
  Filters (decision, trust, class/tag, tool, destination, recipient, date range, search)
  narrow the checks within each card. Each card header shows the prompt that drove the
  turn when prompt persistence is enabled (the Debugging toggle on this tab).
- **What's Yours**: the self side of the boundary — a *Seen recently* list bucketed by
  trust with a one-click "this is mine → add to self", the self-allowlist (stores /
  identities / hosts), a grant banner when identities/hosts are set, and a *Check a
  destination* widget (resolves a hypothetical destination/recipient to its trust,
  read-only).
- **Sharing**: the standing authorization you've granted — trusted recipients, the
  ordered allow/deny rules (add/edit/delete/enable/disable/**reorder**), the
  outward-sharing subtypes (builtin read-only, extra editable), a *Preview a send*
  widget, and an *Impact preview* that replays a candidate rule against recent activity
  before you commit it. Trust/sharing edits are admin-token + confirmation gated.
- **Review**: case-by-case judgment — the privacy **mode** (each option written as a
  who-reviews sentence), the owner/cron authorization context toggles, the verifier
  model, and a verifier **scoreboard** (consulted checks + median latency).
- **Protection**: the floor + machinery + diagnostics — Security Module hard-block
  rules, tool classification overrides (with the unknown-tools mode as a line item at
  the bottom of that list), language packs, retention, a **Debugging** card with the
  opt-in *Persist prompts* toggle (default off, confirmation-gated — writes the
  sanitized user/cron prompt onto activity rows so turn headers show what was asked),
  and the per-check timing / diagnostics table.

Hermes mounts the dashboard API under `/api/plugins/hermes-guardian/`:

```text
GET /api/plugins/hermes-guardian/policy
GET /api/plugins/hermes-guardian/performance
GET /api/plugins/hermes-guardian/activity
GET /api/plugins/hermes-guardian/activity/datatables
GET /api/plugins/hermes-guardian/approvals
GET /api/plugins/hermes-guardian/destinations
GET /api/plugins/hermes-guardian/destinations/resolve
GET /api/plugins/hermes-guardian/sharing/preview
POST /api/plugins/hermes-guardian/sharing/impact
POST /api/plugins/hermes-guardian/privacy/mode
POST /api/plugins/hermes-guardian/privacy/clear-taint
POST /api/plugins/hermes-guardian/privacy/unknown-tools
POST /api/plugins/hermes-guardian/privacy/user-context
POST /api/plugins/hermes-guardian/privacy/cron-context
POST /api/plugins/hermes-guardian/privacy/verifier-model
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
POST /api/plugins/hermes-guardian/destinations/self
POST /api/plugins/hermes-guardian/destinations/self/remove
POST /api/plugins/hermes-guardian/destinations/trusted
POST /api/plugins/hermes-guardian/destinations/trusted/remove
POST /api/plugins/hermes-guardian/destinations/sharing
POST /api/plugins/hermes-guardian/destinations/sharing/remove
```

Mutation routes can be disabled with:

```bash
HERMES_GUARDIAN_DASHBOARD_MUTATIONS=0
```

If `HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN` is set, mutation requests must
include that value in `x-hermes-guardian-token`.

The dashboard stores and displays sanitized metadata, plus the sanitized
verdict rationale (a best-effort-redacted, length-capped free-text string). It
does not store raw tool arguments, email bodies, typed text, tokenized URLs,
file contents, or message content. Recipient context is displayed as a stable
pseudonymous `recipient_<hash>` identity rather than the raw recipient value.

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
/guardian protection language-packs
/guardian protection language-packs disable es
/guardian protection language-packs enable es
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
HERMES_GUARDIAN_ACTIVITY_MAX_ROWS=100
HERMES_GUARDIAN_ACTIVITY_RETENTION_DAYS=7
HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=60
HERMES_GUARDIAN_HISTORY_TIMEZONE=America/Los_Angeles
```

Set a retention value to `0` to disable that specific limit. Set
`HERMES_GUARDIAN_ACTIVITY_GROUP_SECONDS=0` to disable display grouping.

Persistent state stores metadata, plus the sanitized verdict rationale (a
best-effort-redacted, length-capped free-text string; see Limitations). If
rules or activity state cannot be read or written, security-sensitive filtering
still runs and private egress from tainted sessions fails closed.

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
| `core.py` | Composition root: shared constants, module wiring, and `register(ctx)`. |
| `hooks.py` | Hook orchestration. Security checks run before privacy checks. |
| `security/` | Sensitive-content scanner and core-facing wrappers. |
| `privacy/` | Taint tracking, egress classification, rules, approvals, action details, and LLM verifier helpers. |
| `runtime/` | Shared context, SQLite storage, activity shaping/grouping, and lifecycle cleanup. |
| `ui/` | Slash commands, CLI command setup, dashboard action adapters, and presentation helpers. |
| `dashboard/` | Hermes dashboard manifest, FastAPI plugin API adapter, and checked-in static assets. |
| `integrations/` | Cron failure notification support. |
| `language_packs/` | Declarative semantic detection packs. |
| `tests/` | Behavior-focused pytest suite. |

The logic files are real, normally-importable modules. `core.py` imports them in
dependency order at the bottom of the file (after its constants), using the list
in `_CORE_LOGIC_MODULES`; update that tuple and `tests/test_loader_contract.py`
together when changing load order or adding a module. Cross-module references use
module-object imports (`from . import rules`; call `rules._foo()`) so the
import cycles and test/Hermes monkeypatching keep working. Duplicate top-level
definitions across modules must be intentional and listed in
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
- Session taint is intentionally coarse and conservative: egress decisions reason
  over the full ambient session taint, never narrowing on the basis that a payload
  "looks clean." The only narrowing is the `llm`-mode verifier reading the real
  payload. The verbatim-laundering deterministic catch (provenance) was retired in
  favor of that verifier (see Data Classes), so a verbatim laundering payload that
  fools the verifier in `llm` mode is no longer separately caught; `strict` mode
  still reviews every tainted egress.
- The persisted verdict rationale is a sanitized, length-capped free-text
  string, not structured metadata. Redaction of emails, phones, and
  credential-shaped tokens is best-effort, so a paraphrased private detail that
  is none of those could persist in activity and approval storage for the
  retention window.
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
