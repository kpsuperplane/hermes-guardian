# 03 — Config, Slash Commands & Dashboard

> Doc 3 of 5. Read docs 00–02 first. The model rewrite (01, 02) is only half the value; the other half is that the operator can *see and steer* it. This doc specifies the single declarative policy document that replaces today's seven scattered config surfaces, and the slash-command and dashboard changes that expose destination trust.

---

## 1. One declarative policy document (replaces seven surfaces)

### 1.1 What it consolidates

Today the risk posture is spread across: privacy `mode`, the `unknown_tools` toggle, Security-Rule toggles, language packs, env vars (`HERMES_GUARDIAN_*`), the `llm_user_context`/`llm_cron_context`/`llm_verifier_model`/`allow_model_override` switches, the `privacy.tools` override registry, and `privacy.rules`. To answer "what will Guardian do?" you must read all of them.

Consolidate into one document under the existing plugin config key (`plugins.entries.hermes-guardian`), with a stable top-level shape. Everything that defines behavior lives here and is diffable.

### 1.2 Schema (additive to today's `_default_privacy_config`)

Keep the current `version`, `privacy`, `security`, `language_packs` blocks; **add** the `self`, `trusted_recipients`, and `outward_sharing` blocks from doc 01 §4, and fold the env-var knobs into named config so the whole posture is in one place.

```toml
version = 3

[privacy]
mode = "llm"                 # llm | strict | read-only | off   (read-only & strict are presets over one engine — doc 02 §6)
unknown_tools = "gate"       # gate | allow  (unknown destination already fails closed to external; this stays for unrecognized TOOLS)
llm_user_context = true
llm_cron_context = false
llm_verifier_model = ""      # "" = same as agent model; else an allowed model id
allow_model_override = false

# --- doc 01 destination trust ---
[self]
destinations = ["store:files","store:memory","store:todo","store:calendar","store:notion","store:drive","draft:*"]
identities   = []            # operator's own verified send-to-self addresses/handles; EMPTY = none proven
hosts        = []            # operator's own infra hosts; EMPTY = none proven

[trusted_recipients]
entries = []                 # [{ identity = "...", classes = ["personal_private"], note = "..." }]

[outward_sharing]
builtin = ["share","invite","publish","add_collaborator","make_public","set_permissions"]   # cannot be narrowed
extra   = []

# --- declassification rules (purpose x classes x destination) ---
# Ordered; first matching ALLOW/DENY wins (doc 02 §3 step 5).
[[privacy.rules]]
effect      = "allow"        # allow | deny
action      = "*"            # action family/subtype or *
destination = "*"            # destination id/trust or *
classes     = "*"            # policy class(es)/tag(s) (+ separated) or *
purpose     = "*"
recipient   = "*"

# --- tool overrides (unchanged role: teach Guardian unknown tools) ---
[[privacy.tools]]
match       = "crm_*"
direction   = "read"         # NEW: read|write (else inferred from name / MCP annotation)
taints      = ["personal_private"]
destination = "store:crm"    # NEW: lets a custom store be declared, then listed under [self] if owned
egress      = "gate"         # ignore | gate | <family>
note        = ""

[security]
# unchanged: rule toggles

[language_packs]
# unchanged

[retention]
max_rows = 100               # folds in HERMES_GUARDIAN_* env equivalents; env may still override for ops
max_age_days = 7

[dashboard]
mutations = "auto"           # folds HERMES_GUARDIAN_DASHBOARD_MUTATIONS
admin_token_env = "HERMES_GUARDIAN_DASHBOARD_ADMIN_TOKEN"
```

Rules for the loader (`privacy/rules.py`):
- **Back-compat:** a `version = 2` (or absent) config loads with the doc-01 defaults injected (`self` seeded per doc 01 §4, others empty). No operator action required to keep working; they simply gain the FP reductions on `self` defaults.
- **Fail closed:** malformed `self`/`trusted_recipients`/`outward_sharing` → drop to the safe default subset for that block, log, do not crash. A wholly corrupt document still falls back to strict (existing behavior).
- **`outward_sharing.builtin` is not narrowable.** Parsing ignores attempts to remove builtin entries; `extra` may add.
- Env vars still readable for ops overrides, but the *source of truth* is the document; surface env overrides in `status` so they're not invisible.

## 2. Slash commands

Today's surface (verified) includes `/guardian status`, `rules`, `rule add|delete|enable|disable|move`, `privacy mode|unknown-tools|user-context|cron-context|verifier-model`, `tools`, `tool set|delete|enable|disable`, `security`, `language-packs`, `history`, `failures`, `debug`. Extend it to make destination trust first-class and to make the new model legible. **Keep all existing commands working** (alias where renamed).

### 2.1 New commands

```
/guardian self                          show the self-destinations, identities, hosts, and trusted recipients
/guardian self add destination <kind:id>        add an owned store (e.g. store:crm)
/guardian self add identity <addr|handle>        declare an owned send-to-self identity
/guardian self add host <hostname>               declare an owned infra host
/guardian self remove <destination|identity|host> <value>
/guardian trusted add <identity> [classes=<...>] [note=<text>]
/guardian trusted remove <identity>
/guardian sharing                       show outward-sharing subtypes (builtin + extra); builtin marked non-removable
/guardian sharing add <subtype>         add an extra outward-sharing subtype (always external)
/guardian why <id>                      explain a specific decision: the resolved Capability + which decide() step fired
```

`/guardian why <id>` is the reason-about-ability payoff: for an activity/approval id, print the resolved `Capability` (direction, destination id + **trust**, policy classes, fine tags) and the exact `decide` branch that produced the outcome (e.g. "step 3: destination trust=self → allow" or "step 6: external + personal_private, no matching rule → approve"). This makes every block self-explaining.

### 2.2 Changed commands

- **`/guardian debug`** gains `destination_trust` in output and accepts a `recipient=<id>` arg so an operator can preview how a recipient resolves (self/trusted/external/unknown) before sending.
- **`/guardian status`** adds a destination-trust summary: counts of self/trusted/external/unknown destinations seen this session, the active mode-as-preset, and any env overrides shadowing the document.
- **`/guardian tool set`** gains `direction=read|write` and `destination=<kind:id>` (mirrors the override schema §1.2).
- **`/guardian privacy mode`** keeps `strict|read-only|llm|off` strings but they now select engine presets (doc 02 §6), not separate code paths — behavior identical from the operator's view.

Update the help/usage string list at the top of `ui/commands.py` to include the above.

## 3. Dashboard

The dashboard mutation/query functions live in `ui/dashboard.py` (+ `dashboard/plugin_api.py` routes). Add destination trust as a visible, steerable dimension.

### 3.1 New "Destinations & Trust" section

A panel (and matching read endpoint) showing:
- The self-allowlist (stores, identities, hosts) with add/remove controls → call new `_dashboard_self_*_action(...)` functions mirroring the slash commands.
- Trusted recipients with add/remove.
- Outward-sharing subtypes, builtin ones rendered read-only/non-removable, `extra` editable.
- A live tally of destinations observed this session bucketed by trust, so the operator can spot an `external`/`unknown` they expected to be `self` and one-click add it.

Mutations go through the existing admin-token + confirmation guards (`_require_dashboard_admin`, `_require_dashboard_confirmation`) — destination-trust edits are security-relevant, so require confirmation like the cron-context toggle does.

### 3.2 Activity view: show trust + make decisions self-explaining

The activity rows (`runtime/activity_rows.py`) currently carry `decision`, `action_family`, `destination`, `purpose`, `recipient_identity`, `data_classes`, `reason`. Add:
- **`destination_trust`** column (self/trusted/external/public/unknown) — the single most useful new signal, since it tells the operator at a glance whether a block was a boundary crossing.
- **`decision_step`** — which `decide` branch fired (mirrors `/guardian why`), so the activity log explains itself without a separate lookup.
- Keep `data_classes` showing the **fine tags** (audit fidelity, invariant #6); add a derived `policy_class` only if useful for filtering.

Add `destination_trust` to the datatables filterable columns (the allow-list at `runtime/activity_rows.py` ~line 31: `{"destination","tool_name","purpose","recipient_identity"}` → add `"destination_trust"`).

### 3.3 Banners

Keep the existing runtime risk banners (unknown network containment, disabled intrinsic exfiltration). **Add** a banner when:
- `self.identities` or `self.hosts` is non-empty (operator has granted send-to-self / own-infra trust) — informational, so the grant is never invisible.
- `llm_verifier_model` diverges from the agent model (already surfaced per prior work) — keep.

## 4. Cron notifications

Cron notifications (`privacy/rules.py` cron logic + the notifier) must reflect the new model:
- A cron egress that resolves to a `self` destination no longer notifies/gates (it's intra-boundary) — this removes routine cron FP noise.
- The high-risk cron downgrade (doc 02 §3 step 6) is unchanged: a cron run can smooth routine self/low/medium egress but never self-authorize a high-risk *external* export.
- Notification text gains the `destination_trust` and `decision_step` so an unattended block is explainable after the fact.

## 5. At-rest honesty (invariant #5)

Adding `destination_trust` and `decision_step` to activity rows is metadata-only (an enum and a step label — no payload content), so the metadata-only property holds. Do **not** persist resolved recipient raw values beyond the existing pseudonymous `recipient_identity`. The sanitized-rationale caveat is unchanged.

## 6. New / changed code

| File | Change |
|---|---|
| `privacy/rules.py` | Parse/normalize/validate `self`, `trusted_recipients`, `outward_sharing`, `retention`, `dashboard` blocks; back-compat injection; fail-closed; non-narrowable builtin sharing. |
| `ui/commands.py` | New `self`/`trusted`/`sharing`/`why` commands; extend `debug`/`status`/`tool set`/`privacy mode`; update usage strings. |
| `ui/dashboard.py`, `dashboard/plugin_api.py` | `_dashboard_self_*`, `_dashboard_trusted_*`, `_dashboard_sharing_*` actions + read endpoint; Destinations & Trust panel; confirmation-guarded. |
| `runtime/activity_rows.py` | Add `destination_trust`, `decision_step`; add `destination_trust` to filterable columns; keep fine tags in `data_classes`. |
| `runtime/activity_store.py` | Persist the two new metadata fields (enum + label); schema/migration; retention unchanged. |
| cron notifier | Skip self-destination notifications; include trust + step in text. |

## 7. Tests

`tests/test_config_policy_doc.py`, `tests/test_commands_destinations.py`, `tests/test_dashboard_trust.py`.

1. **Back-compat load.** A `version=2` config loads, runs, and gains seeded `self` defaults; no crash, no behavior regression on its existing rules.
2. **Fail-closed parse.** Malformed `self`/`outward_sharing` drops to safe subset; fully corrupt → strict.
3. **Non-narrowable sharing.** Config removing a builtin sharing subtype has no effect.
4. **`/guardian self add/remove` round-trips** and changes resolution (add `store:crm` to self → a write there flips external→self).
5. **`/guardian why <id>`** prints the resolved Capability and the firing `decide` step matching the actual outcome.
6. **`/guardian debug recipient=<id>`** previews recipient trust correctly (self/trusted/external/unknown), including unknown for a templated recipient.
7. **Activity row carries `destination_trust` + `decision_step`**, fine tags preserved in `data_classes`, new column filterable.
8. **Dashboard self-edit is admin+confirmation gated** and persists.
9. **Identity/host grant raises the informational banner.**
10. **At-rest check:** new fields are enums/labels only; no payload content persisted; recipient stays pseudonymous.

## 8. Checklist

- [ ] One policy document parses with all blocks; env overrides surfaced in `status`.
- [ ] Back-compat + fail-closed + non-narrowable sharing verified.
- [ ] `self`/`trusted`/`sharing`/`why` commands work; existing commands unbroken (aliases where renamed).
- [ ] Dashboard Destinations & Trust panel + activity trust column + decision-step shipped, confirmation-guarded.
- [ ] Cron notifications skip self, include trust + step.
- [ ] Activity additions are metadata-only.
