# 03 — Slash commands: grouped to mirror the IA

> Doc 03. Read docs 01–02 first. This regroups `/guardian` subcommands into the same five concepts as the tabs, in the same order, so the help output *is* the mental model. **Renaming + regrouping in `ui/commands.py`**; no engine or config-logic change. **No back-compat:** old command names are removed, not aliased. The new names are the only names.

## 1. Principle

`/guardian` with no args (or `/guardian help`) prints the five concepts in `decide` order, each with its subcommands. A user reading help sees the same structure as the tab bar and the config file. The five top-level group verbs match the tabs: **`activity`, `mine`, `sharing`, `review`, `protection`** (plus the always-useful `why` and `status`).

## 2. Current → grouped command map

Current subcommands: `status`, `why`, `clear-taint`, `rules`, `tools`, `self`, `sharing`, `security`, `language-packs`. Regroup and add:

```
/guardian                          → grouped help (the five concepts, in order)
/guardian status                   → one-screen summary (mode, taint, trust tallies) — unchanged
/guardian why <id>                 → explain a decision — unchanged (already shipped)

ACTIVITY
/guardian activity [filters]       → recent decided actions (new; wraps the activity listing)
/guardian approvals                → list pending approvals (new; GET /approvals)
/guardian approve <id>             → approve a pending item (new; POST /approvals/{id}/approve)
/guardian deny <id>                → deny a pending item (new; POST /approvals/{id}/dismiss)
/guardian clear-taint              → clear session taint — unchanged

WHAT'S YOURS
/guardian mine                     → show self stores/identities/hosts + seen-recently (replaces `self`)
/guardian mine add store|identity|host <value>
/guardian mine remove store|identity|host <value>
/guardian check <destination|recipient>   → resolve trust preview (new; the "check a destination" widget in text)

SHARING
/guardian sharing                  → show trusted recipients + rules + outward-sharing (regrouped parent)
/guardian sharing trusted add|remove <identity> [classes=...]
/guardian sharing rule add|delete|enable|disable|move ...   (absorbs current `rules`)
/guardian sharing outward add|remove <subtype>              (current `sharing` outward behavior)
/guardian sharing preview <action> <destination> <class>    → which step fires (new; preview-a-send)

REVIEW
/guardian review                   → show mode, contexts, verifier model, unknown-tools
/guardian review mode <llm|strict|read-only|off>
/guardian review owner-context <on|off>
/guardian review cron-context <on|off>
/guardian review verifier-model <model|default>
/guardian review unknown-tools <gate|allow>

PROTECTION
/guardian protection               → show security rules, tool overrides, language packs, retention
/guardian protection security ...           (absorbs current `security`)
/guardian protection tool set|delete|enable|disable ...   (absorbs current `tools`)
/guardian protection language-packs ...     (absorbs current `language-packs`)
/guardian protection retention <max-rows|max-age-days> <n>
```

## 3. Rename map (old names removed)

The old subcommands are renamed to their new homes — the old names are deleted from the dispatcher, not kept as aliases. Reuse the existing handler *functions* (don't rewrite the logic); only the command names and grouping change.

| Old command (removed) | New command | Reuses handler |
|---|---|---|
| `/guardian self ...` | `/guardian mine ...` | the current `self` handler |
| `/guardian rules ...` | `/guardian sharing rule ...` | the current `rules` handlers |
| `/guardian sharing` (outward) | `/guardian sharing outward ...` | the current outward-sharing handler |
| `/guardian security ...` | `/guardian protection security ...` | the current `security` handler |
| `/guardian tools ...` | `/guardian protection tool ...` | the current `tools` handlers |
| `/guardian language-packs ...` | `/guardian protection language-packs ...` | the current `language-packs` handler |
| `/guardian status`, `/guardian why`, `/guardian clear-taint` | kept as-is (status/why at top level; clear-taint under Activity) | unchanged |

Implementation: rewrite the dispatcher's `if command == ...` chain to the five group verbs, each parsing its second token and delegating to the same underlying handler functions the old commands called. Delete the old top-level command branches.

## 4. Grouped help (`_HELP`)

Rewrite the `_HELP` string so it's organized under the five headings in order, with `status`/`why` at the top as the everyday commands. The shape of the help text is itself the deliverable — it should read as:

```
/guardian — privacy firewall for your agent

  status                  what's happening right now
  why <id>                explain a specific decision

ACTIVITY — what happened, and what needs you
  activity, approvals, approve <id>, deny <id>, clear-taint

WHAT'S YOURS — where you end and the world begins
  mine, mine add/remove store|identity|host, check <dest>

SHARING — what you've authorized to leave you
  sharing, sharing trusted/rule/outward ..., sharing preview ...

REVIEW — who judges everything else
  review, review mode|owner-context|cron-context|verifier-model|unknown-tools

PROTECTION — the floor that always holds
  protection, protection security|tool|language-packs|retention ...
```

## 5. New command details

- **`/guardian check <value>`**: calls the engine `resolve_destination_trust` read-only; prints `value → <trust>` plus a one-line reason ("not in your self-allowlist → external"). Mirror `/guardian why`'s formatting style.
- **`/guardian sharing preview <action> <destination> <class>`**: calls `decide` with hypothetical inputs read-only; prints the firing step and outcome.
- **`/guardian approvals` / `approve` / `deny`**: list and act on pending approvals via the routes; confirm the dispatcher has access to the same approval store the dashboard uses.
- All new read commands (`check`, `preview`, `activity`, `approvals`) are non-mutating and need no confirmation; `approve`/`deny` and any setter inherit the existing confirmation behavior the old equivalents used.

## 6. Tests (`tests/test_commands_ia.py`)

1. **Renamed commands work** and produce the right effect via the reused handler — one assertion per row of §3 (old name is gone; new name does what the old one did).
2. **Grouped help** lists the five concepts in order with the everyday commands on top.
3. **New commands**: `check` resolves a known destination; `sharing preview` returns the right step for a fixture; `approvals`/`approve`/`deny` round-trip against a seeded pending item.
4. **Delegation, not duplication**: group commands call the same underlying handler functions (assert the renamed command and the original handler produce the same result for identical input).

## 7. Checklist

- [ ] Five group verbs (`activity`/`mine`/`sharing`/`review`/`protection`) + `status`/`why` dispatch correctly.
- [ ] Old command names removed; renamed per §3, each reusing its existing handler (no duplicated logic).
- [ ] `_HELP` regrouped into the five concepts in `decide` order.
- [ ] New `check`, `sharing preview`, `approvals`/`approve`/`deny` implemented, read commands unguarded, setters guarded as before.
- [ ] New commands delegate to existing handlers (no duplicated logic).
- [ ] All §6 tests pass.
