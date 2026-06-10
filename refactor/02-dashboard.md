# 02 — Dashboard: the five-tab IA

> Doc 02. Read doc 01 first (the master map is authoritative). This restructures `dashboard/src` into five tabs. **Frontend + endpoint wiring only** — no engine changes. Endpoints in `dashboard/plugin_api.py` already exist for nearly everything; this is mostly moving components between tabs, merging two, splitting one, and adding three small widgets.

## Target nav (replaces `TAB_DEFS` in `GuardianPage.tsx:23-29`)

```
Activity · What's Yours · Sharing · Review · Protection
```

Order is fixed (it mirrors `decide`). **Default tab becomes `activity`** (currently `settings` at `GuardianPage.tsx:69`). Use new internal ids matching the labels (`activity`, `whats-yours`, `sharing`, `review`, `protection`) and update the conditional renders + the per-tab load effects (`GuardianPage.tsx:86-87,113-115`).

## Tab 1 — Activity

**Merge `BlocksTab` + `HistoryTab` into one `ActivityTab`.** They are the same concept (what the agent did + what Guardian decided); the blocks/history split is an engine artifact.

Contents, top to bottom:
1. **Session taint strip** (header): "This session carries: communications, calendar" + **Clear session taint** button. Wire to the existing clear-taint action (find the action behind `/guardian clear-taint`; expose it as a guarded endpoint if not already, mirroring the other `/privacy/*` mutators). Show nothing if untainted.
2. **Pending approvals** (pinned): a list of items awaiting decision. Source: there are `POST /approvals/{id}/approve` and `POST /approvals/{id}/dismiss` routes but no read list — add `GET /approvals` returning pending items (reuse the activity store; pending = gated-awaiting-decision). Each card: capability summary (`action_family → destination` + **trust pill**), `data_classes`/tags, `recipient_identity`, `purpose`, `decision_step`, sanitized verifier rationale if present. Actions: **Approve** / **Deny** (→ the existing routes). This is the only place in the app with same-screen actions.
3. **Decided stream**: the merged blocks+history rows. Reuse `GET /activity` / `GET /activity/datatables`. Each row: trust pill + deep-linked `decision_step` (see §Deep links). Filters: decision (allowed/gated/blocked) · trust level · class/tag · tool · destination · recipient · date range · search. Fold `useHistory`'s pagination into this view.
4. **Per-row expansion**: full resolved capability (direction, destination kind/id/trust, policy class, fine tags, recipient, decision step, final decision) — the dashboard twin of `/guardian why <id>`.

Delete `BlocksTab.tsx`, `HistoryTab.tsx`/`.css` after porting; `ActivityTab.tsx`/`.css` replaces them. `usePerformance` is unaffected (moves to Protection).

## Tab 2 — What's Yours

**Rename `DestinationsTab` → `WhatsYoursTab` and remove the sharing concepts from it** (trusted recipients + outward-sharing move to Sharing — §Tab 3).

Contents:
1. **"How Guardian decides" blurb** (≤3 sentences, keep the existing one from `DestinationsTab:176`): "Guardian allows anything that stays with you — your own stores, your own machine. It asks for approval when private data is about to reach someone else. Anything it can't confirm is yours is treated as someone else."
2. **Seen recently** (keep `SeenSection`): the session trust tally + **"This is mine → add to self"** on external/unknown entries (`POST /destinations/self`, guarded). Keep as the prominent top interaction.
3. **What's yours** (keep the self section): **Stores**, **Identities**, **Hosts**, each add/remove (`/destinations/self`, `/destinations/self/remove`). Keep the teaching empty-states ("No identities declared — sends to any address are treated as external (the safe default)").
4. **Grant banner**: when identities or hosts are non-empty, an informational (non-dismissable) banner that send-to-self / own-infra trust is active.
5. **Check a destination** (new widget): input a destination (`kind:id`) or recipient → shows resolved trust (self/trusted/external/unknown). Add `GET /destinations/resolve?value=...` calling the engine's `resolve_destination_trust` read-only (no mutation, no guard needed; it computes, changes nothing).

Pull the trusted/sharing rendering out of `DestinationsTab` (lines ~168-171 and their sections) and move to Sharing. Keep `useDestinations` but it now serves both What's Yours and Sharing (it already returns `self`, `trusted_recipients`, `outward_sharing`); the two tabs read different slices of the same payload.

## Tab 3 — Sharing

**New `SharingTab`** assembling standing authorization from three current places: `RulesTab` (rules), and the trusted-recipients + outward-sharing sections moved out of `DestinationsTab`.

Contents:
1. **Trusted recipients**: identity, class scope, note; add/remove (`/destinations/trusted`, `/destinations/trusted/remove`, guarded).
2. **Allow / deny rules**: the ordered first-match list from `RulesTab`. Add / edit / delete / enable / disable / **reorder** (`POST /rules`, `PATCH /rules/{id}`, `DELETE /rules/{id}`). Order is semantics — make reorder explicit (drag or up/down). Fields: effect · action · destination · classes (policy class or fine tag) · purpose · recipient. Reuse `lib/rules.ts`.
3. **Outward sharing**: builtin subtypes read-only ("always external — cannot be disabled"), `extra` add/remove (`/destinations/sharing`, `/destinations/sharing/remove`).
4. **Preview a send** (new widget): action + destination + class → which `decide` step fires + outcome. Add `GET /sharing/preview?...` calling `decide` with hypothetical inputs (read-only).
5. **Impact preview** (new, on rule/recipient add or edit, before commit): replay recent activity through `decide` with the hypothetical change → "this would have auto-allowed 3 of the last week's gated actions: …". Add `POST /sharing/impact` that takes a candidate rule and replays stored capabilities read-only. This is the over-permissiveness guardrail; prioritize it.

Delete `RulesTab.tsx` after porting.

## Tab 4 — Review

**New `ReviewTab`** from the Settings cards that govern case-by-case judgment.

Contents:
1. **Mode selector** (from `SettingsTab` mode card, `POST /privacy/mode`, guarded): options written as who-reviews sentences — `llm` "the verifier pre-screens; you see only genuine boundary crossings" · `strict` "you review every outbound action yourself" · `read-only` "nothing outward is auto-allowed" · `off` as a destructive kill switch with confirm. Keep underlying values identical.
2. **Owner context** (`POST /privacy/user-context`): toggle — "give the verifier your recent request as authorization evidence."
3. **Unattended (cron) context** (`POST /privacy/cron-context`, guarded): toggle + the fixed note that high-risk unattended actions are always downgraded to manual approval regardless.
4. **Verifier model** (`POST /privacy/verifier-model`): the dropdown from `SettingsTab` verifier card, populated from `allowed_models`, gated on `allow_model_override`, "Default (agent model)" first.
5. **Unknown tools** (`POST /privacy/unknown-tools`): gate / allow — "what happens when Guardian doesn't recognize a tool."
6. **Verifier scoreboard** (read-only): "cleared X of Y gated actions this week" + median verifier latency, derived from `GET /performance` timing data.

## Tab 5 — Protection

**New `ProtectionTab`** = the floor + machinery + diagnostics. Banner at top: "These run before everything else and apply to every destination, including your own."

Contents:
1. **Security rules** (from `SettingsTab` security card, `PATCH /security/rules/{id}`, guarded): the hard-block toggles.
2. **Tool classification** (from `ToolsTab`, `POST /tools`, `PATCH /tools/{id}`, `DELETE /tools/{id}`): the override table — match, direction, taints, destination, egress treatment; add/edit/delete/enable/disable. (Note for the user: declaring a custom store *yours* is in What's Yours; *teaching Guardian what a tool is* is here.)
3. **Language packs** (from `SettingsTab`, `PATCH /language-packs/{id}`).
4. **Retention** (from `SettingsTab` runtime card): `max_rows`, `max_age_days`, with the one-sentence at-rest/metadata-only + sanitized-rationale caveat.
5. **Diagnostics** (read-only): the per-check timing table (the whole current `PerformanceTab` demoted to a section), the failures list, runtime info (dashboard-mutations setting, admin-token status shown as state).

Delete `SettingsTab.tsx`/`.css`, `ToolsTab.tsx`/`.css`, `PerformanceTab.tsx` after porting; `ProtectionTab` + `ReviewTab` absorb them. Remove the `onGoToDestinations` prop plumbing (Settings is gone).

## Deep links (the teaching device — §01.5)

In the Activity decision-step line, render each clause as a link:
- "destination = external" / "unknown" → **What's Yours**
- "no matching rule" → **Sharing**
- "approval required (llm/strict)" → **Review**

Implement as a small parser over `decision_step` that maps known clause fragments to `setTab(...)`. Keep it resilient: if a clause isn't recognized, render it as plain text.

## New endpoints to add (read-only unless noted)

| Route | Purpose | Guard |
|---|---|---|
| `GET /approvals` | pending-approvals list for Activity | none (read) |
| `GET /destinations/resolve` | "check a destination" | none (read) |
| `GET /sharing/preview` | "preview a send" | none (read) |
| `POST /sharing/impact` | replay candidate rule vs. recent activity | none (read; computes, no mutation) |
| clear-taint endpoint | if not already exposed, mirror `/privacy/*` | guarded |

All call existing engine functions with hypothetical/real inputs; none add decision logic.

## Tests

- Each new tab renders and round-trips its mutations through the existing guarded routes (port the existing tab tests; add coverage for the merged Activity filters and the moved sections).
- Deep-link parser maps each known clause to the right tab; unknown clause renders as text.
- The three widgets return correct resolutions for known fixtures (self destination → self; templated recipient → unknown; a candidate rule's impact lists the right historical rows).
- `bun run build` + `python -m pytest -q` green.

## Checklist

- [ ] Nav = the five tabs in order; default `activity`.
- [ ] Activity merges blocks+history, pins approvals (with new `GET /approvals`), shows taint strip + clear, trust pills, deep-linked decision steps.
- [ ] What's Yours = self + seen-recently + check-a-destination; trusted/sharing removed from it.
- [ ] Sharing = trusted + rules + outward-sharing + preview-a-send + impact preview.
- [ ] Review = mode + contexts + verifier model + unknown-tools + scoreboard.
- [ ] Protection = security + tool classification + language packs + retention + diagnostics.
- [ ] Old tab components deleted; no control lost (cross-check doc 01 §3).
- [ ] Deep links + three widgets working; guards intact; build + tests green.
