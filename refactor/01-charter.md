# 01 — Guardian IA v2: Charter & Master Map

> Doc 01 of the Guardian design set. For Claude Code, in `kpsuperplane/hermes-guardian` at current `main` (post doc-05).
> **This is a structural redesign of the surfaces, not the engine.** The decision engine (`privacy/policy.py`, `privacy/capability.py`, `privacy/destinations.py`, `decide`) is correct and **must not change**. What changes is how the dashboard, the config file, and the slash commands are *organized*, so the structure itself teaches the user's mental model.

Read this doc first. Then execute docs 02 (dashboard), 03 (slash commands), 04 (config) — they land as separate commits on `main` but share the master map below. Doc 05 (migration/tests) sequences them.

## 1. The principle: structure is isomorphic to the decision

The system's mental model is the decision pipeline. The IA must let a user reconstruct it without reading prose. Every surface — tabs, config blocks, command groups — is organized into the **same five concepts, in the same order**, and that order is the order `decide` evaluates:

| Order | Concept | Pipeline meaning | `decide` step |
|---|---|---|---|
| 1 | **Activity** | what happened, and what needs me | the outcomes + pending approvals |
| 2 | **What's Yours** | where you end and the world begins | steps 2–3 (destination trust; self/local/model never gate) |
| 3 | **Sharing** | standing authorization you've granted | step 5 (declassification rules, trusted recipients, outward-sharing) |
| 4 | **Review** | case-by-case judgment for everything else | step 6 (mode, verifier, owner/cron context, unknown tools) |
| 5 | **Protection** | the floor that holds regardless | the security layer (runs before everything) + machinery + diagnostics |

Reading the nav left-to-right *is* reading `decide` top-to-bottom: **what happened → is it mine → is it covered by a grant → otherwise who judges → and the floor underneath.** Nothing appears in two places; the surface a control lives in *is* the statement of what kind of thing it is.

## 2. What this replaces

The post-doc-05 layout grew incrementally and no longer matches the model:
- **Settings is a junk drawer** (mode + LLM context + verifier + security + language packs + runtime) — five unrelated concepts in one tab.
- **Destinations & Trust conflates two concepts** — what's yours (self) *and* what you've authorized sharing to (trusted recipients, outward-sharing).
- **Rules and Tools are top-level peers** to load-bearing concepts, though one is a sharing grant and the other is engine plumbing.
- **Activity is split** across Blocks and History — an engine distinction (terminal state vs. log), not a user one.
- **Default tab is Settings** — opens on configuration, not on what the agent is doing.

## 3. Master control map (every control → exactly one home)

This table is authoritative. Docs 02–04 implement it on their respective surfaces. Current dashboard component / config key / command in parentheses.

| Control | New home | Currently lives in |
|---|---|---|
| Pending approvals (approve/deny) | **Activity** | (`/approvals/{id}/approve\|dismiss`; not surfaced as a tab list) |
| Decided stream (blocks + log, filters) | **Activity** | `BlocksTab` + `HistoryTab` (merge) |
| Per-row "why" / decision-step detail | **Activity** | `BlocksTab` (partial) + `/guardian why` |
| Clear session taint | **Activity** | `/guardian clear-taint` |
| Self stores / identities / hosts | **What's Yours** | `DestinationsTab` (self section), `[self]`, `/guardian self` |
| "Seen recently" + add-to-self | **What's Yours** | `DestinationsTab` (SeenSection) |
| "Check a destination/recipient" preview | **What's Yours** (new) | — (engine `resolve_destination_trust` exists) |
| Trusted recipients | **Sharing** | `DestinationsTab` (move out), `[trusted_recipients]`, `/guardian sharing` |
| Allow/deny rules (+ reorder) | **Sharing** | `RulesTab`, `[[privacy.rules]]`, `/guardian rules` |
| Outward-sharing subtypes | **Sharing** | `DestinationsTab` (move out), `[outward_sharing]`, `/guardian sharing` |
| Impact preview on rule/recipient edit | **Sharing** (new) | — (replay via `decide`) |
| "Preview a send" widget | **Sharing** (new) | — |
| Mode selector | **Review** | `SettingsTab` (mode card), `privacy.mode`, `/guardian status` |
| Owner-context toggle | **Review** | `SettingsTab` (LLM approval context), `privacy.llm_user_context` |
| Cron-context toggle | **Review** | `SettingsTab`, `privacy.llm_cron_context` |
| Verifier model | **Review** | `SettingsTab` (verifier card), `privacy.llm_verifier_model` |
| Unknown-tools mode | **Review** | (`/privacy/unknown-tools`), `privacy.unknown_tools` |
| Verifier scoreboard (clear-rate, latency) | **Review** (new) | (data in `/performance`) |
| Security hard-block rules | **Protection** | `SettingsTab` (security card), `[security]`, `/guardian security` |
| Tool classification overrides | **Protection** | `ToolsTab`, `[[privacy.tools]]`, `/guardian tools` |
| Language packs | **Protection** | `SettingsTab` (language card), `[language_packs]`, `/guardian language-packs` |
| Retention | **Protection** | `SettingsTab` (runtime card), `[retention]` |
| Diagnostics (timing, failures, runtime) | **Protection** | `PerformanceTab` + `SettingsTab` (runtime) |

After this, the `settings`, `tools`, `rules`, `blocks`, `history`, `performance`, `destinations` tabs are gone as distinct surfaces; their contents are redistributed above.

## 4. Invariants (hold at every commit)

1. **Engine untouched.** No edits to `decide`, `classify`, `resolve_destination_trust`, or the security layer. This is presentation + config-shape + command-grouping only.
2. **No control lost.** Every control in the §3 map must exist after the change, reachable, with its existing guard. Removing a tab never removes a capability.
3. **Guards preserved.** All mutations keep `_require_dashboard_admin` + the relevant `_require_dashboard_confirmation(...)`. Destination-trust and security edits keep their confirmation tokens.
4. **Fail closed.** A malformed/absent config still falls back to strict. Nothing in the reshape changes a decision outcome.
5. **One home per control.** If a control would appear in two surfaces, it's a bug — pick the home per §3.

**Breaking changes are encouraged where they buy cleanliness.** There is no back-compatibility requirement: old config files, old config keys, old slash-command names, and old dashboard tab ids may all be removed or renamed freely. Do not add migration shims, dual-shape loaders, command aliases, or version-detection branches. The new shape is the only shape. (Existing deployments re-author their config and learn the new command names — an acceptable one-time cost for a system this young, and worth it to keep all three surfaces clean and isomorphic.)

## 5. The two cross-cutting devices (the structure-as-teaching payoff)

These are why the IA teaches without prose. Implement them in docs 02/03:

- **Decision-step deep links.** A gated Activity row's explanation renders each clause as a link to the tab that governs it: "destination = external *(What's Yours)* → no matching rule *(Sharing)* → approval required *(Review: llm)*". Every governing tab is reachable from any single block.
- **Pure-function widgets.** "Check a destination" (What's Yours) and "Preview a send" + "Impact preview" (Sharing) all call the existing pure `decide`/`resolve_destination_trust` with hypothetical inputs — no new engine logic, no side effects. They surface the model where the question arises.

## 6. Sequencing

Land in this order (detail in doc 05). Each is independent and reversible — with no back-compat to preserve, none depends on the others.

1. **Doc 02 — Dashboard** first. It's the surface the user sees and the one that most defines the model; it consumes endpoints that already exist. Highest value.
2. **Doc 03 — Slash commands** second. Rename and regroup the subcommands; small and contained.
3. **Doc 04 — Config** third. Replace the file schema outright with the clean five-block shape. No migration step — old files are simply re-authored.

The docs are numbered in this execution order, so "do them in order" is literal: 02, then 03, then 04 (05 is the cross-cutting migration/acceptance guide, applied throughout). They're independent — with no back-compat to preserve, none strictly depends on another — but this order front-loads the highest-value, lowest-risk surface. Land each as its own commit on `main` so a regression bisects to one surface.

## 7. The acceptance test for the whole effort

A new user who has never read `theory.md` opens the dashboard, sees five tabs, and can answer "what does this do?" with: *"it shows what my agent did, knows what's mine, controls what I've allowed to be shared, decides who reviews the rest, and protects some things no matter what."* That sentence is the tab bar read aloud. If the structure doesn't produce that sentence, it isn't done.
