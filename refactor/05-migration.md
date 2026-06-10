# 05 — Migration, Sequencing & Acceptance (IA v2)

> Doc 05. Read docs 01–04 first. Sequences the three surface changes so each ships independently, nothing regresses, and the privacy floor is never touched (it can't be — no doc here edits `decide`).

## 1. Order and why

| # | Doc | Why this order |
|---|---|---|
| 1 | 02 — Dashboard | The surface that defines the model and the one users see; consumes mostly-existing endpoints. Highest value, contained to `dashboard/`. |
| 2 | 03 — Slash commands | Rename + regroup the subcommands (reusing existing handlers); small and contained. |
| 3 | 04 — Config | Replace the file schema outright with the clean five-block shape; old files are re-authored, no migration step. |

Each commit is independently revertable. None changes a decision outcome; the decision corpus (`tests/fixtures/decision_corpus.json` from the refactor) must replay identically after every commit — that's the standing floor check.

## 2. Per-commit guardrails

**Commit 1 (dashboard).** New endpoints (`GET /approvals`, `GET /destinations/resolve`, `GET /sharing/preview`, `POST /sharing/impact`, clear-taint) all call existing engine functions read-only or route through existing guarded mutators — no new decision logic. Delete old tab components only after their controls are confirmed present in the new tabs (cross-check doc 01 §3). Run `bun run build` + `pytest`.

**Commit 2 (commands).** Rename the dispatcher to the five group verbs, each delegating to the existing handler functions; never copy handler logic. Old command names are removed. The test that matters: each renamed command produces the right effect via the reused handler.

**Commit 3 (config).** Replace the old key parsing with the five-block parser; the loader produces the same internal structure the engine already consumes, so `decide` never notices. No version branching, no dual-shape. The test that matters: decision-corpus parity — a v4 file yields identical outcomes to the pre-reshape config that expressed the same policy.

## 3. No-control-lost audit (run before each delete)

Before deleting any old tab/command/key, grep doc 01 §3 and confirm the control exists in its new home with its guard intact. A removed surface must never remove a capability. Keep a checkbox per row of the §3 map in the commit message.

## 4. Acceptance evidence

- **Decision-corpus parity** after each commit: identical outcomes (the floor).
- **`benchmarks/approval_fatigue.py`** unchanged (this is presentation, not policy — numbers should not move; if they do, a mutator was mis-wired).
- **Build + full suite** green on 3.11/3.12/3.13.
- **The doc-01 §7 sentence test**, done manually: open the dashboard cold, confirm the five tabs read as "what happened → what's mine → what I've shared → who judges the rest → the floor."
- **Round-trip walk:** trigger an external send in `llm` mode → it appears in Activity (pending) with trust pill + deep-linked decision step → click the "What's Yours" deep link → add the destination to self → approve nothing, re-trigger → it no longer gates. Then `/guardian why <id>` and `/guardian check <dest>` give the consistent textual answer.

## 5. Rollback

Each commit reverts cleanly. Dashboard is frontend + additive endpoints (revert the commit). Commands are a renamed dispatcher delegating to unchanged handlers (revert restores the old names). Config is a swapped parser front-end over an unchanged internal structure (revert restores the old parser). There is no data migration to undo and no compatibility window to manage — the only cost of a revert is that anyone who re-authored their config to the new shape re-authors it back, which is the same one-time cost the change imposed in the first place. Keep the three as separate commits so a regression bisects to one surface.

## 6. Definition of done

- [ ] Three commits landed on `main` in order; each reverts cleanly.
- [ ] Decision-corpus parity holds after every commit (floor never moved).
- [ ] No control lost (doc 01 §3 audited per commit).
- [ ] Five tabs / five config blocks / five command groups, all in `decide` order, all isomorphic.
- [ ] Deep links + the three pure-function widgets work on the dashboard; `check`/`preview` work in commands.
- [ ] Old config keys and old command names removed (no aliases, no dual-shape); the new shapes are the only shapes.
- [ ] The §4 sentence test and round-trip walk pass by hand.
- [ ] README/theory dashboard descriptions updated to the five-tab IA (small edit, in whichever commit lands the nav).
