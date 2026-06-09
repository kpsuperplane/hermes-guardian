# 04 — Migration & Test Plan

> Doc 4 of 5. Read docs 00–03 first. This doc sequences the refactor so the privacy floor (doc 00 §2) is provable at every step, specifies the test suite that enforces the invariants, and defines the benchmark evidence that proves G1 happened without breaching the floor. Follow the phases in order; do not skip the baseline capture.

---

## 1. Guiding principle: additive first, switch second

Build the new model *alongside* the old one with no behavior change, prove the new model fail-closed in isolation, then flip the decision over to it, then migrate surfaces, then delete dead code. This keeps every intermediate commit shippable and makes a regression bisectable to a single phase.

## 2. Phase 0 — Baselines (do this before any code change)

Capture, commit to the repo (e.g. `benchmarks/baselines/`), and never overwrite:

```bash
# Privacy floor + FP instruments, on pristine main
python -m benchmarks.approval_fatigue --pretty --out benchmarks/baselines/approval_fatigue.main.json
python -m benchmarks.guardian_adversarial --pretty --out benchmarks/baselines/adversarial.main.json
# AgentDojo (optional, local venv per its README)
.venv-agentdojo/bin/python -m benchmarks.agentdojo_guardian --pretty --out benchmarks/baselines/agentdojo.main.json
python -m pytest -q   # record the passing count
```

Also **record a decision corpus** for behavior parity (used by doc 02 §9 test 10): instrument the current `decide` path to log, for a fixed scripted set of tool calls under taint (self-writes, external sends, drafts, shares, unknown tools, cron egress, paraphrase cases, **and verbatim-laundering cases that provenance currently catches**), the `(tool, args-shape, taint, decision)` tuples. Save as `tests/fixtures/decision_corpus.json`. This is the floor's ground truth: every `block` in it must remain a block (or become a block via a different-but-correct path); only `gate→allow` flips on intra-boundary flows, plus the sanctioned provenance carve-out (§7.1), are permitted. Tag the laundering cases so §7.1's replay can bucket them.

## 3. Phase 1 — Destination-trust resolver (additive, doc 01)

- Implement `privacy/destinations.py` and the config blocks; seed defaults.
- **No call site changes yet** — the resolver is dead code in production paths.
- Land `tests/test_destination_trust.py` (doc 01 §7). All 10 must pass.
- Re-run the suite; benchmarks unchanged (nothing is wired in). This phase cannot move any number; if it does, something is mis-wired.

## 4. Phase 2 — Capability model + decision engine (additive, doc 02)

- Implement `privacy/capability.py` (`classify`) and `privacy/policy.py` (`decide`), routing every old→new mapping row (doc 02 §7).
- Run **both** engines in shadow: keep the existing decision authoritative, but compute the new `decide` result alongside and log any divergence (a `shadow_mismatch` counter + structured log). Do not act on the new result yet.
- Land `tests/test_capability.py` and `tests/test_policy_engine.py` (doc 02 §9, tests 1–9).
- Replay `decision_corpus.json` through the new engine (test 10). Triage every divergence into exactly one bucket:
  - **expected gate→allow on intra-boundary** (self/draft/idempotent-self) — the FP wins; record it.
  - **floor breach** (a previously-correct block now allows) — **must be zero before proceeding.** Fix the classifier/resolver until it is.
  - **new block** (something now blocks that didn't) — investigate; acceptable only if it was a true under-block before, otherwise it's a new FP and must be fixed.
- Shadow divergence in a live/dev run should converge to "only the expected intra-boundary flips." Let it bake.

## 5. Phase 3 — Flip the switch

- Make `decide` authoritative; remove the old decision branches now living in it.
- Keep `classify`'s read-side helpers (taint resolution, web suppression, shell logic) — only the *decision* logic is deleted.
- Re-run benchmarks:
  - `approval_fatigue`: benign-gate count must **drop** vs baseline; `unsafe_auto_approvals` must stay **0**.
  - `adversarial` + `agentdojo`: prevented_rate must **not drop** vs baseline. Any drop = floor breach = revert the flip, fix, retry.
- This is the commit where G1 becomes measurable. Record the new numbers next to the baselines.

## 6. Phase 4 — Surfaces (doc 03)

- One policy document + back-compat injection; env overrides surfaced.
- Slash commands (`self`/`trusted`/`sharing`/`why`, extended `debug`/`status`/`tool set`).
- Dashboard Destinations & Trust panel; activity `destination_trust` + `decision_step`.
- Cron notifications skip self, include trust + step.
- Land `tests/test_config_policy_doc.py`, `tests/test_commands_destinations.py`, `tests/test_dashboard_trust.py` (doc 03 §7).
- Verify at-rest additions are metadata-only.

## 7. Phase 5 — Class & mode collapse + provenance retirement (doc 02 §4–§6)

Do this **last**, after the engine is proven, because it changes the shape of records, modes, and the protection surface:
- Introduce the policy-class/tag split; map fine classes → `personal_private` + tag.
- Convert `read-only` and `strict` to engine presets / verifier-toggle; delete mode branching.
- **Retire provenance.** Delete `privacy/provenance.py`, the read-time fingerprint indexing, and the egress-time matching; confirm no code path consumes `exported_source_classes` (the seam is `decide` step 4, which now uses ambient taint). Keep `_guardian_hmac_key()` — approvals and rationale sanitization still use it; only the provenance consumer is removed.
- Re-run the parity replay and benchmarks once more: blocks preserved (except the deliberate provenance carve-out below), fine tags preserved in audit, `strict`/`read-only` parity tests green.
- Delete now-dead class-distinction code paths.

### 7.1 The provenance carve-out in the parity replay (read carefully)

The phase-2 parity rule was "zero floor breaches." Provenance retirement is the **one sanctioned exception** (charter §2.1), and the replay must treat it explicitly rather than letting it hide among the allowed flips:

- Bucket every replay divergence into: (a) expected intra-boundary `gate→allow` (destination-trust — fine), (b) **provenance-laundering flips** — a previously-flagged laundering case that, with provenance gone, now reaches the verifier instead of being deterministically caught, and (c) anything else (must be zero).
- For bucket (b), assert the *intended* new behavior: in `llm` mode the verifier still catches the verbatim laundering case (so the end decision is unchanged — verifier-mediated rather than provenance-mediated); in `strict` mode the flow goes to manual review like every other tainted egress (strict reviews everything by contract, so the human is the catch — not a regression). Add an explicit test `test_provenance_retirement.py`:
  - `llm` mode: a verbatim-laundering payload to an external destination is still held at `APPROVE`/`BLOCK` by the verifier (parity with pre-retirement outcome).
  - `strict` mode: the same payload routes to manual review (as all tainted external egress does); assert that, and annotate `# strict mode reviews every egress — the human is the laundering catch; provenance was an optimization at odds with that contract (charter §2.1)`.
- **FP check specific to retirement:** re-run `approval_fatigue` in `llm` mode with the external-flow cases provenance used to narrow; confirm the verifier recovers the narrowing so `llm`-mode benign-gate counts do **not** rise versus the post-phase-3 numbers. If they rise, the verifier isn't recovering the narrowing and you need to investigate before deleting provenance.

### Results section (acceptance evidence — fill this in)

Put a table in the PR description and in `benchmarks/baselines/RESULTS.md`:

| Metric | main (baseline) | after refactor | floor/▼ |
|---|---|---|---|
| approval_fatigue benign gates (strict) | … | … (lower) | FP ▼ |
| approval_fatigue unsafe_auto_approvals | 0 | **0** | must hold |
| adversarial prevented_rate | … | … (≥ baseline) | floor |
| agentdojo prevented_rate | 0.962 | ≥ 0.962 | floor |
| pytest count | … | … (≥, + new tests) | — |

G1 is demonstrated iff FP/benign-gate counts fall and all three floor rows hold.

## 8. The invariant test suite (cross-cutting, keep green every phase)

Beyond the per-doc tests, maintain `tests/test_invariants.py` asserting the doc 00 §5 invariants directly:

1. **Security-first:** a hard-block credential payload blocks regardless of `destination.trust` (including `self`); the privacy engine is not consulted after a security block.
2. **Fail-closed resolver:** fuzz random `(kind,id,recipient)` triples; assert the resolver never returns `self` without a config/identity/host match; default is `unknown`.
3. **Unknown≡external in decide:** property test (doc 02 §9 #4).
4. **Conservative default (post-provenance):** under taint to an external destination with no rule and no verifier allow, `decide` never returns `ALLOW` on the basis that no private content was detected — it uses ambient taint and routes to `APPROVE` (doc 02 §9 #5).
5. **Corrupt config → strict:** a malformed policy document loads as strict, not as permissive.
6. **At-rest metadata-only:** scan persisted rows for payload content; new fields are enums/labels only.
7. **Audit fidelity:** after class collapse, every record still exposes the fine tag.

These are the regression tripwires. CI runs them on 3.11/3.12/3.13 alongside the existing suite.

## 9. Back-compatibility contract

- **Existing configs keep working.** `version<3` loads with doc 01 defaults injected; existing `privacy.rules`/`privacy.tools` honored unchanged.
- **Existing slash commands keep working;** renamed ones get aliases.
- **Existing activity rows** without the new fields render with `destination_trust="unknown"`/`decision_step=""` (display-safe); no migration of historical rows required beyond additive columns.
- **No operator is forced to configure anything** to retain current safety; they gain FP reductions automatically on the seeded `self` defaults, and gain send-to-self/own-infra only by explicit opt-in.

## 10. Rollback

Because of shadow-first (phase 2) and the additive resolver (phase 1), rollback at any phase is a revert of that phase's commits with no data migration to undo (columns are additive and nullable). If a floor breach is found post-flip (phase 3+), revert to the pre-flip commit (old decision authoritative, new engine back in shadow), fix under shadow divergence, re-flip. Keep phases as separate, individually-revertable commits/PRs.

## 11. Definition of done

- [ ] Baselines + decision corpus captured and committed (phase 0).
- [ ] Resolver + capability + engine implemented, all per-doc tests green (phases 1–2).
- [ ] Parity replay shows **zero floor breaches**; only intra-boundary gate→allow flips (phase 2).
- [ ] Engine flipped authoritative; FP benchmarks down, floor benchmarks held (phase 3).
- [ ] Config document + slash commands + dashboard + cron updated; surfaces tests green (phase 4).
- [ ] Class/mode collapse done; parity + audit-fidelity preserved (phase 5).
- [ ] Provenance retired: `privacy/provenance.py` + call sites deleted, no `exported_source_classes` consumer, `_guardian_hmac_key()` retained for approvals/sanitization; `test_provenance_retirement.py` green (`llm`-mode verifier parity; `strict`-mode routes laundering to review like all tainted egress); `llm`-mode FP did not rise from the removal (§7.1).
- [ ] `tests/test_invariants.py` green on 3.11/3.12/3.13.
- [ ] `RESULTS.md` filled with before/after evidence; PR description states the FP reduction and the held floor.
- [ ] Dead code (old decision branches, mode branching, redundant class-distinction) deleted.
- [ ] Docs (README, theory.md) updated to describe the destination-trust model and the one-file config — but **keep doc-style honesty**: state the conservative defaults, the send-to-self/own-infra opt-in, and that mislabeling external as self is the sole leak path the design guards against.
