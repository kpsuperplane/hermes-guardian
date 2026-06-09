# Guardian Refactor: Destination-Trust & Capability Model — Charter

> **Status:** design, ready for implementation
> **Audience:** the engineer (Claude Code) executing the refactor
> **Scope:** a large, intentional rewrite of Guardian's classification and policy core, plus the config, slash-command, and dashboard surfaces that depend on it.

This is doc 0 of 5. Read it first. It states *why* the refactor exists, the global invariants that must never be violated during it, and the order to execute the other docs in. Do not start coding from a later doc without having read this one.

---

## 1. The problem in one sentence

Guardian classifies *actions* richly (six source regexes, a dozen sink regexes, content scanning, web/terminal sub-logic) but classifies *destinations* not at all — they are opaque string labels — so the policy cannot tell a flow that stays inside the user's own trust boundary (save my inbox summary to my own Notion) from a flow that crosses it (email my inbox summary to a stranger), and gates both. That single gap is the dominant source of false-positive blocks **and** a large share of the configuration complexity.

The code already admits this. In `benchmarks/agentdojo_guardian.py` the `local_write` family is described as "write to the user's own store (files); gated under taint as a conservative measure." Guardian knowingly gates the user moving their own data into their own stores as if it were exfiltration.

## 2. Goals

Two, in priority order, both constrained by a hard privacy floor.

- **G1 — Greatly reduce false-positive blocks and approval prompts**, where a false positive is any block or approval-gate on a flow that exposes data to *no party other than the data's owner*. These protect nothing; removing them has zero privacy cost.
- **G2 — Make configuration and decisions easy to reason about.** The answer to "will this be blocked?" should reduce to one legible question, and the entire risk posture should live in one declarative document.

**Privacy floor (non-negotiable, gates both goals):** No change may move the confidentiality boundary outward. Concretely, after this refactor, for every flow that previously gated *correctly* (private data crossing to a non-owner without authorization), the flow must still gate. The only blocks we remove are ones that never protected anything.

### 2.1 The one carve-out: retiring provenance is a deliberate, scoped protection reduction

The destination-trust changes (moves 1–3) remove only blocks that never protected anything, so they are floor-neutral by construction. **Retiring provenance (move 4) is different and must not be disguised as free** — it removes a deterministic anti-laundering catch (proving an authorized action's payload also carried *other* tainted classes it was not authorized to send). But the protection that is lost is smaller and more defensible than it first appears, scoped by mode:

- **`strict` mode (verifier off):** strict mode's contract is that *every* outward flow from a tainted session is reviewed by a human. Under that contract, laundering is already caught — by the reviewer, on every egress, by definition. Provenance was an *optimization* that let some tainted flows skip review; but skipping review is precisely what strict mode is defined *not* to do. So provenance was always a slightly odd fit for the one mode whose entire point is to refuse the strict/convenience trade. Removing it makes strict mode *more* faithful to its name — strict mode stays strict, intended for users willing to take on the cost of reviewing every egress, and the human remains the laundering catch.
- **`llm` mode (verifier on):** loses the deterministic *backstop*. The verifier reads the real payload (c4ff880) and catches the laundering case semantically, so the common case is still defended — but an adversary who fools the verifier on a *verbatim* laundering payload that provenance would have caught now succeeds. This residual is already partial (provenance never caught *paraphrased* laundering), and §2.2 explains why it is thinner still.

This is the conscious trade: a large complexity reduction in exchange for making `llm`-mode laundering defense verifier-mediated rather than verifier-plus-deterministic, while `strict` mode keeps its human-reviews-everything guarantee intact. It is acceptable and reversible. It is the *only* place in this refactor where a protection is intentionally reduced; everywhere else the floor is absolute.

### 2.2 Why the protection being given up is thinner than it looks

Provenance's deterministic catch is worth less in practice than its design implies, for a reason that is structural rather than incidental: **the agent LLM is optimizing to complete the user's task, so a provenance block is an obstacle it is inclined to route around.** When an exact-fingerprint match blocks an egress, the most natural next action for a task-driven model is to reword, reformat, summarize, or re-encode the content and try again — and any of those defeats a verbatim-fingerprint matcher. Provenance is therefore strongest against an adversary who copies content unchanged and weakest against the very agent it runs inside, whose default response to the block is the one thing that evades it. This is not a tuning problem; it is inherent to exact-match provenance sitting downstream of a model that will paraphrase to make progress.

The consequence for this decision: the deterministic laundering catch we are giving up was already porous against the realistic failure mode (a cooperative-but-redirected agent rewording around the block), not just against a deliberate attacker. What reliably catches the reworded case is the `llm`-mode verifier reading the real payload and judging content against intent semantically — which is exactly where the protection now lives. So retiring provenance concedes a *verbatim-only, agent-evadable* deterministic layer in exchange for a large simplification, and relies on the semantic layer that was already doing the real work. That makes the trade more favorable than §2.1's strict accounting alone suggests.

## 3. Non-goals (explicitly out of scope for this refactor)

- **Taint decay / sub-task taint scoping.** Tempting for FP reduction, but it is the one lever that can *open* false negatives (private data can persist in model context across turns). Explicitly deferred. Do not implement it here.
- **Changing the security hard-block layer** (credentials, OTPs, reset links). Those blocks are correct and stay exactly as they are.
- **Changing the `strict`-mode deterministic path's safety.** We unify modes structurally (doc 02 §6) but `strict` must remain "verifier never consulted, content never sent."

## 4. The shape of the solution

Three moves, of which the first two are the same rewrite seen from two angles:

1. **Add a first-class destination-trust dimension** (doc 01). Every sink's destination is resolved to a trust level — `self`, `trusted_recipient`, `local_system`, `model_provider`, `external`, `public`, `unknown` — relative to the data owner. A tainted flow is a confidentiality event **only when it crosses outward**, toward a principal other than the owner. Self-destination flows are allowed without gating, and the privacy cost is provably zero.

2. **Collapse source + sink + destination resolution into one capability model** (doc 02). Every action resolves *once* into a `Capability` tuple `(direction, destination, data_classes)`, and the entire policy becomes one pure function of `(tainted_classes, exported_classes, direction, destination_trust, purpose, mode)`. The old regex tables become *inputs that build the Capability*, not independent decision points. This is move 1 made concrete, and it is what delivers G2.

3. **Simplify the surfaces that sit on top** (doc 03): collapse seven taint classes to the small set the policy actually distinguishes (keeping the fine ones as audit tags), unify the three modes into "deterministic core + optional declassifier," and consolidate seven scattered configuration surfaces into one declarative policy document.

4. **Retire the provenance subsystem** (doc 02 §4, doc 04 phase 5). Once destination-trust handles intra-boundary flows and the verifier reads the real payload in `llm` mode (the c4ff880 change), provenance is the deterministic *shadow* of two jobs the verifier now does natively — narrowing and anti-laundering. Its one remaining deterministic home, `strict` mode, is the mode whose contract is already "review every egress," so provenance there was an optimization at odds with the very strictness that defines it (§2.1). And in practice its deterministic catch is porous anyway, because the task-driven agent's natural response to a block is to reword around it (§2.2). We remove the fingerprint/index/match machinery and let `decide` use ambient taint, with the verifier doing the narrowing in `llm` mode. **Unlike moves 1–3, this is not floor-neutral** — see §2.1. It is reversible: the mechanism can be reintroduced if a deterministic backstop ever becomes a requirement.

## 5. Global invariants (must hold at every commit, not just the end)

These are the guardrails. A change that violates any of them is wrong even if tests pass.

1. **Security before privacy.** The Security Module still runs first in `pre_tool_call` and short-circuits. The privacy/capability layer never executes if security blocks. Hard-block categories (credentials, OTPs, reset links) block regardless of destination trust — a credential to a `self` destination still hard-blocks.
2. **Fail closed, everywhere.** A destination whose ownership cannot be *proven* is `unknown`, and `unknown` is treated as `external`. A corrupt policy store still falls back to strict. A malformed verifier verdict still denies into manual approval. Mislabeling external as self is the *only* way this design leaks, so every ambiguity resolves toward "not self."
3. **Reads never egress.** Reading a source taints the session; it is never itself a blockable egress. (This is already true; preserve it.)
4. **Conservative default on what's leaving.** The engine never treats "we couldn't detect private content in the payload" as grounds to allow an outward flow. With provenance retired, `decide` uses the full ambient session taint as the set of classes potentially leaving; narrowing happens only via the `llm`-mode verifier reading the real payload, never by inferring absence. (See doc 02 §4.)
5. **At-rest honesty is preserved.** The activity store stays metadata-only modulo the already-documented sanitized-rationale caveat. Adding destination-trust fields must not introduce raw content at rest.
6. **The audit trail does not lose fidelity.** Collapsing policy classes (doc 03 §2) must keep the fine-grained class as a descriptive tag on the record, so "why was this blocked / why is the session tainted" stays answerable at the same granularity as today.
7. **No new network or telemetry.** Destination-trust resolution is local. It calls no vendor service.

## 6. How to validate that G1 happened and the floor held

Do not rely on "tests pass." Use the existing benchmarks as the instrument:

- **`benchmarks/approval_fatigue.py`** measures false-positive friction directly. Capture a baseline run on `main` *before* touching anything, then re-run after each phase. G1 is real only if benign-gate counts drop materially while `unsafe_auto_approvals` stays at 0.
- **`benchmarks/agentdojo_guardian.py`** measures the privacy floor. The attack `prevented_rate` must not regress (currently 0.962, 25/26; the one miss is a pure read, out of scope). If prevented_rate drops, the floor was breached — stop and fix before continuing.
- **`benchmarks/guardian_adversarial.py`** corpus prevented-rate must not regress.

These three numbers, before and after, are the acceptance evidence. Put them in the migration doc's results section (doc 04 §7).

## 7. Document map and execution order

Execute in this order. Each doc is self-contained enough to work through in sequence, and each ends with a checklist.

| # | Doc | What it specifies | Depends on |
|---|---|---|---|
| 00 | this charter | problem, goals, invariants, validation | — |
| 01 | `01-destination-trust-model.md` | the trust levels, the conservative+configurable self-resolution rules, the fail-closed tests | 00 |
| 02 | `02-capability-and-policy-engine.md` | the `Capability` tuple, the resolution pipeline, the single decision function, the class collapse, the old→new mapping | 01 |
| 03 | `03-config-and-surfaces.md` | the one-file policy schema, slash-command changes, dashboard changes, activity-row + cron-notification changes | 01, 02 |
| 04 | `04-migration-and-tests.md` | phased rollout, back-compat, the invariant + FP-regression test suite, benchmark results, rollback | 01, 02, 03 |

**Recommended phasing** (detailed in doc 04): build the destination-trust resolver and capability model behind the existing policy first (additive, no behavior change), prove the resolver fail-closed with tests, *then* switch the decision function over to it, *then* migrate the surfaces, *then* collapse classes and modes. Capture the three benchmark baselines before phase 1.

## 8. A note on ambition and safety

Large rewrites are in scope. But the privacy floor is a true floor: when a simplification and the floor conflict, the floor wins, and the simplification gets a `# CONSERVATIVE:` comment explaining what was left on the table and why. The goal is a system that blocks *less* while protecting *exactly as much* — never one that blocks less by protecting less.
