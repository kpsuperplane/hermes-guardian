# Guardian Refactor Design Docs

A five-doc spec for adding a **destination-trust dimension** to Guardian and collapsing its scattered classification into **one capability model + one decision function** — to greatly reduce false-positive blocks (gating flows that reach no new party) while holding the privacy boundary exactly where it is, and to make configuration and decisions reason-about-able. It also **retires the provenance subsystem** (charter §4 / §2.1–§2.2): once destination-trust handles intra-boundary flows and the `llm`-mode verifier reads the real payload, provenance is the deterministic shadow of jobs the verifier now does. Its one remaining deterministic home is `strict` mode — but strict mode already reviews every egress by contract, so provenance there was an optimization at odds with the strictness that defines it; and its deterministic catch is porous in practice anyway, because the task-driven agent's natural response to a block is to reword around it. That retirement is the single non-floor-neutral change in the plan and is documented as a deliberate, reversible, scoped reduction.

Feed these to Claude Code **in order**. Each is self-contained and ends with a checklist.

| # | File | Read for |
|---|---|---|
| 00 | `00-overview-and-charter.md` | The problem, goals (G1 reduce false positives, G2 simplify), the **privacy floor**, the global invariants, and the execution order. **Start here.** |
| 01 | `01-destination-trust-model.md` | The new concept: trust levels, the conservative-by-default + operator-configurable self-resolution, and the fail-closed tests. The load-bearing, most-dangerous piece. |
| 02 | `02-capability-and-policy-engine.md` | The `Capability` tuple, the resolution pipeline, the single `decide` function, the policy-class collapse, and the old→new mapping so nothing is dropped. |
| 03 | `03-config-and-surfaces.md` | The one declarative policy document (replacing seven config surfaces), plus slash-command and dashboard changes that make destination trust visible and steerable. |
| 04 | `04-migration-and-tests.md` | Additive-then-switch phasing, the invariant test suite, and the **benchmark evidence** (before/after) that proves false positives fell without breaching the floor. |

## The one-line version

A tainted flow is a confidentiality event **only when it crosses outward, to a party other than the data's owner.** Today Guardian can't tell intra-boundary movement (save my data to my own store) from exfiltration, so it gates both. Add a destination-trust dimension — resolved conservatively, with a configurable self-allowlist that fails closed to `external` — and the dominant false-positive class disappears at provably zero privacy cost, while the whole policy collapses to one legible question.

## The non-negotiable

The privacy floor (doc 00 §2): no change may move the boundary outward. The only blocks removed are ones that never protected anything. Mislabeling an external destination as `self` is the sole way this design can leak, and every rule in doc 01 pushes ambiguity away from it. When a simplification and the floor conflict, the floor wins.
