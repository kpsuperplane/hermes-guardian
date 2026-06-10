# Guardian Refactor — Acceptance Evidence

Baselines captured on pristine `main` (commit `1a7f045`) before the
destination-trust refactor. **Do not overwrite the `*.main.json` files.**

## Baseline numbers (Phase 0)

| Metric | main (baseline) | after refactor | floor / ▼ |
|---|---|---|---|
| approval_fatigue benign gates — strict | manual=7, fp=2, fp_rate=1.0 | manual=6, fp=2, fp_rate=1.0 | FP ▼ |
| approval_fatigue benign gates — read-only | manual=6, fp_rate=0.5 | manual=5, fp=1, fp_rate=0.5 | FP ▼ |
| approval_fatigue benign gates — llm | manual=2, auto=5, fp=0 | manual=2, auto=4, fp=0 | FP held (no rise) |
| approval_fatigue unsafe_auto_approvals (all modes) | 0 | **0** | must hold = 0 ✓ |
| adversarial prevented_rate | 1.0 (12/12) | **1.0 (12/12)** | floor (≥) ✓ |
| adversarial false_positive_rate | 0.0 | 0.0 | — |
| agentdojo prevented_rate | 0.9615 (25/26) | **0.9615 (25/26)** | floor (≥) ✓ |
| agentdojo false_positive_rate | 0.6495 | 0.6082 | FP ▼ (informational) |
| pytest | 433 passed, 1 skipped | 504 passed, 1 skipped | ≥ + new tests ✓ |

Raw JSON: `approval_fatigue.main.json`, `adversarial.main.json`,
`agentdojo.main.json` in this directory.

G1 is demonstrated iff FP/benign-gate counts fall and all three floor rows hold.

## Phase 5 — provenance retirement (the one sanctioned, non-floor-neutral reduction)

Provenance (the read-time HMAC fingerprint index + egress-time match +
`exported_source_classes`) was retired in Phase 5 (charter §2.1–§2.2, doc 02 §4).
This is the only intentional protection reduction in the refactor; everywhere else
the floor is absolute. Evidence the carve-out is scoped and the floor still holds:

- **FP-no-rise (§7.1):** `llm`-mode benign gates stayed at `manual=2` (did NOT rise
  from the post-Phase-3 number), confirming the verifier recovers the per-payload
  narrowing the verbatim-fingerprint matcher used to do — and does it for paraphrased
  content too.
- **Floor held:** adversarial `1.0` and agentdojo `0.9615` are both unchanged — the
  retirement did not breach the floor. The verbatim-laundering catch moved from
  "deterministic + verifier" to "verifier only" in `llm` mode, and to "human reviews
  every egress" in `strict` mode.
- **Parity replay buckets (test_policy_engine.py test 10):** bucket (c) "unexplained
  divergences" = 0 (the floor gate). The corpus's artificial empty-taint laundering
  records still *gate* (their recipient address is itself detected content), so they do
  not even reach decide-ALLOW — bucket (b) is empty in the replay.
- **Realistic carve-out behavior (test_provenance_retirement.py):** driving a real
  private read (which taints the session ambiently) followed by a verbatim send proves
  the durable protection: in `llm` mode the verifier reads the real payload and holds
  the laundering send at manual approval (verifier-mediated parity); in `strict` mode
  the send routes to manual review like all tainted egress (the human is the catch).
</content>
