# 02 — Capability Model & Policy Engine

> Doc 2 of 5. Read docs 00 and 01 first. This doc turns Guardian's scattered classification (a dozen regex tables and several sub-logic paths) into **one resolution that produces a `Capability`, and one pure function that decides on it.** It is where G2 (reason-about-ability) is delivered, and it is the consumer of doc 01's destination trust.

---

## 1. The two-step model

Every tool call becomes:

```
classify:  (tool_name, args, session) -> Capability
decide:    (Capability, session_taint, purpose, mode) -> Decision
```

`classify` is where all the current regex tables, MCP annotations, content scanning, and doc-01 trust resolution converge — they become *inputs that build the Capability*, not independent decision points. `decide` is a single, total, side-effect-free function. After this refactor:

- "What does tool X do?" = print its resolved `Capability`.
- "Will Y be blocked?" = call `decide` and read the result.

There is no other place a block can come from (except the security layer, which still runs first and is unchanged).

## 2. The `Capability` tuple

```python
@dataclass(frozen=True)
class Destination:
    kind: str            # "store" | "message" | "network" | "shell" | "model" | "browser" | "subagent" | "draft"
    id: str              # stable label: connector name, host, recipient id, "files", ...
    trust: DestinationTrust   # from doc 01 §3

@dataclass(frozen=True)
class Capability:
    direction: str                 # "read" | "write"
    destination: Destination
    data_classes: frozenset[str]   # POLICY classes being moved (see §5). For reads: classes the read taints with.
    data_tags: frozenset[str]      # DESCRIPTIVE fine tags for audit (communications/contacts/calendar/...). Never load-bearing.
    action_subtype: str            # normalized verb: "create"|"update"|"send"|"share"|"publish"|"read"|"query"|...
```

> **Note (provenance retired):** earlier drafts carried `exported_source_classes` / per-argument `source_classes` derived from the provenance fingerprint subsystem. Provenance is being retired (charter §4, §2.1), so these fields are gone. `decide` reasons over the ambient session taint and the verifier does payload-level narrowing in `llm` mode. See §4.

`data_classes` is the *policy* set (small, doc §5). `data_tags` preserves the current fine granularity for the audit trail and optional purpose rules — this is how invariant #6 (no audit fidelity loss) is honored.

## 3. The single decision function

This replaces the branching across `_egress_tool_action`, the family/destination gating, the mode handling, and the verifier-gating glue. It is the *only* arbiter.

```python
def decide(cap, taint, purpose, mode) -> Decision:
    # 0. Security hard-blocks already ran upstream (pre_tool_call) and short-circuited.
    #    decide() is never reached for a hard-blocked credential/OTP/reset-link payload.

    # 1. Reads never egress. They taint; they are not blockable here.
    if cap.direction == "read":
        return ALLOW

    # 2. Boundary check. Treat unknown EXACTLY as external (doc 01 §2).
    trust = EXTERNAL if cap.destination.trust == UNKNOWN else cap.destination.trust

    # 3. Intra-boundary destinations never gate: the data reaches no new party.
    if trust in (SELF, LOCAL_SYSTEM, MODEL_PROVIDER):
        return ALLOW

    # 4. What private data is potentially leaving? With provenance retired, this is
    #    the full ambient session taint (conservative — charter invariant #4).
    #    Narrowing, if any, happens in step 6 via the llm-mode verifier, not here.
    private_exported = taint.classes & PRIVATE_POLICY_CLASSES
    if not private_exported:
        return ALLOW   # session holds nothing private to leak

    # 5. Crossing outward with private data. Look for an explicit declassification rule
    #    (purpose x classes x destination). First matching allow rule wins.
    rule = match_declassification_rule(purpose, private_exported, cap.destination, trust)
    if rule and rule.effect == ALLOW:
        return ALLOW
    if rule and rule.effect == DENY:
        return BLOCK

    # 6. No rule: gate for human approval. In `llm` mode the verifier may UPGRADE to allow
    #    (reading the real payload, bounded by authorization scoped to private_exported),
    #    but can never override a hard-block class or a high-risk cron action.
    return APPROVE
```

Properties to preserve from today, now centralized here:

- **Cron + high-risk downgrade.** If the session is a cron/unattended session and the verifier would return a high-risk `allow`, downgrade to `APPROVE`. Keep the existing structural enforcement (doc 03 surfaces it); it lives at the verifier-verdict boundary, fed into step 6.
- **Laundering guard (now verifier-mediated).** With provenance retired, there is no deterministic `exported_source_classes` to scope authorization to what is *provably* sent. In `llm` mode the verifier reads the real payload (c4ff880) and is responsible for catching a payload that carries classes beyond what the purpose authorized — a content/intent mismatch it routes back to manual approval. This is a deliberate, scoped reduction in protection (charter §2.1–§2.2): in `strict` mode every egress is reviewed by a human regardless, so the human is the laundering catch (strict stays strict); in `llm` mode the verifier keeps the semantic catch but loses the deterministic backstop — a backstop that was verbatim-only and agent-evadable anyway. `decide` step 4 therefore uses ambient taint; step 6's verifier authorization covers `private_exported` (= the ambient private classes).
- **Verifier validation.** The `_validated_llm_security_verdict` guards (deny on malformed, reject high-risk allow without authorization) stay; they wrap step 6's upgrade.

## 4. Provenance is retired — `decide` uses ambient taint (charter §2.1, §4)

Provenance (the HMAC fingerprint subsystem and `exported_source_classes`) is being removed. The reasoning, in full, is in the charter (§2.1–§2.2) and the prior design discussion; the short version: once destination-trust short-circuits intra-boundary flows and the `llm`-mode verifier reads the real payload, provenance is the deterministic shadow of two jobs the verifier now does. Its one remaining deterministic home is `strict` mode — but strict mode already reviews every egress by contract, so provenance there was an optimization at odds with that strictness. And its deterministic catch is porous in practice: the task-driven agent's natural response to a provenance block is to reword the content and retry, which defeats exact-fingerprint matching (charter §2.2). So what is being retired is a verbatim-only, agent-evadable layer; the durable laundering/narrowing work lives in the verifier reading the real payload.

What this means for `decide`:

- **Step 4 uses the full ambient `taint.classes`.** There is no payload-level class set to narrow with. This is strictly more conservative than the old provenance path on external flows.
- **Narrowing moves to the verifier.** The FP that provenance used to remove deterministically — "read calendar, then send an *external* email containing no calendar content" — is now removed in `llm` mode by the verifier reading the real payload and allowing in step 6. In `strict` mode that flow goes to manual review, which is `strict` mode working as intended (review every egress), not a regression.
- **Do not reintroduce an "absence means safe" inference.** Conservative default stands: absent positive evidence (a verifier allow, a declassification rule, an intra-boundary destination), the full ambient taint applies.

**Net effect on FP:** in `llm` mode, retiring provenance should not increase false positives — the verifier recovers the narrowing the verbatim-fingerprint matcher used to do, and does it for paraphrased content too. The change shifts external-flow narrowing from "deterministic + verifier" to "verifier only." The migration (doc 04) must confirm `llm`-mode FP does not regress when provenance is removed.

**Reversibility:** if `strict`-mode laundering defense ever becomes a requirement, the mechanism can be reintroduced as a `Capability.exported_source_classes` field feeding step 4, scoped to external destinations only. Keep the seam clean (step 4 is the single consumer) so a future re-add is local.

## 5. Policy-class collapse (G2 simplification, invariant #6 preserved)

Today there are seven taint classes: `communications, contacts, memory, documents, calendar, local_system, browser_private_input`. Audit what the **decision** distinguishes. The egress decision treats communications/contacts/calendar/documents/memory identically — all are "personal-private, gate when crossing outward." They differ only in (a) the audit label and (b) *optional* purpose-scoped rules.

So define two layers:

```python
# POLICY classes — what decide() reasons over. Small and total.
PRIVATE_POLICY_CLASSES = frozenset({"personal_private"})
POLICY_CLASSES = frozenset({"personal_private", "local_system", "browser_private", "public"})

# DESCRIPTIVE tags — preserved on every record for audit + optional rules.
DATA_TAGS = frozenset({"communications", "contacts", "calendar", "documents", "memory"})
```

Mapping:
- `communications, contacts, calendar, documents, memory` → policy class `personal_private`, with the original kept as a `data_tag`.
- `local_system` → policy class `local_system`.
- `browser_private_input` → policy class `browser_private`.

Consequences, all positive:
- `decide` no longer needs the fine classes to be *correctly disambiguated* — it only needs "is this personal_private." This removes the FP pressure on the fine-grained detectors (role-localpart / consumer-domain / email-vs-contact splitting): they become **best-effort tagging that is never load-bearing for a block.** Keep them for tags; if they misfire, a tag is slightly wrong, but no decision changes.
- Declassification rules may still target a fine tag when an operator wants (e.g. "allow `calendar` to this scheduling service") — rule matching checks tags when a rule specifies one, else the policy class. Document this in doc 03's rule schema.
- The audit trail keeps the fine tag (invariant #6).

**Do not** collapse the read-side web suppression logic into this (doc 01 §5). That logic decides *whether something taints at all*, not *which class*; it stays.

## 6. Mode unification (G2 simplification)

Three modes today (`strict`, `llm`, `read-only`, plus `off`) branch through the code. Replace with **one path + composable settings**:

```
deterministic core (always runs)  +  optional declassifier (the verifier)
```

- `strict` ≡ verifier **off**. `decide` never reaches a verifier upgrade in step 6; APPROVE stands. Content is never sent. (Preserves the strict safety invariant.)
- `llm` ≡ verifier **on**. Step 6 may upgrade.
- `read-only` ≡ a **destination-policy preset**, not a separate code path: it maps to "no writes to non-self destinations are auto-allowed; everything outward gates." Express it as a built-in declassification rule set, not a mode branch.
- `off` ≡ Guardian disabled (unchanged semantics; keep the explicit off switch).

Net: one decision path, one verifier toggle, and `read-only` becomes data (a preset rule bundle) rather than control flow. Far fewer branches to trace.

## 7. Old → new mapping (so nothing is silently dropped)

Build the `Capability` by routing the existing logic into the classifier. Every current rule has a home:

| Current symbol / logic | New home | Becomes |
|---|---|---|
| `_SOURCE_TAINT_RULES` (6 name regexes) | classifier, read path | sets `direction=read`, `data_tags`, policy class `personal_private` |
| `_web_content_taint_classes`, role-localpart, consumer-domain | classifier, read path (web) | best-effort `data_tags`; suppression preserved (doc 01 §5) |
| `_local_system_result_taint_classes`, safe-remote-read, metadata-only command logic | classifier, read path (shell) | sets `local_system` tag or no taint, as today |
| `_egress_tool_action` family table (`mcp_write`, `message_*`, `web_api`, `local_write`, `kanban_write`, `model_api`, `terminal_exec`, `browser_*`, `cron_write`, …) | classifier, write path | sets `direction=write`, `Destination.kind`, `action_subtype` |
| `_mcp_destination`, `_browser_host`, `_safe_destination_from_args`, host parsing | classifier → `Destination.id` | feeds doc 01 resolver to get `Destination.trust` |
| `_GENERIC_WRITE_TOOL_RE` over-broad sink match | classifier | replaced by direction + subtype + destination resolution; drafts/idempotent-self-writes now resolve to `self`, removing their FP |
| unknown-tools gating (`_unknown_tools_mode`, `_recognized_builtin_tool`) | classifier fallback + `decide` | unknown tool → `Destination.trust=unknown` (→ external); gated under taint exactly as the current "gate" mode, now via the unified path |
| `exported_source_classes` / `source_classes` (provenance) | **retired** (charter §4) | deleted; `decide` step 4 uses ambient taint, verifier narrows in `llm` mode (doc 04 phase 5 deletes the subsystem) |
| `privacy/provenance.py` + the egress-time fingerprint match + the read-time index | **retired** | delete module and call sites; remove the shared-HMAC consumer (the key itself stays for approvals/sanitization) |
| mode branching (`strict`/`llm`/`read-only`) | §6 | verifier toggle + preset rules |
| cron high-risk downgrade | `decide` step 6 boundary | unchanged effect, centralized |
| `_validated_llm_security_verdict` | wraps `decide` step 6 upgrade | unchanged |

If a current behavior is not in this table, find its home before deleting it. The migration doc (04) requires a behavior-parity pass.

## 8. New / changed code

| File | Change |
|---|---|
| `privacy/capability.py` *(new)* | `Destination`, `Capability` dataclasses; `classify(tool_name, args, session) -> Capability` that routes the §7 logic; the policy-class/tag mapping (§5). |
| `privacy/policy.py` *(new or refactor of the decision glue)* | `decide(cap, taint, purpose, mode) -> Decision` (§3), total and pure; `match_declassification_rule(...)`. |
| `privacy/tool_policy.py` | Becomes a thin adapter: feed tool/args into `classify`; delete the scattered decision logic now living in `decide`. Keep the read-side taint resolution as classifier helpers. |
| `privacy/module.py` | Call `classify` then `decide`; keep security-first ordering; route verifier upgrade + cron downgrade through `decide` step 6. |
| `privacy/llm.py` | Verifier consumes `Capability`; unchanged sanitization/validation; reads the real payload and is now the sole catcher of laundering/narrowing in `llm` mode (no `exported_source_classes` input). Authorization reasons over the ambient `private_exported`. |
| `privacy/provenance.py` + provenance call sites | **Deleted** (doc 04 phase 5). Read-time fingerprint indexing and egress-time matching removed. The shared `_guardian_hmac_key()` stays (approvals + rationale sanitization still use it); only the provenance consumer goes. |
| `core.py` | Reduce `_ALL_PRIVACY_CLASSES` usage to the policy/tag split; keep fine tags defined for audit. |

## 9. Tests that MUST pass

Put in `tests/test_policy_engine.py` and `tests/test_capability.py`.

1. **`decide` is total and pure.** Property test over the cross-product of trust × direction × class-sets × mode returns a valid `Decision` with no exceptions and no side effects.
2. **Self/local/model never gate.** For every intra-boundary trust, a write of `personal_private` under full taint returns `ALLOW`.
3. **External + private + no rule → APPROVE; +deny rule → BLOCK; +allow rule → ALLOW.**
4. **Unknown == external in `decide`.** Same inputs with `unknown` vs `external` produce identical `Decision`.
5. **Conservative ambient default; verifier narrows in llm.** Under taint with an external destination and no rule: `decide` returns `APPROVE` using ambient classes (never `ALLOW` on the basis that no private content was detected). Then assert that in `llm` mode the verifier reading a payload with no private content upgrades to `ALLOW`, and a payload carrying an unauthorized class is held at `APPROVE`. (This is the post-provenance replacement for the old "provenance narrows" test.)
6. **Class collapse preserves blocks.** Each fine class, mapped to `personal_private`, still gates an external write identically. Audit record still carries the fine tag.
7. **Tag-misfire changes no decision.** Inject a deliberately wrong fine tag; assert the `Decision` is unchanged (tags non-load-bearing).
8. **Mode unification parity.** `strict` ≡ verifier-off produces the pre-refactor strict decisions on a fixed trace; `read-only` preset reproduces pre-refactor read-only decisions.
9. **Draft / idempotent-self write no longer gates.** A compose-draft and a self-store update that gated pre-refactor now ALLOW.
10. **Behavior-parity on a captured corpus.** Replay a recorded set of pre-refactor decisions (doc 04 §5) and assert: every previously-correct block still blocks (floor), and the only flips are gate→allow on intra-boundary flows.

## 10. Checklist

- [ ] `Capability`/`Destination` defined; `classify` routes every §7 row (no orphaned behavior).
- [ ] `decide` implemented exactly as §3; the only block source besides the security layer.
- [ ] Policy/tag split (§5) in place; fine tags retained on records.
- [ ] Mode unification (§6): `strict`=verifier-off, `read-only`=preset rules, no mode branching in `decide`.
- [ ] Provenance retired: `decide` step 4 uses ambient taint; no code path consumes `exported_source_classes`; `privacy/provenance.py` + call sites deleted in phase 5; the conservative default (no allow-on-absence) holds.
- [ ] All §9 tests pass; benchmark floor (doc 00 §6) holds.
