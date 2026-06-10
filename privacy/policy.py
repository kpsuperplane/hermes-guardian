"""The single decision function ``decide`` (doc 02 §3, §6).

Phase 2 of the destination-trust refactor. ADDITIVE / SHADOW: ``decide`` is the one
arbiter (besides the security layer, which runs first and is unchanged). It is run
alongside the authoritative decision and only logged in Phase 2; it becomes
authoritative in Phase 3.

``decide`` is TOTAL and PURE: no side effects, no exceptions, no I/O. A property test
(``tests/test_policy_engine.py``) asserts this. It reasons over the AMBIENT session taint
(provenance retired, doc 02 §4) — never inferring "absence of detected private content
means safe" (charter invariant #4).

This file follows the exec-loaded loader style (AGENTS.md "Loader And Namespace Rules"):
it does NOT import sibling plugin modules; it references shared globals
(``DestinationTrust``, ``PRIVATE_POLICY_CLASSES``, ``_persistent_privacy_rules``,
``re``, …) directly. Loaded AFTER ``privacy/capability`` and before ``privacy/module``
(see ``core.py`` ``_CORE_LOGIC_MODULES``). Only standard-library imports appear.
"""

from __future__ import annotations

from typing import Any


# --- Decision outcomes (doc 02 §3) -------------------------------------------
# The codebase represents outcomes as plain strings in activity rows and hook returns
# ("blocked"/"allowed"/"security_blocked"). ``decide`` works in a small, typed vocabulary
# of three policy outcomes; the caller maps these onto the hook/activity strings in
# Phase 3. APPROVE is "gate for human approval" — a GATE, not an allow.
ALLOW = "allow"
APPROVE = "approve"
BLOCK = "block"

_DECISIONS = frozenset({ALLOW, APPROVE, BLOCK})


# --- Mode unification as data (doc 02 §6) ------------------------------------
# Modes are data, not control flow inside ``decide``:
#   strict    -> verifier OFF: step 6 APPROVE stands, no upgrade.
#   llm       -> verifier ON: step 6 may be upgraded to ALLOW by the caller's verifier
#                (the actual verifier call stays in privacy/llm.py — decide just returns
#                the deterministic APPROVE and the caller may upgrade; SEAM documented).
#   read-only -> a preset rule bundle (no auto-allow of non-self outward writes).
#   off       -> Guardian disabled (handled before decide is reached).
# ``decide`` itself does not branch on mode for the deterministic outcome; mode only
# governs whether the caller is permitted to upgrade a step-6 APPROVE. ``_mode_allows_
# verifier_upgrade`` exposes that seam for the caller / tests.
_VERIFIER_MODES = frozenset({"llm"})


# Policy classes that gate an OUTWARD (non-intra-boundary) flow: every non-public class.
# ``PRIVATE_POLICY_CLASSES`` ({personal_private}) is the declassification-rule / audit
# vocabulary (doc 02 §5); this is the floor set for "what may not silently leave to a
# non-owner" and additionally covers ``local_system`` and ``browser_private`` so a session
# tainted by local-system reads or private browser input still gates on outward egress.
_EGRESS_GATING_POLICY_CLASSES = frozenset(
    {"personal_private", "local_system", "browser_private"}
)


def _mode_allows_verifier_upgrade(mode: Any) -> bool:
    """True iff ``mode`` permits the caller's verifier to upgrade a step-6 APPROVE to
    ALLOW (doc 02 §6). ``strict``/``read-only``/``off`` never upgrade.

    SEAM (doc 02 §6): in shadow Phase 2 ``decide`` always returns the deterministic
    APPROVE; the verifier-upgrade is wired through the caller in ``privacy/module.py``
    /``privacy/llm.py``, gated by this predicate. ``decide`` stays pure.
    """
    return str(mode or "").strip().lower().replace("_", "-") in _VERIFIER_MODES


# --- Taint adapter -----------------------------------------------------------
def _taint_policy_classes(taint: Any) -> frozenset[str]:
    """Extract the POLICY class set from whatever ``taint`` representation is passed.

    Accepts a set/frozenset/list of class strings, or an object exposing ``.classes``.
    Fine classes are collapsed to policy classes via ``_policy_classes_for`` (doc 02 §5),
    so a caller may pass either fine taint classes or already-collapsed policy classes —
    both normalize correctly. Total: anything unusable yields the empty set.

    FAIL CLOSED on an UNRECOGNIZED taint token (charter invariant #2/#4): a class that is
    neither a known POLICY class nor a known fine class is treated as ``personal_private``,
    never dropped. Dropping it would be an "absence means safe" inference — exactly what
    invariant #4 forbids — and would let a tainted session egress freely just because the
    taint label is one the policy/tag map does not enumerate (e.g. an upstream "email"
    taint). Only the explicitly non-private known classes (``local_system``,
    ``browser_private``) map to their own non-private policy class by design (doc 02 §5).
    """
    classes = getattr(taint, "classes", taint)
    try:
        raw = set(classes)
    except TypeError:
        return frozenset()
    out: set[str] = set()
    for cls in raw:
        text = str(cls)
        if text in POLICY_CLASSES:
            out.add(text)
            continue
        mapped = _policy_classes_for({text})
        if mapped:
            out |= mapped
        else:
            # Unrecognized taint token: fail closed to personal_private (conservative).
            out.add("personal_private")
    return frozenset(out)


# --- Declassification rule matching (doc 02 §3 step 5) -----------------------
def match_declassification_rule(
    purpose: Any,
    private_exported: Any,
    destination: Any,
    trust: Any,
) -> dict[str, Any] | None:
    """Return the first matching declassification rule (allow/deny), or None.

    Reads the ordered ``privacy.rules`` (first matching allow/deny wins, doc 02 §3 step
    5 / §5). A rule may target a fine TAG or the POLICY class: a rule's ``data_classes``
    are matched against the union of the exported policy classes and (for tag-targeted
    rules) the fine tags carried on the capability. ``purpose`` and ``destination`` are
    matched by exact token or ``*`` wildcard.

    Total and pure: any malformed rule store yields None (fail-closed: no allow).
    """
    try:
        rules = _persistent_privacy_rules()
    except Exception:
        return None
    if not isinstance(rules, list):
        return None

    purpose_token = str(purpose or "unknown").strip().lower() or "unknown"
    exported = set(str(c) for c in (private_exported or ()))
    dest_id = str(getattr(destination, "id", destination) or "")
    dest_kind = str(getattr(destination, "kind", "") or "")
    dest_tokens = {tok for tok in (dest_id, dest_kind, f"{dest_kind}:{dest_id}") if tok}
    # Tag set the capability carries, if the destination object exposes it (rules may
    # target a fine tag — doc 02 §5). Falls back to the exported policy classes.
    dest_tags = set(str(t) for t in getattr(destination, "_data_tags", ()) or ())
    matchable = exported | dest_tags

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not rule.get("enabled", True):
            continue
        effect = str(rule.get("effect") or "").strip().lower()
        if effect not in {"allow", "deny"}:
            continue
        match = rule.get("match") if isinstance(rule.get("match"), dict) else {}

        rule_purpose = str(match.get("purpose", "*") or "*").strip().lower()
        if rule_purpose not in {"*", purpose_token}:
            continue

        rule_dest = str(match.get("destination", "*") or "*").strip().lower()
        if rule_dest != "*" and rule_dest not in {tok.lower() for tok in dest_tokens}:
            continue

        rule_classes = set(str(c).strip().lower() for c in (match.get("data_classes") or ["*"]))
        if "*" not in rule_classes and not (rule_classes & {m.lower() for m in matchable}):
            # An allow rule must positively cover an exported class/tag; a deny rule with
            # no class overlap also does not apply here.
            continue

        return {"effect": effect, "rule_id": str(rule.get("id") or "")}
    return None


# --- The single decision function (doc 02 §3) --------------------------------
def decide(cap: Any, taint: Any = None, purpose: Any = "unknown", mode: Any = "strict") -> str:
    """Decide on a ``Capability`` (doc 02 §3). Total and pure.

    Implements steps 0-6 exactly:
      0. security hard-blocks already ran upstream — never reached here.
      1. reads never egress -> ALLOW.
      2. unknown trust is treated EXACTLY as external (doc 01 §2).
      3. intra-boundary (self/local_system/model_provider) -> ALLOW.
      4. ambient private taint: ``taint.classes & PRIVATE_POLICY_CLASSES`` (provenance
         retired — uses AMBIENT taint, never a payload-derived "absence means safe"
         inference, charter invariant #4). Empty -> ALLOW.
      5. declassification rule lookup: allow -> ALLOW, deny -> BLOCK.
      6. else -> APPROVE (gate for human approval). In ``llm`` mode the caller's verifier
         may upgrade this to ALLOW — that upgrade is the caller's, not decide's (§6 seam).
    """
    direction = str(getattr(cap, "direction", "") or "")

    # 1. Reads never egress (charter invariant #3).
    if direction == "read":
        return ALLOW

    # 2. Boundary check; unknown == external (doc 01 §2).
    destination = getattr(cap, "destination", None)
    raw_trust = getattr(destination, "trust", None)
    trust = _normalize_trust(raw_trust)
    if trust == DestinationTrust.UNKNOWN:
        trust = DestinationTrust.EXTERNAL

    # 3. Intra-boundary destinations never gate.
    if trust in (
        DestinationTrust.SELF,
        DestinationTrust.LOCAL_SYSTEM,
        DestinationTrust.MODEL_PROVIDER,
    ):
        return ALLOW

    # 4. What confidential data is potentially leaving? Ambient taint (doc 02 §4).
    #    The egress-gating set is every non-public policy class: personal_private PLUS
    #    local_system (data read off the operator's machine) and browser_private (private
    #    input the operator typed into a browser). All three are confidential relative to
    #    a NON-owner destination — sending local config or a typed password out to an
    #    external site is a confidentiality event, so they must gate when crossing outward
    #    (the floor; preserves the browser-private-input / local-system exfil protections).
    #    Intra-boundary destinations already returned ALLOW at step 3, so this only ever
    #    gates a genuinely outward flow. ``public`` never gates. ``PRIVATE_POLICY_CLASSES``
    #    stays {personal_private} for the audit/declassification-rule vocabulary (doc 02
    #    §5); the broader EGRESS set is the floor for "what may not leave silently".
    private_exported = _taint_policy_classes(taint) & _EGRESS_GATING_POLICY_CLASSES
    if not private_exported:
        return ALLOW  # session holds nothing confidential to leak

    # 5. Crossing outward with private data: look for a declassification rule.
    rule = match_declassification_rule(purpose, private_exported, destination, trust)
    if rule is not None:
        if rule.get("effect") == "allow":
            return ALLOW
        if rule.get("effect") == "deny":
            return BLOCK

    # 6. No rule: gate for human approval. (Verifier upgrade, if any, is the caller's in
    #    llm mode — see _mode_allows_verifier_upgrade; decide returns the deterministic
    #    gate regardless of mode so it stays pure.)
    return APPROVE


def decide_with_step(
    cap: Any, taint: Any = None, purpose: Any = "unknown", mode: Any = "strict"
) -> tuple[str, str]:
    """Like :func:`decide`, but also returns the firing step label (doc 03 §2, §3.2).

    The label is the SAME step vocabulary ``/guardian why`` prints and that lands in the
    activity row's ``decision_step``. This recomputes the branch deterministically — it is
    pure and total like ``decide`` — so the label always matches the outcome ``decide``
    returns (a test asserts the pair is consistent). Kept beside ``decide`` so the two can
    never drift.
    """
    direction = str(getattr(cap, "direction", "") or "")
    if direction == "read":
        return ALLOW, "step1_read"

    destination = getattr(cap, "destination", None)
    trust = _normalize_trust(getattr(destination, "trust", None))
    if trust == DestinationTrust.UNKNOWN:
        trust = DestinationTrust.EXTERNAL
        unknown_origin = True
    else:
        unknown_origin = False

    if trust in (
        DestinationTrust.SELF,
        DestinationTrust.LOCAL_SYSTEM,
        DestinationTrust.MODEL_PROVIDER,
    ):
        return ALLOW, f"step3_intra_boundary_{_trust_value(trust)}"

    private_exported = _taint_policy_classes(taint) & _EGRESS_GATING_POLICY_CLASSES
    if not private_exported:
        return ALLOW, "step4_no_private_taint"

    rule = match_declassification_rule(purpose, private_exported, destination, trust)
    if rule is not None:
        if rule.get("effect") == "allow":
            return ALLOW, f"step5_allow_rule:{rule.get('rule_id', '')}".rstrip(":")
        if rule.get("effect") == "deny":
            return BLOCK, f"step5_deny_rule:{rule.get('rule_id', '')}".rstrip(":")

    suffix = "external" if not unknown_origin else "unknown_as_external"
    return APPROVE, f"step6_approve_{suffix}"


def _trust_value(trust: Any) -> str:
    value = getattr(trust, "value", None)
    return str(value if value is not None else (trust or "unknown"))


def _normalize_trust(raw_trust: Any) -> Any:
    """Coerce ``raw_trust`` to a ``DestinationTrust`` member; fail-closed to UNKNOWN.

    Keeps ``decide`` total: a missing/garbage trust resolves to UNKNOWN (-> external),
    never to an intra-boundary trust.
    """
    if isinstance(raw_trust, DestinationTrust):
        return raw_trust
    try:
        return DestinationTrust(str(raw_trust).strip().lower())
    except Exception:
        return DestinationTrust.UNKNOWN


# --- Facade bridging (AGENTS.md "Loader And Namespace Rules") -----------------
# Expose underscore-prefixed aliases for the public names so the facade bridges them to
# tests (same pattern as privacy/capability and privacy/destinations).
_decide = decide
_decide_with_step = decide_with_step
_match_declassification_rule = match_declassification_rule
_DECISION_ALLOW = ALLOW
_DECISION_APPROVE = APPROVE
_DECISION_BLOCK = BLOCK
_decide_mode_allows_verifier_upgrade = _mode_allows_verifier_upgrade
_EGRESS_GATING_POLICY_CLASSES_ALIAS = _EGRESS_GATING_POLICY_CLASSES
