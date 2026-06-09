# 01 — Destination-Trust Model

> Doc 1 of 5. Read doc 00 first. This is the load-bearing, most-dangerous-to-get-wrong piece of the refactor: it introduces the concept that decides what counts as "leaving the user's boundary." Get the fail-closed behavior wrong and the system leaks. Everything here is designed so that the *only* way to leak is to mislabel an external destination as `self`, and every rule below pushes ambiguity away from that.

---

## 1. The core idea

Privacy is about *who* can see the data, not *whether a write happened*. A flow compromises confidentiality only if it reaches a **party other than the data's owner**. So the policy must know, for every sink, *who owns the destination relative to the data owner*.

Today it doesn't: destinations are opaque labels (`_mcp_destination(lower)`, a host string, `"messaging"`, `"kanban"`, `"cron"`). We add a trust level to every destination and make the policy gate on **boundary crossing** rather than on **write**.

## 2. Trust levels

A `DestinationTrust` enum, ordered from most-owned to least-known:

| Trust | Meaning | Default policy effect under taint |
|---|---|---|
| `self` | Owned by the same principal the data belongs to (the operator's own stores / send-to-self). | **Allow without gating.** No new party sees the data. Privacy cost provably zero. |
| `local_system` | The operator's own machine / shell, *with no network egress in the action*. | Allow without gating for non-networked local effects; networked shell actions are not `local_system`, they resolve to their network destination. |
| `model_provider` | The LLM provider the agent already uses. | Allow. Already inside the practical trust boundary (the agent sends it private content for every turn); withholding protects nothing. Documented in theory §"Model/provider visibility". |
| `trusted_recipient` | A correspondent the operator has explicitly declared trusted. | Allow, or light-gate per declassification rule; never auto-approve a hard-block class. |
| `external` | A known outside party / third-party service. | **Gate** tainted private flows: declassification-rule lookup, else manual approval. |
| `public` | A public, world-readable destination (open web). | Gate as `external`; this label exists for clearer audit + rules, not weaker treatment. |
| `unknown` | Ownership could not be proven. | **Treated exactly as `external`.** This is the fail-closed default. |

**Critical:** `unknown` is not a fourth state to reason about separately — it collapses to `external` at decision time. Code may *record* `unknown` for audit clarity, but the decision function must treat `unknown` and `external` identically. (See doc 02 §3.)

## 3. How a destination's trust is resolved (conservative + configurable)

This is the heart of the design and the answer to "how do you reliably know what's self?": **you don't infer it permissively — you resolve it against an explicit, conservative allowlist that ships with safe defaults and that the operator customizes.** Inference is used only to *seed suggestions*, never to silently widen `self`.

The resolver is a pure function:

```
resolve_destination_trust(dest_kind, dest_id, action_subtype, recipient_identity, config) -> DestinationTrust
```

It applies these rules **in order**, first match wins, and the final fallback is `unknown` (→ external):

### 3.1 Outward-sharing actions are never `self`, even on a self-owned store

Resolve this *first*, before any ownership check. Some actions on an otherwise-self store still reach other people: `share`, `invite`, `publish`, `add_collaborator`, `make_public`, `send`/`email` to a non-self recipient, changing permissions. These are `external` regardless of which connector they target. A write to your own Notion page is `self`; sharing that page with a collaborator is `external`.

Detection: an `outward_sharing` action-subtype set (config-extensible), matched against the resolved action subtype. If matched → `external`. This rule prevents the most plausible "self store but actually leaks" mistake.

### 3.2 Messaging: resolve the recipient against owned identities

For message/send actions, trust is a property of the **recipient**, not the tool:

- Recipient resolves to one of the operator's **verified own addresses/handles** (from `config.self.identities`) → `self` (send-to-self).
- Recipient resolves to a declared **trusted recipient** (`config.trusted_recipients`) → `trusted_recipient`.
- Recipient is a real external party → `external`.
- Recipient cannot be resolved (templated, attacker-controlled, empty) → `unknown` (→ external). **Never guess a recipient is self.**

### 3.3 Stores: match against the configured self-destination allowlist

For write/store actions, look up `(dest_kind, dest_id)` in `config.self.destinations`:

- Exact or prefix match in the self allowlist → `self`.
- Match in `config.trusted_recipients` (for non-store external services the user trusts) → `trusted_recipient`.
- Otherwise → continue.

### 3.4 Local & model

- Non-networked local effect on the operator's machine (write to own file store, memory, todo, draft) → `self` if in the self allowlist (it is, by default — see §4), else `local_system`.
- A shell/terminal action that performs **network egress** does not get `local_system`; it resolves to the network destination it targets (host/url), then falls through the host rules below.
- The configured verifier/agent model endpoint → `model_provider`.

### 3.5 Network hosts

- Host is in `config.self.hosts` (operator's own infra they've declared) → `self`.
- Host is a private/metadata IP and `private_network_reads` security rule logic applies → handled by the security layer as today (unchanged).
- Host is public → `public`.
- Otherwise → `external`.

### 3.6 Fallback

Anything unmatched → `unknown` → external. **This is the safety net. It must be the literal default return.**

## 4. The default self-allowlist (ships with the product)

Seed `config.self` with a conservative-but-useful default set so the common FP cases vanish out of the box, while anything shareable-or-ambiguous still gates. These are destinations that are single-operator-owned by construction because the operator authenticated to them *as themselves*:

```toml
[self]
# Stores the operator owns. Writes here reach no new party.
# Match by destination kind + id/prefix as resolved by the capability layer.
destinations = [
  "store:files",        # own filesystem / write_file / local_write to own paths
  "store:memory",       # memory / mnemosyne (own memory store)
  "store:todo",         # own todo store
  "store:calendar",     # own calendar (event create/update on own calendar)
  "store:notion",       # own Notion workspace
  "store:drive",        # own Drive
  "draft:*",            # composing a draft is not transmission
]

# The operator's own verified identities (for send-to-self detection).
# EMPTY by default — the operator fills these in; an unfilled identity
# resolves to unknown->external, which is the safe direction.
identities = []

# The operator's own infrastructure hosts (e.g. their VPS). EMPTY by default.
hosts = []

[trusted_recipients]
# Optional. Declared correspondents. EMPTY by default.
# entries = [{ identity = "...", classes = ["personal_private"] }]
entries = []

[outward_sharing]
# Action subtypes that reach other parties even on a self store.
# These are ALWAYS external. Operator may extend, not narrow below the builtin set.
builtin = ["share", "invite", "publish", "add_collaborator", "make_public", "set_permissions"]
extra = []
```

Design decisions baked into this default, each deliberate:

- **`calendar`, `notion`, `drive` default to `self`.** These are accounts the operator authenticated as themselves; writing to them reaches no new party. This is where most of the FP reduction comes from. The conservatism that keeps it safe is §3.1 (sharing/inviting on these is still `external`) and the fact that *unfilled* identities/hosts fail closed.
- **`identities` and `hosts` are empty by default.** Send-to-self and own-infra are powerful `self` grants, so the operator must opt in explicitly. An empty list means "I can't prove this recipient/host is yours" → external. Safe.
- **Drafts are `self`.** A draft is not transmitted; gating it protects nothing.
- **The operator can *add* to `self`, and can *add* to `outward_sharing`, but the builtin `outward_sharing` set cannot be narrowed.** You can declare more things self; you cannot declare a share action safe.

## 5. Public-source allowlist interaction (unchanged but clarified)

Reading from a `self` store taints (the data is private). Reading from `public`/web is confidence-gated as today (`_web_content_taint_classes`, role-localpart, consumer-domain). **The class collapse in doc 02 §5 does not remove this read-side suppression** — it only stops the policy from needing to distinguish communications-vs-contacts. Keep the web read-side logic; it prevents tainting on every `support@` on the open web.

## 6. New / changed code

| File | Change |
|---|---|
| `privacy/destinations.py` *(new)* | `DestinationTrust` enum; `resolve_destination_trust(...)` implementing §3 in order; the self-allowlist / trusted-recipient / outward-sharing matchers; `_recipient_resolves_to_self(...)`. Pure, local, no I/O beyond reading the loaded config. |
| `privacy/rules.py` | Parse + normalize the new `self`, `trusted_recipients`, `outward_sharing` config blocks (doc 03 §1); supply the §4 defaults; validate types; fail closed on malformed (drop to safe subset, log, do not crash). |
| `core.py` | Expose the seeded defaults; wire config load → resolver. |
| `privacy/tool_policy.py` | Stop returning bare destination strings; return `Destination(kind, id, trust)` (doc 02 builds the `Capability` around this). |

## 7. Tests that MUST pass (fail-closed is the point)

Put these in `tests/test_destination_trust.py`. They are the safety contract for this doc.

1. **Unknown destination → external.** An unrecognized store/host/recipient resolves to `unknown`, and the decision function treats it as `external` (gates under taint). Assert both the recorded `unknown` and the gating effect.
2. **Empty identities → no send-to-self.** With default (empty) `identities`, a send addressed to *any* address — including one that looks like the operator's — resolves to `external`, never `self`.
3. **Outward-sharing beats ownership.** `notion_share` / `*_invite` / `*_publish` on a `self`-listed connector resolves to `external`, not `self`. One test per builtin sharing subtype.
4. **Self store write is self.** `write_file`/`notion_create_page`/`calendar_create_event`/`memory write`/`todo` to the operator's own store resolves to `self` and is allowed without gating under taint.
5. **Draft is self.** A compose/draft action resolves to `self`.
6. **Configured identity enables send-to-self.** After adding an own identity to config, a send to that identity resolves to `self`; a send to a *different* address still resolves to `external`.
7. **Templated/empty recipient → unknown→external.** A send with a templated or empty recipient resolves to `unknown` and gates.
8. **Operator cannot narrow builtin sharing set.** Attempting to remove a builtin `outward_sharing` subtype via config has no effect (the builtin set still applies).
9. **Networked shell is not local_system.** A `terminal` command performing network egress resolves to its network destination (external/public), not `local_system`; a pure local read stays `local_system`/no-taint as today.
10. **Credential to self still hard-blocks.** A credential-bearing payload to a `self` destination is hard-blocked by the security layer (destination trust does not soften security hard-blocks). This guards invariant #1.

## 8. Checklist for this doc

- [ ] `privacy/destinations.py` created; resolver implements §3 rules in order with `unknown` as literal fallback.
- [ ] Default `self`/`trusted_recipients`/`outward_sharing` blocks (§4) parsed, normalized, and seeded.
- [ ] Config validation fails closed on malformed input.
- [ ] All 10 tests in §7 pass.
- [ ] `resolve_destination_trust` performs no network I/O (assert in test or by review).
- [ ] No decision-time code path distinguishes `unknown` from `external`.
