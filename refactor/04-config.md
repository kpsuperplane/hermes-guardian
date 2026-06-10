# 04 — Config: a schema that mirrors the IA

> Doc 04. Read docs 01–02 first. This reshapes the policy document so its top-level blocks are the same five concepts as the tabs, in the same order — reading the config is reading the decision. **Loader/normalizer work in `privacy/rules.py` only**; no decision-logic changes. **There is no back-compatibility:** the new schema replaces the old one outright. No version detection, no dual-shape loader, no key migration — old files are re-authored. The only constraint is that the loader still produces the same *internal* structure the engine consumes, so `decide` is untouched.

## 1. Why reshape the config at all

Today the keys are organized by implementation, not by concept: `privacy.mode` sits next to `privacy.unknown_tools` and `privacy.llm_*`, while `[self]`, `[trusted_recipients]`, `[outward_sharing]`, `[[privacy.rules]]`, `[[privacy.tools]]`, `[security]`, `[language_packs]`, `[retention]` are scattered siblings. A user reading the file can't see the five concepts. Making the config isomorphic to the IA means the file, the dashboard, and `decide` all have the same shape — the structure teaches the model on every surface.

## 2. Target schema

Five top-level blocks, IA order. (Activity has no configuration — it's pure output — so the file has four config blocks plus meta.)

```toml
version = 4    # schema version, for future use only — the loader does not branch on it

# 2 — WHAT'S YOURS  (destination trust; decide steps 2–3)
[whats_yours]
stores     = ["store:files","store:notes","store:calendar","store:drive","draft:*"]
identities = []          # your verified send-to-self addresses
hosts      = []          # your own infrastructure hosts

# 3 — SHARING  (standing authorization; decide step 5)
[sharing]
[[sharing.trusted_recipients]]
identity = "..."
classes  = ["personal_private"]
note     = ""

[[sharing.rules]]        # ordered, first match wins
effect = "allow"         # allow | deny
action = "*"
destination = "*"
classes = "*"
purpose = "*"
recipient = "*"

[sharing.outward]
extra = []               # builtin share/invite/publish/etc. always external, not listed here

# 4 — REVIEW  (case-by-case judgment; decide step 6)
[review]
mode = "llm"             # llm | strict | read-only | off
owner_context = true     # llm_user_context
cron_context = false     # llm_cron_context
verifier_model = ""      # "" = agent model
allow_model_override = false
unknown_tools = "gate"   # gate | allow

# 5 — PROTECTION  (the floor + machinery)
[protection]
[protection.security]    # hard-block rule toggles (unchanged inner shape)
# rule_id = true/false ...

[[protection.tools]]     # tool classification overrides
match = "crm_*"
direction = "read"
taints = ["personal_private"]
destination = "store:crm"
egress = "gate"

[protection.language_packs]
# pack_id = true/false ...

[protection.retention]
max_rows = 100
max_age_days = 7

[protection.runtime]
dashboard_mutations = "auto"
```

## 3. The loader

The loader (`_default_privacy_config` + the `_normalize_*` family in `privacy/rules.py`) parses this schema directly into the internal structure the engine already consumes. The work is purely "read the new keys instead of the old ones":

1. **One shape, no detection.** Parse the five-block schema. There is no other shape to support; remove the old key paths entirely rather than leaving them as a fallback.
2. **Same internal structure.** Whatever normalized in-memory representation the engine consumes today stays exactly the same — only the parsing front-end changes. `decide`, `classify`, and `resolve_destination_trust` must not notice the file reshape.
3. **Fill from defaults.** Missing blocks fill from the safe defaults (seed `whats_yours` per the safe set; `review.mode` default `llm`; empty `sharing`). A file with only `[whats_yours]` is valid.
4. **Fail closed.** A malformed block drops to its safe default and logs; a wholly corrupt file falls back to strict — as today. Builtin outward-sharing subtypes are always code-owned and are never read from config.
5. **Delete the old key handling.** The current `[self]` / `[trusted_recipients]` / `[outward_sharing]` / `[[privacy.rules]]` / `[[privacy.tools]]` / flat `privacy.*` / `[security]` / `[language_packs]` / `[retention]` / `[dashboard]` parsing is removed and replaced by the block parsers above. An old file failing to load is acceptable and expected; it surfaces as the normal fail-closed-to-strict path with a clear log line ("unrecognized config shape — re-author per the v4 schema").

For reference, the conceptual correspondence (not a migration map — just where each old concept now lives):

| Concept | New key |
|---|---|
| self stores / identities / hosts | `whats_yours.stores` / `.identities` / `.hosts` |
| trusted recipients | `sharing.trusted_recipients` |
| allow/deny rules | `sharing.rules` |
| outward-sharing extras | `sharing.outward.extra` |
| mode / contexts / verifier / unknown-tools | `review.mode` / `.owner_context` / `.cron_context` / `.verifier_model` / `.allow_model_override` / `.unknown_tools` |
| security toggles | `protection.security` |
| tool overrides | `protection.tools` |
| language packs | `protection.language_packs` |
| retention | `protection.retention` |
| dashboard runtime | `protection.runtime` |

## 4. Surfaces consume the internal structure, not the file

The dashboard mutators (`/privacy/mode`, `/destinations/self`, `/rules`, …) and the slash commands operate on the normalized internal config via the guardian object, not on raw TOML, and they persist via the loader. Since the internal structure is unchanged, **docs 02 and 03 need no config-shape awareness** — they read/write the normalized form and the loader emits the v4 file. Verify this indirection holds; if any mutator writes raw config keys, route it through the normalizer so it emits the new shape.

## 5. Tests (`tests/test_config_ia.py`)

1. **Schema loads.** A full v4 file parses to the expected internal structure, and `decide` outcomes on the decision corpus are identical to pre-reshape (proves the front-end swap changed no decisions).
2. **Partial file.** A file with only `[whats_yours]` fills the rest from defaults; `review.mode` defaults to `llm`.
3. **Fail-closed.** A malformed `[sharing.rules]` drops to empty rules + logs; a corrupt file → strict.
4. **Old shape rejected cleanly.** An old-style file does not silently half-load — it fails closed to strict with a clear log line, not a partial/ambiguous parse.
5. **Builtin sharing not narrowable** (code-owned, never read from config).
6. **Round-trip.** A dashboard/command mutation persists the v4 shape and re-loads to the same internal structure.

## 6. Checklist

- [ ] v4 schema parsed directly; internal structure unchanged from the engine's view.
- [ ] Old key paths deleted (no dual-shape, no version branching).
- [ ] Partial/malformed handled; fail-closed to strict preserved; old files fail closed cleanly.
- [ ] Mutations persist the v4 shape via the normalizer.
- [ ] Decision-corpus parity: zero outcome changes from the config reshape.
- [ ] All §5 tests pass.
