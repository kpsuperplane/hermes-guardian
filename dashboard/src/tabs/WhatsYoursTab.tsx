import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { CheckDestination } from "@/components/CheckDestination";
import { Field } from "@/components/Field";
import { Mono } from "@/components/Mono";
import { TrustPill } from "@/components/TrustPill";
import { text } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { SeenDestination, SelfAllowlist } from "@/types";

export interface WhatsYoursTabProps {
  controller: DestinationsController;
}

// Show the boundary-crossing buckets first (those are the actionable ones), then the
// owned buckets so the operator sees the full picture.
const TRUST_ORDER = [
  "external",
  "unknown",
  "public",
  "trusted_recipient",
  "model_provider",
  "local_system",
  "self",
];

function trustRank(trust: string): number {
  const idx = TRUST_ORDER.indexOf(String(trust || "unknown").toLowerCase());
  return idx === -1 ? TRUST_ORDER.length : idx;
}

// "Seen recently" categories. The first three mirror the declarable self kinds;
// "other" catches services/system surfaces (cron, model, subagent, browser,
// web search, …) that are NOT a store, recipient, or host — so Stores stops being
// a junk drawer. Rendered one row per non-empty category.
type SeenCategory = "stores" | "identities" | "hosts" | "other";
type SelfItemKind = "destination" | "identity" | "host";

const SEEN_CATEGORIES: Array<{ key: SeenCategory; title: string }> = [
  { key: "stores", title: "Stores" },
  { key: "identities", title: "Identities (recipients)" },
  { key: "hosts", title: "Hosts" },
  { key: "other", title: "Other (services & system)" },
];

const SEEN_STORE_LABELS = ["local", "memory", "todo", "file", "kanban"];

const SELF_ITEM_OPTIONS: Array<{
  kind: SelfItemKind;
  title: string;
  modalLabel: string;
  placeholder: string;
  emptyHint: string;
  suggested: string[];
}> = [
  {
    kind: "destination",
    title: "Stores",
    modalLabel: "Store",
    placeholder: "store:crm or draft:*",
    emptyHint: "No owned stores.",
    suggested: ["store:files", "store:memory", "store:todo", "store:calendar", "store:drive", "draft:*"],
  },
  {
    kind: "identity",
    title: "Identities (send-to-self)",
    modalLabel: "Identity",
    placeholder: "you@example.com",
    emptyHint:
      "No identities declared — sends to any address are treated as external (the safe default).",
    suggested: [],
  },
  {
    kind: "host",
    title: "Hosts (own infrastructure)",
    modalLabel: "Host",
    placeholder: "myvps.example.com",
    emptyHint: "No hosts declared — every host is treated as external until you add it.",
    suggested: [],
  },
];

function selfOption(kind: SelfItemKind) {
  return SELF_ITEM_OPTIONS.find((option) => option.kind === kind) || SELF_ITEM_OPTIONS[0];
}

function selfItems(self: SelfAllowlist, kind: SelfItemKind): string[] {
  if (kind === "identity") return self.identities || [];
  if (kind === "host") return self.hosts || [];
  return self.destinations || [];
}

function uniqueValues(values: string[]): string[] {
  const seen: Record<string, boolean> = {};
  const result: string[] = [];
  values.forEach((value) => {
    const trimmed = value.trim();
    const key = trimmed.toLowerCase();
    if (!trimmed || seen[key]) return;
    seen[key] = true;
    result.push(trimmed);
  });
  return result;
}

function selfSuggestions(kind: SelfItemKind, seen: SeenDestination[], self: SelfAllowlist): string[] {
  const existing = selfItems(self, kind).map((value) => value.toLowerCase());
  const fromSeen = seen
    .map((entry) => entry.suggest)
    .filter((suggest): suggest is { kind: string; value: string } => Boolean(suggest))
    .filter((suggest) => suggest.kind === kind)
    .map((suggest) => text(suggest.value));
  return uniqueValues(selfOption(kind).suggested.concat(fromSeen)).filter(
    (value) => existing.indexOf(value.toLowerCase()) === -1,
  );
}

// Bucket an observed destination by what it actually is. Categorization tracks
// claimability: the backend's self-grant suggestion is authoritative when present
// (host / store), messaging rows carry a pseudonymized recipient and read as an
// identity, real hostnames/IPs are hosts, and everything else — services, system
// surfaces, opaque tool sinks — falls to "other" rather than masquerading as a store.
function seenKind(entry: SeenDestination): SeenCategory {
  const suggest = entry.suggest;
  if (suggest && suggest.kind === "host") return "hosts";
  if (suggest && suggest.kind === "destination") return "stores";
  if (suggest && suggest.kind === "identity") return "identities";
  const recipient = text(entry.recipient_identity).toLowerCase();
  const d = text(entry.destination).toLowerCase();
  if ((recipient && recipient !== "none") || d === "messaging") return "identities";
  if (/^(store:|draft:|mcp:)/.test(d) || SEEN_STORE_LABELS.indexOf(d) >= 0) return "stores";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(d) || /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d)) return "hosts";
  return "other";
}

// What to show on a seen tile: for a recipient-bearing messaging row, the
// (pseudonymized) recipient token; otherwise the destination string.
function seenDisplay(entry: SeenDestination): string {
  const recipient = text(entry.recipient_identity);
  const destination = text(entry.destination, "(none)");
  if (recipient && recipient.toLowerCase() !== "none" && (destination === "messaging" || !destination)) {
    return recipient;
  }
  return destination;
}

function AddSelfItemModal(props: {
  controller: DestinationsController;
  self: SelfAllowlist;
  seen: SeenDestination[];
  onCancel: () => void;
}) {
  const { busy, addSelf } = props.controller;
  const [kind, setKind] = useState<SelfItemKind>("destination");
  const [value, setValue] = useState("");
  const [formError, setFormError] = useState("");
  const option = selfOption(kind);
  const suggestions = selfSuggestions(kind, props.seen, props.self).slice(0, 8);
  const listId = "hermes-guardian-self-suggestions-" + kind;

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmed = value.trim();
    if (!trimmed) {
      setFormError("Enter a value to add.");
      return;
    }
    addSelf(kind, trimmed, undefined, true);
    props.onCancel();
  }

  function updateKind(next: SelfItemKind) {
    setKind(next);
    setValue("");
    setFormError("");
  }

  return (
    <div
      className="hermes-guardian-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) props.onCancel();
      }}
    >
      <form className="hermes-guardian-modal" onSubmit={submit}>
        <div className="hermes-guardian-card-head">
          <div>
            <h2 className="hermes-guardian-title">Add item</h2>
            <div className="hermes-guardian-subtitle">
              Declare a store, identity, or host that should resolve as yours.
            </div>
          </div>
          <Button variant="secondary" onClick={props.onCancel}>
            Close
          </Button>
        </div>
        <div className="hermes-guardian-modal-body">
          <div className="hermes-guardian-radio-row">
            {SELF_ITEM_OPTIONS.map((item) => (
              <label key={item.kind} className="hermes-guardian-check">
                <input
                  type="radio"
                  checked={kind === item.kind}
                  onChange={() => updateKind(item.kind)}
                />
                {item.modalLabel}
              </label>
            ))}
          </div>

          <Field label={option.modalLabel}>
            <input
              className="hermes-guardian-input"
              type="text"
              value={value}
              list={listId}
              placeholder={option.placeholder}
              disabled={busy}
              onChange={(event) => {
                setValue(event.target.value);
                setFormError("");
              }}
            />
            <datalist id={listId}>
              {suggestions.map((item) => (
                <option key={item} value={item} />
              ))}
            </datalist>
          </Field>

          {suggestions.length ? (
            <div className="hermes-guardian-suggestion-row" aria-label="Suggested values">
              {suggestions.map((item) => (
                <button
                  key={item}
                  type="button"
                  className="hermes-guardian-suggestion-chip"
                  disabled={busy}
                  onClick={() => {
                    setValue(item);
                    setFormError("");
                  }}
                >
                  <Mono>{item}</Mono>
                </button>
              ))}
            </div>
          ) : null}

          <div className="hermes-guardian-banner">
            Items you add here are treated as yours. Outbound writes to matching destinations are
            not gated as a boundary crossing; the security layer still blocks sensitive
            account-security content.
          </div>
          {formError ? <div className="hermes-guardian-banner">{formError}</div> : null}
          <div className="hermes-guardian-actions">
            <Button type="submit" disabled={busy}>
              Add item
            </Button>
            <Button variant="secondary" onClick={props.onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}

function SelfTile(props: {
  kind: SelfItemKind;
  value: string;
  disabled?: boolean;
  onRemove: (kind: SelfItemKind, value: string) => void;
}) {
  return (
    <div className="hermes-guardian-seen-tile hermes-guardian-self-tile">
      <div className="hermes-guardian-seen-tile-head">
        <TrustPill trust="self" />
      </div>
      <div className="hermes-guardian-seen-tile-dest">
        <Mono>{props.value}</Mono>
      </div>
      <Button
        variant="secondary"
        disabled={props.disabled}
        onClick={() => props.onRemove(props.kind, props.value)}
      >
        Remove
      </Button>
    </div>
  );
}

function EditableSelfRow(props: {
  kind: SelfItemKind;
  title: string;
  items: string[];
  emptyHint: string;
  disabled?: boolean;
  onRemove: (kind: SelfItemKind, value: string) => void;
}) {
  return (
    <div className="hermes-guardian-seen-cat">
      <div className="hermes-guardian-seen-cat-title">{props.title}</div>
      {props.items.length ? (
        <div className="hermes-guardian-seen-track">
          {props.items.map((item) => (
            <SelfTile
              key={item}
              kind={props.kind}
              value={item}
              disabled={props.disabled}
              onRemove={props.onRemove}
            />
          ))}
        </div>
      ) : (
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">{props.emptyHint}</div>
      )}
    </div>
  );
}

function SeenTile(props: {
  entry: SeenDestination;
  busy?: boolean;
  onAddToSelf: (suggest: { kind: string; value: string }, destination: string) => void;
}) {
  const { entry } = props;
  const display = seenDisplay(entry);
  return (
    <div className="hermes-guardian-seen-tile">
      <div className="hermes-guardian-seen-tile-head">
        <TrustPill trust={entry.trust} />
        {entry.count ? <span className="hermes-guardian-muted">{"x" + entry.count}</span> : null}
      </div>
      <div className="hermes-guardian-seen-tile-dest">
        <Mono>{display}</Mono>
      </div>
      {entry.suggest ? (
        <Button
          variant="secondary"
          disabled={props.busy}
          title={"Add " + entry.suggest.kind + " " + entry.suggest.value + " to your self-allowlist"}
          onClick={() => props.onAddToSelf(entry.suggest as { kind: string; value: string }, display)}
        >
          I own this
        </Button>
      ) : null}
    </div>
  );
}

function SeenSection(props: {
  seen: SeenDestination[];
  tally: Record<string, number>;
  busy?: boolean;
  onAddToSelf: (suggest: { kind: string; value: string }, destination: string) => void;
}) {
  const sorted = props.seen
    .slice()
    .sort((a, b) => trustRank(text(a.trust)) - trustRank(text(b.trust)) || (b.count || 0) - (a.count || 0));
  const tallyKeys = Object.keys(props.tally || {}).sort((a, b) => trustRank(a) - trustRank(b));
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Seen recently</div>
          <div className="hermes-guardian-muted">
            Destinations your agent has acted on, by trust. Spot an external or unknown that
            should be yours and claim it in one click.
          </div>
        </div>
        <div className="hermes-guardian-dest-tally">
          {tallyKeys.map((key) => (
            <span key={key} className="hermes-guardian-dest-tally-item">
              <TrustPill trust={key} />
              <span className="hermes-guardian-muted">{props.tally[key]}</span>
            </span>
          ))}
        </div>
      </div>
      {sorted.length ? (
        SEEN_CATEGORIES.map((cat) => {
          const entries = sorted.filter((entry) => seenKind(entry) === cat.key);
          if (!entries.length) return null;
          return (
            <div key={cat.key} className="hermes-guardian-seen-cat">
              <div className="hermes-guardian-seen-cat-title">{cat.title}</div>
              <div className="hermes-guardian-seen-track">
                {entries.map((entry, index) => (
                  <SeenTile
                    key={
                      text(entry.destination) +
                      ":" +
                      text(entry.recipient_identity) +
                      ":" +
                      text(entry.trust) +
                      ":" +
                      index
                    }
                    entry={entry}
                    busy={props.busy}
                    onAddToSelf={props.onAddToSelf}
                  />
                ))}
              </div>
            </div>
          );
        })
      ) : (
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">
          No outbound destinations observed yet.
        </div>
      )}
    </div>
  );
}

export function WhatsYoursTab({ controller }: WhatsYoursTabProps) {
  const { data, loading, error, busy, addSelf, removeSelf } = controller;
  const [showAddModal, setShowAddModal] = useState(false);

  if (loading && !data) {
    return <div className="hermes-guardian-muted">Loading destinations...</div>;
  }
  if (error && !data) {
    return <div className="hermes-guardian-banner">{error}</div>;
  }

  const self = (data && data.self) || {};
  const identities = self.identities || [];
  const hosts = self.hosts || [];
  const seen = (data && data.seen) || [];
  const grantActive = identities.length > 0 || hosts.length > 0;

  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-card hermes-guardian-dest-blurb">
        <div className="hermes-guardian-card-title">How Guardian decides</div>
        <div className="hermes-guardian-muted">
          Guardian allows anything that stays with you — your own stores, your own machine. It
          asks for approval when private data is about to reach someone else. Anything it can't
          confirm is yours is treated as someone else.
        </div>
      </div>

      <SeenSection
        seen={seen}
        tally={(data && data.tally) || {}}
        busy={busy}
        onAddToSelf={(suggest, destination) =>
          addSelf(
            suggest.kind,
            suggest.value,
            'Treat "' +
              destination +
              '" as yours? Outbound actions to it will no longer be gated as a boundary crossing.',
          )
        }
      />

      {grantActive ? (
        <div className="hermes-guardian-card hermes-guardian-grant-banner">
          <div className="hermes-guardian-muted">
            Send-to-self / own-infrastructure trust is active: outbound actions to your declared
            identities and hosts resolve as yours and are not gated.
          </div>
        </div>
      ) : null}

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">What's yours</div>
            <div className="hermes-guardian-muted">
              Destinations Guardian treats as you. Writes here reach no new party, so they are
              never gated.
            </div>
          </div>
          <Button onClick={() => setShowAddModal(true)} disabled={busy}>
            Add item
          </Button>
        </div>

        {SELF_ITEM_OPTIONS.map((item) => (
          <EditableSelfRow
            key={item.kind}
            kind={item.kind}
            title={item.title}
            items={selfItems(self, item.kind)}
            disabled={busy}
            emptyHint={item.emptyHint}
            onRemove={removeSelf}
          />
        ))}
      </div>

      <CheckDestination />
      {showAddModal ? (
        <AddSelfItemModal
          controller={controller}
          self={self}
          seen={seen}
          onCancel={() => setShowAddModal(false)}
        />
      ) : null}
    </div>
  );
}
