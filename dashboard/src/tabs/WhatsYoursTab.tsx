import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { CheckDestination } from "@/components/CheckDestination";
import { Mono } from "@/components/Mono";
import { TrustPill } from "@/components/TrustPill";
import { text } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { SeenDestination } from "@/types";

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

const SEEN_CATEGORIES: Array<{ key: SeenCategory; title: string }> = [
  { key: "stores", title: "Stores" },
  { key: "identities", title: "Identities (recipients)" },
  { key: "hosts", title: "Hosts" },
  { key: "other", title: "Other (services & system)" },
];

const SEEN_STORE_LABELS = ["local", "memory", "todo", "file", "kanban"];

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

// A single add-input + button row used by every editable list.
function AddRow(props: {
  placeholder: string;
  buttonLabel: string;
  disabled?: boolean;
  onAdd: (value: string) => void;
}) {
  const [value, setValue] = useState("");
  const submit = () => {
    const trimmed = value.trim();
    if (!trimmed) return;
    props.onAdd(trimmed);
    setValue("");
  };
  return (
    <div className="hermes-guardian-dest-addrow">
      <input
        className="hermes-guardian-input"
        type="text"
        value={value}
        placeholder={props.placeholder}
        disabled={props.disabled}
        onChange={(event) => setValue(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter") submit();
        }}
      />
      <Button variant="secondary" disabled={props.disabled} onClick={submit}>
        {props.buttonLabel}
      </Button>
    </div>
  );
}

function EditableList(props: {
  items: string[];
  emptyHint: string;
  disabled?: boolean;
  onRemove: (value: string) => void;
}) {
  if (!props.items.length) {
    return <div className="hermes-guardian-muted hermes-guardian-dest-empty">{props.emptyHint}</div>;
  }
  return (
    <ul className="hermes-guardian-dest-list">
      {props.items.map((item) => (
        <li key={item} className="hermes-guardian-dest-item">
          <Mono>{item}</Mono>
          <Button variant="secondary" disabled={props.disabled} onClick={() => props.onRemove(item)}>
            Remove
          </Button>
        </li>
      ))}
    </ul>
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
          This is mine → add to self
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

  if (loading && !data) {
    return <div className="hermes-guardian-muted">Loading destinations...</div>;
  }
  if (error && !data) {
    return <div className="hermes-guardian-banner">{error}</div>;
  }

  const self = (data && data.self) || {};
  const stores = self.destinations || [];
  const identities = self.identities || [];
  const hosts = self.hosts || [];
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
        seen={(data && data.seen) || []}
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
        </div>

        <div className="hermes-guardian-dest-columns">
          <div className="hermes-guardian-dest-group">
            <div className="hermes-guardian-dest-group-title">Stores</div>
            <EditableList
              items={stores}
              disabled={busy}
              emptyHint="No owned stores."
              onRemove={(value) => removeSelf("destination", value)}
            />
            <AddRow
              placeholder="store:crm or draft:*"
              buttonLabel="Add store"
              disabled={busy}
              onAdd={(value) => addSelf("destination", value)}
            />
          </div>

          <div className="hermes-guardian-dest-group">
            <div className="hermes-guardian-dest-group-title">Identities (send-to-self)</div>
            <EditableList
              items={identities}
              disabled={busy}
              emptyHint="No identities declared — sends to any address are treated as external (the safe default)."
              onRemove={(value) => removeSelf("identity", value)}
            />
            <AddRow
              placeholder="you@example.com"
              buttonLabel="Add identity"
              disabled={busy}
              onAdd={(value) => addSelf("identity", value)}
            />
          </div>

          <div className="hermes-guardian-dest-group">
            <div className="hermes-guardian-dest-group-title">Hosts (own infrastructure)</div>
            <EditableList
              items={hosts}
              disabled={busy}
              emptyHint="No hosts declared — every host is treated as external until you add it."
              onRemove={(value) => removeSelf("host", value)}
            />
            <AddRow
              placeholder="myvps.example.com"
              buttonLabel="Add host"
              disabled={busy}
              onAdd={(value) => addSelf("host", value)}
            />
          </div>
        </div>
      </div>

      <CheckDestination />
    </div>
  );
}
