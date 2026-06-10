import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { TrustPill } from "@/components/TrustPill";
import { text } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { SeenDestination } from "@/types";

export interface DestinationsTabProps {
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
          <code>{item}</code>
          <Button
            variant="secondary"
            disabled={props.disabled}
            onClick={() => props.onRemove(item)}
          >
            Remove
          </Button>
        </li>
      ))}
    </ul>
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
        <ul className="hermes-guardian-dest-list">
          {sorted.map((entry, index) => {
            const destination = text(entry.destination, "(none)");
            return (
              <li key={destination + ":" + text(entry.trust) + ":" + index} className="hermes-guardian-dest-item">
                <span className="hermes-guardian-dest-seen-label">
                  <TrustPill trust={entry.trust} />
                  <code>{destination}</code>
                  {entry.count ? <span className="hermes-guardian-muted">{"x" + entry.count}</span> : null}
                </span>
                {entry.suggest ? (
                  <Button
                    variant="secondary"
                    disabled={props.busy}
                    title={"Add " + entry.suggest.kind + " " + entry.suggest.value + " to your self-allowlist"}
                    onClick={() => props.onAddToSelf(entry.suggest as { kind: string; value: string }, destination)}
                  >
                    This is mine → add to self
                  </Button>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : (
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">
          No outbound destinations observed yet.
        </div>
      )}
    </div>
  );
}

export function DestinationsTab({ controller }: DestinationsTabProps) {
  const { data, loading, error, busy, addSelf, removeSelf, addTrusted, removeTrusted, addSharing, removeSharing } =
    controller;

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
  const trusted = (data && data.trusted_recipients) || [];
  const sharing = (data && data.outward_sharing) || {};
  const sharingBuiltin = sharing.builtin || [];
  const sharingExtra = sharing.extra || [];

  return (
    <div className="hermes-guardian-grid">
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

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Trusted recipients</div>
            <div className="hermes-guardian-muted">
              Correspondents you have explicitly declared trusted. Private data may be shared with
              them without a prompt.
            </div>
          </div>
        </div>
        {trusted.length ? (
          <ul className="hermes-guardian-dest-list">
            {trusted.map((entry) => {
              const identity = text(entry.identity);
              return (
                <li key={identity} className="hermes-guardian-dest-item">
                  <span className="hermes-guardian-dest-seen-label">
                    <code>{identity}</code>
                    {entry.classes && entry.classes.length ? (
                      <span className="hermes-guardian-muted">{entry.classes.join(", ")}</span>
                    ) : null}
                    {entry.note ? <span className="hermes-guardian-muted">{entry.note}</span> : null}
                  </span>
                  <Button variant="secondary" disabled={busy} onClick={() => removeTrusted(identity)}>
                    Remove
                  </Button>
                </li>
              );
            })}
          </ul>
        ) : (
          <div className="hermes-guardian-muted hermes-guardian-dest-empty">
            No trusted recipients — every recipient is treated as external until you add them.
          </div>
        )}
        <AddRow
          placeholder="teammate@example.com"
          buttonLabel="Add trusted"
          disabled={busy}
          onAdd={(value) => addTrusted(value)}
        />
      </div>

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Sharing actions</div>
            <div className="hermes-guardian-muted">
              Actions that reach other people even on a store that is yours (sharing, inviting,
              publishing). These are always treated as external.
            </div>
          </div>
        </div>
        <div className="hermes-guardian-dest-group">
          <div className="hermes-guardian-dest-group-title">Built-in (cannot be disabled)</div>
          <div className="hermes-guardian-chips">
            {sharingBuiltin.map((subtype) => (
              <span key={subtype} className="hermes-guardian-pill hermes-guardian-trust-external">
                {subtype}
              </span>
            ))}
          </div>
        </div>
        <div className="hermes-guardian-dest-group">
          <div className="hermes-guardian-dest-group-title">Extra</div>
          <EditableList
            items={sharingExtra}
            disabled={busy}
            emptyHint="No extra sharing actions."
            onRemove={(value) => removeSharing(value)}
          />
          <AddRow
            placeholder="export_link"
            buttonLabel="Add sharing action"
            disabled={busy}
            onAdd={(value) => addSharing(value)}
          />
        </div>
      </div>
    </div>
  );
}
