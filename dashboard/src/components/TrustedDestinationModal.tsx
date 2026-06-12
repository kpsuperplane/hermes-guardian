import { React, useEffect, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { IconButton } from "@/components/IconButton";
import type { DestinationsController } from "@/hooks/useDestinations";

type TrustedDestinationKind = "identity" | "command";

export interface TrustedDestinationModalProps {
  controller: DestinationsController;
  onCancel: () => void;
}

export function TrustedDestinationModal({ controller, onCancel }: TrustedDestinationModalProps) {
  const { busy, suggestions, loadSuggestions, addTrusted, addCommand } = controller;
  const [kind, setKind] = useState<TrustedDestinationKind>("identity");
  const [identity, setIdentity] = useState("");
  const [command, setCommand] = useState("");
  const [classes, setClasses] = useState("");
  const [note, setNote] = useState("");
  const [formError, setFormError] = useState("");

  useEffect(() => {
    loadSuggestions();
  }, [loadSuggestions]);

  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const trimmedClasses = classes.trim() || undefined;
    const trimmedNote = note.trim() || undefined;
    if (kind === "identity") {
      const value = identity.trim();
      if (!value) {
        setFormError("Enter a recipient identity to trust.");
        return;
      }
      addTrusted(value, trimmedClasses, trimmedNote, true);
      onCancel();
      return;
    }
    const value = command.trim();
    if (!value) {
      setFormError("Choose a command to trust.");
      return;
    }
    addCommand(value, trimmedClasses, trimmedNote, true);
    onCancel();
  }

  function updateKind(next: TrustedDestinationKind) {
    setKind(next);
    setFormError("");
  }

  return (
    <div
      className="hermes-guardian-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <form className="hermes-guardian-modal" onSubmit={submit}>
        <div className="hermes-guardian-card-head">
          <div>
            <h2 className="hermes-guardian-title">Add trusted destination</h2>
            <div className="hermes-guardian-subtitle">
              Trust either a recipient or a command, scoped to the data classes you set.
            </div>
          </div>
          <IconButton icon="x" label="Close trusted destination dialog" onClick={onCancel} />
        </div>
        <div className="hermes-guardian-modal-body">
          <div className="hermes-guardian-radio-row">
            <label className="hermes-guardian-check">
              <input
                type="radio"
                checked={kind === "identity"}
                onChange={() => updateKind("identity")}
              />
              Recipient
            </label>
            <label className="hermes-guardian-check">
              <input
                type="radio"
                checked={kind === "command"}
                onChange={() => updateKind("command")}
              />
              Command
            </label>
          </div>

          {kind === "identity" ? (
            <Field label="Recipient identity">
              <input
                className="hermes-guardian-input"
                type="text"
                value={identity}
                placeholder="teammate@example.com"
                disabled={busy}
                onChange={(event) => {
                  setIdentity(event.target.value);
                  setFormError("");
                }}
              />
            </Field>
          ) : (
            <Field label="Command">
              <select
                className="hermes-guardian-select"
                value={command}
                disabled={busy}
                onChange={(event) => {
                  setCommand(event.target.value);
                  setFormError("");
                }}
              >
                <option value="">Pick a command to trust...</option>
                {suggestions.map((item) => (
                  <option key={item.value} value={item.value}>
                    {(item.label || item.value) + (item.wildcard ? " (wildcard)" : "")}
                  </option>
                ))}
              </select>
            </Field>
          )}

          <div className="hermes-guardian-form-grid">
            <Field label="Data classes">
              <input
                className="hermes-guardian-input"
                type="text"
                value={classes}
                placeholder="Blank means all"
                disabled={busy}
                onChange={(event) => setClasses(event.target.value)}
              />
            </Field>
            <Field label="Note">
              <input
                className="hermes-guardian-input"
                type="text"
                value={note}
                placeholder="Optional"
                disabled={busy}
                onChange={(event) => setNote(event.target.value)}
              />
            </Field>
          </div>

          <div className="hermes-guardian-banner">
            Trusted destinations may receive private data without a prompt when the destination and
            data class match. The security layer still blocks sensitive account-security content.
          </div>
          {formError ? <div className="hermes-guardian-banner">{formError}</div> : null}
          <div className="hermes-guardian-actions">
            <Button type="submit" disabled={busy}>
              Add trusted destination
            </Button>
            <Button variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}
