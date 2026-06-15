import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { IconButton } from "@/components/IconButton";
import { DEFAULT_PRIVACY_CLASSES, TOOL_EGRESS_OPTIONS } from "@/constants";
import { text } from "@/lib/format";
import type { OverrideForm, Policy } from "@/types";

export interface OverrideModalProps {
  kind: "reading" | "sharing";
  policy: Policy;
  form: OverrideForm;
  setForm: (form: OverrideForm) => void;
  formError: string;
  onSubmit: React.FormEventHandler<HTMLFormElement>;
  onCancel: () => void;
}

export function OverrideModal({
  kind,
  policy,
  form,
  setForm,
  formError,
  onSubmit,
  onCancel,
}: OverrideModalProps) {
  const isReading = kind === "reading";
  const allClasses = policy.all_privacy_classes || DEFAULT_PRIVACY_CLASSES;
  const egressOptions = policy.sharing_tool_egress_options
    ? [""].concat(policy.sharing_tool_egress_options)
    : TOOL_EGRESS_OPTIONS;
  const matchSuggestions =
    policy.tool_name_suggestions || (policy.suggestions && policy.suggestions.tool_names) || [];
  const taintSet = new Set(form.taints || []);
  const concreteEgress = form.egress && form.egress !== "ignore" && form.egress !== "gate";
  const publicSource = isReading && form.source === "public";

  function update<K extends keyof OverrideForm>(key: K, value: OverrideForm[K]) {
    const next = Object.assign({}, form, { [key]: value });
    if (key === "source" && value === "public") {
      next.taints = [];
    }
    setForm(next);
  }

  function toggleTaint(cls: string) {
    const next = new Set(taintSet);
    if (next.has(cls)) next.delete(cls);
    else next.add(cls);
    update("taints", Array.from(next).sort());
  }

  return (
    <div
      className="hermes-guardian-modal-backdrop"
      role="presentation"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onCancel();
      }}
    >
      <form className="hermes-guardian-modal" onSubmit={onSubmit}>
        <div className="hermes-guardian-card-head">
          <div>
            <h2 className="hermes-guardian-title">
              {form.isEdit
                ? isReading
                  ? "Edit source classification"
                  : "Edit egress classification"
                : isReading
                  ? "New source classification"
                  : "New egress classification"}
            </h2>
            <div className="hermes-guardian-subtitle">
              {form.isEdit
                ? text(form.match)
                : isReading
                  ? "Teach Guardian what a tool reads"
                  : "Teach Guardian when a tool sends data"}
            </div>
          </div>
          <IconButton icon="x" label="Close tool classification dialog" onClick={onCancel} />
        </div>
        <div className="hermes-guardian-modal-body">
          <datalist id="hermes-guardian-override-match-options">
            {matchSuggestions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
          <div className="hermes-guardian-form-grid">
            <Field label="Tool match">
              <input
                className="hermes-guardian-input"
                list="hermes-guardian-override-match-options"
                value={form.match}
                placeholder="tool_name or prefix_*"
                disabled={form.isEdit}
                onChange={(event) => update("match", event.target.value)}
              />
            </Field>
            {!isReading ? (
              <Field label="Egress Type">
                <select
                  className="hermes-guardian-select"
                  value={form.egress}
                  onChange={(event) => update("egress", event.target.value)}
                >
                  {egressOptions.map((value) => {
                    const label =
                      value === ""
                        ? "Default"
                        : value === "ignore"
                          ? "No egress"
                          : value;
                    return (
                      <option key={value || "none"} value={value}>
                        {label}
                      </option>
                    );
                  })}
                </select>
              </Field>
            ) : null}
            {!isReading && concreteEgress ? (
              <Field label="Destination">
                <input
                  className="hermes-guardian-input"
                  value={form.destination}
                  placeholder="optional"
                  onChange={(event) => update("destination", event.target.value)}
                />
              </Field>
            ) : null}
            {isReading ? (
              <Field label="Source">
                <select
                  className="hermes-guardian-select"
                  value={form.source}
                  onChange={(event) => update("source", event.target.value)}
                >
                  <option value="">Default</option>
                  <option value="reference">Reference material</option>
                  <option value="private">Personal data</option>
                  <option value="public">Public</option>
                  <option value="unknown">Unknown</option>
                </select>
              </Field>
            ) : null}
          </div>
          {isReading ? (
            <div className="hermes-guardian-field">
              Taints applied when this tool's results are read
              {publicSource ? (
                <div className="hermes-guardian-muted">
                  Public sources do not apply privacy taints.
                </div>
              ) : null}
              <div className="hermes-guardian-check-grid">
                {allClasses.map((cls) => (
                  <label key={cls} className="hermes-guardian-check">
                    <input
                      type="checkbox"
                      checked={taintSet.has(cls)}
                      disabled={publicSource}
                      onChange={() => toggleTaint(cls)}
                    />
                    {cls}
                  </label>
                ))}
              </div>
            </div>
          ) : null}
          <div className="hermes-guardian-form-grid">
            <Field label="Note">
              <input
                className="hermes-guardian-input"
                value={form.note}
                placeholder="optional note"
                onChange={(event) => update("note", event.target.value)}
              />
            </Field>
            <Field label="Enabled">
              <label className="hermes-guardian-check">
                <input
                  type="checkbox"
                  checked={form.enabled !== false}
                  onChange={(event) => update("enabled", event.target.checked)}
                />
                Override is active
              </label>
            </Field>
          </div>
          {!isReading && form.egress === "ignore" ? (
            <div className="hermes-guardian-banner">
              "No egress" marks this tool as a safe non-sink: it will be allowed even under
              taint. This weakens egress protection and requires confirmation.
            </div>
          ) : null}
          {formError ? <div className="hermes-guardian-banner">{formError}</div> : null}
          <div className="hermes-guardian-actions">
            <Button type="submit">{form.isEdit ? "Save changes" : "Create override"}</Button>
            <Button variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}
