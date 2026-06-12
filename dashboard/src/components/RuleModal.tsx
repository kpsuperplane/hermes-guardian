import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { Field } from "@/components/Field";
import { IconButton } from "@/components/IconButton";
import { ImpactPreview } from "@/components/ImpactPreview";
import { ACTIONS } from "@/constants";
import type { CronJob, Policy, RuleForm } from "@/types";

export interface RuleModalProps {
  policy: Policy;
  form: RuleForm;
  setForm: (form: RuleForm) => void;
  formError: string;
  onSubmit: React.FormEventHandler<HTMLFormElement>;
  onCancel: () => void;
}

export function RuleModal({
  policy,
  form,
  setForm,
  formError,
  onSubmit,
  onCancel,
}: RuleModalProps) {
  const allClasses = policy.all_privacy_classes || [
    "contacts",
    "email",
    "files",
    "location",
    "messages",
    "personal",
    "secrets",
  ];
  const cronJobs = policy.cron_jobs || [];
  const suggestions = policy.suggestions || {};
  const destinationSuggestions =
    policy.destination_suggestions || suggestions.destinations || [];
  const toolNameSuggestions = policy.tool_name_suggestions || suggestions.tool_names || [];
  const purposeSuggestions = policy.purpose_suggestions || suggestions.purposes || [];
  const recipientIdentitySuggestions =
    policy.recipient_identity_suggestions || suggestions.recipient_identities || [];
  const classSet = new Set(form.data_classes || ["*"]);

  function update<K extends keyof RuleForm>(key: K, value: RuleForm[K]) {
    setForm(Object.assign({}, form, { [key]: value }));
  }

  function toggleClass(cls: string) {
    if (cls === "*") {
      update("data_classes", classSet.has("*") ? [] : ["*"]);
      return;
    }
    const next = new Set(classSet);
    next.delete("*");
    if (next.has(cls)) next.delete(cls);
    else next.add(cls);
    update("data_classes", Array.from(next).sort());
  }

  function setCron(jobId: string) {
    const job = cronJobs.find((candidate: CronJob) => candidate.id === jobId);
    setForm(
      Object.assign({}, form, {
        cron_job_id: jobId || "",
        cron_job_name: job ? job.name : "",
      }),
    );
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
            <h2 className="hermes-guardian-title">{form.id ? "Edit rule" : "New rule"}</h2>
            <div className="hermes-guardian-subtitle">
              {form.id ? form.id : "Create a privacy allow or deny rule"}
            </div>
          </div>
          <IconButton icon="x" label="Close rule dialog" onClick={onCancel} />
        </div>
        <div className="hermes-guardian-modal-body">
          <datalist id="hermes-guardian-destination-options">
            {destinationSuggestions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
          <datalist id="hermes-guardian-tool-name-options">
            {toolNameSuggestions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
          <datalist id="hermes-guardian-purpose-options">
            {purposeSuggestions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
          <datalist id="hermes-guardian-recipient-options">
            {recipientIdentitySuggestions.map((value) => (
              <option key={value} value={value} />
            ))}
          </datalist>
          <div className="hermes-guardian-radio-row">
            <label className="hermes-guardian-check">
              <input
                type="radio"
                checked={form.effect === "allow"}
                onChange={() => update("effect", "allow")}
              />
              Allow
            </label>
            <label className="hermes-guardian-check">
              <input
                type="radio"
                checked={form.effect === "deny"}
                onChange={() => update("effect", "deny")}
              />
              Deny
            </label>
          </div>
          <div className="hermes-guardian-form-grid">
            <Field label="Action family">
              <select
                className="hermes-guardian-select"
                value={form.action_family}
                onChange={(event) => update("action_family", event.target.value)}
              >
                {ACTIONS.map((value) => (
                  <option key={value} value={value}>
                    {value}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Destination">
              <input
                className="hermes-guardian-input"
                list="hermes-guardian-destination-options"
                value={form.destination}
                placeholder="Any destination"
                onChange={(event) => update("destination", event.target.value)}
              />
            </Field>
            <Field label="Tool name">
              <input
                className="hermes-guardian-input"
                list="hermes-guardian-tool-name-options"
                value={form.tool_name}
                placeholder="Any tool"
                onChange={(event) => update("tool_name", event.target.value)}
              />
            </Field>
          </div>
          <div className="hermes-guardian-form-grid">
            <Field label="Purpose">
              <input
                className="hermes-guardian-input"
                list="hermes-guardian-purpose-options"
                value={form.purpose}
                placeholder="Any purpose"
                onChange={(event) => update("purpose", event.target.value)}
              />
            </Field>
            <Field label="Recipient identity">
              <input
                className="hermes-guardian-input"
                list="hermes-guardian-recipient-options"
                value={form.recipient_identity}
                placeholder="Any recipient"
                onChange={(event) => update("recipient_identity", event.target.value)}
              />
            </Field>
          </div>
          <div className="hermes-guardian-check-grid">
            <label className="hermes-guardian-check">
              <input
                type="checkbox"
                checked={classSet.has("*")}
                onChange={() => toggleClass("*")}
              />
              All data classes
            </label>
            {allClasses.map((cls) => (
              <label key={cls} className="hermes-guardian-check">
                <input
                  type="checkbox"
                  checked={!classSet.has("*") && classSet.has(cls)}
                  onChange={() => toggleClass(cls)}
                />
                {cls}
              </label>
            ))}
          </div>
          <div className="hermes-guardian-form-grid">
            <Field label="Expiry">
              <select
                className="hermes-guardian-select"
                value={form.expiry}
                onChange={(event) =>
                  update("expiry", event.target.value as RuleForm["expiry"])
                }
              >
                <option value="forever">Forever</option>
                <option value="5m">5 minutes</option>
                <option value="1h">1 hour</option>
                <option value="custom">Unix timestamp</option>
              </select>
            </Field>
            {form.expiry === "custom" ? (
              <Field label="Expires at">
                <input
                  className="hermes-guardian-input"
                  inputMode="numeric"
                  value={form.expires_at}
                  placeholder="Unix timestamp"
                  onChange={(event) => update("expires_at", event.target.value)}
                />
              </Field>
            ) : null}
          </div>
          <div className="hermes-guardian-form-grid">
            <Field label="Owner hash">
              <input
                className="hermes-guardian-input"
                value={form.owner_hash}
                placeholder="Any owner"
                onChange={(event) => update("owner_hash", event.target.value)}
              />
            </Field>
            <Field label="Cron scope">
              <select
                className="hermes-guardian-select"
                value={form.cron_job_id}
                onChange={(event) => setCron(event.target.value)}
              >
                <option value="">No cron scope</option>
                {cronJobs.map((job) => (
                  <option key={job.id} value={job.id}>
                    {job.name + (job.active === false ? " (paused)" : "")}
                  </option>
                ))}
              </select>
            </Field>
          </div>
          {/* Impact preview before commit (doc 02 §Tab3.5): replays this candidate
              rule against recent activity so an over-permissive rule is visible. */}
          <ImpactPreview
            candidate={{
              effect: form.effect || "allow",
              match: {
                action_family: form.action_family || "*",
                destination: form.destination || "*",
                purpose: form.purpose || "*",
                data_classes:
                  form.data_classes && form.data_classes.length ? form.data_classes : ["*"],
              },
            }}
            label="Preview impact before saving"
          />
          {formError ? <div className="hermes-guardian-banner">{formError}</div> : null}
          <div className="hermes-guardian-actions">
            <Button type="submit">{form.id ? "Save changes" : "Create rule"}</Button>
            <Button variant="secondary" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </div>
      </form>
    </div>
  );
}
