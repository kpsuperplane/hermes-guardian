import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { Mono } from "@/components/Mono";
import { ImpactPreview } from "@/components/ImpactPreview";
import { PreviewSend } from "@/components/PreviewSend";
import { displayText, remainingPillText, ruleScopeText, text } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { Rule } from "@/types";

export interface SharingTabProps {
  controller: DestinationsController;
  rules: Rule[];
  onNewRule: () => void;
  onEditRule: (rule: Rule) => void;
  onPatchRule: (ruleId: string, payload: Record<string, unknown>) => void;
  onDeleteRule: (ruleId: string) => void;
  onMoveRule: (rule: Rule, direction: "up" | "down") => void;
}

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

// --- Trusted recipients (moved out of DestinationsTab, doc 02 §Tab3.1) -------
function TrustedRecipients(props: { controller: DestinationsController }) {
  const { data, busy, addTrusted, removeTrusted } = props.controller;
  const trusted = (data && data.trusted_recipients) || [];
  return (
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
                  <Mono>{identity}</Mono>
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
  );
}

// --- Allow / deny rules (ported from RulesTab, doc 02 §Tab3.2) ---------------
function RuleCard(props: {
  rule: Rule;
  index: number;
  total: number;
  onEditRule: (rule: Rule) => void;
  onPatchRule: (ruleId: string, payload: Record<string, unknown>) => void;
  onDeleteRule: (ruleId: string) => void;
  onMoveRule: (rule: Rule, direction: "up" | "down") => void;
}) {
  const { rule, index, total, onEditRule, onPatchRule, onDeleteRule, onMoveRule } = props;
  const disabled = rule.enabled === false;
  const remaining = remainingPillText(rule);
  const classes = ["hermes-guardian-card"];
  if (disabled) classes.push("hermes-guardian-rule-disabled");
  return (
    <div className={classes.join(" ")}>
      <div className="hermes-guardian-rule-head">
        <div className="hermes-guardian-rule-main">
          <div className="hermes-guardian-rule-title">
            {text(rule.effect, "allow") +
              " " +
              displayText(rule.action_family, "*") +
              " -> " +
              displayText(rule.destination, "*")}
          </div>
          <div className="hermes-guardian-rule-subline">
            <span className="hermes-guardian-rule-id">{rule.rule_id}</span>
            {remaining ? <span className="hermes-guardian-pill">{remaining}</span> : null}
          </div>
        </div>
        <div className="hermes-guardian-actions">
          <Button variant="secondary" disabled={index === 0} onClick={() => onMoveRule(rule, "up")}>
            Up
          </Button>
          <Button
            variant="secondary"
            disabled={index === total - 1}
            onClick={() => onMoveRule(rule, "down")}
          >
            Down
          </Button>
          <Button variant="secondary" onClick={() => onEditRule(rule)}>
            Edit
          </Button>
          <Button
            variant="secondary"
            onClick={() => onPatchRule(rule.rule_id as string, { enabled: !rule.enabled })}
          >
            {rule.enabled === false ? "Enable" : "Disable"}
          </Button>
          <Button variant="danger" onClick={() => onDeleteRule(rule.rule_id as string)}>
            Delete
          </Button>
        </div>
      </div>
      <div className="hermes-guardian-rule-meta">
        <span>{ruleScopeText(rule)}</span>
        <span>{"Purpose " + displayText(rule.purpose, "*")}</span>
        <span>{"Recipient " + displayText(rule.recipient_identity, "*")}</span>
      </div>
      <div className="hermes-guardian-chips">
        {(rule.data_classes || []).map((cls) => (
          <span key={cls} className="hermes-guardian-chip">
            {cls === "*" ? "all data classes" : cls}
          </span>
        ))}
      </div>
      {/* Impact preview for the existing rule: replays it against recent activity. */}
      <ImpactPreview
        candidate={{
          effect: text(rule.effect, "allow"),
          match: {
            action_family: displayText(rule.action_family, "*"),
            destination: displayText(rule.destination, "*"),
            purpose: displayText(rule.purpose, "*"),
            data_classes: rule.data_classes && rule.data_classes.length ? rule.data_classes : ["*"],
          },
        }}
        label="Preview impact"
      />
    </div>
  );
}

// --- Outward sharing (moved out of DestinationsTab, doc 02 §Tab3.3) ----------
function OutwardSharing(props: { controller: DestinationsController }) {
  const { data, busy, addSharing, removeSharing } = props.controller;
  const sharing = (data && data.outward_sharing) || {};
  const sharingBuiltin = sharing.builtin || [];
  const sharingExtra = sharing.extra || [];
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Outward sharing</div>
          <div className="hermes-guardian-muted">
            Actions that reach other people even on a store that is yours (sharing, inviting,
            publishing). These are always treated as external.
          </div>
        </div>
      </div>
      <div className="hermes-guardian-dest-group">
        <div className="hermes-guardian-dest-group-title">Built-in (always external — cannot be disabled)</div>
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
        {sharingExtra.length ? (
          <ul className="hermes-guardian-dest-list">
            {sharingExtra.map((item) => (
              <li key={item} className="hermes-guardian-dest-item">
                <Mono>{item}</Mono>
                <Button variant="secondary" disabled={busy} onClick={() => removeSharing(item)}>
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        ) : (
          <div className="hermes-guardian-muted hermes-guardian-dest-empty">
            No extra sharing actions.
          </div>
        )}
        <AddRow
          placeholder="export_link"
          buttonLabel="Add sharing action"
          disabled={busy}
          onAdd={(value) => addSharing(value)}
        />
      </div>
    </div>
  );
}

export function SharingTab(props: SharingTabProps) {
  const { controller, rules, onNewRule, onEditRule, onPatchRule, onDeleteRule, onMoveRule } = props;

  if (controller.loading && !controller.data) {
    return <div className="hermes-guardian-muted">Loading sharing settings...</div>;
  }

  return (
    <div className="hermes-guardian-grid">
      <TrustedRecipients controller={controller} />

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Allow / deny rules</div>
            <p className="hermes-guardian-muted hermes-guardian-rule-description">
              The ordered, first-match list that decides which tainted private data can leave by
              matching action, destination, purpose, recipient, and data class. Order is semantics —
              use Up / Down to reorder.
            </p>
          </div>
        </div>
        {rules.length ? (
          <div className="hermes-guardian-grid">
            {rules.map((rule, index) => (
              <RuleCard
                key={rule.rule_id}
                rule={rule}
                index={index}
                total={rules.length}
                onEditRule={onEditRule}
                onPatchRule={onPatchRule}
                onDeleteRule={onDeleteRule}
                onMoveRule={onMoveRule}
              />
            ))}
          </div>
        ) : (
          <div className="hermes-guardian-muted">No privacy rules.</div>
        )}
        <div className="hermes-guardian-tools-override-actions">
          <Button onClick={onNewRule}>New rule</Button>
        </div>
      </div>

      <OutwardSharing controller={controller} />

      <PreviewSend />
    </div>
  );
}
