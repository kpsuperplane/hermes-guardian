import { React, useState } from "@/sdk";
import { sharingImpact } from "@/api/client";
import { Button } from "@/components/Button";
import { Mono } from "@/components/Mono";
import { PreviewSend } from "@/components/PreviewSend";
import { TrustPill } from "@/components/TrustPill";
import { TrustedDestinationModal } from "@/components/TrustedDestinationModal";
import { classesText, displayText, expiryPillText, ruleScopeText, text, timeText } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { ImpactPreview as ImpactPreviewData, Rule } from "@/types";

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

// --- Trusted destinations: identities + commands you've consented to share with --
function TrustedDestinations(props: { controller: DestinationsController }) {
  const { data, busy, removeTrusted } = props.controller;
  const [showModal, setShowModal] = useState(false);
  const trusted = (data && data.trusted_recipients) || [];
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Trusted destinations</div>
          <div className="hermes-guardian-muted">
            Recipients and commands you've consented to share with. A matching egress is allowed
            without a prompt, scoped to the data classes you set — and runs with reduced egress
            checks. The security layer still applies.
          </div>
        </div>
      </div>
      {trusted.length ? (
        <div className="hermes-guardian-sharing-tile-track">
          {trusted.map((entry) => {
            const kind = text(entry.kind) || "identity";
            const value = text(entry.value) || text(entry.identity);
            const isCommand = kind === "command";
            return (
              <div key={kind + ":" + value} className="hermes-guardian-sharing-tile">
                <div className="hermes-guardian-sharing-tile-head">
                  <TrustPill trust="trusted_recipient" />
                  <span className="hermes-guardian-pill">{isCommand ? "command" : "recipient"}</span>
                </div>
                <div className="hermes-guardian-sharing-tile-main">
                  <Mono>{value}</Mono>
                </div>
                {entry.classes && entry.classes.length ? (
                  <div className="hermes-guardian-sharing-tile-meta">{entry.classes.join(", ")}</div>
                ) : null}
                {entry.note ? (
                  <div className="hermes-guardian-sharing-tile-meta">{entry.note}</div>
                ) : null}
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => removeTrusted(kind, value)}
                >
                  Remove
                </Button>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">
          No trusted destinations — every recipient and command is treated as external until you add
          one.
        </div>
      )}
      <div className="hermes-guardian-tools-override-actions">
        <Button disabled={busy} onClick={() => setShowModal(true)}>
          Add trusted destination
        </Button>
      </div>
      {showModal ? (
        <TrustedDestinationModal
          controller={props.controller}
          onCancel={() => setShowModal(false)}
        />
      ) : null}
    </div>
  );
}

type RuleIconName = "left" | "right" | "eye" | "edit" | "power" | "trash";

function RuleIcon({ name }: { name: RuleIconName }) {
  const common = {
    fill: "none",
    stroke: "currentColor",
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    strokeWidth: 2,
  };
  if (name === "left") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
        <path {...common} d="M15 18l-6-6 6-6" />
      </svg>
    );
  }
  if (name === "right") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
        <path {...common} d="M9 6l6 6-6 6" />
      </svg>
    );
  }
  if (name === "eye") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
        <path {...common} d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6-10-6-10-6z" />
        <circle {...common} cx="12" cy="12" r="2.5" />
      </svg>
    );
  }
  if (name === "edit") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
        <path {...common} d="M4 20h4l11-11-4-4L4 16v4z" />
        <path {...common} d="M13 7l4 4" />
      </svg>
    );
  }
  if (name === "power") {
    return (
      <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
        <path {...common} d="M12 3v8" />
        <path {...common} d="M7 6.5a8 8 0 1 0 10 0" />
      </svg>
    );
  }
  return (
    <svg aria-hidden="true" viewBox="0 0 24 24" className="hermes-guardian-rule-icon">
      <path {...common} d="M4 7h16" />
      <path {...common} d="M10 11v6" />
      <path {...common} d="M14 11v6" />
      <path {...common} d="M6 7l1 14h10l1-14" />
      <path {...common} d="M9 7V4h6v3" />
    </svg>
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
  const [impact, setImpact] = useState<ImpactPreviewData | null>(null);
  const [impactError, setImpactError] = useState("");
  const [impactBusy, setImpactBusy] = useState(false);
  const disabled = rule.enabled === false;
  const expiry = expiryPillText(rule);
  const effect = text(rule.effect, "allow") === "deny" ? "deny" : "allow";
  const classes = ["hermes-guardian-sharing-tile", "hermes-guardian-rule-tile"];
  if (disabled) classes.push("hermes-guardian-rule-disabled");
  const ruleId = rule.rule_id as string;
  const impactCandidate = {
    effect: text(rule.effect, "allow"),
    match: {
      action_family: displayText(rule.action_family, "*"),
      destination: displayText(rule.destination, "*"),
      purpose: displayText(rule.purpose, "*"),
      data_classes: rule.data_classes && rule.data_classes.length ? rule.data_classes : ["*"],
    },
  };
  const impactCount = impact ? Number(impact.matched_count || 0) : 0;
  const impactVerb = (impact && impact.verb) || "covered";

  function previewImpact() {
    setImpactBusy(true);
    setImpactError("");
    sharingImpact(impactCandidate)
      .then((payload: ImpactPreviewData) => setImpact(payload || null))
      .catch((err: unknown) => {
        setImpact(null);
        setImpactError(String((err as Error)?.message || err));
      })
      .finally(() => setImpactBusy(false));
  }

  return (
    <div className={classes.join(" ")}>
      <div className="hermes-guardian-sharing-tile-head hermes-guardian-rule-toolbar">
        <div className="hermes-guardian-rule-order-group">
          <span className="hermes-guardian-rule-order">{"#" + (index + 1)}</span>
          <span className={"hermes-guardian-pill hermes-guardian-rule-effect-" + effect}>
            {effect}
          </span>
          {expiry ? <span className="hermes-guardian-pill">{expiry}</span> : null}
        </div>
        <div className="hermes-guardian-rule-move-actions">
          <Button
            variant="secondary"
            disabled={index === 0}
            title="Move rule left"
            aria-label={"Move rule " + (index + 1) + " left"}
            onClick={() => onMoveRule(rule, "up")}
          >
            <RuleIcon name="left" />
          </Button>
          <Button
            variant="secondary"
            disabled={index === total - 1}
            title="Move rule right"
            aria-label={"Move rule " + (index + 1) + " right"}
            onClick={() => onMoveRule(rule, "down")}
          >
            <RuleIcon name="right" />
          </Button>
        </div>
      </div>
      <div className="hermes-guardian-rule-head hermes-guardian-rule-tile-head">
        <div className="hermes-guardian-rule-main">
          <div className="hermes-guardian-rule-title">
            {displayText(rule.action_family, "*") +
              " → " +
              displayText(rule.destination, "*")}
          </div>
          <div className="hermes-guardian-rule-subline">
            <span className="hermes-guardian-rule-id">{rule.rule_id}</span>
          </div>
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
      <div className="hermes-guardian-actions hermes-guardian-rule-tile-actions">
        <Button
          variant="secondary"
          disabled={impactBusy}
          title="Preview impact"
          aria-label={"Preview impact for rule " + (index + 1)}
          onClick={previewImpact}
        >
          <RuleIcon name="eye" />
        </Button>
        <Button
          variant="secondary"
          title="Edit rule"
          aria-label={"Edit rule " + (index + 1)}
          onClick={() => onEditRule(rule)}
        >
          <RuleIcon name="edit" />
        </Button>
        <Button
          variant="secondary"
          title={rule.enabled === false ? "Enable rule" : "Disable rule"}
          aria-label={(rule.enabled === false ? "Enable" : "Disable") + " rule " + (index + 1)}
          onClick={() => onPatchRule(ruleId, { enabled: !rule.enabled })}
        >
          <RuleIcon name="power" />
        </Button>
        <Button
          variant="danger"
          title="Delete rule"
          aria-label={"Delete rule " + (index + 1)}
          onClick={() => onDeleteRule(ruleId)}
        >
          <RuleIcon name="trash" />
        </Button>
      </div>
      {impact ? (
        <div className="hermes-guardian-muted hermes-guardian-rule-impact-summary">
          {"Would have " +
            impactVerb +
            " " +
            impactCount +
            " of the last " +
            Number(impact.considered || 0) +
            " recorded actions."}
        </div>
      ) : null}
      {impactError ? <div className="hermes-guardian-banner">{impactError}</div> : null}
      {impact && impactCount ? (
        <ul className="hermes-guardian-dest-list hermes-guardian-impact-list hermes-guardian-rule-impact-list">
          {(impact.matched || []).map((row, rowIndex) => (
            <li key={text(row.id) + ":" + rowIndex} className="hermes-guardian-dest-item">
              <span className="hermes-guardian-dest-seen-label">
                <span className="hermes-guardian-pill">{text(row.decision)}</span>
                <Mono>{text(row.action_family) + " -> " + text(row.destination)}</Mono>
                <span className="hermes-guardian-muted">{classesText(row.data_classes)}</span>
              </span>
              <span className="hermes-guardian-muted">{timeText(row.created_at)}</span>
            </li>
          ))}
        </ul>
      ) : impact ? (
        <div className="hermes-guardian-muted hermes-guardian-rule-impact-summary">
          No recent actions would have been affected by this rule.
        </div>
      ) : null}
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
      <TrustedDestinations controller={controller} />

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
          <div className="hermes-guardian-sharing-tile-track hermes-guardian-rule-tile-track">
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
