import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { displayText, remainingPillText, ruleScopeText, text } from "@/lib/format";
import type { Rule } from "@/types";

export interface RulesTabProps {
  rules: Rule[];
  onNewRule: () => void;
  onEditRule: (rule: Rule) => void;
  onPatchRule: (ruleId: string, payload: Record<string, unknown>) => void;
  onDeleteRule: (ruleId: string) => void;
  onMoveRule: (rule: Rule, direction: "up" | "down") => void;
}

export function RulesTab({
  rules,
  onNewRule,
  onEditRule,
  onPatchRule,
  onDeleteRule,
  onMoveRule,
}: RulesTabProps) {
  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-topbar">
        <p className="hermes-guardian-muted hermes-guardian-rule-description">
          Egress rules decide which tainted private data can leave Guardian by matching
          action, destination, purpose, recipient identity, data class, and owner/session or
          cron scope.
        </p>
        <Button onClick={onNewRule}>New rule</Button>
      </div>
      {rules.length ? (
        rules.map((rule, index) => {
          const disabled = rule.enabled === false;
          const remaining = remainingPillText(rule);
          const classes = ["hermes-guardian-card"];
          if (disabled) classes.push("hermes-guardian-rule-disabled");
          return (
            <div key={rule.rule_id} className={classes.join(" ")}>
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
                    {remaining ? (
                      <span className="hermes-guardian-pill">{remaining}</span>
                    ) : null}
                  </div>
                </div>
                <div className="hermes-guardian-actions">
                  <Button
                    variant="secondary"
                    disabled={index === 0}
                    onClick={() => onMoveRule(rule, "up")}
                  >
                    Up
                  </Button>
                  <Button
                    variant="secondary"
                    disabled={index === rules.length - 1}
                    onClick={() => onMoveRule(rule, "down")}
                  >
                    Down
                  </Button>
                  <Button variant="secondary" onClick={() => onEditRule(rule)}>
                    Edit
                  </Button>
                  <Button
                    variant="secondary"
                    onClick={() =>
                      onPatchRule(rule.rule_id as string, { enabled: !rule.enabled })
                    }
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
            </div>
          );
        })
      ) : (
        <div className="hermes-guardian-card hermes-guardian-muted">No privacy rules.</div>
      )}
    </div>
  );
}
