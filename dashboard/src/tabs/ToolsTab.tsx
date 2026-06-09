import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { text } from "@/lib/format";
import type { Policy, ToolOverride } from "@/types";

const UNKNOWN_TOOL_MODES = ["gate", "allow"];

export interface ToolsTabProps {
  policy: Policy | null;
  unknownTools: string;
  unknownToolsSaving: boolean;
  onChangeUnknownTools: (mode: string) => void;
  onNewOverride: () => void;
  onEditOverride: (override: ToolOverride) => void;
  onToggleOverride: (override: ToolOverride) => void;
  onDeleteOverride: (override: ToolOverride) => void;
}

export function ToolsTab({
  policy,
  unknownTools,
  unknownToolsSaving,
  onChangeUnknownTools,
  onNewOverride,
  onEditOverride,
  onToggleOverride,
  onDeleteOverride,
}: ToolsTabProps) {
  const toolOverrides = (policy && policy.tool_overrides) || [];
  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Unknown tools</div>
            <div className="hermes-guardian-muted">
              Unrecognized tools (custom or third-party) are gated under taint by default.
              'allow' restores the legacy permissive behavior and is not recommended.
            </div>
          </div>
          <div className="hermes-guardian-actions">
            <select
              className="hermes-guardian-select"
              value={unknownTools}
              disabled={unknownToolsSaving}
              onChange={(event) => onChangeUnknownTools(event.target.value)}
            >
              {UNKNOWN_TOOL_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {mode}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Tool overrides</div>
            <div className="hermes-guardian-muted">
              Declare how Guardian treats specific tools: which private classes they read
              (taints) and whether they are a safe non-sink (No egress), forced to gate, or a
              specific action family. Overrides never bypass the Security Module.
            </div>
          </div>
        </div>
        {toolOverrides.length ? (
          <div className="hermes-guardian-grid">
            {toolOverrides.map((override) => {
              const disabled = override.enabled === false;
              const cardClasses = ["hermes-guardian-card"];
              if (disabled) cardClasses.push("hermes-guardian-rule-disabled");
              return (
                <div key={override.id} className={cardClasses.join(" ")}>
                  <div className="hermes-guardian-rule-head">
                    <div className="hermes-guardian-rule-main">
                      <div className="hermes-guardian-rule-title">{text(override.match)}</div>
                      <div className="hermes-guardian-rule-subline">
                        <span className="hermes-guardian-rule-id">{text(override.id)}</span>
                        {override.egress ? (
                          <span className="hermes-guardian-pill">
                            {"egress " +
                              (override.egress === "ignore" ? "none" : override.egress)}
                          </span>
                        ) : null}
                        {override.destination ? (
                          <span className="hermes-guardian-pill">
                            {"dest " + override.destination}
                          </span>
                        ) : null}
                      </div>
                    </div>
                    <div className="hermes-guardian-actions">
                      <Button variant="secondary" onClick={() => onEditOverride(override)}>
                        Edit
                      </Button>
                      <Button variant="secondary" onClick={() => onToggleOverride(override)}>
                        {disabled ? "Enable" : "Disable"}
                      </Button>
                      <Button variant="danger" onClick={() => onDeleteOverride(override)}>
                        Delete
                      </Button>
                    </div>
                  </div>
                  {override.taints && override.taints.length ? (
                    <div className="hermes-guardian-chips">
                      {override.taints.map((cls) => (
                        <span key={cls} className="hermes-guardian-chip">
                          {cls}
                        </span>
                      ))}
                    </div>
                  ) : null}
                  {override.note ? (
                    <div className="hermes-guardian-muted">{text(override.note)}</div>
                  ) : null}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="hermes-guardian-muted">
            No tool overrides. Unrecognized tools follow the unknown-tools mode above.
          </div>
        )}
        <div className="hermes-guardian-tools-override-actions">
          <Button onClick={onNewOverride}>New override</Button>
        </div>
      </div>
    </div>
  );
}
