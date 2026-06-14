import { React, useEffect } from "@/sdk";
import { Button } from "@/components/Button";
import { IconButton } from "@/components/IconButton";
import { Mono } from "@/components/Mono";
import { text } from "@/lib/format";
import type { Policy, SourceSuggestion, ToolOverride } from "@/types";

const TAINT_CLASSIFICATION_MODES = ["balanced", "strict", "relaxed"];

export interface ReadingTabProps {
  policy: Policy | null;
  onNewOverride: () => void;
  onEditOverride: (override: ToolOverride) => void;
  onToggleOverride: (override: ToolOverride) => void;
  onDeleteOverride: (override: ToolOverride) => void;
  taintClassification: string;
  taintClassificationSaving: boolean;
  onChangeTaintClassification: (mode: string) => void;
  sourceSuggestions: SourceSuggestion[];
  onLoadSourceSuggestions: () => void;
  onClassifySource: (server: string, mode: "reference" | "private") => void;
}

function ToolClassification(props: {
  policy: Policy | null;
  onNewOverride: () => void;
  onEditOverride: (override: ToolOverride) => void;
  onToggleOverride: (override: ToolOverride) => void;
  onDeleteOverride: (override: ToolOverride) => void;
  taintClassification: string;
  taintClassificationSaving: boolean;
  onChangeTaintClassification: (mode: string) => void;
}) {
  const toolOverrides = (props.policy && props.policy.tool_overrides) || [];
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Tool classification</div>
          <div className="hermes-guardian-muted">
            Teach Guardian what a tool is: which private classes it reads (taints) and whether it
            is a safe non-sink (No egress), forced to gate, or a specific action family. (Declaring
            a custom store yours lives in What's Yours; teaching Guardian what a tool is lives
            here.) Overrides never bypass the Security Module.
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
                          {"egress " + (override.egress === "ignore" ? "none" : override.egress)}
                        </span>
                      ) : null}
                      {override.source ? (
                        <span className="hermes-guardian-pill">{"source " + override.source}</span>
                      ) : null}
                      {override.destination ? (
                        <span className="hermes-guardian-pill">{"dest " + override.destination}</span>
                      ) : null}
                    </div>
                  </div>
                  <div className="hermes-guardian-actions">
                    <IconButton
                      icon="edit"
                      label={"Edit tool override " + text(override.match)}
                      onClick={() => props.onEditOverride(override)}
                    />
                    <Button variant="secondary" onClick={() => props.onToggleOverride(override)}>
                      {disabled ? "Enable" : "Disable"}
                    </Button>
                    <IconButton
                      icon="trash"
                      variant="danger"
                      label={"Delete tool override " + text(override.match)}
                      onClick={() => props.onDeleteOverride(override)}
                    />
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
          No tool overrides. Unrecognized tools follow Taint Classification in Reading.
        </div>
      )}
      <div className="hermes-guardian-tools-override-actions">
        <Button onClick={props.onNewOverride}>New override</Button>
      </div>
      <div className="hermes-guardian-taint-classification-row">
        <div className="hermes-guardian-taint-classification-label">
          <span>Taint Classification</span>
          <span className="hermes-guardian-muted">
            Balanced uses recognized sources, declarations, and content signals. Strict also
            treats otherwise-unknown read results as documents. Relaxed allows unrecognized
            tools under taint.
          </span>
        </div>
        <select
          className="hermes-guardian-select"
          value={props.taintClassification}
          disabled={props.taintClassificationSaving}
          onChange={(event) => props.onChangeTaintClassification(event.target.value)}
        >
          {TAINT_CLASSIFICATION_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {mode}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}

function SourcesSeen(props: {
  suggestions: SourceSuggestion[];
  onLoad: () => void;
  onClassify: (server: string, mode: "reference" | "private") => void;
}) {
  useEffect(() => {
    props.onLoad();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  if (!props.suggestions.length) return null;
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Sources seen</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        Guardian saw document reads from these MCP servers and tainted them conservatively
        because their provenance is undeclared. Classify each: reference material is scanned
        leniently (placeholder-tolerant); personal data always taints.
      </div>
      <div className="hermes-guardian-grid">
        {props.suggestions.map((item) => (
          <div key={item.server} className="hermes-guardian-rule-head">
            <div className="hermes-guardian-rule-main">
              <div className="hermes-guardian-rule-title">
                <Mono>{text(item.server)}</Mono>
              </div>
              <div className="hermes-guardian-muted">{(item.hits || 0) + " read(s) seen"}</div>
            </div>
            <div className="hermes-guardian-actions">
              <Button variant="secondary" onClick={() => props.onClassify(item.server, "reference")}>
                Reference material
              </Button>
              <Button variant="secondary" onClick={() => props.onClassify(item.server, "private")}>
                Personal data
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export function ReadingTab(props: ReadingTabProps) {
  return (
    <div className="hermes-guardian-grid">
      <ToolClassification
        policy={props.policy}
        onNewOverride={props.onNewOverride}
        onEditOverride={props.onEditOverride}
        onToggleOverride={props.onToggleOverride}
        onDeleteOverride={props.onDeleteOverride}
        taintClassification={props.taintClassification}
        taintClassificationSaving={props.taintClassificationSaving}
        onChangeTaintClassification={props.onChangeTaintClassification}
      />
      <SourcesSeen
        suggestions={props.sourceSuggestions}
        onLoad={props.onLoadSourceSuggestions}
        onClassify={props.onClassifySource}
      />
    </div>
  );
}
