import { React, useEffect } from "@/sdk";
import { Button } from "@/components/Button";
import { IconButton } from "@/components/IconButton";
import { Mono } from "@/components/Mono";
import { text } from "@/lib/format";
import type { Policy, ReadingTool, SourceSuggestion } from "@/types";

const TAINT_CLASSIFICATION_MODES = ["balanced", "strict", "relaxed"];

export interface ReadingTabProps {
  policy: Policy | null;
  onNewOverride: () => void;
  onEditOverride: (override: ReadingTool) => void;
  onToggleOverride: (override: ReadingTool) => void;
  onDeleteOverride: (override: ReadingTool) => void;
  taintClassification: string;
  taintClassificationSaving: boolean;
  onChangeTaintClassification: (mode: string) => void;
  llmSourceClassification: boolean;
  llmSourceClassificationSaving: boolean;
  onChangeLlmSourceClassification: (enabled: boolean) => void;
  sourceSuggestions: SourceSuggestion[];
  onLoadSourceSuggestions: () => void;
  onClassifySource: (server: string, mode: "reference" | "private" | "unknown") => void;
}

function ToolClassification(props: {
  policy: Policy | null;
  onNewOverride: () => void;
  onEditOverride: (override: ReadingTool) => void;
  onToggleOverride: (override: ReadingTool) => void;
  onDeleteOverride: (override: ReadingTool) => void;
  taintClassification: string;
  taintClassificationSaving: boolean;
  onChangeTaintClassification: (mode: string) => void;
  llmSourceClassification: boolean;
  llmSourceClassificationSaving: boolean;
  onChangeLlmSourceClassification: (enabled: boolean) => void;
}) {
  const toolOverrides = (props.policy && props.policy.reading_tools) || [];
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Source tool classification</div>
          <div className="hermes-guardian-muted">
            Teach Guardian what a tool reads: which private classes its results apply and whether
            its reads are reference material, personal data, or still unknown. Egress behavior
            lives in Sharing. Classifications never bypass the Security Module.
          </div>
        </div>
      </div>
      <div className="hermes-guardian-tools-override-actions">
        <Button onClick={props.onNewOverride}>New source classification</Button>
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
                      {override.source ? (
                        <span className="hermes-guardian-pill">{"source " + override.source}</span>
                      ) : null}
                    </div>
                  </div>
                  <div className="hermes-guardian-actions">
                    <IconButton
                      icon="edit"
                      label={"Edit source classification " + text(override.match)}
                      onClick={() => props.onEditOverride(override)}
                    />
                    <Button variant="secondary" onClick={() => props.onToggleOverride(override)}>
                      {disabled ? "Enable" : "Disable"}
                    </Button>
                    <IconButton
                      icon="trash"
                      variant="danger"
                      label={"Delete source classification " + text(override.match)}
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
          No Reading tool classifications yet.
        </div>
      )}
      <div className="hermes-guardian-card hermes-guardian-reading-fallthrough">
        <div className="hermes-guardian-rule-head">
          <div className="hermes-guardian-rule-main">
            <div className="hermes-guardian-rule-title">Default for unknown reads</div>
            <div className="hermes-guardian-rule-subline">
              <span className="hermes-guardian-pill">fallthrough</span>
              <span className="hermes-guardian-pill">{props.taintClassification}</span>
            </div>
          </div>
          <select
            className="hermes-guardian-select"
            value={props.taintClassification}
            disabled={props.taintClassificationSaving}
            aria-label="Default for unknown reads"
            onChange={(event) => props.onChangeTaintClassification(event.target.value)}
          >
            {TAINT_CLASSIFICATION_MODES.map((mode) => (
              <option key={mode} value={mode}>
                {mode}
              </option>
            ))}
          </select>
        </div>
        <div className="hermes-guardian-muted">
          Balanced uses recognized sources, declarations, and content signals. Strict also treats
          otherwise-unknown read results as documents. Relaxed keeps balanced read inference and
          allows unrecognized non-MCP tools under taint.
        </div>
        <div className="hermes-guardian-field">
          <label className="hermes-guardian-checkbox">
            <input
              type="checkbox"
              checked={props.llmSourceClassification}
              disabled={props.llmSourceClassificationSaving}
              onChange={(event) => props.onChangeLlmSourceClassification(event.target.checked)}
            />
            LLM source classifier
          </label>
          <div className="hermes-guardian-muted">
            Uses metadata only to save reference, private, or unknown source rules for future
            reads. Result content and raw argument values are not sent.
          </div>
        </div>
      </div>
    </div>
  );
}

function SourcesSeen(props: {
  suggestions: SourceSuggestion[];
  onLoad: () => void;
  onClassify: (server: string, mode: "reference" | "private" | "unknown") => void;
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
        leniently (placeholder-tolerant); personal data always taints; unknown remembers that
        provenance is unresolved.
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
              <Button variant="secondary" onClick={() => props.onClassify(item.server, "unknown")}>
                Unknown
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
        llmSourceClassification={props.llmSourceClassification}
        llmSourceClassificationSaving={props.llmSourceClassificationSaving}
        onChangeLlmSourceClassification={props.onChangeLlmSourceClassification}
      />
      <SourcesSeen
        suggestions={props.sourceSuggestions}
        onLoad={props.onLoadSourceSuggestions}
        onClassify={props.onClassifySource}
      />
    </div>
  );
}
