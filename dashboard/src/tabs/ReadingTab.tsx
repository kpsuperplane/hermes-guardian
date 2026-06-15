import { React, useEffect } from "@/sdk";
import { Button } from "@/components/Button";
import { IconButton } from "@/components/IconButton";
import { Mono } from "@/components/Mono";
import { text, timeText } from "@/lib/format";
import type { Policy, ReadingTool, SourceSuggestion, ToolInventoryRow } from "@/types";

const TAINT_CLASSIFICATION_MODES = ["balanced", "strict", "relaxed"];

export interface ReadingTabProps {
  policy: Policy | null;
  onNewOverride: (match?: string) => void;
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
  onNewOverride: (match?: string) => void;
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
  const rows = (props.policy && props.policy.reading_tool_inventory) || [];
  function rowPolicy(row: ToolInventoryRow): ReadingTool | null {
    return row.policy ? (row.policy as ReadingTool) : null;
  }
  function policyLabel(row: ToolInventoryRow): string {
    const state = text(row.policy_state, "none");
    if (state === "exact") return "Exact";
    if (state === "inherited") return "Inherited";
    if (state === "policy_only") return "Policy only";
    return "No policy";
  }
  function rowMatch(row: ToolInventoryRow): string {
    return text(row.match || row.tool_name || row.group);
  }
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
        <Button onClick={() => props.onNewOverride()}>New source classification</Button>
      </div>
      {rows.length ? (
        <div className="hermes-guardian-tool-table-wrap">
          <table className="hermes-guardian-tool-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Seen</th>
                <th>Last seen</th>
                <th>Source</th>
                <th>Taints</th>
                <th>Policy</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => {
                const policy = rowPolicy(row);
                const source = text(policy && policy.source, "default");
                const taints = policy && policy.taints && policy.taints.length
                  ? policy.taints.join(", ")
                  : "none";
                const isGroup = row.row_type === "group";
                const rowClasses = [
                  isGroup ? "hermes-guardian-tool-row-group" : "",
                  policy && policy.enabled === false ? "hermes-guardian-rule-disabled" : "",
                ].filter(Boolean).join(" ");
                const match = rowMatch(row);
                const seen = Number(row.seen_count || 0);
                const label = isGroup
                  ? match + " (" + Number(row.child_count || 0) + ")"
                  : match;
                const observed = (row.observed_read_families || []).join(", ");
                const createMatch = text(row.match || row.tool_name || row.group);
                return (
                  <tr key={text(row.key, match)} className={rowClasses}>
                    <td>
                      <div
                        className="hermes-guardian-tool-tree-cell"
                        style={{ paddingLeft: String(Math.max(0, Number(row.depth || 0)) * 1.1) + "rem" }}
                      >
                        <Mono>{label}</Mono>
                        {observed ? <span className="hermes-guardian-muted">{observed}</span> : null}
                      </div>
                    </td>
                    <td>{seen || "policy"}</td>
                    <td>{timeText(row.last_seen)}</td>
                    <td><span className="hermes-guardian-pill">{source}</span></td>
                    <td>{taints}</td>
                    <td>
                      <span className="hermes-guardian-pill">{policyLabel(row)}</span>
                      {policy && policy.match ? (
                        <span className="hermes-guardian-muted"> {text(policy.match)}</span>
                      ) : null}
                    </td>
                    <td>
                      <div className="hermes-guardian-actions">
                        {policy ? (
                          <>
                            <IconButton
                              icon="edit"
                              label={"Edit source classification " + text(policy.match)}
                              onClick={() => props.onEditOverride(policy)}
                            />
                            <Button variant="secondary" onClick={() => props.onToggleOverride(policy)}>
                              {policy.enabled === false ? "Enable" : "Disable"}
                            </Button>
                            <IconButton
                              icon="trash"
                              variant="danger"
                              label={"Delete source classification " + text(policy.match)}
                              onClick={() => props.onDeleteOverride(policy)}
                            />
                          </>
                        ) : (
                          <Button variant="secondary" onClick={() => props.onNewOverride(createMatch)}>
                            Add policy
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="hermes-guardian-muted">
          No tools seen yet.
        </div>
      )}
      <div className="hermes-guardian-reading-fallthrough">
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
          <div className="hermes-guardian-rule-title">LLM source classifier</div>
          <label className="hermes-guardian-checkbox">
            <input
              type="checkbox"
              checked={props.llmSourceClassification}
              disabled={props.llmSourceClassificationSaving}
              onChange={(event) => props.onChangeLlmSourceClassification(event.target.checked)}
            />
            Enabled
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
