import { React, useState } from "@/sdk";
import { sharingImpact } from "@/api/client";
import { Button } from "@/components/Button";
import { IconButton } from "@/components/IconButton";
import { Mono } from "@/components/Mono";
import { PreviewSend } from "@/components/PreviewSend";
import { TrustPill } from "@/components/TrustPill";
import { TrustedDestinationModal } from "@/components/TrustedDestinationModal";
import { classesText, displayText, expiryPillText, ruleScopeText, text, timeText } from "@/lib/format";
import type { DestinationsController } from "@/hooks/useDestinations";
import type { ImpactPreview as ImpactPreviewData, Performance, Policy, Rule, SharingTool, ToolInventoryRow } from "@/types";

const MODE_OPTIONS: Array<{ value: string; label: string; consequence: string }> = [
  {
    value: "llm",
    label: "LLM pre-screen (llm)",
    consequence: "The verifier pre-screens; you see only genuine boundary crossings.",
  },
  {
    value: "strict",
    label: "Manual review (strict)",
    consequence: "You review every outbound action yourself.",
  },
  {
    value: "read-only",
    label: "Read-only preset",
    consequence: "Nothing outward is auto-allowed.",
  },
  {
    value: "off",
    label: "off",
    consequence: "Kill switch; privacy egress checks off. Security filtering still runs.",
  },
];

export interface SharingTabProps {
  controller: DestinationsController;
  policy: Policy | null;
  egressSafety: string;
  modeSaving: boolean;
  onChangeEgressSafety: (mode: string) => void;
  llmUserContext: boolean;
  llmCronContext: boolean;
  userContextSaving: boolean;
  cronContextSaving: boolean;
  onChangeUserContext: (enabled: boolean) => void;
  onChangeCronContext: (enabled: boolean) => void;
  llmVerifierModel: string;
  verifierModelSaving: boolean;
  onChangeVerifierModel: (model: string) => void;
  performance: Performance | null;
  rules: Rule[];
  sharingTools: SharingTool[];
  toolInventory: ToolInventoryRow[];
  onNewRule: () => void;
  onEditRule: (rule: Rule) => void;
  onPatchRule: (ruleId: string, payload: Record<string, unknown>) => void;
  onDeleteRule: (ruleId: string) => void;
  onMoveRule: (rule: Rule, direction: "up" | "down") => void;
  onNewTool: (match?: string) => void;
  onEditTool: (tool: SharingTool) => void;
  onToggleTool: (tool: SharingTool) => void;
  onDeleteTool: (tool: SharingTool) => void;
}

function ms(value: number): string {
  return (Number(value) || 0).toFixed(0) + " ms";
}

function EgressSafetySettings(props: {
  policy: Policy | null;
  egressSafety: string;
  modeSaving: boolean;
  onChangeEgressSafety: (mode: string) => void;
  llmUserContext: boolean;
  llmCronContext: boolean;
  userContextSaving: boolean;
  cronContextSaving: boolean;
  onChangeUserContext: (enabled: boolean) => void;
  onChangeCronContext: (enabled: boolean) => void;
  llmVerifierModel: string;
  verifierModelSaving: boolean;
  onChangeVerifierModel: (model: string) => void;
  performance: Performance | null;
}) {
  const verifierModelOptions = (props.policy && props.policy.llm_verifier_model_options) || [];
  const llmStats = props.performance && props.performance.llm;
  const llmCount = llmStats ? Number(llmStats.count || 0) : 0;
  const llmMedian = llmStats ? llmStats.p50_ms : 0;

  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Egress Safety</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        Controls how Guardian handles tainted private data when it is about to leave.
      </div>
      <div className="hermes-guardian-sharing-egress-control">
        <select
          className="hermes-guardian-select"
          value={props.egressSafety}
          disabled={props.modeSaving}
          onChange={(event) => props.onChangeEgressSafety(event.target.value)}
        >
          {MODE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label + " - " + option.consequence}
            </option>
          ))}
        </select>
      </div>

      {props.egressSafety === "llm" ? (
        <div className="hermes-guardian-sharing-egress-llm">
          <div className="hermes-guardian-card-title">Authorization context</div>
          <div className="hermes-guardian-muted hermes-guardian-section-description">
            In llm mode the verifier reads the real action payload to check content against
            intent. These toggles feed it extra authorization evidence.
          </div>
          <div className="hermes-guardian-grid">
            <label className="hermes-guardian-check hermes-guardian-security-check">
              <input
                type="checkbox"
                checked={props.llmUserContext}
                disabled={props.userContextSaving}
                onChange={(event) => props.onChangeUserContext(event.target.checked)}
              />
              <span className="hermes-guardian-security-rule-text">
                <span>Owner context</span>
                <span className="hermes-guardian-muted">
                  Give the verifier your recent request as authorization evidence for
                  owner-initiated egress.
                </span>
              </span>
            </label>
            <label className="hermes-guardian-check hermes-guardian-security-check">
              <input
                type="checkbox"
                checked={props.llmCronContext}
                disabled={props.cronContextSaving}
                onChange={(event) => props.onChangeCronContext(event.target.checked)}
              />
              <span className="hermes-guardian-security-rule-text">
                <span>Unattended (cron) context</span>
                <span className="hermes-guardian-muted">
                  Include a cron job's own stored instruction as evidence for that job's egress.
                  High-risk unattended actions always require manual approval.
                </span>
              </span>
            </label>
          </div>
          <div className="hermes-guardian-card-title">Verifier model</div>
          <div className="hermes-guardian-muted">
            Run the verifier on a faster model than the agent's. Options come from this
            plugin's <Mono>allowed_models</Mono>; grant{" "}
            <Mono>plugins.entries.hermes-guardian.llm.allow_model_override</Mono> to populate
            them. Guardian falls back to the default model if an override is rejected.
          </div>
          <div className="hermes-guardian-sharing-egress-control">
            <select
              className="hermes-guardian-select"
              value={props.llmVerifierModel || ""}
              disabled={props.verifierModelSaving}
              onChange={(event) => props.onChangeVerifierModel(event.target.value)}
            >
              <option value="">Default (agent model)</option>
              {verifierModelOptions.map((model) => (
                <option key={model} value={model}>
                  {model}
                </option>
              ))}
            </select>
          </div>
        </div>
      ) : null}

      <div className="hermes-guardian-sharing-egress-scoreboard">
        <div className="hermes-guardian-card-title">Verifier scoreboard</div>
        <div className="hermes-guardian-rule-meta">
          <span>{"Verifier-consulted checks: " + llmCount}</span>
          <span>{"Median verifier latency: " + ms(llmMedian)}</span>
          {props.performance ? (
            <span>{"Window: last " + text(props.performance.window_size) + " checks"}</span>
          ) : null}
        </div>
      </div>
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
                <IconButton
                  icon="trash"
                  label={"Remove trusted destination " + value}
                  disabled={busy}
                  onClick={() => removeTrusted(kind, value)}
                />
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

function EgressToolClassification(props: {
  tools: SharingTool[];
  inventory: ToolInventoryRow[];
  onNewTool: (match?: string) => void;
  onEditTool: (tool: SharingTool) => void;
  onToggleTool: (tool: SharingTool) => void;
  onDeleteTool: (tool: SharingTool) => void;
}) {
  function rowPolicy(row: ToolInventoryRow): SharingTool | null {
    return row.policy ? (row.policy as SharingTool) : null;
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
          <div className="hermes-guardian-card-title">Egress tool classification</div>
          <div className="hermes-guardian-muted">
            Teach Guardian whether a tool sends data: no egress, gate as unknown, or a specific
            action family and destination. Source taints live in Reading.
          </div>
        </div>
      </div>
      {props.inventory.length ? (
        <div className="hermes-guardian-tool-table-wrap">
          <table className="hermes-guardian-tool-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Egress</th>
                <th>Destination</th>
                <th>Observed action</th>
                <th>Policy</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {props.inventory.map((row) => {
                const policy = rowPolicy(row);
                const egress = text(policy && policy.egress, "default");
                const destination = text(policy && policy.destination, "default");
                const observed = (row.observed_egress_families || []).join(", ") || "none";
                const match = rowMatch(row);
                const label = row.row_type === "group"
                  ? match + " (" + Number(row.child_count || 0) + ")"
                  : match;
                const rowClasses = [
                  row.row_type === "group" ? "hermes-guardian-tool-row-group" : "",
                  policy && policy.enabled === false ? "hermes-guardian-rule-disabled" : "",
                ].filter(Boolean).join(" ");
                const createMatch = text(row.match || row.tool_name || row.group);
                return (
                  <tr key={text(row.key, match)} className={rowClasses}>
                    <td>
                      <div
                        className="hermes-guardian-tool-tree-cell"
                        style={{ paddingLeft: String(Math.max(0, Number(row.depth || 0)) * 1.1) + "rem" }}
                      >
                        <Mono>{label}</Mono>
                      </div>
                    </td>
                    <td>
                      <span className="hermes-guardian-pill">
                        {egress === "ignore" ? "No egress" : egress}
                      </span>
                    </td>
                    <td>{destination}</td>
                    <td>{observed}</td>
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
                              label={"Edit egress classification " + text(policy.match)}
                              onClick={() => props.onEditTool(policy)}
                            />
                            <Button variant="secondary" onClick={() => props.onToggleTool(policy)}>
                              {policy.enabled === false ? "Enable" : "Disable"}
                            </Button>
                            <IconButton
                              icon="trash"
                              variant="danger"
                              label={"Delete egress classification " + text(policy.match)}
                              onClick={() => props.onDeleteTool(policy)}
                            />
                          </>
                        ) : (
                          <Button variant="secondary" onClick={() => props.onNewTool(createMatch)}>
                            Set policy
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
        <div className="hermes-guardian-muted">No tools seen yet.</div>
      )}
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
          <IconButton
            icon="chevron-left"
            disabled={index === 0}
            label={"Move rule " + (index + 1) + " left"}
            onClick={() => onMoveRule(rule, "up")}
          />
          <IconButton
            icon="chevron-right"
            disabled={index === total - 1}
            label={"Move rule " + (index + 1) + " right"}
            onClick={() => onMoveRule(rule, "down")}
          />
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
        <IconButton
          icon="eye"
          disabled={impactBusy}
          label={"Preview impact for rule " + (index + 1)}
          onClick={previewImpact}
        />
        <IconButton
          icon="edit"
          label={"Edit rule " + (index + 1)}
          onClick={() => onEditRule(rule)}
        />
        <Button
          variant="secondary"
          title={rule.enabled === false ? "Enable rule" : "Disable rule"}
          aria-label={(rule.enabled === false ? "Enable" : "Disable") + " rule " + (index + 1)}
          className="hermes-guardian-rule-toggle-button"
          onClick={() => onPatchRule(ruleId, { enabled: !rule.enabled })}
        >
          {rule.enabled === false ? "Enable" : "Disable"}
        </Button>
        <IconButton
          icon="trash"
          variant="danger"
          label={"Delete rule " + (index + 1)}
          onClick={() => onDeleteRule(ruleId)}
        />
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
  const [selectedSubtype, setSelectedSubtype] = useState("");
  const sharing = (data && data.outward_sharing) || {};
  const sharingBuiltin = sharing.builtin || [];
  const sharingExtra = sharing.extra || [];
  const configured = new Set([...sharingBuiltin, ...sharingExtra]);
  const sharingSuggestions = (sharing.suggestions || []).filter((item) => item && !configured.has(item));
  const addSelectedSubtype = () => {
    if (!selectedSubtype) return;
    addSharing(selectedSubtype);
    setSelectedSubtype("");
  };
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-head">
        <div>
          <div className="hermes-guardian-card-title">Outward sharing</div>
          <div className="hermes-guardian-muted">
            Action names that mean "this reaches someone else" even when the destination store is
            yours. When a tool call looks like one of these actions, Guardian treats it as an
            external boundary crossing and asks for review unless a trusted destination or rule
            covers it.
          </div>
        </div>
      </div>
      <div className="hermes-guardian-dest-group">
        <div className="hermes-guardian-dest-group-title">
          Built-in sharing actions (always external — cannot be disabled)
        </div>
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">
          These catch common verbs such as sharing a document, inviting a collaborator, publishing
          a page, or making something public.
        </div>
        <div className="hermes-guardian-chips">
          {sharingBuiltin.map((subtype) => (
            <span key={subtype} className="hermes-guardian-pill hermes-guardian-trust-external">
              {subtype}
            </span>
          ))}
        </div>
      </div>
      <div className="hermes-guardian-dest-group">
        <div className="hermes-guardian-dest-group-title">Extra action names</div>
        <div className="hermes-guardian-muted hermes-guardian-dest-empty">
          Add tool-specific verbs here when your apps use another name for outward sharing, for
          example <Mono>crosspost</Mono> or <Mono>send_invite</Mono>.
        </div>
        {sharingExtra.length ? (
          <ul className="hermes-guardian-dest-list">
            {sharingExtra.map((item) => (
              <li key={item} className="hermes-guardian-dest-item">
                <Mono>{item}</Mono>
                <IconButton
                  icon="trash"
                  label={"Remove sharing action " + item}
                  disabled={busy}
                  onClick={() => removeSharing(item)}
                />
              </li>
            ))}
          </ul>
        ) : (
          <div className="hermes-guardian-muted hermes-guardian-dest-empty">
            No extra sharing actions.
          </div>
        )}
        {sharingSuggestions.length ? (
          <div className="hermes-guardian-widget-form hermes-guardian-outward-picker">
            <select
              className="hermes-guardian-select"
              value={selectedSubtype}
              disabled={busy}
              aria-label="Choose a recent outward sharing action name"
              onChange={(event) => setSelectedSubtype(event.target.value)}
            >
              <option value="">Choose from recent action history</option>
              {sharingSuggestions.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <Button
              variant="secondary"
              disabled={busy || !selectedSubtype}
              onClick={addSelectedSubtype}
            >
              Add action name
            </Button>
          </div>
        ) : (
          <div className="hermes-guardian-muted hermes-guardian-dest-empty">
            No recent unconfigured sharing action names found yet.
          </div>
        )}
      </div>
    </div>
  );
}

export function SharingTab(props: SharingTabProps) {
  const {
    controller,
    policy,
    egressSafety,
    modeSaving,
    onChangeEgressSafety,
    llmUserContext,
    llmCronContext,
    userContextSaving,
    cronContextSaving,
    onChangeUserContext,
    onChangeCronContext,
    llmVerifierModel,
    verifierModelSaving,
    onChangeVerifierModel,
    performance,
    rules,
    sharingTools,
    toolInventory,
    onNewRule,
    onEditRule,
    onPatchRule,
    onDeleteRule,
    onMoveRule,
    onNewTool,
    onEditTool,
    onToggleTool,
    onDeleteTool,
  } = props;

  if (controller.loading && !controller.data) {
    return <div className="hermes-guardian-muted">Loading sharing settings...</div>;
  }

  return (
    <div className="hermes-guardian-grid">
      <EgressSafetySettings
        policy={policy}
        egressSafety={egressSafety}
        modeSaving={modeSaving}
        onChangeEgressSafety={onChangeEgressSafety}
        llmUserContext={llmUserContext}
        llmCronContext={llmCronContext}
        userContextSaving={userContextSaving}
        cronContextSaving={cronContextSaving}
        onChangeUserContext={onChangeUserContext}
        onChangeCronContext={onChangeCronContext}
        llmVerifierModel={llmVerifierModel}
        verifierModelSaving={verifierModelSaving}
        onChangeVerifierModel={onChangeVerifierModel}
        performance={performance}
      />

      <TrustedDestinations controller={controller} />

      <EgressToolClassification
        tools={sharingTools}
        inventory={toolInventory}
        onNewTool={onNewTool}
        onEditTool={onEditTool}
        onToggleTool={onToggleTool}
        onDeleteTool={onDeleteTool}
      />

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
