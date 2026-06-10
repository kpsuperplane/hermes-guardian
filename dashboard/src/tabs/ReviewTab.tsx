import { React } from "@/sdk";
import { Mono } from "@/components/Mono";
import { text } from "@/lib/format";
import type { Performance, Policy } from "@/types";

// Mode options written as who-reviews sentences (doc 02 §Tab4.1). Values are the
// existing privacy.mode values, unchanged.
const MODE_OPTIONS: Array<{ value: string; label: string; consequence: string }> = [
  {
    value: "llm",
    label: "llm",
    consequence: "The verifier pre-screens; you see only genuine boundary crossings.",
  },
  {
    value: "strict",
    label: "strict",
    consequence: "You review every outbound action yourself.",
  },
  {
    value: "read-only",
    label: "read-only",
    consequence: "Nothing outward is auto-allowed.",
  },
  {
    value: "off",
    label: "off",
    consequence: "Kill switch — privacy egress checks off (security filtering still runs).",
  },
];

const UNKNOWN_TOOL_MODES = ["gate", "allow"];

export interface ReviewTabProps {
  policy: Policy | null;
  privacyMode: string;
  modeSaving: boolean;
  onChangePrivacyMode: (mode: string) => void;
  llmUserContext: boolean;
  llmCronContext: boolean;
  userContextSaving: boolean;
  cronContextSaving: boolean;
  onChangeUserContext: (enabled: boolean) => void;
  onChangeCronContext: (enabled: boolean) => void;
  llmVerifierModel: string;
  verifierModelSaving: boolean;
  onChangeVerifierModel: (model: string) => void;
  unknownTools: string;
  unknownToolsSaving: boolean;
  onChangeUnknownTools: (mode: string) => void;
  performance: Performance | null;
}

function ms(value: number): string {
  return (Number(value) || 0).toFixed(0) + " ms";
}

export function ReviewTab(props: ReviewTabProps) {
  const {
    policy,
    privacyMode,
    modeSaving,
    onChangePrivacyMode,
    llmUserContext,
    llmCronContext,
    userContextSaving,
    cronContextSaving,
    onChangeUserContext,
    onChangeCronContext,
    llmVerifierModel,
    verifierModelSaving,
    onChangeVerifierModel,
    unknownTools,
    unknownToolsSaving,
    onChangeUnknownTools,
    performance,
  } = props;

  const verifierModelOptions = (policy && policy.llm_verifier_model_options) || [];
  const currentMode = MODE_OPTIONS.find((option) => option.value === privacyMode);

  // Verifier scoreboard (doc 02 §Tab4.6) derived from the timing summary.
  const llmStats = performance && performance.llm;
  const llmCount = llmStats ? Number(llmStats.count || 0) : 0;
  const llmMedian = llmStats ? llmStats.p50_ms : 0;

  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Who reviews outbound actions</div>
        <div className="hermes-guardian-muted">
          {currentMode ? currentMode.consequence : "Security filtering runs in every mode."}
        </div>
        <div className="hermes-guardian-review-control">
          <select
            className="hermes-guardian-select"
            value={privacyMode}
            disabled={modeSaving}
            onChange={(event) => onChangePrivacyMode(event.target.value)}
          >
            {MODE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label + " — " + option.consequence}
              </option>
            ))}
          </select>
        </div>
      </div>

      {privacyMode === "llm" ? (
        <div className="hermes-guardian-card">
          <div className="hermes-guardian-card-title">Authorization context</div>
          <div className="hermes-guardian-muted hermes-guardian-section-description">
            In llm mode the verifier reads the real action payload (the same model Hermes runs as
            the agent) to check content against intent. The toggles below feed it extra
            authorization evidence.
          </div>
          <div className="hermes-guardian-grid">
            <label className="hermes-guardian-check hermes-guardian-security-check">
              <input
                type="checkbox"
                checked={llmUserContext}
                disabled={userContextSaving}
                onChange={(event) => onChangeUserContext(event.target.checked)}
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
                checked={llmCronContext}
                disabled={cronContextSaving}
                onChange={(event) => onChangeCronContext(event.target.checked)}
              />
              <span className="hermes-guardian-security-rule-text">
                <span>Unattended (cron) context</span>
                <span className="hermes-guardian-muted">
                  Include a cron job's own stored instruction as evidence for that job's egress.
                  High-risk unattended actions are always downgraded to manual approval regardless.
                  Off by default.
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
          <div className="hermes-guardian-review-control">
            <select
              className="hermes-guardian-select"
              value={llmVerifierModel || ""}
              disabled={verifierModelSaving}
              onChange={(event) => onChangeVerifierModel(event.target.value)}
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

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Unknown tools</div>
        <div className="hermes-guardian-muted">
          What happens when Guardian doesn't recognize a tool. Unrecognized tools are gated
          under taint by default; 'allow' restores the legacy permissive behavior and is not
          recommended.
        </div>
        <div className="hermes-guardian-review-control">
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

      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Verifier scoreboard</div>
        <div className="hermes-guardian-muted hermes-guardian-section-description">
          How the llm verifier is performing, from the recorded timing samples.
        </div>
        <div className="hermes-guardian-rule-meta">
          <span>{"Verifier-consulted checks: " + llmCount}</span>
          <span>{"Median verifier latency: " + ms(llmMedian)}</span>
          {performance ? (
            <span>{"Window: last " + text(performance.window_size) + " checks"}</span>
          ) : null}
        </div>
      </div>
    </div>
  );
}
