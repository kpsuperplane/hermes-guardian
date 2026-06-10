import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { text } from "@/lib/format";
import type { LanguagePack, Policy } from "@/types";

const PRIVACY_MODES = ["llm", "strict", "read-only", "off"];

// One-line consequence for each mode (doc 03 commit 3b). Values are unchanged; this
// is help text only.
const MODE_CONSEQUENCES: Record<string, string> = {
  llm: "Review only genuine boundary crossings (recommended).",
  strict: "Review every outbound action yourself.",
  "read-only": "Block all outbound sharing.",
  off: "Guardian disabled (security filtering still runs).",
};

export interface SettingsTabProps {
  policy: Policy | null;
  privacyMode: string;
  modeSaving: boolean;
  onChangePrivacyMode: (mode: string) => void;
  onGoToDestinations: () => void;
  llmUserContext: boolean;
  llmCronContext: boolean;
  userContextSaving: boolean;
  cronContextSaving: boolean;
  onChangeUserContext: (enabled: boolean) => void;
  onChangeCronContext: (enabled: boolean) => void;
  llmVerifierModel: string;
  verifierModelSaving: boolean;
  onChangeVerifierModel: (model: string) => void;
  onPatchSecurityRule: (ruleId: string, enabled: boolean) => void;
  languagePacksSaving: boolean;
  onPatchLanguagePack: (packId: string, enabled: boolean) => void;
  onSetAllLanguagePacks: (enabled: boolean) => void;
}

export function SettingsTab({
  policy,
  privacyMode,
  modeSaving,
  onChangePrivacyMode,
  onGoToDestinations,
  llmUserContext,
  llmCronContext,
  userContextSaving,
  cronContextSaving,
  onChangeUserContext,
  onChangeCronContext,
  llmVerifierModel,
  verifierModelSaving,
  onChangeVerifierModel,
  onPatchSecurityRule,
  languagePacksSaving,
  onPatchLanguagePack,
  onSetAllLanguagePacks,
}: SettingsTabProps) {
  const verifierModelOptions = (policy && policy.llm_verifier_model_options) || [];
  const securityRules = (policy && policy.security_rules) || [];
  const languagePacks = (policy && policy.language_packs) || [];
  const optionalLanguagePacks = languagePacks.filter((pack) => pack.required !== true);
  const enabledLanguagePacks = languagePacks.filter((pack) => pack.enabled !== false);
  const enabledOptionalLanguagePacks = optionalLanguagePacks.filter(
    (pack) => pack.enabled !== false,
  );
  const allOptionalLanguagePacksEnabled = optionalLanguagePacks.length
    ? enabledOptionalLanguagePacks.length === optionalLanguagePacks.length
    : true;
  const languagePackSummary =
    enabledLanguagePacks.length + " of " + languagePacks.length + " enabled";

  const trust = (policy && policy.destination_trust) || {};
  const trustSelf = trust.self || {};
  const yoursSummary =
    (trustSelf.destinations || []).length +
    " stores · " +
    (trustSelf.identities || []).length +
    " identities · " +
    (trustSelf.hosts || []).length +
    " hosts · " +
    ((trust.trusted_recipients || []).length) +
    " trusted";

  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">What's yours</div>
            <div className="hermes-guardian-muted">
              The destinations Guardian treats as you — writes there are never gated. Anything
              it can't confirm is yours is treated as someone else.
            </div>
            <div className="hermes-guardian-rule-meta">
              <span>{yoursSummary}</span>
            </div>
          </div>
          <div className="hermes-guardian-actions">
            <Button variant="secondary" onClick={onGoToDestinations}>
              Manage in Destinations & Trust
            </Button>
          </div>
        </div>
      </div>
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">What happens when data leaves you</div>
            <div className="hermes-guardian-muted">
              {MODE_CONSEQUENCES[privacyMode] || "Security filtering runs in every mode."}
            </div>
          </div>
          <div className="hermes-guardian-actions">
            <select
              className="hermes-guardian-select"
              value={privacyMode}
              disabled={modeSaving}
              onChange={(event) => onChangePrivacyMode(event.target.value)}
            >
              {PRIVACY_MODES.map((mode) => (
                <option key={mode} value={mode}>
                  {mode + " — " + (MODE_CONSEQUENCES[mode] || "")}
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>
      <details className="hermes-guardian-advanced">
        <summary>Advanced</summary>
        <div className="hermes-guardian-grid hermes-guardian-advanced-body">
      {privacyMode === "llm" ? (
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">LLM approval context</div>
        <div className="hermes-guardian-muted hermes-guardian-section-description">
          In llm mode, the verifier reads the real action payload (the same model
          Hermes already runs as the agent) so it can check content against intent;
          security-sensitive content is still stripped and stored rationales are
          sanitized. This assumes the verifier LLM shares the agent's trust boundary.
          The settings below feed it authorization evidence; high-risk cron egress
          always still requires manual approval, even with cron context on.
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
              <span>User prompt context</span>
              <span className="hermes-guardian-muted">
                Include an authenticated owner's most recent request as authorization
                evidence for owner-initiated egress.
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
              <span>Cron context</span>
              <span className="hermes-guardian-muted">
                Include a cron job's own stored instruction as authorization evidence
                for that job's egress. Off by default.
              </span>
            </span>
          </label>
        </div>
        <div className="hermes-guardian-card-head">
          <div>
            <div className="hermes-guardian-card-title">Verifier model</div>
            <div className="hermes-guardian-muted">
              Run the verifier on a faster model than the agent's to cut latency.
              Options come from this plugin's <code>allowed_models</code> in your Hermes
              config; grant <code>plugins.entries.hermes-guardian.llm.allow_model_override</code> to
              populate them. Guardian falls back to the default model if an override is rejected.
            </div>
          </div>
          <div className="hermes-guardian-actions">
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
      </div>
      ) : null}
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Security policy</div>
        {securityRules.length ? (
          <div className="hermes-guardian-grid">
            {securityRules.map((rule) => (
              <label
                key={rule.id}
                className="hermes-guardian-check hermes-guardian-security-check"
              >
                <input
                  type="checkbox"
                  checked={rule.enabled !== false}
                  onChange={(event) => onPatchSecurityRule(rule.id, event.target.checked)}
                />
                <span className="hermes-guardian-security-rule-text">
                  <span>{text(rule.label || rule.id)}</span>
                  {rule.description ? (
                    <span className="hermes-guardian-muted">{text(rule.description)}</span>
                  ) : null}
                </span>
              </label>
            ))}
          </div>
        ) : (
          <div className="hermes-guardian-muted">No security policy rules.</div>
        )}
      </div>
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Language packs</div>
        <div className="hermes-guardian-muted hermes-guardian-section-description">
          Language packs extend Guardian detection for security-sensitive phrases, private
          field labels, browser private-context hints, and sensitive links across languages.
        </div>
        {languagePacks.length ? (
          <div className="hermes-guardian-language-grid">
            <label
              key="select-all"
              className={
                "hermes-guardian-language-card hermes-guardian-language-card-all" +
                (allOptionalLanguagePacksEnabled
                  ? " hermes-guardian-language-card-active"
                  : "")
              }
              title={
                allOptionalLanguagePacksEnabled
                  ? "Disable all optional language packs"
                  : "Enable all language packs"
              }
            >
              <input
                type="checkbox"
                checked={allOptionalLanguagePacksEnabled}
                disabled={languagePacksSaving || !optionalLanguagePacks.length}
                onChange={(event) => onSetAllLanguagePacks(event.target.checked)}
              />
              <span className="hermes-guardian-language-card-body">
                <span className="hermes-guardian-language-card-top">
                  <span className="hermes-guardian-language-name">Select all</span>
                  <span className="hermes-guardian-language-code">bulk</span>
                </span>
                <span className="hermes-guardian-muted">{languagePackSummary}</span>
              </span>
            </label>
            {languagePacks.map((pack: LanguagePack) => {
              const enabled = pack.enabled !== false;
              const required = pack.required === true;
              const classes = ["hermes-guardian-language-card"];
              if (enabled) classes.push("hermes-guardian-language-card-active");
              if (required) classes.push("hermes-guardian-language-card-required");
              return (
                <label key={pack.id} className={classes.join(" ")}>
                  <input
                    type="checkbox"
                    checked={enabled}
                    disabled={languagePacksSaving || required}
                    onChange={(event) => onPatchLanguagePack(pack.id, event.target.checked)}
                  />
                  <span className="hermes-guardian-language-card-body">
                    <span className="hermes-guardian-language-card-top">
                      <span className="hermes-guardian-language-name">
                        {text(pack.name || pack.id)}
                      </span>
                      <span className="hermes-guardian-language-code">
                        {text(pack.id) + (required ? " · required" : "")}
                      </span>
                    </span>
                    <span className="hermes-guardian-muted">
                      {required ? "Always on" : enabled ? "Enabled" : "Disabled"}
                    </span>
                  </span>
                </label>
              );
            })}
          </div>
        ) : (
          <div className="hermes-guardian-muted">No language packs.</div>
        )}
      </div>
      <div className="hermes-guardian-card">
        <div className="hermes-guardian-card-title">Runtime</div>
        <div className="hermes-guardian-rule-meta">
          <span>{"Rows " + text(policy && policy.activity_max_rows)}</span>
          <span>
            {"Retention " + text(policy && policy.activity_retention_days) + " days"}
          </span>
          <span>
            {"Grouping " + text(policy && policy.activity_group_seconds) + " seconds"}
          </span>
        </div>
      </div>
        </div>
      </details>
    </div>
  );
}
