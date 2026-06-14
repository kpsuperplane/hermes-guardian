import { React } from "@/sdk";
import { text } from "@/lib/format";
import type { LanguagePack, Performance, PerfStats, Policy } from "@/types";

export interface ProtectionTabProps {
  policy: Policy | null;
  onPatchSecurityRule: (ruleId: string, enabled: boolean) => void;
  languagePacksSaving: boolean;
  onPatchLanguagePack: (packId: string, enabled: boolean) => void;
  onSetAllLanguagePacks: (enabled: boolean) => void;
  performance: Performance | null;
  performanceLoading: boolean;
  performanceError: string;
}

function ms(value: number): string {
  return (Number(value) || 0).toFixed(2) + " ms";
}

function StatCard(props: { title: string; subtitle?: string; stats: PerfStats }) {
  const { title, subtitle, stats } = props;
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">{title}</div>
      {subtitle ? (
        <div className="hermes-guardian-muted hermes-guardian-section-description">{subtitle}</div>
      ) : null}
      <div className="hermes-guardian-rule-meta">
        <span>{"checks " + stats.count}</span>
        <span>{"avg " + ms(stats.avg_ms)}</span>
        <span>{"p50 " + ms(stats.p50_ms)}</span>
        <span>{"p95 " + ms(stats.p95_ms)}</span>
        <span>{"max " + ms(stats.max_ms)}</span>
      </div>
    </div>
  );
}

function SecurityRules(props: {
  policy: Policy | null;
  onPatch: (ruleId: string, enabled: boolean) => void;
}) {
  const securityRules = (props.policy && props.policy.security_rules) || [];
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Security policy</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        These run before everything else and apply to every destination, including your own.
      </div>
      {securityRules.length ? (
        <div className="hermes-guardian-grid">
          {securityRules.map((rule) => (
            <label key={rule.id} className="hermes-guardian-check hermes-guardian-security-check">
              <input
                type="checkbox"
                checked={rule.enabled !== false}
                onChange={(event) => props.onPatch(rule.id, event.target.checked)}
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
  );
}

function LanguagePacks(props: {
  policy: Policy | null;
  saving: boolean;
  onPatch: (packId: string, enabled: boolean) => void;
  onSetAll: (enabled: boolean) => void;
}) {
  const languagePacks = (props.policy && props.policy.language_packs) || [];
  const optionalLanguagePacks = languagePacks.filter((pack) => pack.required !== true);
  const enabledLanguagePacks = languagePacks.filter((pack) => pack.enabled !== false);
  const enabledOptional = optionalLanguagePacks.filter((pack) => pack.enabled !== false);
  const allOptionalEnabled = optionalLanguagePacks.length
    ? enabledOptional.length === optionalLanguagePacks.length
    : true;
  const summary = enabledLanguagePacks.length + " of " + languagePacks.length + " enabled";

  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Language packs</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        Language packs extend Guardian detection for security-sensitive phrases, private field
        labels, browser private-context hints, and sensitive links across languages.
      </div>
      {languagePacks.length ? (
        <div className="hermes-guardian-language-grid">
          <label
            key="select-all"
            className={
              "hermes-guardian-language-card hermes-guardian-language-card-all" +
              (allOptionalEnabled ? " hermes-guardian-language-card-active" : "")
            }
            title={allOptionalEnabled ? "Disable all optional language packs" : "Enable all language packs"}
          >
            <input
              type="checkbox"
              checked={allOptionalEnabled}
              disabled={props.saving || !optionalLanguagePacks.length}
              onChange={(event) => props.onSetAll(event.target.checked)}
            />
            <span className="hermes-guardian-language-card-body">
              <span className="hermes-guardian-language-card-top">
                <span className="hermes-guardian-language-name">Select all</span>
                <span className="hermes-guardian-language-code">bulk</span>
              </span>
              <span className="hermes-guardian-muted">{summary}</span>
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
                  disabled={props.saving || required}
                  onChange={(event) => props.onPatch(pack.id, event.target.checked)}
                />
                <span className="hermes-guardian-language-card-body">
                  <span className="hermes-guardian-language-card-top">
                    <span className="hermes-guardian-language-name">{text(pack.name || pack.id)}</span>
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
  );
}

function Retention(props: { policy: Policy | null }) {
  const { policy } = props;
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Retention</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        Activity storage is metadata-only and sanitized (including verifier rationales); raw
        content is never persisted. These caps bound how much is kept at rest.
      </div>
      <div className="hermes-guardian-rule-meta">
        <span>{"Max rows " + text(policy && policy.activity_max_rows)}</span>
        <span>{"Max age " + text(policy && policy.activity_retention_days) + " days"}</span>
        <span>{"Grouping " + text(policy && policy.activity_group_seconds) + " seconds"}</span>
      </div>
    </div>
  );
}

function Diagnostics(props: {
  performance: Performance | null;
  loading: boolean;
  error: string;
}) {
  const { performance, loading, error } = props;
  const byHook = (performance && performance.by_hook) || [];
  const windowSize = (performance && performance.window_size) || 0;
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Diagnostics</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        {loading
          ? "Loading diagnostics..."
          : "Overhead Guardian adds per check, over the last " +
            windowSize +
            " checks. Deterministic checks are sub-millisecond; the LLM verifier dominates when consulted."}
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      {performance ? (
        <React.Fragment>
          <div className="hermes-guardian-grid">
            <StatCard title="Overall" stats={performance.overall} />
            <StatCard
              title="LLM verifier"
              subtitle="Checks that consulted the model (network-bound)."
              stats={performance.llm}
            />
            <StatCard
              title="Deterministic"
              subtitle="Checks decided locally, without the model."
              stats={performance.deterministic}
            />
          </div>
          <div className="hermes-guardian-table-wrap">
            <table className="hermes-guardian-table">
              <thead>
                <tr>
                  {["Check", "Count", "Avg", "p50", "p95", "Max", "Total"].map((label) => (
                    <th key={label}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {byHook.length ? (
                  byHook.map((hook) => (
                    <tr key={hook.hook}>
                      <td>{text(hook.label || hook.hook)}</td>
                      <td>{hook.count}</td>
                      <td>{ms(hook.avg_ms)}</td>
                      <td>{ms(hook.p50_ms)}</td>
                      <td>{ms(hook.p95_ms)}</td>
                      <td>{ms(hook.max_ms)}</td>
                      <td>{ms(hook.total_ms)}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={7} className="hermes-guardian-muted">
                      No checks recorded yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </React.Fragment>
      ) : (
        <div className="hermes-guardian-muted">
          {loading ? "Loading..." : "No diagnostics data yet."}
        </div>
      )}
    </div>
  );
}

export function ProtectionTab(props: ProtectionTabProps) {
  return (
    <div className="hermes-guardian-grid">
      <SecurityRules policy={props.policy} onPatch={props.onPatchSecurityRule} />
      <LanguagePacks
        policy={props.policy}
        saving={props.languagePacksSaving}
        onPatch={props.onPatchLanguagePack}
        onSetAll={props.onSetAllLanguagePacks}
      />
      <Retention policy={props.policy} />
      <Diagnostics
        performance={props.performance}
        loading={props.performanceLoading}
        error={props.performanceError}
      />
    </div>
  );
}
