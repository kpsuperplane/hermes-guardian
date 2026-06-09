import { React } from "@/sdk";
import { text } from "@/lib/format";
import type { PerfStats, Performance } from "@/types";

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

export interface PerformanceTabProps {
  performance: Performance | null;
  loading: boolean;
  error: string;
}

export function PerformanceTab({ performance, loading, error }: PerformanceTabProps) {
  const byHook = (performance && performance.by_hook) || [];
  const windowSize = (performance && performance.window_size) || 0;

  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        {loading
          ? "Loading performance..."
          : "Overhead Guardian adds per check, over the last " +
            windowSize +
            " checks. Deterministic checks are sub-millisecond; the LLM verifier dominates when it is consulted. Use Refresh at the top to update."}
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
          <div className="hermes-guardian-card">
            <div className="hermes-guardian-card-title">By check type</div>
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
          </div>
        </React.Fragment>
      ) : (
        <div className="hermes-guardian-muted">
          {loading ? "Loading..." : "No performance data yet."}
        </div>
      )}
    </div>
  );
}
