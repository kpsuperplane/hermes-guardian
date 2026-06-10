import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { Mono } from "@/components/Mono";
import { sharingImpact } from "@/api/client";
import { classesText, text, timeText } from "@/lib/format";
import type { ImpactPreview as ImpactPreviewData } from "@/types";

export interface ImpactPreviewProps {
  // A candidate rule payload ({ effect, match: {...} }). When null, the widget
  // shows nothing actionable (used before a form has a usable candidate).
  candidate: Record<string, unknown> | null;
  // Optional label for the trigger button.
  label?: string;
}

// "Impact preview" (Sharing, doc 02 §Tab3 / charter §5). The over-permissiveness
// guardrail: replays recent stored activity against a candidate rule through the
// read-only POST /sharing/impact and lists the historical rows the rule would
// have changed. Computes only — no mutation.
export function ImpactPreview({ candidate, label }: ImpactPreviewProps) {
  const [result, setResult] = useState<ImpactPreviewData | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const run = () => {
    if (!candidate) return;
    setBusy(true);
    setError("");
    sharingImpact(candidate)
      .then((payload: ImpactPreviewData) => setResult(payload || null))
      .catch((err: unknown) => {
        setResult(null);
        setError(String((err as Error)?.message || err));
      })
      .finally(() => setBusy(false));
  };

  const count = result ? Number(result.matched_count || 0) : 0;
  const verb = (result && result.verb) || "covered";

  return (
    <div className="hermes-guardian-impact">
      <div className="hermes-guardian-impact-head">
        <Button variant="secondary" disabled={busy || !candidate} onClick={run}>
          {label || "Preview impact"}
        </Button>
        {result ? (
          <span className="hermes-guardian-muted">
            {"This would have " +
              verb +
              " " +
              count +
              " of the last " +
              Number(result.considered || 0) +
              " recorded actions."}
          </span>
        ) : null}
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      {result && count ? (
        <ul className="hermes-guardian-dest-list hermes-guardian-impact-list">
          {(result.matched || []).map((row, index) => (
            <li key={text(row.id) + ":" + index} className="hermes-guardian-dest-item">
              <span className="hermes-guardian-dest-seen-label">
                <span className="hermes-guardian-pill">{text(row.decision)}</span>
                <Mono>{text(row.action_family) + " -> " + text(row.destination)}</Mono>
                <span className="hermes-guardian-muted">{classesText(row.data_classes)}</span>
              </span>
              <span className="hermes-guardian-muted">{timeText(row.created_at)}</span>
            </li>
          ))}
        </ul>
      ) : result ? (
        <div className="hermes-guardian-muted">
          No recent actions would have been affected by this rule.
        </div>
      ) : null}
    </div>
  );
}
