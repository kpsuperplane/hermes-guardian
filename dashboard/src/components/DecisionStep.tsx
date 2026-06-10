import { React } from "@/sdk";
import { decisionStepSegments } from "@/lib/deepLinks";
import type { TabId } from "@/lib/deepLinks";

export interface DecisionStepProps {
  step: unknown;
  onNavigate: (tab: TabId) => void;
}

// Renders an engine decision_step as deep-linked clauses (charter §01.5). Each
// clause that names a governing tab becomes a button switching to it; unknown
// clauses render as plain text.
export function DecisionStep({ step, onNavigate }: DecisionStepProps) {
  const segments = decisionStepSegments(step);
  if (!segments.length) return null;
  return (
    <span
      className="hermes-guardian-decision-step"
      title="Which decide() step produced this outcome — click a clause to open the tab that governs it"
    >
      {segments.map((segment, index) =>
        segment.tab ? (
          <button
            key={index}
            type="button"
            className="hermes-guardian-deeplink"
            onClick={() => onNavigate(segment.tab as TabId)}
          >
            {segment.text}
          </button>
        ) : (
          <span key={index}>{segment.text}</span>
        ),
      )}
    </span>
  );
}
