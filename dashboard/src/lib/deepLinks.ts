// Decision-step deep links (charter §01.5, doc 02 §Deep links).
//
// A gated Activity row's decision_step is rendered as a sequence of clauses,
// each linking to the tab that governs it. This pure parser maps an engine
// decision_step label to an ordered list of clause segments; each segment is
// either plain text or a link carrying a target tab id. Unknown clauses render
// as plain text (resilient by design — a future step never breaks the row).

export type TabId = "activity" | "whats-yours" | "sharing" | "review" | "protection";

export interface DeepLinkSegment {
  text: string;
  tab?: TabId; // present => render as a link that switches to this tab
}

// Maps a normalized decision_step base label (the part before any ":rule_id")
// to its ordered, deep-linked explanation. Each clause names the governing tab.
function segmentsForStep(base: string): DeepLinkSegment[] | null {
  if (base === "step1_read") {
    return [{ text: "read — taints the session, never an egress" }];
  }
  if (base.indexOf("step3_intra_boundary_") === 0) {
    const where = base.slice("step3_intra_boundary_".length).replace(/_/g, " ") || "owned";
    return [
      { text: "stays with you (" + where + ")", tab: "whats-yours" },
      { text: " → allowed" },
    ];
  }
  if (base === "step4_no_private_taint") {
    return [{ text: "no private data in scope → allowed" }];
  }
  if (base === "step5_allow_rule") {
    return [
      { text: "matched an allow rule", tab: "sharing" },
      { text: " → allowed" },
    ];
  }
  if (base === "step5_deny_rule") {
    return [
      { text: "matched a deny rule", tab: "sharing" },
      { text: " → blocked" },
    ];
  }
  if (base === "step6_approve_external") {
    return [
      { text: "destination = external", tab: "whats-yours" },
      { text: " → no matching rule", tab: "sharing" },
      { text: " → approval required", tab: "review" },
    ];
  }
  if (base === "step6_approve_unknown_as_external") {
    return [
      { text: "destination = unknown (treated as external)", tab: "whats-yours" },
      { text: " → no matching rule", tab: "sharing" },
      { text: " → approval required", tab: "review" },
    ];
  }
  return null;
}

// Public: turn a raw decision_step label into deep-linked segments. Unknown
// labels fall back to a single plain-text segment (de-snaked), never a link.
export function decisionStepSegments(step: unknown): DeepLinkSegment[] {
  const raw = step == null ? "" : String(step);
  if (!raw) return [];
  const base = raw.split(":")[0];
  const known = segmentsForStep(base);
  if (known) return known;
  // Resilient fallback: render the unknown clause as plain text only.
  const fallback = base.replace(/^step\d+_/, "").replace(/_/g, " ");
  return [{ text: fallback }];
}
