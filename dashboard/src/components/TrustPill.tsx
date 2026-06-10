import { React } from "@/sdk";

// Destination-trust levels (doc 01 §2). "Owned" levels reach no new party and read
// calm; trusted_recipient is a soft accent; external/public/unknown are the boundary
// crossings Guardian gates, so they read as a warning. unknown is shown (not hidden)
// on purpose: it means "couldn't confirm this is yours," which is exactly what the
// operator should notice.
const OWNED = new Set(["self", "local_system", "model_provider"]);

const TRUST_LABEL: Record<string, string> = {
  self: "self",
  local_system: "local",
  model_provider: "model",
  trusted_recipient: "trusted",
  external: "external",
  public: "public",
  unknown: "unknown",
};

export function trustLabel(trust?: string): string {
  const t = String(trust || "unknown").toLowerCase();
  return TRUST_LABEL[t] || t;
}

export function trustPillClass(trust: string): string {
  const t = String(trust || "unknown").toLowerCase();
  if (OWNED.has(t)) return "hermes-guardian-trust-owned";
  if (t === "trusted_recipient") return "hermes-guardian-trust-trusted";
  return "hermes-guardian-trust-external";
}

export function TrustPill({ trust }: { trust?: string }) {
  const t = String(trust || "unknown").toLowerCase();
  return (
    <span
      className={"hermes-guardian-pill " + trustPillClass(t)}
      title={"Destination trust: " + t}
    >
      {TRUST_LABEL[t] || t}
    </span>
  );
}
