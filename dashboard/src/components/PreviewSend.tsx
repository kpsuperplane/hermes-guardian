import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { TrustPill } from "@/components/TrustPill";
import { previewSend } from "@/api/client";
import { ACTIONS, DEFAULT_PRIVACY_CLASSES } from "@/constants";
import { decisionStepText, text } from "@/lib/format";
import type { SendPreview } from "@/types";

// "Preview a send" widget (Sharing, doc 02 §Tab3 / charter §5). Calls the
// read-only GET /sharing/preview, which runs the pure decide_with_step on a
// hypothetical capability — which step fires and the outcome.
const PREVIEW_ACTIONS = ACTIONS.filter((action) => action !== "*");

export function PreviewSend() {
  const [action, setAction] = useState("message_send");
  const [destination, setDestination] = useState("");
  const [dataClass, setDataClass] = useState(DEFAULT_PRIVACY_CLASSES[0] || "email");
  const [result, setResult] = useState<SendPreview | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const run = () => {
    const dest = destination.trim();
    if (!dest) return;
    setBusy(true);
    setError("");
    previewSend(action, dest, [dataClass])
      .then((payload: SendPreview) => setResult(payload || null))
      .catch((err: unknown) => {
        setResult(null);
        setError(String((err as Error)?.message || err));
      })
      .finally(() => setBusy(false));
  };

  const decision = text(result && result.decision);
  const decisionClass =
    decision === "allow"
      ? "hermes-guardian-trust-self"
      : decision === "block"
        ? "hermes-guardian-trust-external"
        : "";

  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Preview a send</div>
      <div className="hermes-guardian-muted">
        Try a hypothetical action + destination + data class and see which decide() step fires and
        the outcome. Read-only — it changes nothing.
      </div>
      <div className="hermes-guardian-widget-form">
        <select
          className="hermes-guardian-select"
          value={action}
          disabled={busy}
          onChange={(event) => setAction(event.target.value)}
        >
          {PREVIEW_ACTIONS.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <input
          className="hermes-guardian-input"
          type="text"
          value={destination}
          placeholder="stranger@example.com or host:example.com"
          disabled={busy}
          onChange={(event) => setDestination(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") run();
          }}
        />
        <select
          className="hermes-guardian-select"
          value={dataClass}
          disabled={busy}
          onChange={(event) => setDataClass(event.target.value)}
        >
          {DEFAULT_PRIVACY_CLASSES.map((cls) => (
            <option key={cls} value={cls}>
              {cls}
            </option>
          ))}
        </select>
        <Button variant="secondary" disabled={busy} onClick={run}>
          Preview
        </Button>
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      {result ? (
        <div className="hermes-guardian-rule-meta hermes-guardian-widget-result">
          <span className="hermes-guardian-dest-seen-label">
            destination <TrustPill trust={result.destination_trust} />
          </span>
          <span className={"hermes-guardian-pill " + decisionClass}>{decision || "n/a"}</span>
          <span>{decisionStepText(result.decision_step)}</span>
        </div>
      ) : null}
    </div>
  );
}
