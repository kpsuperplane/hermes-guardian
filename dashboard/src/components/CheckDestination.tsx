import { React, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { TrustPill } from "@/components/TrustPill";
import { resolveDestination } from "@/api/client";
import { text } from "@/lib/format";
import type { DestinationResolution } from "@/types";

// "Check a destination" widget (What's Yours, doc 02 §Tab2 / charter §5).
// Calls the read-only GET /destinations/resolve, which runs the engine's pure
// resolve_destination_trust with a hypothetical destination/recipient.
export function CheckDestination() {
  const [value, setValue] = useState("");
  const [result, setResult] = useState<DestinationResolution | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const check = () => {
    const trimmed = value.trim();
    if (!trimmed) return;
    setBusy(true);
    setError("");
    resolveDestination(trimmed)
      .then((payload: DestinationResolution) => setResult(payload || null))
      .catch((err: unknown) => {
        setResult(null);
        setError(String((err as Error)?.message || err));
      })
      .finally(() => setBusy(false));
  };

  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Check a destination</div>
      <div className="hermes-guardian-muted">
        Enter a destination (<code>kind:id</code>, e.g. <code>host:myvps.example.com</code>) or a
        recipient (<code>you@example.com</code>) to see how Guardian resolves its trust. Nothing is
        changed.
      </div>
      <div className="hermes-guardian-dest-addrow">
        <input
          className="hermes-guardian-input"
          type="text"
          value={value}
          placeholder="host:example.com or you@example.com"
          disabled={busy}
          onChange={(event) => setValue(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter") check();
          }}
        />
        <Button variant="secondary" disabled={busy} onClick={check}>
          Check
        </Button>
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      {result ? (
        <div className="hermes-guardian-rule-meta hermes-guardian-widget-result">
          <span>
            {text(result.kind, "?") + ":" + text(result.id)}
          </span>
          <span className="hermes-guardian-dest-seen-label">
            resolves to <TrustPill trust={result.trust} />
          </span>
        </div>
      ) : null}
    </div>
  );
}
