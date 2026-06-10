import { useCallback, useEffect, useState } from "@/sdk";
import {
  addSelfDestination,
  addSharingSubtype,
  addTrustedRecipient,
  getDestinations,
  removeSelfDestination,
  removeSharingSubtype,
  removeTrustedRecipient,
} from "@/api/client";
import type { DestinationsSummary } from "@/types";

type ShowToast = (message?: unknown, variant?: "success" | "error") => void;

export interface DestinationsController {
  data: DestinationsSummary | null;
  loading: boolean;
  error: string;
  busy: boolean;
  refetch: () => Promise<void>;
  addSelf: (kind: string, value: string, confirmText?: string) => void;
  removeSelf: (kind: string, value: string) => void;
  addTrusted: (identity: string, classes?: string, note?: string) => void;
  removeTrusted: (identity: string) => void;
  addSharing: (subtype: string) => void;
  removeSharing: (subtype: string) => void;
}

function errText(err: unknown): string {
  return String((err as Error)?.message || err);
}

// Destination-trust edits are security-relevant (they change what counts as "yours"),
// so every mutation confirms first — mirroring the cron-context toggle's window.confirm
// gate — and the backend independently requires the confirmation token (defense in depth).
export function useDestinations(showToast: ShowToast): DestinationsController {
  const [data, setData] = useState<DestinationsSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const refetch = useCallback(() => {
    setLoading(true);
    setError("");
    return getDestinations()
      .then((value: DestinationsSummary) => {
        setData(value || null);
      })
      .catch((err: unknown) => {
        setError(errText(err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    refetch();
  }, [refetch]);

  const run = useCallback(
    (confirmMessage: string, action: () => Promise<any>) => {
      if (!window.confirm(confirmMessage)) return;
      setBusy(true);
      action()
        .then((payload: any) => {
          showToast(payload && payload.message ? payload.message : "Saved.");
          return refetch();
        })
        .catch((err: unknown) => {
          showToast(errText(err), "error");
        })
        .finally(() => setBusy(false));
    },
    [refetch, showToast],
  );

  const addSelf = useCallback(
    (kind: string, value: string, confirmText?: string) => {
      run(
        confirmText ||
          'Add "' +
            value +
            '" to your self-allowlist? Writes there will no longer be gated as a boundary crossing.',
        () => addSelfDestination(kind, value),
      );
    },
    [run],
  );

  const removeSelf = useCallback(
    (kind: string, value: string) => {
      run('Remove "' + value + '" from your self-allowlist?', () =>
        removeSelfDestination(kind, value),
      );
    },
    [run],
  );

  const addTrusted = useCallback(
    (identity: string, classes?: string, note?: string) => {
      run(
        'Declare "' + identity + '" a trusted recipient? Private data may be shared with them.',
        () => addTrustedRecipient(identity, classes, note),
      );
    },
    [run],
  );

  const removeTrusted = useCallback(
    (identity: string) => {
      run('Remove trusted recipient "' + identity + '"?', () => removeTrustedRecipient(identity));
    },
    [run],
  );

  const addSharing = useCallback(
    (subtype: string) => {
      run('Add "' + subtype + '" as an outward-sharing action (always treated as external)?', () =>
        addSharingSubtype(subtype),
      );
    },
    [run],
  );

  const removeSharing = useCallback(
    (subtype: string) => {
      run('Remove the extra outward-sharing action "' + subtype + '"?', () =>
        removeSharingSubtype(subtype),
      );
    },
    [run],
  );

  return {
    data,
    loading,
    error,
    busy,
    refetch,
    addSelf,
    removeSelf,
    addTrusted,
    removeTrusted,
    addSharing,
    removeSharing,
  };
}
