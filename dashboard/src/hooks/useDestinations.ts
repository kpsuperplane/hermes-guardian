import { useCallback, useEffect, useState } from "@/sdk";
import {
  addSelfDestination,
  addSharingSubtype,
  addTrustedCommand,
  addTrustedRecipient,
  getDestinations,
  getTrustedCommandSuggestions,
  removeSelfDestination,
  removeSharingSubtype,
  removeTrustedDestination,
} from "@/api/client";
import type { DestinationsSummary, TrustedCommandSuggestion } from "@/types";

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
  addCommand: (value: string, classes?: string, note?: string) => void;
  removeTrusted: (kind: string, value: string) => void;
  addSharing: (subtype: string) => void;
  removeSharing: (subtype: string) => void;
  suggestions: TrustedCommandSuggestion[];
  loadSuggestions: () => Promise<void>;
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
        'Declare "' + identity + '" a trusted destination? Private data may be shared with it.',
        () => addTrustedRecipient(identity, classes, note),
      );
    },
    [run],
  );

  const addCommand = useCallback(
    (value: string, classes?: string, note?: string) => {
      run(
        'Trust the command "' +
          value +
          '"? It will run with reduced egress checks (scoped to the classes you set).',
        () => addTrustedCommand(value, classes, note),
      );
    },
    [run],
  );

  const removeTrusted = useCallback(
    (kind: string, value: string) => {
      run('Remove trusted destination "' + value + '"?', () =>
        removeTrustedDestination(kind, value),
      );
    },
    [run],
  );

  const [suggestions, setSuggestions] = useState<TrustedCommandSuggestion[]>([]);
  const loadSuggestions = useCallback(() => {
    return getTrustedCommandSuggestions()
      .then((value: { suggestions?: TrustedCommandSuggestion[] }) => {
        setSuggestions((value && value.suggestions) || []);
      })
      .catch(() => setSuggestions([]));
  }, []);

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
    addCommand,
    removeTrusted,
    addSharing,
    removeSharing,
    suggestions,
    loadSuggestions,
  };
}
