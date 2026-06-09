import { useCallback, useEffect, useState } from "@/sdk";
import { api } from "@/api/client";
import type { Policy } from "@/types";

export interface PolicyController {
  policy: Policy | null;
  loading: boolean;
  error: string;
  privacyMode: string;
  setPrivacyMode: (mode: string) => void;
  unknownTools: string;
  setUnknownTools: (mode: string) => void;
  load: () => Promise<void>;
}

// Loads the full policy snapshot and tracks the privacy/unknown-tools modes it
// reports. The mode setters are exposed so the Settings/Tools tabs can apply
// optimistic updates (and roll back on failure).
export function usePolicy(): PolicyController {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [privacyMode, setPrivacyMode] = useState("llm");
  const [unknownTools, setUnknownTools] = useState("gate");

  const load = useCallback(() => {
    setLoading(true);
    setError("");
    return api("/policy")
      .then((value: Policy) => {
        setPolicy(value);
        setPrivacyMode(value.privacy_mode || value.privacy_policy || "llm");
        setUnknownTools(value.unknown_tools || "gate");
      })
      .catch((err: unknown) => {
        setError(String((err as Error)?.message || err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return {
    policy,
    loading,
    error,
    privacyMode,
    setPrivacyMode,
    unknownTools,
    setUnknownTools,
    load,
  };
}
