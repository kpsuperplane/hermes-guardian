import { useCallback, useState } from "@/sdk";
import { api } from "@/api/client";
import type { Performance } from "@/types";

export interface PerformanceController {
  performance: Performance | null;
  loading: boolean;
  error: string;
  loadPerformance: () => Promise<void>;
}

// Fetches the per-check timing summary. Loaded when the Performance tab opens
// (and on Refresh), mirroring how useHistory is driven from GuardianPage.
export function usePerformance(): PerformanceController {
  const [performance, setPerformance] = useState<Performance | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadPerformance = useCallback(() => {
    setLoading(true);
    setError("");
    return api("/performance")
      .then((value: Performance) => {
        setPerformance(value);
      })
      .catch((err: unknown) => {
        setError(String((err as Error)?.message || err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return { performance, loading, error, loadPerformance };
}
