import { useCallback, useState } from "@/sdk";
import { getApprovals } from "@/api/client";
import type { PendingApproval } from "@/types";

export interface ApprovalsController {
  approvals: PendingApproval[];
  loading: boolean;
  error: string;
  loadApprovals: () => Promise<void>;
}

// Pending-approvals read list for the Activity tab (doc 02 §Tab1). Backed by the
// new read-only GET /approvals, which returns the policy snapshot's "pending"
// slice. Driven from GuardianPage like useHistory / usePerformance.
export function useApprovals(): ApprovalsController {
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadApprovals = useCallback(() => {
    setLoading(true);
    setError("");
    return getApprovals()
      .then((payload: { approvals?: PendingApproval[] }) => {
        setApprovals((payload && payload.approvals) || []);
      })
      .catch((err: unknown) => {
        setApprovals([]);
        setError(String((err as Error)?.message || err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return { approvals, loading, error, loadApprovals };
}
