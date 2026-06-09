import { useCallback, useState } from "@/sdk";
import { api } from "@/api/client";
import { HISTORY_PAGE_SIZES } from "@/constants";
import type { ActivityRow, HistoryResponse } from "@/types";

export interface HistoryController {
  activity: ActivityRow[];
  page: number;
  setPage: (page: number) => void;
  pageSize: number;
  setPageSize: (size: number) => void;
  total: number;
  loading: boolean;
  error: string;
  loadHistory: (page: number, pageSize: number) => Promise<void>;
}

// Paginated activity history backed by the DataTables endpoint. The effect that
// triggers loadHistory when the active tab/page changes lives in GuardianPage,
// since it depends on which tab is showing.
export function useHistory(): HistoryController {
  const [activity, setActivity] = useState<ActivityRow[]>([]);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(25);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadHistory = useCallback((nextPage: number, nextPageSize: number) => {
    const safePage = Math.max(0, Math.trunc(Number(nextPage) || 0));
    const safeSize =
      HISTORY_PAGE_SIZES.indexOf(Number(nextPageSize)) >= 0 ? Number(nextPageSize) : 25;
    const start = safePage * safeSize;
    setLoading(true);
    setError("");
    return api(
      "/activity/datatables?draw=1&start=" +
        encodeURIComponent(start) +
        "&length=" +
        encodeURIComponent(safeSize),
    )
      .then((payload: HistoryResponse) => {
        setActivity(payload.data || []);
        setTotal(Number(payload.recordsFiltered || payload.recordsTotal || 0));
      })
      .catch((err: unknown) => {
        setActivity([]);
        setTotal(0);
        setError(String((err as Error)?.message || err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  return {
    activity,
    page,
    setPage,
    pageSize,
    setPageSize,
    total,
    loading,
    error,
    loadHistory,
  };
}
