import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { TrustPill } from "@/components/TrustPill";
import { HISTORY_PAGE_SIZES } from "@/constants";
import { decisionStepText, text, timeText } from "@/lib/format";
import type { ActivityRow } from "@/types";

export interface HistoryTabProps {
  activity: ActivityRow[];
  loading: boolean;
  error: string;
  total: number;
  page: number;
  pageSize: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
}

function historyTargetCell(row: ActivityRow) {
  const tool = text(row.tool_name || row.tool, "n/a");
  const action = text(row.action_family, "n/a");
  const destination = text(row.destination, "n/a");
  const purpose = text(row.purpose);
  const recipient = text(row.recipient_identity);
  // Reads taint the session but never egress, so destination trust isn't meaningful
  // for them — only show the pill on outbound (non-read) rows.
  const isRead = text(row.decision) === "read" || text(row.decision) === "tainted";
  return (
    <div className="hermes-guardian-history-target">
      <div className="hermes-guardian-history-tool">{tool}</div>
      <div className="hermes-guardian-history-route">
        {action + " -> " + destination}
        {!isRead && row.destination_trust ? <TrustPill trust={row.destination_trust} /> : null}
      </div>
      {purpose || recipient ? (
        <div className="hermes-guardian-muted">
          {"purpose " + text(purpose, "unknown") + " recipient " + text(recipient, "none")}
        </div>
      ) : null}
    </div>
  );
}

function historyReasonCell(row: ActivityRow): React.ReactNode {
  const full = text(row.reason || row.reason_short);
  const short = text(row.reason_short || row.reason);
  const step = decisionStepText(row.decision_step);
  const reason =
    !full || full === short ? (
      full
    ) : (
      <details className="hermes-guardian-history-reason" title={full}>
        <summary>{short}</summary>
        <div className="hermes-guardian-history-reason-full">{full}</div>
      </details>
    );
  if (!step) return reason;
  return (
    <div className="hermes-guardian-history-reason-cell">
      <div>{reason}</div>
      <div className="hermes-guardian-muted" title="Which decide() step produced this outcome">
        {step}
      </div>
    </div>
  );
}

export function HistoryTab({
  activity,
  loading,
  error,
  total,
  page,
  pageSize,
  setPage,
  setPageSize,
}: HistoryTabProps) {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, totalPages - 1);
  const start = total ? currentPage * pageSize + 1 : 0;
  const end = total ? Math.min(total, (currentPage + 1) * pageSize) : 0;
  return (
    <div className="hermes-guardian-grid">
      <div className="hermes-guardian-history-toolbar">
        <div className="hermes-guardian-muted">
          {loading
            ? "Loading history..."
            : total
              ? "Showing " + start + "-" + end + " of " + total
              : "No history yet."}
        </div>
        <div className="hermes-guardian-actions">
          <select
            className="hermes-guardian-select"
            value={pageSize}
            onChange={(event) => {
              setPageSize(Number(event.target.value));
              setPage(0);
            }}
          >
            {HISTORY_PAGE_SIZES.map((size) => (
              <option key={size} value={size}>
                {size + " per page"}
              </option>
            ))}
          </select>
          <Button
            variant="secondary"
            disabled={loading || currentPage <= 0}
            onClick={() => setPage(Math.max(0, currentPage - 1))}
          >
            Previous
          </Button>
          <Button
            variant="secondary"
            disabled={loading || currentPage >= totalPages - 1}
            onClick={() => setPage(currentPage + 1)}
          >
            Next
          </Button>
        </div>
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      <div className="hermes-guardian-table-wrap">
        <table className="hermes-guardian-table">
          <colgroup>
            <col className="hermes-guardian-history-status-col" />
            <col className="hermes-guardian-history-time-col" />
            <col className="hermes-guardian-history-target-col" />
            <col className="hermes-guardian-history-taints-col" />
            <col className="hermes-guardian-history-reason-col" />
          </colgroup>
          <thead>
            <tr>
              {["Status", "Time", "Tool / route", "Taints", "Reason"].map((label) => (
                <th key={label}>{label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {activity.length ? (
              activity.map((row, index) => (
                <tr key={row.id || index}>
                  <td>{text(row.decision)}</td>
                  <td>{text(row.time, timeText(row.ts))}</td>
                  <td>{historyTargetCell(row)}</td>
                  <td>{text(row.data_classes)}</td>
                  <td>{historyReasonCell(row)}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="hermes-guardian-muted">
                  {loading ? "Loading history..." : "No history yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
