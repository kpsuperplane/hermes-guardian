import { React, useMemo, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { DecisionStep } from "@/components/DecisionStep";
import { TrustPill } from "@/components/TrustPill";
import { HISTORY_PAGE_SIZES } from "@/constants";
import { classesText, text, timeText } from "@/lib/format";
import type { TabId } from "@/lib/deepLinks";
import type { ActivityRow, PendingApproval } from "@/types";
import type { ApprovalAction } from "@/hooks/useGuardianActions";

export interface ActivityTabProps {
  // Session taint strip
  taint: string[];
  onClearTaint: () => void;
  // Pinned pending approvals (same-screen approve/deny)
  approvals: PendingApproval[];
  approvalsLoading: boolean;
  onApprovalAction: (approval: PendingApproval, action: ApprovalAction) => void;
  // Decided stream (merged blocks + history)
  activity: ActivityRow[];
  loading: boolean;
  error: string;
  total: number;
  page: number;
  pageSize: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
  // Deep-link navigation to the governing tab
  onNavigate: (tab: TabId) => void;
}

// --- Session taint strip (doc 02 §Tab1.1) ------------------------------------
function TaintStrip(props: { taint: string[]; onClear: () => void }) {
  if (!props.taint.length) return null;
  return (
    <div className="hermes-guardian-card hermes-guardian-taint-strip">
      <div>
        <span className="hermes-guardian-card-title">This session carries: </span>
        <span>{props.taint.join(", ")}</span>
      </div>
      <Button variant="secondary" onClick={props.onClear}>
        Clear session taint
      </Button>
    </div>
  );
}

// --- Pinned pending approvals (doc 02 §Tab1.2) -------------------------------
function ApprovalCard(props: {
  approval: PendingApproval;
  onAction: (approval: PendingApproval, action: ApprovalAction) => void;
  onNavigate: (tab: TabId) => void;
}) {
  const { approval, onAction, onNavigate } = props;
  const covered = approval.covered_by_rule === true;
  const coveredTitle = covered
    ? "Covered by " +
      (text(approval.covered_rule_id) || "an existing rule") +
      ". The matching allow rule already permits this retry, so approving is not needed."
    : "";
  return (
    <div className="hermes-guardian-card hermes-guardian-approval-card">
      <div className="hermes-guardian-block-head">
        <div>
          <div className="hermes-guardian-block-title">
            {text(approval.action_family) + " -> " + text(approval.destination)}
            <TrustPill trust={approval.destination_trust} />
          </div>
          <div className="hermes-guardian-rule-subline">
            {approval.id ? <span className="hermes-guardian-rule-id">{text(approval.id)}</span> : null}
            <span className="hermes-guardian-pill">pending approval</span>
          </div>
        </div>
        <div className="hermes-guardian-actions">
          <Button
            disabled={covered}
            title={coveredTitle || undefined}
            onClick={() => onAction(approval, "approve-once")}
          >
            Approve
          </Button>
          <Button variant="secondary" onClick={() => onAction(approval, "dismiss")}>
            Deny
          </Button>
        </div>
      </div>
      <div className="hermes-guardian-block-meta">
        <span>{"Tool " + text(approval.tool_name, "n/a")}</span>
        <span>{"Taints " + classesText(approval.data_classes)}</span>
        <span>{"Purpose " + text(approval.purpose, "unknown")}</span>
        <span>{"Recipient " + text(approval.recipient_identity, "none")}</span>
        {approval.decision_step ? (
          <span className="hermes-guardian-decision-step-wrap">
            {"Decision "}
            <DecisionStep step={approval.decision_step} onNavigate={onNavigate} />
          </span>
        ) : null}
        {approval.reason ? <span>{"Reason " + text(approval.reason)}</span> : null}
      </div>
    </div>
  );
}

// --- Decided stream filters (doc 02 §Tab1.3) ---------------------------------
interface Filters {
  decision: string;
  trust: string;
  classTag: string;
  tool: string;
  destination: string;
  recipient: string;
  from: string;
  to: string;
  search: string;
}

const EMPTY_FILTERS: Filters = {
  decision: "",
  trust: "",
  classTag: "",
  tool: "",
  destination: "",
  recipient: "",
  from: "",
  to: "",
  search: "",
};

function rowMatchesFilters(row: ActivityRow, filters: Filters): boolean {
  const decision = text(row.decision).toLowerCase();
  if (filters.decision && decision !== filters.decision.toLowerCase()) return false;
  if (filters.trust && text(row.destination_trust).toLowerCase() !== filters.trust.toLowerCase())
    return false;
  if (
    filters.classTag &&
    text(row.data_classes).toLowerCase().indexOf(filters.classTag.toLowerCase()) < 0
  )
    return false;
  if (
    filters.tool &&
    text(row.tool_name || row.tool).toLowerCase().indexOf(filters.tool.toLowerCase()) < 0
  )
    return false;
  if (
    filters.destination &&
    text(row.destination).toLowerCase().indexOf(filters.destination.toLowerCase()) < 0
  )
    return false;
  if (
    filters.recipient &&
    text(row.recipient_identity).toLowerCase().indexOf(filters.recipient.toLowerCase()) < 0
  )
    return false;
  const ts = Number(row.ts || 0);
  if (filters.from) {
    const fromTs = new Date(filters.from).getTime() / 1000;
    if (Number.isFinite(fromTs) && ts && ts < fromTs) return false;
  }
  if (filters.to) {
    const toTs = new Date(filters.to).getTime() / 1000 + 86400;
    if (Number.isFinite(toTs) && ts && ts > toTs) return false;
  }
  if (filters.search) {
    const haystack = [
      row.tool_name,
      row.tool,
      row.action_family,
      row.destination,
      row.recipient_identity,
      row.purpose,
      row.reason,
      row.reason_short,
      row.data_classes,
    ]
      .map((value) => text(value))
      .join(" ")
      .toLowerCase();
    if (haystack.indexOf(filters.search.toLowerCase()) < 0) return false;
  }
  return true;
}

const TRUST_LEVELS = [
  "self",
  "local_system",
  "model_provider",
  "trusted_recipient",
  "public",
  "external",
  "unknown",
];

// Field-level filters tucked behind the "More filters" disclosure so the
// default toolbar stays a single compact row.
const ADVANCED_FILTER_KEYS: (keyof Filters)[] = [
  "classTag",
  "tool",
  "destination",
  "recipient",
  "from",
  "to",
];

function activeFilterCount(filters: Filters, keys: (keyof Filters)[]): number {
  return keys.filter((key) => text(filters[key]).length > 0).length;
}

function FilterBar(props: { filters: Filters; setFilters: (next: Filters) => void }) {
  const { filters, setFilters } = props;
  const [expanded, setExpanded] = useState(false);
  const set = (key: keyof Filters, value: string) =>
    setFilters(Object.assign({}, filters, { [key]: value }));

  const advancedActive = activeFilterCount(filters, ADVANCED_FILTER_KEYS);
  const anyActive = activeFilterCount(filters, Object.keys(filters) as (keyof Filters)[]) > 0;

  return (
    <div className="hermes-guardian-activity-filterbar">
      <div className="hermes-guardian-activity-filterbar-main">
        <input
          className="hermes-guardian-input hermes-guardian-filter-search"
          type="search"
          placeholder="Search activity"
          value={filters.search}
          onChange={(event) => set("search", event.target.value)}
        />
        <select
          className="hermes-guardian-select hermes-guardian-filter-compact"
          value={filters.decision}
          onChange={(event) => set("decision", event.target.value)}
        >
          <option value="">All decisions</option>
          <option value="allowed">allowed</option>
          <option value="gated">gated</option>
          <option value="blocked">blocked</option>
          <option value="denied">denied</option>
          <option value="read">read</option>
        </select>
        <select
          className="hermes-guardian-select hermes-guardian-filter-compact"
          value={filters.trust}
          onChange={(event) => set("trust", event.target.value)}
        >
          <option value="">All trust</option>
          {TRUST_LEVELS.map((level) => (
            <option key={level} value={level}>
              {level}
            </option>
          ))}
        </select>
        <Button
          variant="secondary"
          onClick={() => setExpanded(!expanded)}
          title="Filter by tool, destination, recipient, class, or date"
        >
          {(expanded ? "Fewer filters" : "More filters") +
            (advancedActive ? " (" + advancedActive + ")" : "")}
        </Button>
        {anyActive ? (
          <Button variant="secondary" onClick={() => setFilters(EMPTY_FILTERS)}>
            Clear
          </Button>
        ) : null}
      </div>
      {expanded ? (
        <div className="hermes-guardian-activity-filters-advanced">
          <input
            className="hermes-guardian-input"
            type="text"
            placeholder="class / tag"
            value={filters.classTag}
            onChange={(event) => set("classTag", event.target.value)}
          />
          <input
            className="hermes-guardian-input"
            type="text"
            placeholder="tool"
            value={filters.tool}
            onChange={(event) => set("tool", event.target.value)}
          />
          <input
            className="hermes-guardian-input"
            type="text"
            placeholder="destination"
            value={filters.destination}
            onChange={(event) => set("destination", event.target.value)}
          />
          <input
            className="hermes-guardian-input"
            type="text"
            placeholder="recipient"
            value={filters.recipient}
            onChange={(event) => set("recipient", event.target.value)}
          />
          <input
            className="hermes-guardian-input"
            type="date"
            title="From date"
            value={filters.from}
            onChange={(event) => set("from", event.target.value)}
          />
          <input
            className="hermes-guardian-input"
            type="date"
            title="To date"
            value={filters.to}
            onChange={(event) => set("to", event.target.value)}
          />
        </div>
      ) : null}
    </div>
  );
}

function ActivityRowItem(props: {
  row: ActivityRow;
  index: number;
  onNavigate: (tab: TabId) => void;
}) {
  const { row, onNavigate } = props;
  const [open, setOpen] = useState(false);
  const tool = text(row.tool_name || row.tool, "n/a");
  const destination = text(row.destination, "n/a");
  const action = text(row.action_family, "n/a");
  const isRead = text(row.decision) === "read" || text(row.decision) === "tainted";
  return (
    <tr
      className="hermes-guardian-activity-row"
      onClick={() => setOpen(!open)}
      style={{ cursor: "pointer" }}
    >
      <td>{text(row.decision)}</td>
      <td>{text(row.time, timeText(row.ts))}</td>
      <td>
        <div className="hermes-guardian-history-target">
          <div className="hermes-guardian-history-tool">{tool}</div>
          <div className="hermes-guardian-history-route">
            {action + " -> " + destination}
            {!isRead && row.destination_trust ? <TrustPill trust={row.destination_trust} /> : null}
          </div>
          {row.decision_step ? (
            <div className="hermes-guardian-muted">
              <DecisionStep step={row.decision_step} onNavigate={onNavigate} />
            </div>
          ) : null}
          {open ? (
            <div className="hermes-guardian-activity-expand hermes-guardian-muted">
              <div>{"direction " + (isRead ? "read" : "write")}</div>
              <div>{"destination " + destination + " (" + text(row.destination_trust, "unknown") + ")"}</div>
              <div>{"purpose " + text(row.purpose, "unknown")}</div>
              <div>{"recipient " + text(row.recipient_identity, "none")}</div>
              <div>{"classes " + text(row.data_classes, "none")}</div>
              <div>{"decision " + text(row.decision)}</div>
              {row.reason ? <div>{"reason " + text(row.reason)}</div> : null}
            </div>
          ) : null}
        </div>
      </td>
      <td>{text(row.data_classes)}</td>
    </tr>
  );
}

export function ActivityTab(props: ActivityTabProps) {
  const {
    taint,
    onClearTaint,
    approvals,
    approvalsLoading,
    onApprovalAction,
    activity,
    loading,
    error,
    total,
    page,
    pageSize,
    setPage,
    setPageSize,
    onNavigate,
  } = props;

  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);

  const filtered = useMemo(
    () => activity.filter((row) => rowMatchesFilters(row, filters)),
    [activity, filters],
  );

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, totalPages - 1);

  return (
    <div className="hermes-guardian-grid">
      <TaintStrip taint={taint} onClear={onClearTaint} />

      <div className="hermes-guardian-card hermes-guardian-approvals-section">
        <div className="hermes-guardian-card-title">Pending approvals</div>
        <div className="hermes-guardian-muted">
          Actions awaiting your decision. This is the only place with same-screen actions.
        </div>
        {approvalsLoading && !approvals.length ? (
          <div className="hermes-guardian-muted">Loading approvals...</div>
        ) : approvals.length ? (
          <div className="hermes-guardian-grid">
            {approvals.map((approval) => (
              <ApprovalCard
                key={text(approval.id)}
                approval={approval}
                onAction={onApprovalAction}
                onNavigate={onNavigate}
              />
            ))}
          </div>
        ) : (
          <div className="hermes-guardian-muted">Nothing is waiting on you.</div>
        )}
      </div>

      <div className="hermes-guardian-card-title">Decided</div>
      <FilterBar filters={filters} setFilters={setFilters} />
      <div className="hermes-guardian-history-toolbar">
        <div className="hermes-guardian-muted">
          {loading
            ? "Loading activity..."
            : total
              ? "Showing " + filtered.length + " of " + total + " (page " + (currentPage + 1) + "/" + totalPages + ")"
              : "No activity yet."}
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
          </colgroup>
          <thead>
            <tr>
              {["Status", "Time", "Tool / route / why", "Taints"].map((label) => (
                <th key={label}>{label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? (
              filtered.map((row, index) => (
                <ActivityRowItem
                  key={row.id || index}
                  row={row}
                  index={index}
                  onNavigate={onNavigate}
                />
              ))
            ) : (
              <tr>
                <td colSpan={4} className="hermes-guardian-muted">
                  {loading ? "Loading activity..." : "No matching activity."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
