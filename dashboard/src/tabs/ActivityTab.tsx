import { React, useMemo, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { DecisionStep } from "@/components/DecisionStep";
import { TrustPill, trustLabel } from "@/components/TrustPill";
import { HISTORY_PAGE_SIZES } from "@/constants";
import { classesText, text, timeText } from "@/lib/format";
import type { TabId } from "@/lib/deepLinks";
import type { ActivityRow, PendingApproval } from "@/types";
import type { ApprovalAction } from "@/hooks/useGuardianActions";

export interface ActivityTabProps {
  // Session taint strip
  taint: string[];
  onClearTaint: () => void;
  // Pinned pending approvals (same-screen approve/dismiss)
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
  // Prompt persistence (debugging) — controls whether turn headers show the prompt
  persistPrompts: boolean;
  persistPromptsSaving: boolean;
  onChangePersistPrompts: (enabled: boolean) => void;
  // Deep-link navigation to the governing tab
  onNavigate: (tab: TabId) => void;
}

// --- Debugging: opt-in prompt persistence (controls the turn-header prompt) ----
function Debugging(props: {
  persistPrompts: boolean;
  saving: boolean;
  onChange: (enabled: boolean) => void;
}) {
  return (
    <div className="hermes-guardian-card">
      <div className="hermes-guardian-card-title">Debugging</div>
      <div className="hermes-guardian-muted hermes-guardian-section-description">
        History is always grouped by turn (one user prompt and the actions it drove). Turn
        this on to also record the sanitized user/cron prompt on each turn so the turn
        header shows what was asked. Off by default — it relaxes the metadata-only invariant;
        turn it off when you're done. The stored prompt is the same redacted excerpt the
        verifier sees (emails, phone numbers, URLs, quoted strings, and tokens removed) and
        is pruned with every other row by Retention.
      </div>
      <label className="hermes-guardian-check hermes-guardian-security-check">
        <input
          type="checkbox"
          checked={props.persistPrompts}
          disabled={props.saving}
          onChange={(event) => props.onChange(event.target.checked)}
        />
        <span className="hermes-guardian-security-rule-text">
          <span>Persist prompts on activity rows</span>
          <span className="hermes-guardian-muted">
            Writes the sanitized user/cron prompt to the activity log for debugging.
          </span>
        </span>
      </label>
    </div>
  );
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
            Dismiss
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

// --- Turn grouping (doc: group history by turn) ------------------------------
// Rows arrive sorted ts DESC; walk them and start a new group whenever turn_id
// changes. Rows with an empty turn_id (legacy / pre-migration) each become their
// own singleton group with no header. A turn that straddles a server-side page
// boundary renders as two partial groups (a header on each page) — accepted.
interface TurnGroup {
  turnId: string;
  rows: ActivityRow[];
}

function groupByTurn(rows: ActivityRow[]): TurnGroup[] {
  const groups: TurnGroup[] = [];
  for (const row of rows) {
    const turnId = text(row.turn_id);
    const last = groups[groups.length - 1];
    if (last && turnId && last.turnId === turnId) {
      last.rows.push(row);
    } else {
      groups.push({ turnId, rows: [row] });
    }
  }
  return groups;
}

function TurnHeaderRow(props: { group: TurnGroup }) {
  const { group } = props;
  const first = group.rows[0];
  // The persisted prompt may be on any row of the turn (whichever was emitted while
  // the setting was on); take the first non-empty one.
  const prompt = text(group.rows.map((r) => text(r.user_prompt)).find(Boolean));
  const when = text(first.time, timeText(first.ts));
  const n = group.rows.length;
  return (
    <tr className="hermes-guardian-turn-header">
      <td colSpan={5}>
        <div className="hermes-guardian-turn-head">
          <span className="hermes-guardian-turn-label">Turn</span>
          {prompt ? (
            <span className="hermes-guardian-turn-prompt">{prompt}</span>
          ) : (
            <span className="hermes-guardian-muted">(prompt not recorded)</span>
          )}
          <span className="hermes-guardian-turn-meta hermes-guardian-muted">
            {when + " · " + n + (n === 1 ? " action" : " actions")}
          </span>
        </div>
      </td>
    </tr>
  );
}

function ActivityRowItem(props: {
  row: ActivityRow;
  index: number;
  inTurn?: boolean;
  last?: boolean;
  onNavigate: (tab: TabId) => void;
}) {
  const { row, onNavigate } = props;
  const [open, setOpen] = useState(false);
  const tool = text(row.tool_name || row.tool, "n/a");
  const destination = text(row.destination, "n/a");
  const action = text(row.action_family, "n/a");
  const isRead = text(row.decision) === "read" || text(row.decision) === "tainted";
  // data_classes can arrive as an array or as a delimiter-joined string; render
  // one chip per taint either way.
  const taints = (
    Array.isArray(row.data_classes) ? row.data_classes : text(row.data_classes).split(/[,]/)
  )
    .map((cls) => text(cls).trim())
    .filter(Boolean);
  // Key/value pairs for the expanded detail, rendered as a full-width table below
  // the row. Classes render as chips; everything else as text.
  const detailPairs: Array<{ label: string; value: React.ReactNode }> = [
    { label: "Direction", value: isRead ? "read" : "write" },
    {
      label: "Destination",
      value: destination + " (" + text(row.destination_trust, "unknown") + ")",
    },
    { label: "Purpose", value: text(row.purpose, "unknown") },
    { label: "Recipient", value: text(row.recipient_identity, "none") },
    {
      label: "Classes",
      value: taints.length ? (
        <span className="hermes-guardian-chips hermes-guardian-history-taint-chips">
          {taints.map((cls) => (
            <span key={cls} className="hermes-guardian-chip">
              {cls}
            </span>
          ))}
        </span>
      ) : (
        "none"
      ),
    },
    { label: "Decision", value: text(row.decision) },
  ];
  if (row.reason) detailPairs.push({ label: "Reason", value: text(row.reason) });

  const nest = props.inTurn ? " hermes-guardian-row-nested" : "";
  const lastNest = props.inTurn && props.last && !open ? " hermes-guardian-row-nested-last" : "";
  return (
    <React.Fragment>
      <tr
        className={
          "hermes-guardian-activity-row" +
          (open ? " hermes-guardian-activity-row-open" : "") +
          nest +
          lastNest
        }
        onClick={() => setOpen(!open)}
        style={{ cursor: "pointer" }}
      >
        <td>{text(row.decision)}</td>
        <td>{text(row.time, timeText(row.ts))}</td>
        <td>
          <div className="hermes-guardian-history-target">
            <div className="hermes-guardian-history-tool">{tool}</div>
            <div className="hermes-guardian-history-route">{action + " -> " + destination}</div>
            {row.decision_step ? (
              <div className="hermes-guardian-muted">
                <DecisionStep step={row.decision_step} onNavigate={onNavigate} />
              </div>
            ) : null}
          </div>
        </td>
        <td className="hermes-guardian-history-trust">
          {!isRead && row.destination_trust ? trustLabel(row.destination_trust) : ""}
        </td>
        <td>
          {taints.length ? (
            <div className="hermes-guardian-chips hermes-guardian-history-taint-chips">
              {taints.map((cls) => (
                <span key={cls} className="hermes-guardian-chip">
                  {cls}
                </span>
              ))}
            </div>
          ) : null}
        </td>
      </tr>
      {open ? (
        <tr
          className={
            "hermes-guardian-activity-detail-row" +
            nest +
            (props.inTurn && props.last ? " hermes-guardian-row-nested-last" : "")
          }
        >
          <td colSpan={5}>
            <dl className="hermes-guardian-activity-detail">
              {detailPairs.map((pair) => (
                <React.Fragment key={pair.label}>
                  <dt>{pair.label}</dt>
                  <dd>{pair.value}</dd>
                </React.Fragment>
              ))}
            </dl>
          </td>
        </tr>
      ) : null}
    </React.Fragment>
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
    persistPrompts,
    persistPromptsSaving,
    onChangePersistPrompts,
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
          Actions paused until you approve or dismiss them.
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
          <div className="hermes-guardian-muted">Nothing needs your approval right now.</div>
        )}
      </div>

      <Debugging
        persistPrompts={persistPrompts}
        saving={persistPromptsSaving}
        onChange={onChangePersistPrompts}
      />

      <div className="hermes-guardian-card-title">History</div>
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
            <col className="hermes-guardian-history-trust-col" />
            <col className="hermes-guardian-history-taints-col" />
          </colgroup>
          <thead>
            <tr>
              {["Status", "Time", "Tool / route / why", "Trust", "Taints"].map((label) => (
                <th key={label}>{label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? (
              groupByTurn(filtered).map((group, gIndex) => (
                <React.Fragment key={"turn-" + group.turnId + "-" + gIndex}>
                  {group.turnId ? <TurnHeaderRow group={group} /> : null}
                  {group.rows.map((row, index) => (
                    <ActivityRowItem
                      key={row.id || group.turnId + ":" + index}
                      row={row}
                      index={index}
                      inTurn={Boolean(group.turnId)}
                      last={Boolean(group.turnId) && index === group.rows.length - 1}
                      onNavigate={onNavigate}
                    />
                  ))}
                </React.Fragment>
              ))
            ) : (
              <tr>
                <td colSpan={5} className="hermes-guardian-muted">
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
