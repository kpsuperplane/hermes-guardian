import { React, useEffect, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { DecisionStep } from "@/components/DecisionStep";
import { IconButton } from "@/components/IconButton";
import { TrustPill } from "@/components/TrustPill";
import { HISTORY_PAGE_SIZES } from "@/constants";
import { buildAttentionItems, type AttentionItem } from "@/lib/attention";
import { activityTimeNoYearText, classesText, latencyText, text, timeText } from "@/lib/format";
import type { TabId } from "@/lib/deepLinks";
import type {
  ActivityRow,
  ActivityTurn,
  PendingApproval,
  PermitOption,
  Policy,
  SourceSuggestion,
} from "@/types";
import type { ApprovalAction } from "@/hooks/useGuardianActions";

export interface ActivityTabProps {
  // Session taint strip
  taint: string[];
  onClearTaint: () => void;
  // Pinned pending approvals (same-screen approve/dismiss)
  approvals: PendingApproval[];
  approvalsLoading: boolean;
  onApprovalAction: (approval: PendingApproval, action: ApprovalAction) => void;
  policy: Policy | null;
  sourceSuggestions: SourceSuggestion[];
  onLoadSourceSuggestions: () => void;
  onClassifySource: (server: string, mode: "private" | "unknown") => void;
  onOpenReadingTool: (match?: string) => void;
  onOpenSharingTool: (match?: string) => void;
  onDismissAttention: (item: AttentionItem) => void;
  onRestoreAttention: () => void;
  // History grouped by turn (server-paginated by turn)
  turns: ActivityTurn[];
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

function OptionalFlowMeta(props: { whyNow?: unknown; flowBoundaryLabel?: unknown }) {
  const boundary = text(props.flowBoundaryLabel);
  const whyNow = whyNowSummary(props.whyNow);
  return (
    <>
      {boundary ? <span>{"Boundary " + boundary}</span> : null}
      {whyNow ? <span>{"Why now " + whyNow}</span> : null}
    </>
  );
}

function whyNowSummary(value: unknown): string {
  if (value && typeof value === "object" && "summary" in value) {
    return text((value as { summary?: unknown }).summary);
  }
  return text(value);
}

function activeAttentionDismissalCount(policy: Policy | null): number {
  const now = Math.floor(Date.now() / 1000);
  return ((policy && policy.attention_dismissals) || []).filter(
    (item) => Number(item.expires_at || 0) > now,
  ).length;
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
  const groupOrder = ["Approval options", "Trusted Destination Options", "Ownership options"];
  const groups = groupOrder
    .map((group) => ({
      group,
      options: (approval.permit_options || []).filter(
        (option: PermitOption) => text(option.group, "Approval options") === group,
      ),
    }))
    .filter((entry) => entry.options.length);
  const selectableOptions = groups.flatMap((entry) =>
    entry.options.filter((option) => option.structural || !covered),
  );
  const optionByMethod = new Map<string, PermitOption>();
  groups.forEach((entry) => {
    entry.options.forEach((option) => optionByMethod.set(option.method, option));
  });
  const approvalTitle = covered && !selectableOptions.length ? coveredTitle : "Choose an approval action";
  const optionLabel = (option: PermitOption) =>
    option.structural && option.value
      ? option.label + " " + option.value
      : option.label;
  return (
    <div className="hermes-guardian-card hermes-guardian-approval-card">
      <div className="hermes-guardian-block-head">
        <div>
          <div className="hermes-guardian-block-title">
            {text(approval.action_family) + " → " + text(approval.destination)}
            <TrustPill trust={approval.destination_trust} />
          </div>
          <div className="hermes-guardian-rule-subline">
            {approval.id ? <span className="hermes-guardian-rule-id">{text(approval.id)}</span> : null}
            <span className="hermes-guardian-pill">pending approval</span>
          </div>
        </div>
        <div className="hermes-guardian-approval-actions">
          <select
            className="hermes-guardian-select hermes-guardian-approval-select"
            aria-label={"Approve pending approval " + text(approval.id)}
            defaultValue=""
            disabled={!selectableOptions.length}
            title={approvalTitle}
            onChange={(event) => {
              const method = event.currentTarget.value;
              event.currentTarget.value = "";
              const option = optionByMethod.get(method);
              if (!option) return;
              onAction(approval, {
                kind: "permit",
                method: option.method,
                structural: option.structural,
              });
            }}
          >
            <option value="" disabled>
              Approve...
            </option>
            {groups.map((entry) => (
              <optgroup key={entry.group} label={entry.group}>
                {entry.options.map((option) => (
                  <option key={option.method} value={option.method} disabled={!option.structural && covered}>
                    {optionLabel(option)}
                  </option>
                ))}
              </optgroup>
            ))}
          </select>
          <IconButton
            icon="x"
            label={"Dismiss pending approval " + text(approval.id)}
            onClick={() => onAction(approval, { kind: "dismiss" })}
          />
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
        <OptionalFlowMeta
          flowBoundaryLabel={approval.flow_boundary_label}
          whyNow={approval.why_now}
        />
        {approval.reason ? <span>{"Reason " + text(approval.reason)}</span> : null}
      </div>
    </div>
  );
}

function AttentionSuggestionCard(props: {
  item: AttentionItem;
  onNavigate: (tab: TabId) => void;
  onClassifySource: (server: string, mode: "private" | "unknown") => void;
  onOpenReadingTool: (match?: string) => void;
  onOpenSharingTool: (match?: string) => void;
  onDismiss: (item: AttentionItem) => void;
}) {
  const { item, onNavigate, onClassifySource, onOpenReadingTool, onOpenSharingTool, onDismiss } = props;
  const meta = (item.meta || []).filter(Boolean);
  const hasTarget = Boolean(item.targetTab);
  return (
    <div className={"hermes-guardian-card hermes-guardian-attention-card hermes-guardian-attention-" + item.kind}>
      <div className="hermes-guardian-block-head">
        <div className="hermes-guardian-rule-main">
          <div className="hermes-guardian-block-title">{item.title}</div>
          {item.detail ? <div className="hermes-guardian-muted">{item.detail}</div> : null}
          {meta.length ? (
            <div className="hermes-guardian-block-meta">
              {meta.map((entry) => (
                <span key={entry} className="hermes-guardian-pill">
                  {entry}
                </span>
              ))}
            </div>
          ) : null}
        </div>
        <div className="hermes-guardian-attention-actions">
          {item.kind === "source" ? (
            <>
              <Button variant="secondary" onClick={() => onClassifySource(item.server, "private")}>
                Personal data
              </Button>
              <Button variant="secondary" onClick={() => onClassifySource(item.server, "unknown")}>
                Unknown
              </Button>
              <Button variant="secondary" onClick={() => onNavigate("reading")}>
                Review
              </Button>
            </>
          ) : null}
          {item.kind === "egress-tool" ? (
            <>
              <Button variant="secondary" onClick={() => onOpenSharingTool(item.match)}>
                Set policy
              </Button>
              <Button variant="secondary" onClick={() => onNavigate("sharing")}>
                Review
              </Button>
            </>
          ) : null}
          {item.kind === "read-tool" ? (
            <>
              <Button variant="secondary" onClick={() => onOpenReadingTool(item.match)}>
                Set policy
              </Button>
              <Button variant="secondary" onClick={() => onNavigate("reading")}>
                Review
              </Button>
            </>
          ) : null}
          {(item.kind === "risk" || item.kind === "info") && hasTarget ? (
            <Button variant="secondary" onClick={() => onNavigate(item.targetTab as TabId)}>
              Review
            </Button>
          ) : null}
          {item.dismissKey ? (
            <IconButton
              icon="x"
              label={"Dismiss Attention item " + item.title}
              onClick={() => onDismiss(item)}
            />
          ) : null}
        </div>
      </div>
    </div>
  );
}

function AttentionSection(props: {
  items: AttentionItem[];
  approvalsLoading: boolean;
  onApprovalAction: (approval: PendingApproval, action: ApprovalAction) => void;
  onNavigate: (tab: TabId) => void;
  onClassifySource: (server: string, mode: "private" | "unknown") => void;
  onOpenReadingTool: (match?: string) => void;
  onOpenSharingTool: (match?: string) => void;
  onDismissAttention: (item: AttentionItem) => void;
  onRestoreAttention: () => void;
  snoozedCount: number;
}) {
  const topItem = props.items[0];
  const itemCount = props.items.length;
  const hasStack = itemCount > 1;
  const hiddenCardCount = Math.min(itemCount - 1, 2);
  const renderTopCard = (item: AttentionItem) =>
    item.kind === "approval" ? (
      <ApprovalCard
        key={item.id}
        approval={item.approval}
        onAction={props.onApprovalAction}
        onNavigate={props.onNavigate}
      />
    ) : (
      <AttentionSuggestionCard
        key={item.id}
        item={item}
        onNavigate={props.onNavigate}
        onClassifySource={props.onClassifySource}
        onOpenReadingTool={props.onOpenReadingTool}
        onOpenSharingTool={props.onOpenSharingTool}
        onDismiss={props.onDismissAttention}
      />
    );

  return (
    <section className="hermes-guardian-attention-section" aria-labelledby="hermes-guardian-attention-title">
      <div className="hermes-guardian-attention-head">
        <div>
          <div className="hermes-guardian-attention-title-row">
            <div id="hermes-guardian-attention-title" className="hermes-guardian-card-title">
              Attention
            </div>
            {itemCount ? (
              <span className="hermes-guardian-pill hermes-guardian-attention-count">
                {"1 of " + itemCount}
              </span>
            ) : null}
          </div>
          <div className="hermes-guardian-muted">
            Pending decisions and setup suggestions from current dashboard metadata.
          </div>
        </div>
        {props.approvalsLoading ? (
          <span className="hermes-guardian-muted hermes-guardian-attention-loading">
            Refreshing approvals...
          </span>
        ) : null}
        {props.snoozedCount ? (
          <Button variant="secondary" onClick={props.onRestoreAttention}>
            {"Restore snoozed (" + props.snoozedCount + ")"}
          </Button>
        ) : null}
      </div>
      {topItem ? (
        <div
          className={
            "hermes-guardian-attention-stack" +
            (hasStack ? " hermes-guardian-attention-stack-layered" : "")
          }
        >
          {hasStack ? (
            <>
              {hiddenCardCount > 1 ? (
                <div className="hermes-guardian-attention-stack-shadow hermes-guardian-attention-stack-shadow-2" />
              ) : null}
              <div className="hermes-guardian-attention-stack-shadow hermes-guardian-attention-stack-shadow-1" />
            </>
          ) : null}
          <div className="hermes-guardian-attention-stack-card">
            {renderTopCard(topItem)}
          </div>
        </div>
      ) : (
        <div className="hermes-guardian-card hermes-guardian-muted hermes-guardian-attention-empty">
          No approvals or dashboard suggestions need attention.
        </div>
      )}
    </section>
  );
}

// --- Turn cards (history grouped by turn) ------------------------------------
// The decision shows as an emoji (✅/❌/📥/🌐, from the backend `icon`), followed by
// 🤖 when the LLM verifier was involved (an auto-approval, or any verdict whose reason
// mentions the verifier). The full word is kept as a tooltip.
function checkInvolvesLlm(row: ActivityRow): boolean {
  if (text(row.decision) === "auto_approved") return true;
  return (text(row.reason) + " " + text(row.reason_short)).toLowerCase().indexOf("llm") >= 0;
}

function decisionEmoji(row: ActivityRow): string {
  return (text(row.icon) || "•") + (checkInvolvesLlm(row) ? "🤖" : "");
}

// A "check" line-item: one activity row inside a turn card. Click to expand the full
// key/value detail (the dashboard twin of /guardian why).
function CheckItem(props: { row: ActivityRow; onNavigate: (tab: TabId) => void }) {
  const { row, onNavigate } = props;
  const [open, setOpen] = useState(false);
  const tool = text(row.tool_name || row.tool, "n/a");
  const destination = text(row.destination, "n/a");
  const direction =
    text(row.direction) ||
    (text(row.decision) === "read" || text(row.decision) === "tainted" ? "read" : "write");
  const action = text(row.action_family, direction === "read" ? "read" : "n/a");
  const route = direction === "read" && !text(row.destination) ? action : action + " → " + destination;
  const latency = latencyText(row.latency_ms);
  const isRead = direction === "read";
  const flowBoundary = text(row.flow_boundary_label);
  const whyNow = whyNowSummary(row.why_now);
  // data_classes can arrive as an array or a delimiter-joined string; one chip per taint.
  const taints = (
    Array.isArray(row.data_classes) ? row.data_classes : text(row.data_classes).split(/[,]/)
  )
    .map((cls) => text(cls).trim())
    .filter(Boolean);
  const detailPairs: Array<{ label: string; value: React.ReactNode }> = [
    { label: "Direction", value: direction },
    {
      label: "Destination",
      value: destination + (taints.length > 0 ? " (" + text(row.destination_trust, "unknown") + ")" : ""),
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
  if (flowBoundary) detailPairs.push({ label: "Boundary", value: flowBoundary });
  if (whyNow) detailPairs.push({ label: "Why now", value: whyNow });
  if (latency) detailPairs.push({ label: "Latency", value: latency });
  if (row.action_detail) detailPairs.push({ label: "Action", value: text(row.action_detail) });
  if (row.reason) detailPairs.push({ label: "Reason", value: text(row.reason) });

  return (
    <div className={"hermes-guardian-check-item" + (open ? " hermes-guardian-check-item-open" : "")}>
      <div
        className="hermes-guardian-check-row"
        onClick={() => setOpen(!open)}
        style={{ cursor: "pointer" }}
      >
        <span className="hermes-guardian-chevron" aria-hidden="true">▶</span>
        <span className="hermes-guardian-check-target">
          <span className="hermes-guardian-check-tool">{tool}</span>
          <span className="hermes-guardian-check-route hermes-guardian-muted">
            {route}
          </span>
        </span>
        <span className="hermes-guardian-check-decision" title={text(row.decision)}>
          {decisionEmoji(row)}
        </span>
        {/* Trust is only resolved when private data is in scope; for reads / no-private-data
           allows it defaults to "unknown" (not evaluated), so only show the pill when the
           check actually carried a taint — where the trust level is meaningful. */}
        {!isRead && taints.length > 0 && row.destination_trust ? (
          <TrustPill trust={row.destination_trust} />
        ) : null}
        {flowBoundary ? (
          <span className="hermes-guardian-pill hermes-guardian-flow-boundary">
            {flowBoundary}
          </span>
        ) : null}
        {taints.length ? (
          <span className="hermes-guardian-chips hermes-guardian-history-taint-chips">
            {taints.map((cls) => (
              <span key={cls} className="hermes-guardian-chip">
                {cls}
              </span>
            ))}
          </span>
        ) : null}
        {latency ? (
          <span className="hermes-guardian-check-latency hermes-guardian-muted">
            {"Latency " + latency}
          </span>
        ) : null}
        <span className="hermes-guardian-check-time hermes-guardian-muted">
          {text(row.time_short, timeText(row.ts))}
        </span>
      </div>
      {row.decision_step ? (
        <div className="hermes-guardian-check-step hermes-guardian-muted">
          <DecisionStep step={row.decision_step} onNavigate={onNavigate} />
        </div>
      ) : null}
      {whyNow ? (
        <div className="hermes-guardian-check-step hermes-guardian-muted">
          {"Why now: " + whyNow}
        </div>
      ) : null}
      {open ? (
        <dl className="hermes-guardian-activity-detail hermes-guardian-check-detail">
          {detailPairs.map((pair) => (
            <React.Fragment key={pair.label}>
              <dt>{pair.label}</dt>
              <dd>{pair.value}</dd>
            </React.Fragment>
          ))}
        </dl>
      ) : null}
    </div>
  );
}

// A turn card: the prompt (or a "Turn" label) + a meta line, then its checks nested
// inside.
function TurnCard(props: { turn: ActivityTurn; onNavigate: (tab: TabId) => void }) {
  const { turn } = props;
  const [open, setOpen] = useState(true); // turns are expanded by default; click to collapse
  const rows = turn.rows || [];
  const prompt = text(turn.user_prompt);
  const first = rows[0] || {};
  const when = activityTimeNoYearText(first.time, turn.ts);
  const totalLatency = latencyText(turn.total_latency_ms);
  const meta = when + (totalLatency ? " · Total " + totalLatency : "");
  return (
    <div
      className={"hermes-guardian-card hermes-guardian-turn-card" + (open ? " hermes-guardian-turn-card-open" : "")}
    >
      <div
        className="hermes-guardian-turn-card-head"
        onClick={() => setOpen(!open)}
        style={{ cursor: "pointer" }}
      >
        <span className="hermes-guardian-chevron" aria-hidden="true">▶</span>
        <div className="hermes-guardian-turn-card-title">
          <span
            className="hermes-guardian-turn-label"
            title={turn.is_cron ? "Cron job" : "User turn"}
          >
            {turn.is_cron ? "⏲️" : "👤"}
          </span>
          {prompt ? (
            <span className="hermes-guardian-turn-prompt">{prompt}</span>
          ) : (
            <span className="hermes-guardian-muted">prompt not recorded</span>
          )}
        </div>
        <div className="hermes-guardian-turn-card-meta hermes-guardian-muted">
          {meta}
        </div>
      </div>
      {open ? (
        <div className="hermes-guardian-turn-checks">
          {rows.map((row, index) => (
            <CheckItem key={row.id || index} row={row} onNavigate={props.onNavigate} />
          ))}
        </div>
      ) : null}
    </div>
  );
}

export function ActivityTab(props: ActivityTabProps) {
  const {
    taint,
    onClearTaint,
    approvals,
    approvalsLoading,
    onApprovalAction,
    policy,
    sourceSuggestions,
    onLoadSourceSuggestions,
    onClassifySource,
    onOpenReadingTool,
    onOpenSharingTool,
    onDismissAttention,
    onRestoreAttention,
    turns,
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

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const currentPage = Math.min(page, totalPages - 1);
  const showPagination = totalPages > 1;
  const attentionItems = buildAttentionItems({ approvals, policy, sourceSuggestions });
  const snoozedCount = activeAttentionDismissalCount(policy);

  useEffect(() => {
    onLoadSourceSuggestions();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="hermes-guardian-grid">
      <AttentionSection
        items={attentionItems}
        approvalsLoading={approvalsLoading}
        onApprovalAction={onApprovalAction}
        onNavigate={onNavigate}
        onClassifySource={onClassifySource}
        onOpenReadingTool={onOpenReadingTool}
        onOpenSharingTool={onOpenSharingTool}
        onDismissAttention={onDismissAttention}
        onRestoreAttention={onRestoreAttention}
        snoozedCount={snoozedCount}
      />

      <TaintStrip taint={taint} onClear={onClearTaint} />

      <Debugging
        persistPrompts={persistPrompts}
        saving={persistPromptsSaving}
        onChange={onChangePersistPrompts}
      />

      <div className="hermes-guardian-card-title">History</div>
      <div className="hermes-guardian-history-toolbar">
        <div className="hermes-guardian-muted">
          {loading
            ? "Loading activity..."
            : total
              ? "Showing " +
                turns.length +
                " of " +
                total +
                (total === 1 ? " turn" : " turns") +
                (showPagination ? " (page " + (currentPage + 1) + "/" + totalPages + ")" : "")
              : "No activity yet."}
        </div>
        {showPagination ? (
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
            <IconButton
              icon="chevron-left"
              label="Previous history page"
              disabled={loading || currentPage <= 0}
              onClick={() => setPage(Math.max(0, currentPage - 1))}
            />
            <IconButton
              icon="chevron-right"
              label="Next history page"
              disabled={loading || currentPage >= totalPages - 1}
              onClick={() => setPage(currentPage + 1)}
            />
          </div>
        ) : null}
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      {turns.length ? (
        turns.map((turn, index) => (
          <TurnCard key={turn.turn_id || "turn-" + index} turn={turn} onNavigate={onNavigate} />
        ))
      ) : (
        <div className="hermes-guardian-card hermes-guardian-muted">
          {loading ? "Loading activity..." : "No activity yet."}
        </div>
      )}
    </div>
  );
}
