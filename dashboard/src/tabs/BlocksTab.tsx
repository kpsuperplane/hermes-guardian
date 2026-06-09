import { React } from "@/sdk";
import { Button } from "@/components/Button";
import { classesText, text, timeText } from "@/lib/format";
import type { RecentBlock } from "@/types";

export type ApprovalAction = "approve-once" | "approve-always" | "dismiss";

export interface BlocksTabProps {
  blocks: RecentBlock[];
  onApprovalAction: (block: RecentBlock, action: ApprovalAction) => void;
}

function coveredRuleTitle(block: RecentBlock): string {
  const ruleId = text(block.covered_rule_id);
  const source = text(block.covered_rule_source);
  const prefix = ruleId
    ? "Covered by " + ruleId
    : source
      ? "Covered by " + source + " rule"
      : "Covered by an existing rule";
  return (
    prefix +
    ". The matching allow rule already permits this retry, so approving this pending request is not needed."
  );
}

function staleApprovalTitle(block: RecentBlock): string {
  const approvalId = text(block.historical_approval_id || block.approval_id);
  const suffix = approvalId ? " " + approvalId : "";
  if (block.approval_status === "expired") {
    const expires = Number(block.expires_at || 0);
    const when = expires ? " at " + timeText(expires) : "";
    return (
      "Approval" +
      suffix +
      " expired" +
      when +
      ". Approve is unavailable; retry the action to create a new approval."
    );
  }
  if (block.approval_status === "dismissed") {
    return "Approval" + suffix + " was dismissed and is no longer actionable.";
  }
  return (
    "Approval" + suffix + " is no longer pending. It may have been approved, dismissed, or expired."
  );
}

function staleApprovalText(block: RecentBlock): string {
  const approvalId = text(block.historical_approval_id || block.approval_id);
  const label = approvalId ? "Approval " + approvalId : "Approval";
  if (block.approval_status === "expired") {
    const expires = Number(block.expires_at || 0);
    return label + " expired" + (expires ? " " + timeText(expires) : "") + "; approve is unavailable.";
  }
  if (block.approval_status === "dismissed") return label + " was dismissed.";
  return label + " is no longer pending.";
}

function DisabledActionButton({ label, title }: { label: string; title: string }) {
  return (
    <span className="hermes-guardian-disabled-action" title={title}>
      <Button disabled title={title}>
        {label}
      </Button>
    </span>
  );
}

export function BlocksTab({ blocks, onApprovalAction }: BlocksTabProps) {
  function approvalButton(
    block: RecentBlock,
    action: ApprovalAction,
    label: string,
    disabled: boolean,
    title: string,
  ) {
    if (disabled) return <DisabledActionButton label={label} title={title} />;
    return (
      <Button title={title} onClick={() => onApprovalAction(block, action)}>
        {label}
      </Button>
    );
  }

  return (
    <div className="hermes-guardian-grid">
      {blocks.length ? (
        blocks.map((block) => {
          const pending = block.pending === true || !!block.approval_id;
          const covered = pending && block.covered_by_rule === true;
          const staleApproval = !pending && !!block.historical_approval_id;
          const expiredApproval = staleApproval && block.approval_status === "expired";
          const staleTitle = staleApproval ? staleApprovalTitle(block) : "";
          const blockId = text(block.approval_id || block.id || block.activity_id);
          const status = pending
            ? "pending approval"
            : expiredApproval
              ? "approval expired"
              : staleApproval
                ? "not approvable"
                : text(block.decision, "blocked");
          return (
            <div key={block.id} className="hermes-guardian-card">
              <div className="hermes-guardian-block-head">
                <div>
                  <div className="hermes-guardian-block-title">
                    {text(block.action_family) + " -> " + text(block.destination)}
                  </div>
                  <div className="hermes-guardian-rule-subline">
                    {blockId ? (
                      <span className="hermes-guardian-rule-id">{blockId}</span>
                    ) : null}
                    <span className="hermes-guardian-pill" title={staleTitle || undefined}>
                      {status}
                    </span>
                  </div>
                </div>
                {pending ? (
                  <div className="hermes-guardian-actions">
                    {approvalButton(
                      block,
                      "approve-once",
                      "Approve once",
                      covered,
                      covered ? coveredRuleTitle(block) : "",
                    )}
                    {approvalButton(
                      block,
                      "approve-always",
                      "Approve always",
                      covered,
                      covered ? coveredRuleTitle(block) : "",
                    )}
                    <Button
                      variant="secondary"
                      onClick={() => onApprovalAction(block, "dismiss")}
                    >
                      Dismiss
                    </Button>
                  </div>
                ) : expiredApproval ? (
                  <div className="hermes-guardian-actions">
                    {approvalButton(block, "approve-once", "Approve once", true, staleTitle)}
                    {approvalButton(block, "approve-always", "Approve always", true, staleTitle)}
                    <Button
                      variant="secondary"
                      title={staleTitle}
                      onClick={() => onApprovalAction(block, "dismiss")}
                    >
                      Dismiss
                    </Button>
                  </div>
                ) : null}
              </div>
              <div className="hermes-guardian-block-meta">
                <span>{"Tool " + text(block.tool_name, "n/a")}</span>
                {block.module ? <span>{"Module " + text(block.module)}</span> : null}
                <span>{"Taints " + classesText(block.data_classes)}</span>
                <span>{"Purpose " + text(block.purpose, "unknown")}</span>
                <span>{"Recipient " + text(block.recipient_identity, "none")}</span>
                <span>{"Created " + timeText(block.created_at)}</span>
                {staleApproval ? (
                  <span title={staleTitle}>{staleApprovalText(block)}</span>
                ) : null}
                <span>{"Reason " + text(block.reason, "n/a")}</span>
              </div>
            </div>
          );
        })
      ) : (
        <div className="hermes-guardian-card hermes-guardian-muted">No recent blocks.</div>
      )}
    </div>
  );
}
