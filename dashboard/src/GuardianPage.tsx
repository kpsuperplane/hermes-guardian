import { React, useEffect, useState } from "@/sdk";
import { IconButton } from "@/components/IconButton";
import { OverrideModal } from "@/components/OverrideModal";
import { RiskBanners } from "@/components/RiskBanners";
import { RuleModal } from "@/components/RuleModal";
import { ToastRegion } from "@/components/ToastRegion";
import { useApprovals } from "@/hooks/useApprovals";
import { useDestinations } from "@/hooks/useDestinations";
import { useGuardianActions } from "@/hooks/useGuardianActions";
import { useHistory } from "@/hooks/useHistory";
import { usePerformance } from "@/hooks/usePerformance";
import { usePolicy } from "@/hooks/usePolicy";
import { useToasts } from "@/hooks/useToasts";
import type { TabId } from "@/lib/deepLinks";
import { ActivityTab } from "@/tabs/ActivityTab";
import { ProtectionTab } from "@/tabs/ProtectionTab";
import { ReviewTab } from "@/tabs/ReviewTab";
import { SharingTab } from "@/tabs/SharingTab";
import { WhatsYoursTab } from "@/tabs/WhatsYoursTab";
import type { PendingApproval } from "@/types";

// The five-tab IA (charter §1, doc 02). Order is fixed: it mirrors decide().
// Reading left-to-right is reading decide() top-to-bottom: what happened ->
// is it mine -> is it covered by a grant -> who judges the rest -> the floor.
const TABS: Array<[TabId, string]> = [
  ["activity", "Activity"],
  ["whats-yours", "What's Yours"],
  ["sharing", "Sharing"],
  ["review", "Review"],
  ["protection", "Protection"],
];

export function GuardianPage() {
  const {
    policy,
    loading,
    error,
    privacyMode,
    setPrivacyMode,
    unknownTools,
    setUnknownTools,
    llmUserContext,
    setLlmUserContext,
    llmCronContext,
    setLlmCronContext,
    persistPrompts,
    setPersistPrompts,
    llmVerifierModel,
    setLlmVerifierModel,
    load,
  } = usePolicy();
  const { toasts, showToast, dismissToast } = useToasts();
  const history = useHistory();
  const performance = usePerformance();
  const approvals = useApprovals();
  const destinations = useDestinations(showToast);
  const actions = useGuardianActions({
    policy,
    load,
    privacyMode,
    setPrivacyMode,
    unknownTools,
    setUnknownTools,
    llmUserContext,
    setLlmUserContext,
    llmCronContext,
    setLlmCronContext,
    persistPrompts,
    setPersistPrompts,
    llmVerifierModel,
    setLlmVerifierModel,
    reloadApprovals: approvals.loadApprovals,
    showToast,
  });

  const [tab, setTab] = useState<TabId>("activity");

  // Warm the lazily-fetched data once on mount so the first tab switch is instant
  // (the first plugin-API call per endpoint pays a one-time host-side cost).
  useEffect(() => {
    history.loadHistory(history.page, history.pageSize);
    performance.loadPerformance();
    approvals.loadApprovals();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (tab === "activity") {
      history.loadHistory(history.page, history.pageSize);
      approvals.loadApprovals();
    }
    if (tab === "review" || tab === "protection") performance.loadPerformance();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, history.page, history.pageSize]);

  const rules = (policy && policy.rules) || [];
  const riskBanners = (policy && policy.risk_banners) || [];

  // Session taint shown in the Activity strip: the union of taint across the
  // owner's live sessions, from the policy snapshot.
  const sessions = (policy && (policy as any).sessions) || [];
  const taint = Array.from(
    new Set(
      sessions.flatMap((session: any) => (Array.isArray(session.taint) ? session.taint : [])),
    ),
  ) as string[];

  function refreshActive() {
    load();
    if (tab === "activity") {
      history.loadHistory(history.page, history.pageSize);
      approvals.loadApprovals();
    }
    if (tab === "review" || tab === "protection") performance.loadPerformance();
    if (tab === "whats-yours" || tab === "sharing") destinations.refetch();
  }

  if (loading && !policy) {
    return <div className="hermes-guardian hermes-guardian-muted">Loading Guardian...</div>;
  }

  return (
    <div className="hermes-guardian">
      <div className="hermes-guardian-topbar">
        <div>
          <h1 className="hermes-guardian-title">Hermes Guardian</h1>
          <div className="hermes-guardian-subtitle">
            Security filtering and privacy egress rules
          </div>
        </div>
        <div className="hermes-guardian-actions">
          <IconButton icon="refresh" label="Refresh dashboard" onClick={refreshActive} />
        </div>
      </div>
      {error ? <div className="hermes-guardian-banner">{error}</div> : null}
      <RiskBanners banners={riskBanners} />
      <ToastRegion toasts={toasts} onDismiss={dismissToast} />
      <div className="hermes-guardian-tabs" role="tablist">
        {TABS.map((item) => (
          <button
            key={item[0]}
            type="button"
            className={
              "hermes-guardian-tab " + (tab === item[0] ? "hermes-guardian-tab-active" : "")
            }
            onClick={() => setTab(item[0])}
          >
            {item[1]}
          </button>
        ))}
      </div>

      {tab === "activity" ? (
        <ActivityTab
          taint={taint}
          onClearTaint={actions.clearTaintAction}
          approvals={approvals.approvals}
          approvalsLoading={approvals.loading}
          onApprovalAction={(approval: PendingApproval, action) =>
            actions.approvalAction(approval, action)
          }
          turns={history.turns}
          loading={history.loading}
          error={history.error}
          total={history.total}
          page={history.page}
          pageSize={history.pageSize}
          setPage={history.setPage}
          setPageSize={history.setPageSize}
          persistPrompts={persistPrompts}
          persistPromptsSaving={actions.persistPromptsSaving}
          onChangePersistPrompts={actions.savePersistPrompts}
          onNavigate={setTab}
        />
      ) : null}

      {tab === "whats-yours" ? <WhatsYoursTab controller={destinations} /> : null}

      {tab === "sharing" ? (
        <SharingTab
          controller={destinations}
          rules={rules}
          onNewRule={actions.openCreate}
          onEditRule={actions.openEdit}
          onPatchRule={actions.patchRule}
          onDeleteRule={actions.deleteRule}
          onMoveRule={actions.moveRule}
        />
      ) : null}

      {tab === "review" ? (
        <ReviewTab
          policy={policy}
          privacyMode={privacyMode}
          modeSaving={actions.modeSaving}
          onChangePrivacyMode={actions.saveMode}
          llmUserContext={llmUserContext}
          llmCronContext={llmCronContext}
          userContextSaving={actions.userContextSaving}
          cronContextSaving={actions.cronContextSaving}
          onChangeUserContext={actions.saveUserContext}
          onChangeCronContext={actions.saveCronContext}
          llmVerifierModel={llmVerifierModel}
          verifierModelSaving={actions.verifierModelSaving}
          onChangeVerifierModel={actions.saveVerifierModel}
          performance={performance.performance}
        />
      ) : null}

      {tab === "protection" ? (
        <ProtectionTab
          policy={policy}
          onPatchSecurityRule={actions.patchSecurityRule}
          onNewOverride={actions.openCreateOverride}
          onEditOverride={actions.openEditOverride}
          onToggleOverride={actions.toggleOverride}
          onDeleteOverride={actions.deleteOverride}
          unknownTools={unknownTools}
          unknownToolsSaving={actions.unknownToolsSaving}
          onChangeUnknownTools={actions.saveUnknownTools}
          sourceSuggestions={actions.sourceSuggestions}
          onLoadSourceSuggestions={actions.loadSourceSuggestions}
          onClassifySource={actions.classifySource}
          languagePacksSaving={actions.languagePacksSaving}
          onPatchLanguagePack={actions.patchLanguagePack}
          onSetAllLanguagePacks={actions.setAllLanguagePacks}
          performance={performance.performance}
          performanceLoading={performance.loading}
          performanceError={performance.error}
        />
      ) : null}

      {actions.showModal ? (
        <RuleModal
          policy={policy || {}}
          form={actions.form}
          setForm={actions.setForm}
          formError={actions.formError}
          onSubmit={actions.submitRule}
          onCancel={() => actions.setShowModal(false)}
        />
      ) : null}
      {actions.showOverrideModal ? (
        <OverrideModal
          policy={policy || {}}
          form={actions.overrideForm}
          setForm={actions.setOverrideForm}
          formError={actions.overrideFormError}
          onSubmit={actions.submitOverride}
          onCancel={() => actions.setShowOverrideModal(false)}
        />
      ) : null}
    </div>
  );
}
