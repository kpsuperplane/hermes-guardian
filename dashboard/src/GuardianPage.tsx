import { React, useEffect, useState } from "@/sdk";
import { Button } from "@/components/Button";
import { OverrideModal } from "@/components/OverrideModal";
import { RiskBanners } from "@/components/RiskBanners";
import { RuleModal } from "@/components/RuleModal";
import { ToastRegion } from "@/components/ToastRegion";
import { useGuardianActions } from "@/hooks/useGuardianActions";
import { useHistory } from "@/hooks/useHistory";
import { usePolicy } from "@/hooks/usePolicy";
import { useToasts } from "@/hooks/useToasts";
import { BlocksTab } from "@/tabs/BlocksTab";
import { HistoryTab } from "@/tabs/HistoryTab";
import { RulesTab } from "@/tabs/RulesTab";
import { SettingsTab } from "@/tabs/SettingsTab";
import { ToolsTab } from "@/tabs/ToolsTab";

const TABS: Array<[string, string]> = [
  ["settings", "Settings"],
  ["tools", "Tools"],
  ["rules", "Egress Rules"],
  ["blocks", "Recent Blocks"],
  ["history", "History"],
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
    load,
  } = usePolicy();
  const { toasts, showToast, dismissToast } = useToasts();
  const history = useHistory();
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
    showToast,
  });

  const [tab, setTab] = useState("settings");

  useEffect(() => {
    if (tab === "history") history.loadHistory(history.page, history.pageSize);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, history.page, history.pageSize]);

  const rules = (policy && policy.rules) || [];
  const blocks = (policy && policy.recent_blocks) || [];
  const riskBanners = (policy && policy.risk_banners) || [];

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
          <Button
            variant="secondary"
            onClick={() => {
              load();
              if (tab === "history") history.loadHistory(history.page, history.pageSize);
            }}
          >
            Refresh
          </Button>
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
      {tab === "settings" ? (
        <SettingsTab
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
          onPatchSecurityRule={actions.patchSecurityRule}
          languagePacksSaving={actions.languagePacksSaving}
          onPatchLanguagePack={actions.patchLanguagePack}
          onSetAllLanguagePacks={actions.setAllLanguagePacks}
        />
      ) : null}
      {tab === "tools" ? (
        <ToolsTab
          policy={policy}
          unknownTools={unknownTools}
          unknownToolsSaving={actions.unknownToolsSaving}
          onChangeUnknownTools={actions.saveUnknownTools}
          onNewOverride={actions.openCreateOverride}
          onEditOverride={actions.openEditOverride}
          onToggleOverride={actions.toggleOverride}
          onDeleteOverride={actions.deleteOverride}
        />
      ) : null}
      {tab === "rules" ? (
        <RulesTab
          rules={rules}
          onNewRule={actions.openCreate}
          onEditRule={actions.openEdit}
          onPatchRule={actions.patchRule}
          onDeleteRule={actions.deleteRule}
          onMoveRule={actions.moveRule}
        />
      ) : null}
      {tab === "blocks" ? (
        <BlocksTab blocks={blocks} onApprovalAction={actions.approvalAction} />
      ) : null}
      {tab === "history" ? (
        <HistoryTab
          activity={history.activity}
          loading={history.loading}
          error={history.error}
          total={history.total}
          page={history.page}
          pageSize={history.pageSize}
          setPage={history.setPage}
          setPageSize={history.setPageSize}
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
