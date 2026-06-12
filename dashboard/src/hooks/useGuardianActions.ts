import type * as React from "react";
import { useState } from "@/sdk";
import { api } from "@/api/client";
import { DEFAULT_FORM, DEFAULT_OVERRIDE_FORM } from "@/constants";
import { text } from "@/lib/format";
import { formToPayload, payloadIsWildcardAllow, ruleToForm } from "@/lib/rules";
import type {
  OverrideForm,
  PendingApproval,
  Policy,
  Rule,
  RuleForm,
  SourceSuggestion,
  ToastVariant,
  ToolOverride,
} from "@/types";

export interface GuardianActionDeps {
  policy: Policy | null;
  load: () => Promise<void>;
  privacyMode: string;
  setPrivacyMode: (mode: string) => void;
  unknownTools: string;
  setUnknownTools: (mode: string) => void;
  llmUserContext: boolean;
  setLlmUserContext: (enabled: boolean) => void;
  llmCronContext: boolean;
  setLlmCronContext: (enabled: boolean) => void;
  persistPrompts: boolean;
  setPersistPrompts: (enabled: boolean) => void;
  llmVerifierModel: string;
  setLlmVerifierModel: (model: string) => void;
  reloadApprovals: () => Promise<void>;
  showToast: (message?: unknown, variant?: ToastVariant) => void;
}

// Same-screen approval verbs (Activity tab). A permit grants one approval/ownership/
// trusted-destination method; a dismiss drops the pending approval.
// `structural` marks a trust-boundary-widening method that needs the admin confirm.
export type ApprovalAction =
  | { kind: "permit"; method: string; structural?: boolean }
  | { kind: "dismiss" };

function errText(err: unknown): string {
  return String((err as Error)?.message || err);
}

// All Guardian write operations and the modal/saving state they drive. Keeping
// this out of GuardianPage leaves the page as a thin composition root that just
// wires hooks to the presentational tabs.
export function useGuardianActions(deps: GuardianActionDeps) {
  const {
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
    reloadApprovals,
    showToast,
  } = deps;

  const [modeSaving, setModeSaving] = useState(false);
  const [languagePacksSaving, setLanguagePacksSaving] = useState(false);
  const [unknownToolsSaving, setUnknownToolsSaving] = useState(false);
  const [userContextSaving, setUserContextSaving] = useState(false);
  const [cronContextSaving, setCronContextSaving] = useState(false);
  const [persistPromptsSaving, setPersistPromptsSaving] = useState(false);
  const [verifierModelSaving, setVerifierModelSaving] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<RuleForm>(Object.assign({}, DEFAULT_FORM));
  const [formError, setFormError] = useState("");
  const [showOverrideModal, setShowOverrideModal] = useState(false);
  const [overrideForm, setOverrideForm] = useState<OverrideForm>(
    Object.assign({}, DEFAULT_OVERRIDE_FORM),
  );
  const [overrideFormError, setOverrideFormError] = useState("");
  const [sourceSuggestions, setSourceSuggestions] = useState<SourceSuggestion[]>([]);

  function saveMode(nextMode: string) {
    const mode = text(nextMode, privacyMode);
    if (mode === privacyMode) return;
    const previousMode = privacyMode;
    const body: { mode: string; confirm?: string } = { mode };
    if (mode === "off") {
      if (
        !window.confirm(
          "Turn Guardian privacy egress checks off? Security-sensitive blocking remains active.",
        )
      ) {
        return;
      }
      body.confirm = "privacy-off";
    }
    setPrivacyMode(mode);
    setModeSaving(true);
    api("/privacy/mode", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setPrivacyMode(previousMode);
        showToast(errText(err), "error");
      })
      .finally(() => setModeSaving(false));
  }

  function saveUnknownTools(nextMode: string) {
    const mode = text(nextMode, unknownTools);
    if (mode === unknownTools) return;
    const previousMode = unknownTools;
    const body: { mode: string; confirm?: string } = { mode };
    if (mode === "allow") {
      if (
        !window.confirm(
          "Allow unrecognized tools to run untracked under taint? This restores the legacy fail-open behavior and reduces protection.",
        )
      ) {
        return;
      }
      body.confirm = "unknown-tools-allow";
    }
    setUnknownTools(mode);
    setUnknownToolsSaving(true);
    api("/privacy/unknown-tools", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setUnknownTools(previousMode);
        showToast(errText(err), "error");
      })
      .finally(() => setUnknownToolsSaving(false));
  }

  function saveUserContext(enabled: boolean) {
    if (enabled === llmUserContext) return;
    const previous = llmUserContext;
    setLlmUserContext(enabled);
    setUserContextSaving(true);
    api("/privacy/user-context", { method: "POST", body: JSON.stringify({ enabled }) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setLlmUserContext(previous);
        showToast(errText(err), "error");
      })
      .finally(() => setUserContextSaving(false));
  }

  function saveCronContext(enabled: boolean) {
    if (enabled === llmCronContext) return;
    const previous = llmCronContext;
    const body: { enabled: boolean; confirm?: string } = { enabled };
    if (enabled) {
      if (
        !window.confirm(
          "Enable cron context? Cron jobs will supply their own stored instruction to the LLM approver as authorization evidence. High-risk cron egress still always requires manual approval.",
        )
      ) {
        return;
      }
      body.confirm = "cron-context-on";
    }
    setLlmCronContext(enabled);
    setCronContextSaving(true);
    api("/privacy/cron-context", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setLlmCronContext(previous);
        showToast(errText(err), "error");
      })
      .finally(() => setCronContextSaving(false));
  }

  function savePersistPrompts(enabled: boolean) {
    if (enabled === persistPrompts) return;
    const previous = persistPrompts;
    const body: { enabled: boolean; confirm?: string } = { enabled };
    if (enabled) {
      if (
        !window.confirm(
          "Turn on prompt persistence? The sanitized user/cron prompt will be written to the activity log for debugging. This relaxes the metadata-only invariant — turn it off when you're done.",
        )
      ) {
        return;
      }
      body.confirm = "persist-prompts-on";
    }
    setPersistPrompts(enabled);
    setPersistPromptsSaving(true);
    api("/protection/persist-prompts", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setPersistPrompts(previous);
        showToast(errText(err), "error");
      })
      .finally(() => setPersistPromptsSaving(false));
  }

  function saveVerifierModel(nextModel: string) {
    const model = text(nextModel).trim();
    if (model === (llmVerifierModel || "")) return;
    const previous = llmVerifierModel;
    setLlmVerifierModel(model);
    setVerifierModelSaving(true);
    api("/privacy/verifier-model", { method: "POST", body: JSON.stringify({ model }) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setLlmVerifierModel(previous);
        showToast(errText(err), "error");
      })
      .finally(() => setVerifierModelSaving(false));
  }

  function openCreateOverride() {
    setOverrideForm(Object.assign({}, DEFAULT_OVERRIDE_FORM));
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function openEditOverride(override: ToolOverride) {
    setOverrideForm({
      id: text(override.id),
      match: text(override.match),
      egress: text(override.egress),
      source: text(override.source),
      destination: text(override.destination),
      taints: Array.isArray(override.taints) ? override.taints.slice() : [],
      note: text(override.note),
      enabled: override.enabled !== false,
      isEdit: true,
    });
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function submitOverride(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const current = overrideForm;
    if (!text(current.match)) {
      setOverrideFormError("Provide a tool name or prefix (e.g. mcp_acme_*).");
      return;
    }
    const payload: {
      match: string;
      egress: string;
      source: string;
      destination: string;
      taints: string[];
      note: string;
      enabled: boolean;
      confirm?: string;
    } = {
      match: current.match,
      egress: current.egress || "",
      source: current.source || "",
      destination: current.destination || "",
      taints: current.taints || [],
      note: current.note || "",
      enabled: current.enabled !== false,
    };
    if (current.egress === "ignore") {
      if (
        !window.confirm(
          "Mark '" +
            current.match +
            "' as a safe non-sink (No egress)? It will be allowed even under taint.",
        )
      ) {
        return;
      }
      payload.confirm = "tool-ignore";
    }
    setOverrideFormError("");
    api("/tools", { method: "POST", body: JSON.stringify(payload) })
      .then((result) => {
        showToast(result.message || "Override saved.");
        setShowOverrideModal(false);
        return load();
      })
      .catch((err) => {
        setOverrideFormError(errText(err));
      });
  }

  function toggleOverride(override: ToolOverride) {
    const enabled = override.enabled !== false;
    api("/tools/" + encodeURIComponent(text(override.id)), {
      method: "PATCH",
      body: JSON.stringify({ enabled: !enabled }),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function deleteOverride(override: ToolOverride) {
    if (!window.confirm("Delete the tool override for '" + text(override.match) + "'?")) return;
    api("/tools/" + encodeURIComponent(text(override.id)), { method: "DELETE" })
      .then((result) => {
        showToast(result.message || "Deleted.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function loadSourceSuggestions() {
    return api("/tools/source-suggestions")
      .then((value: { suggestions?: SourceSuggestion[] }) => {
        setSourceSuggestions((value && value.suggestions) || []);
      })
      .catch(() => {
        setSourceSuggestions([]);
      });
  }

  function classifySource(server: string, mode: "reference" | "private") {
    const body: { server: string; source: string; confirm?: string } = { server, source: mode };
    if (mode === "reference") {
      if (
        !window.confirm(
          "Treat reads from '" +
            server +
            "' as reference material? Their content will be scanned leniently (placeholder-tolerant).",
        )
      ) {
        return;
      }
      body.confirm = "source-reference";
    }
    api("/tools/source", { method: "POST", body: JSON.stringify(body) })
      .then((result) => {
        showToast(result.message || "Source classified.");
        return Promise.all([loadSourceSuggestions(), load()]);
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function openCreate() {
    setForm(Object.assign({}, DEFAULT_FORM));
    setFormError("");
    setShowModal(true);
  }

  function openEdit(rule: Rule) {
    setForm(ruleToForm(rule));
    setFormError("");
    setShowModal(true);
  }

  function submitRule(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!form.data_classes || !form.data_classes.length) {
      setFormError("Select at least one data class or choose All data classes.");
      return;
    }
    const payload = formToPayload(form);
    if (payloadIsWildcardAllow(payload)) {
      if (
        !window.confirm(
          "Create a wildcard allow rule for all tools, destinations, and data classes?",
        )
      ) {
        return;
      }
      payload.confirm = "wildcard-allow";
    }
    const request = form.id
      ? api("/rules/" + encodeURIComponent(form.id), {
          method: "PATCH",
          body: JSON.stringify(payload),
        })
      : api("/rules", {
          method: "POST",
          body: JSON.stringify(Object.assign({ enabled: true }, payload)),
        });
    setFormError("");
    request
      .then((result) => {
        showToast(result.message || "Rule saved.");
        setShowModal(false);
        return load();
      })
      .catch((err) => {
        setFormError(errText(err));
      });
  }

  function patchRule(ruleId: string, payload: Record<string, unknown>) {
    return api("/rules/" + encodeURIComponent(ruleId), {
      method: "PATCH",
      body: JSON.stringify(payload),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function patchSecurityRule(ruleId: string, enabled: boolean) {
    return api("/security/rules/" + encodeURIComponent(ruleId), {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function patchLanguagePack(packId: string, enabled: boolean) {
    setLanguagePacksSaving(true);
    return api("/language-packs/" + encodeURIComponent(packId), {
      method: "PATCH",
      body: JSON.stringify({ enabled }),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      })
      .finally(() => setLanguagePacksSaving(false));
  }

  function setAllLanguagePacks(enabled: boolean) {
    const currentLanguagePacks = (policy && policy.language_packs) || [];
    const targets = currentLanguagePacks.filter(
      (pack) => pack.required !== true && (pack.enabled !== false) !== enabled,
    );
    if (!targets.length) {
      showToast(
        enabled
          ? "All language packs are already enabled."
          : "Optional language packs are already disabled.",
      );
      return;
    }
    setLanguagePacksSaving(true);
    let request: Promise<unknown> = Promise.resolve(null);
    targets.forEach((pack) => {
      request = request.then(() =>
        api("/language-packs/" + encodeURIComponent(pack.id), {
          method: "PATCH",
          body: JSON.stringify({ enabled }),
        }),
      );
    });
    request
      .then(() => {
        showToast(
          enabled
            ? "Enabled all optional language packs."
            : "Disabled all optional language packs.",
        );
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      })
      .finally(() => setLanguagePacksSaving(false));
  }

  function deleteRule(ruleId: string) {
    if (!window.confirm("Delete this persistent Guardian privacy rule?")) return;
    api("/rules/" + encodeURIComponent(ruleId), { method: "DELETE" })
      .then((result) => {
        showToast(result.message || "Deleted.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function moveRule(rule: Rule, direction: "up" | "down") {
    const rules = (policy && policy.rules) || [];
    const index = rules.findIndex((candidate) => candidate.rule_id === rule.rule_id);
    const target = direction === "up" ? rules[index - 1] : rules[index + 1];
    if (!target) return;
    patchRule(rule.rule_id as string, {
      move: { where: direction === "up" ? "before" : "after", target_id: target.rule_id },
    });
  }

  function clearTaintAction() {
    if (
      !window.confirm(
        "Clear Guardian taint for your active Guardian sessions?",
      )
    ) {
      return;
    }
    api("/privacy/clear-taint", { method: "POST", body: JSON.stringify({}) })
      .then((result) => {
        showToast(result.message || "Cleared.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function approvalAction(approval: PendingApproval, action: ApprovalAction) {
    const actionId = text(approval.id);
    if (!actionId) return;
    // Structural permits permanently widen what counts as yours/trusted; confirm first
    // (mirroring the destination-trust edits) and send the same confirmation token.
    if (action.kind === "permit" && action.structural) {
      if (
        !window.confirm(
          "This permanently changes what Guardian treats as yours or trusted, for every " +
            "future action — not just this one. Continue?",
        )
      ) {
        return;
      }
    }
    const path =
      action.kind === "dismiss"
        ? "/approvals/" + encodeURIComponent(actionId) + "/dismiss"
        : "/approvals/" + encodeURIComponent(actionId) + "/approve";
    const body: Record<string, unknown> =
      action.kind === "dismiss"
        ? {}
        : action.structural
          ? { method: action.method, confirm: "destination-trust" }
          : { method: action.method };
    api(path, {
      method: "POST",
      body: JSON.stringify(body),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        // Refresh the pending-approvals list so the acted-on item disappears without a
        // manual page refresh; also refresh the policy snapshot (taint/banners).
        reloadApprovals();
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
        // Re-sync in case the item already resolved server-side.
        reloadApprovals();
      });
  }

  return {
    // saving flags
    modeSaving,
    unknownToolsSaving,
    userContextSaving,
    cronContextSaving,
    verifierModelSaving,
    persistPromptsSaving,
    languagePacksSaving,
    // rule modal
    showModal,
    setShowModal,
    form,
    setForm,
    formError,
    // override modal
    showOverrideModal,
    setShowOverrideModal,
    overrideForm,
    setOverrideForm,
    overrideFormError,
    // settings / tools
    saveMode,
    saveUnknownTools,
    saveUserContext,
    saveCronContext,
    savePersistPrompts,
    saveVerifierModel,
    patchSecurityRule,
    patchLanguagePack,
    setAllLanguagePacks,
    openCreateOverride,
    openEditOverride,
    submitOverride,
    toggleOverride,
    deleteOverride,
    sourceSuggestions,
    loadSourceSuggestions,
    classifySource,
    // rules
    openCreate,
    openEdit,
    submitRule,
    patchRule,
    deleteRule,
    moveRule,
    // activity
    approvalAction,
    clearTaintAction,
  };
}
