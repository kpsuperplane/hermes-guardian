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
  ReadingTool,
  Rule,
  RuleForm,
  SharingTool,
  SourceSuggestion,
  ToastVariant,
} from "@/types";

export interface GuardianActionDeps {
  policy: Policy | null;
  load: () => Promise<void>;
  egressSafety: string;
  setEgressSafety: (mode: string) => void;
  taintClassification: string;
  setTaintClassification: (mode: string) => void;
  llmSourceClassification: boolean;
  setLlmSourceClassification: (enabled: boolean) => void;
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
    egressSafety,
    setEgressSafety,
    taintClassification,
    setTaintClassification,
    llmSourceClassification,
    setLlmSourceClassification,
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
  const [taintClassificationSaving, setTaintClassificationSaving] = useState(false);
  const [llmSourceClassificationSaving, setLlmSourceClassificationSaving] = useState(false);
  const [userContextSaving, setUserContextSaving] = useState(false);
  const [cronContextSaving, setCronContextSaving] = useState(false);
  const [persistPromptsSaving, setPersistPromptsSaving] = useState(false);
  const [verifierModelSaving, setVerifierModelSaving] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<RuleForm>(Object.assign({}, DEFAULT_FORM));
  const [formError, setFormError] = useState("");
  const [showOverrideModal, setShowOverrideModal] = useState(false);
  const [toolFormKind, setToolFormKind] = useState<"reading" | "sharing">("reading");
  const [overrideForm, setOverrideForm] = useState<OverrideForm>(
    Object.assign({}, DEFAULT_OVERRIDE_FORM),
  );
  const [overrideFormError, setOverrideFormError] = useState("");
  const [sourceSuggestions, setSourceSuggestions] = useState<SourceSuggestion[]>([]);

  function saveMode(nextMode: string) {
    const mode = text(nextMode, egressSafety);
    if (mode === egressSafety) return;
    const previousMode = egressSafety;
    const body: { mode: string; confirm?: string } = { mode };
    if (mode === "off") {
      if (
        !window.confirm(
          "Turn Egress Safety off? Security-sensitive blocking remains active.",
        )
      ) {
        return;
      }
      body.confirm = "egress-safety-off";
    }
    setEgressSafety(mode);
    setModeSaving(true);
    api("/privacy/egress-safety", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setEgressSafety(previousMode);
        showToast(errText(err), "error");
      })
      .finally(() => setModeSaving(false));
  }

  function saveTaintClassification(nextMode: string) {
    const mode = text(nextMode, taintClassification);
    if (mode === taintClassification) return;
    const previousMode = taintClassification;
    const body: { mode: string; confirm?: string } = { mode };
    if (mode === "relaxed") {
      if (
        !window.confirm(
          "Relax Taint Classification? Unrecognized tools will not be gated under taint.",
        )
      ) {
        return;
      }
      body.confirm = "taint-classification-relaxed";
    }
    setTaintClassification(mode);
    setTaintClassificationSaving(true);
    api("/reading/taint-classification", { method: "POST", body: JSON.stringify(body) })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setTaintClassification(previousMode);
        showToast(errText(err), "error");
      })
      .finally(() => setTaintClassificationSaving(false));
  }

  function saveLlmSourceClassification(enabled: boolean) {
    if (enabled === llmSourceClassification) return;
    const previous = llmSourceClassification;
    setLlmSourceClassification(enabled);
    setLlmSourceClassificationSaving(true);
    api("/reading/llm-source-classification", {
      method: "POST",
      body: JSON.stringify({ enabled }),
    })
      .then((payload) => {
        showToast(payload.message || "Saved.");
        return load();
      })
      .catch((err) => {
        setLlmSourceClassification(previous);
        showToast(errText(err), "error");
      })
      .finally(() => setLlmSourceClassificationSaving(false));
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

  function openCreateReadingTool(match?: string) {
    setToolFormKind("reading");
    setOverrideForm(Object.assign({}, DEFAULT_OVERRIDE_FORM, { match: text(match) }));
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function openEditReadingTool(tool: ReadingTool) {
    setToolFormKind("reading");
    setOverrideForm({
      id: text(tool.id),
      match: text(tool.match),
      egress: "",
      source: text(tool.source),
      destination: "",
      taints: Array.isArray(tool.taints) ? tool.taints.slice() : [],
      note: text(tool.note),
      enabled: tool.enabled !== false,
      isEdit: true,
    });
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function openCreateSharingTool(match?: string) {
    setToolFormKind("sharing");
    setOverrideForm(Object.assign({}, DEFAULT_OVERRIDE_FORM, { match: text(match) }));
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function openEditSharingTool(tool: SharingTool) {
    setToolFormKind("sharing");
    setOverrideForm({
      id: text(tool.id),
      match: text(tool.match),
      egress: text(tool.egress),
      source: "",
      destination: text(tool.destination),
      taints: [],
      note: text(tool.note),
      enabled: tool.enabled !== false,
      isEdit: true,
    });
    setOverrideFormError("");
    setShowOverrideModal(true);
  }

  function submitToolClassification(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const current = overrideForm;
    if (!text(current.match)) {
      setOverrideFormError("Provide a tool name or prefix (e.g. mcp_acme_*).");
      return;
    }
    const readingPayload: {
      match: string;
      source: string;
      taints: string[];
      note: string;
      enabled: boolean;
      confirm?: string;
    } = {
      match: current.match,
      source: current.source || "",
      taints: current.taints || [],
      note: current.note || "",
      enabled: current.enabled !== false,
    };
    const sharingPayload: {
      match: string;
      egress: string;
      destination: string;
      note: string;
      enabled: boolean;
      confirm?: string;
    } = {
      match: current.match,
      egress: current.egress || "",
      destination: current.destination || "",
      note: current.note || "",
      enabled: current.enabled !== false,
    };
    if (toolFormKind === "sharing" && current.egress === "ignore") {
      if (
        !window.confirm(
          "Mark '" +
            current.match +
            "' as a safe non-sink (No egress)? It will be allowed even under taint.",
        )
      ) {
        return;
      }
      sharingPayload.confirm = "tool-ignore";
    }
    if (toolFormKind === "reading" && current.source === "reference") {
      if (
        !window.confirm(
          "Treat reads from '" +
            current.match +
            "' as reference material? Their content will be scanned leniently (placeholder-tolerant).",
        )
      ) {
        return;
      }
      readingPayload.confirm = "source-reference";
    }
    if (toolFormKind === "reading" && current.source === "public") {
      if (
        !window.confirm(
          "Treat reads from '" +
            current.match +
            "' as public? Guardian will not privacy-taint from this tool's results.",
        )
      ) {
        return;
      }
      readingPayload.confirm = "source-public";
    }
    setOverrideFormError("");
    api(toolFormKind === "reading" ? "/reading/tools" : "/sharing/tools", {
      method: "POST",
      body: JSON.stringify(toolFormKind === "reading" ? readingPayload : sharingPayload),
    })
      .then((result) => {
        showToast(result.message || "Tool classification saved.");
        setShowOverrideModal(false);
        return load();
      })
      .catch((err) => {
        setOverrideFormError(errText(err));
      });
  }

  function toggleReadingTool(tool: ReadingTool) {
    const enabled = tool.enabled !== false;
    api("/reading/tools/" + encodeURIComponent(text(tool.id)), {
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

  function deleteReadingTool(tool: ReadingTool) {
    if (!window.confirm("Delete the Reading tool classification for '" + text(tool.match) + "'?")) return;
    api("/reading/tools/" + encodeURIComponent(text(tool.id)), { method: "DELETE" })
      .then((result) => {
        showToast(result.message || "Deleted.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function toggleSharingTool(tool: SharingTool) {
    const enabled = tool.enabled !== false;
    api("/sharing/tools/" + encodeURIComponent(text(tool.id)), {
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

  function deleteSharingTool(tool: SharingTool) {
    if (!window.confirm("Delete the Sharing tool classification for '" + text(tool.match) + "'?")) return;
    api("/sharing/tools/" + encodeURIComponent(text(tool.id)), { method: "DELETE" })
      .then((result) => {
        showToast(result.message || "Deleted.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  function loadSourceSuggestions() {
    return api("/reading/source-suggestions")
      .then((value: { suggestions?: SourceSuggestion[] }) => {
        setSourceSuggestions((value && value.suggestions) || []);
      })
      .catch(() => {
        setSourceSuggestions([]);
      });
  }

  function classifySource(server: string, mode: "reference" | "private" | "public" | "unknown") {
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
    if (mode === "public") {
      if (
        !window.confirm(
          "Treat reads from '" +
            server +
            "' as public? Guardian will not privacy-taint from this source's results.",
        )
      ) {
        return;
      }
      body.confirm = "source-public";
    }
    api("/reading/source-classification", { method: "POST", body: JSON.stringify(body) })
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
    taintClassificationSaving,
    llmSourceClassificationSaving,
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
    toolFormKind,
    overrideForm,
    setOverrideForm,
    overrideFormError,
    // settings / tools
    saveMode,
    saveTaintClassification,
    saveLlmSourceClassification,
    saveUserContext,
    saveCronContext,
    savePersistPrompts,
    saveVerifierModel,
    patchSecurityRule,
    patchLanguagePack,
    setAllLanguagePacks,
    openCreateReadingTool,
    openEditReadingTool,
    submitToolClassification,
    toggleReadingTool,
    deleteReadingTool,
    openCreateSharingTool,
    openEditSharingTool,
    toggleSharingTool,
    deleteSharingTool,
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
