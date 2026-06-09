import type * as React from "react";
import { useState } from "@/sdk";
import { api } from "@/api/client";
import { DEFAULT_FORM, DEFAULT_OVERRIDE_FORM } from "@/constants";
import { text } from "@/lib/format";
import { formToPayload, payloadIsWildcardAllow, ruleToForm } from "@/lib/rules";
import type { ApprovalAction } from "@/tabs/BlocksTab";
import type {
  OverrideForm,
  Policy,
  RecentBlock,
  Rule,
  RuleForm,
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
  showToast: (message?: unknown, variant?: ToastVariant) => void;
}

function errText(err: unknown): string {
  return String((err as Error)?.message || err);
}

// All Guardian write operations and the modal/saving state they drive. Keeping
// this out of GuardianPage leaves the page as a thin composition root that just
// wires hooks to the presentational tabs.
export function useGuardianActions(deps: GuardianActionDeps) {
  const { policy, load, privacyMode, setPrivacyMode, unknownTools, setUnknownTools, showToast } =
    deps;

  const [modeSaving, setModeSaving] = useState(false);
  const [languagePacksSaving, setLanguagePacksSaving] = useState(false);
  const [unknownToolsSaving, setUnknownToolsSaving] = useState(false);
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<RuleForm>(Object.assign({}, DEFAULT_FORM));
  const [formError, setFormError] = useState("");
  const [showOverrideModal, setShowOverrideModal] = useState(false);
  const [overrideForm, setOverrideForm] = useState<OverrideForm>(
    Object.assign({}, DEFAULT_OVERRIDE_FORM),
  );
  const [overrideFormError, setOverrideFormError] = useState("");

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
      destination: string;
      taints: string[];
      note: string;
      enabled: boolean;
      confirm?: string;
    } = {
      match: current.match,
      egress: current.egress || "",
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

  function approvalAction(block: RecentBlock, action: ApprovalAction) {
    const actionId =
      action === "dismiss"
        ? text(block.dismiss_id || block.approval_id || block.id)
        : text(block.approval_id || block.id);
    if (!actionId) return;
    const path =
      action === "dismiss"
        ? "/approvals/" + encodeURIComponent(actionId) + "/dismiss"
        : "/approvals/" + encodeURIComponent(actionId) + "/approve";
    const body = action === "approve-always" ? { scope: "always" } : { scope: "once" };
    api(path, {
      method: "POST",
      body: JSON.stringify(action === "dismiss" ? {} : body),
    })
      .then((result) => {
        showToast(result.message || "Updated.");
        return load();
      })
      .catch((err) => {
        showToast(errText(err), "error");
      });
  }

  return {
    // saving flags
    modeSaving,
    unknownToolsSaving,
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
    patchSecurityRule,
    patchLanguagePack,
    setAllLanguagePacks,
    openCreateOverride,
    openEditOverride,
    submitOverride,
    toggleOverride,
    deleteOverride,
    // rules
    openCreate,
    openEdit,
    submitRule,
    patchRule,
    deleteRule,
    moveRule,
    // blocks
    approvalAction,
  };
}
