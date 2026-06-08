(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK || !window.__HERMES_PLUGINS__) return;

  const React = SDK.React;
  const hooks = SDK.hooks;
  const h = React.createElement;
  const API = "/api/plugins/hermes-guardian";

  const ACTIONS = ["*", "browser_console", "browser_read", "browser_type", "cron_write", "final_response", "local_write", "mcp_read_query", "mcp_unknown", "mcp_write", "message_send", "terminal_exec", "web_api", "web_read"];
  const HISTORY_PAGE_SIZES = [25, 50, 100];
  const DEFAULT_FORM = {
    id: "",
    enabled: true,
    effect: "allow",
    action_family: "*",
    destination: "",
    tool_name: "",
    data_classes: ["*"],
    lifetime: "always",
    remaining_invocations: 5,
    owner_hash: "",
    session_id: "",
    cron_job_id: "",
    cron_job_name: "",
  };

  function api(path, options) {
    const init = Object.assign({}, options || {});
    if (init.body) {
      const headers = new Headers(init.headers || {});
      if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
      init.headers = headers;
    }
    return SDK.fetchJSON(API + path, init);
  }

  function text(value, fallback) {
    const out = value == null ? "" : String(value);
    return out || (fallback || "");
  }

  function displayText(value, fallback) {
    const out = text(value, "");
    return out === "*" ? (fallback || "Any") : (out || (fallback || "Any"));
  }

  function classesText(classes) {
    return Array.isArray(classes) && classes.length ? classes.join(", ") : "none";
  }

  function timeText(seconds) {
    const value = Number(seconds || 0);
    if (!Number.isFinite(value) || value <= 0) return "n/a";
    return new Date(value * 1000).toLocaleString();
  }

  function ruleScopeText(rule) {
    const cronName = text(rule.cron_job_name);
    const cronId = text(rule.cron_job_id);
    if (cronName || cronId) return "[Cron] " + (cronName || cronId);
    if (text(rule.session_id)) return "Session scoped";
    const owner = text(rule.owner_hash);
    const scope = text(rule.scope).toLowerCase();
    if (!owner || owner === "*" || scope === "all owners" || scope === "global") return "Runs everywhere";
    if (scope === "session") return "Session scoped";
    if (scope.indexOf("cron job ") === 0) return "[Cron] " + scope.slice("cron job ".length).replace(/\s+\([^)]+\)$/, "");
    return "Owner scoped";
  }

  function remainingPillText(rule) {
    const remaining = Number(rule.remaining_invocations);
    if (!Number.isFinite(remaining) || remaining < 0) return "";
    return remaining === 1 ? "1 invocation left" : Math.trunc(remaining) + " invocations left";
  }

  function ruleToForm(rule) {
    const remaining = Number(rule.remaining_invocations);
    let lifetime = "always";
    let custom = 5;
    if (Number.isFinite(remaining) && remaining === 1) {
      lifetime = "once";
      custom = 1;
    } else if (Number.isFinite(remaining) && remaining > 1) {
      lifetime = "custom";
      custom = Math.trunc(remaining);
    }
    return {
      id: text(rule.rule_id || rule.id),
      enabled: rule.enabled !== false,
      effect: text(rule.effect, "allow"),
      action_family: text(rule.action_family, "*"),
      destination: text(rule.destination) === "*" ? "" : text(rule.destination),
      tool_name: text(rule.tool_name) === "*" ? "" : text(rule.tool_name),
      data_classes: Array.isArray(rule.data_classes) && rule.data_classes.length ? rule.data_classes.slice() : ["*"],
      lifetime: lifetime,
      remaining_invocations: custom,
      owner_hash: text(rule.owner_hash) === "*" ? "" : text(rule.owner_hash),
      session_id: text(rule.session_id),
      cron_job_id: text(rule.cron_job_id),
      cron_job_name: text(rule.cron_job_name),
    };
  }

  function formToPayload(form) {
    let remaining = -1;
    if (form.lifetime === "once") remaining = 1;
    if (form.lifetime === "custom") remaining = Math.max(1, Math.trunc(Number(form.remaining_invocations) || 1));
    const classes = form.data_classes && form.data_classes.length ? form.data_classes : ["*"];
    return {
      effect: form.effect,
      match: {
        tool_name: text(form.tool_name, "*"),
        action_family: text(form.action_family, "*"),
        destination: text(form.destination, "*"),
        data_classes: classes.indexOf("*") >= 0 ? ["*"] : classes,
      },
      scope: {
        owner_hash: text(form.owner_hash, "*"),
        session_id: text(form.session_id),
        cron_job_id: text(form.cron_job_id),
        cron_job_name: text(form.cron_job_name),
      },
      remaining_invocations: remaining,
    };
  }

  function payloadIsWildcardAllow(payload) {
    const match = payload && payload.match ? payload.match : {};
    const classes = Array.isArray(match.data_classes) ? match.data_classes : [];
    return payload.effect === "allow"
      && text(match.tool_name, "*") === "*"
      && text(match.action_family, "*") === "*"
      && text(match.destination, "*") === "*"
      && classes.indexOf("*") >= 0;
  }

  function Field(props) {
    return h("label", { className: "hermes-guardian-field" },
      props.label,
      props.children,
    );
  }

  function Button(props) {
    const cls = props.variant === "danger" ? "hermes-guardian-danger" : props.variant === "secondary" ? "hermes-guardian-secondary" : "hermes-guardian-button";
    return h("button", Object.assign({}, props, { className: cls, type: props.type || "button", variant: undefined }), props.children);
  }

  function ToastRegion(props) {
    const toasts = props.toasts || [];
    if (!toasts.length) return null;
    return h("div", { className: "hermes-guardian-toast-region", "aria-live": "polite", "aria-atomic": "false" },
      toasts.map(function (toast) {
        const classes = ["hermes-guardian-toast"];
        if (toast.variant === "error") classes.push("hermes-guardian-toast-error");
        return h("div", { key: toast.id, className: classes.join(" "), role: toast.variant === "error" ? "alert" : "status" },
          h("div", { className: "hermes-guardian-toast-message" }, toast.message),
          h("button", {
            type: "button",
            className: "hermes-guardian-toast-close",
            "aria-label": "Dismiss notification",
            onClick: function () { props.onDismiss(toast.id); },
          }, "x"),
        );
      }),
    );
  }

  function RuleModal(props) {
    const policy = props.policy || {};
    const allClasses = policy.all_privacy_classes || ["contacts", "email", "files", "location", "messages", "personal", "secrets"];
    const cronJobs = policy.cron_jobs || [];
    const suggestions = policy.suggestions || {};
    const destinationSuggestions = policy.destination_suggestions || suggestions.destinations || [];
    const toolNameSuggestions = policy.tool_name_suggestions || suggestions.tool_names || [];
    const form = props.form;
    const setForm = props.setForm;
    const classSet = new Set(form.data_classes || ["*"]);

    function update(key, value) {
      setForm(Object.assign({}, form, { [key]: value }));
    }

    function toggleClass(cls) {
      if (cls === "*") {
        update("data_classes", classSet.has("*") ? [] : ["*"]);
        return;
      }
      const next = new Set(classSet);
      next.delete("*");
      if (next.has(cls)) next.delete(cls);
      else next.add(cls);
      update("data_classes", Array.from(next).sort());
    }

    function setCron(jobId) {
      const job = cronJobs.find(function (candidate) { return candidate.id === jobId; });
      setForm(Object.assign({}, form, {
        cron_job_id: jobId || "",
        cron_job_name: job ? job.name : "",
      }));
    }

    return h("div", { className: "hermes-guardian-modal-backdrop", role: "presentation", onMouseDown: function (event) {
      if (event.target === event.currentTarget) props.onCancel();
    } },
      h("form", { className: "hermes-guardian-modal", onSubmit: props.onSubmit },
        h("div", { className: "hermes-guardian-card-head" },
          h("div", null,
            h("h2", { className: "hermes-guardian-title" }, form.id ? "Edit rule" : "New rule"),
            h("div", { className: "hermes-guardian-subtitle" }, form.id ? form.id : "Create a privacy allow or deny rule"),
          ),
          h(Button, { variant: "secondary", onClick: props.onCancel }, "Close"),
        ),
        h("div", { className: "hermes-guardian-modal-body" },
          h("datalist", { id: "hermes-guardian-destination-options" }, destinationSuggestions.map(function (value) {
            return h("option", { key: value, value: value });
          })),
          h("datalist", { id: "hermes-guardian-tool-name-options" }, toolNameSuggestions.map(function (value) {
            return h("option", { key: value, value: value });
          })),
          h("div", { className: "hermes-guardian-radio-row" },
            h("label", { className: "hermes-guardian-check" }, h("input", { type: "radio", checked: form.effect === "allow", onChange: function () { update("effect", "allow"); } }), "Allow"),
            h("label", { className: "hermes-guardian-check" }, h("input", { type: "radio", checked: form.effect === "deny", onChange: function () { update("effect", "deny"); } }), "Deny"),
          ),
          h("div", { className: "hermes-guardian-form-grid" },
            h(Field, { label: "Action family" }, h("select", { className: "hermes-guardian-select", value: form.action_family, onChange: function (event) { update("action_family", event.target.value); } }, ACTIONS.map(function (value) {
              return h("option", { key: value, value: value }, value);
            }))),
            h(Field, { label: "Destination" }, h("input", { className: "hermes-guardian-input", list: "hermes-guardian-destination-options", value: form.destination, placeholder: "Any destination", onChange: function (event) { update("destination", event.target.value); } })),
            h(Field, { label: "Tool name" }, h("input", { className: "hermes-guardian-input", list: "hermes-guardian-tool-name-options", value: form.tool_name, placeholder: "Any tool", onChange: function (event) { update("tool_name", event.target.value); } })),
          ),
          h("div", { className: "hermes-guardian-check-grid" },
            h("label", { className: "hermes-guardian-check" }, h("input", { type: "checkbox", checked: classSet.has("*"), onChange: function () { toggleClass("*"); } }), "All data classes"),
            allClasses.map(function (cls) {
              return h("label", { key: cls, className: "hermes-guardian-check" },
                h("input", { type: "checkbox", checked: !classSet.has("*") && classSet.has(cls), onChange: function () { toggleClass(cls); } }),
                cls,
              );
            }),
          ),
          h("div", { className: "hermes-guardian-form-grid" },
            h(Field, { label: "Invocation count" }, h("select", { className: "hermes-guardian-select", value: form.lifetime, onChange: function (event) { update("lifetime", event.target.value); } },
              h("option", { value: "always" }, "Forever"),
              h("option", { value: "once" }, "Once"),
              h("option", { value: "custom" }, "Custom"),
            )),
            form.lifetime === "custom" ? h(Field, { label: "Custom count" }, h("input", { className: "hermes-guardian-input", inputMode: "numeric", value: form.remaining_invocations, onChange: function (event) { update("remaining_invocations", event.target.value); } })) : null,
          ),
          h("div", { className: "hermes-guardian-form-grid" },
            h(Field, { label: "Owner hash" }, h("input", { className: "hermes-guardian-input", value: form.owner_hash, placeholder: "Any owner", onChange: function (event) { update("owner_hash", event.target.value); } })),
            h(Field, { label: "Session ID" }, h("input", { className: "hermes-guardian-input", value: form.session_id, placeholder: "Any session", onChange: function (event) { update("session_id", event.target.value); } })),
            h(Field, { label: "Cron scope" }, h("select", { className: "hermes-guardian-select", value: form.cron_job_id, onChange: function (event) { setCron(event.target.value); } },
              h("option", { value: "" }, "No cron scope"),
              cronJobs.map(function (job) {
                return h("option", { key: job.id, value: job.id }, job.name + (job.active === false ? " (paused)" : ""));
              }),
            )),
          ),
          props.formError ? h("div", { className: "hermes-guardian-banner" }, props.formError) : null,
          h("div", { className: "hermes-guardian-actions" },
            h(Button, { type: "submit" }, form.id ? "Save changes" : "Create rule"),
            h(Button, { variant: "secondary", onClick: props.onCancel }, "Cancel"),
          ),
        ),
      ),
    );
  }

  function GuardianPage() {
    const useState = hooks.useState;
    const useEffect = hooks.useEffect;
    const useCallback = hooks.useCallback;
    const useRef = hooks.useRef || React.useRef;
    const statePolicy = useState(null);
    const policy = statePolicy[0];
    const setPolicy = statePolicy[1];
    const stateActivity = useState([]);
    const activity = stateActivity[0];
    const setActivity = stateActivity[1];
    const stateHistoryPage = useState(0);
    const historyPage = stateHistoryPage[0];
    const setHistoryPage = stateHistoryPage[1];
    const stateHistoryPageSize = useState(25);
    const historyPageSize = stateHistoryPageSize[0];
    const setHistoryPageSize = stateHistoryPageSize[1];
    const stateHistoryTotal = useState(0);
    const historyTotal = stateHistoryTotal[0];
    const setHistoryTotal = stateHistoryTotal[1];
    const stateHistoryLoading = useState(false);
    const historyLoading = stateHistoryLoading[0];
    const setHistoryLoading = stateHistoryLoading[1];
    const stateHistoryError = useState("");
    const historyError = stateHistoryError[0];
    const setHistoryError = stateHistoryError[1];
    const stateTab = useState("settings");
    const tab = stateTab[0];
    const setTab = stateTab[1];
    const stateLoading = useState(true);
    const loading = stateLoading[0];
    const setLoading = stateLoading[1];
    const stateError = useState("");
    const error = stateError[0];
    const setError = stateError[1];
    const stateToasts = useState([]);
    const toasts = stateToasts[0];
    const setToasts = stateToasts[1];
    const toastTimers = useRef({});
    const stateMode = useState("strict");
    const privacyMode = stateMode[0];
    const setPrivacyMode = stateMode[1];
    const stateModeSaving = useState(false);
    const modeSaving = stateModeSaving[0];
    const setModeSaving = stateModeSaving[1];
    const stateModal = useState(false);
    const showModal = stateModal[0];
    const setShowModal = stateModal[1];
    const stateForm = useState(Object.assign({}, DEFAULT_FORM));
    const form = stateForm[0];
    const setForm = stateForm[1];
    const stateFormError = useState("");
    const formError = stateFormError[0];
    const setFormError = stateFormError[1];

    function dismissToast(id) {
      const timers = toastTimers.current || {};
      if (timers[id]) {
        window.clearTimeout(timers[id]);
        delete timers[id];
      }
      setToasts(function (items) {
        return items.filter(function (toast) { return toast.id !== id; });
      });
    }

    function showToast(message, variant) {
      const id = "toast_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
      const toast = {
        id: id,
        message: text(message, variant === "error" ? "Something went wrong." : "Saved."),
        variant: variant || "success",
      };
      setToasts(function (items) {
        return items.concat([toast]).slice(-4);
      });
      toastTimers.current[id] = window.setTimeout(function () {
        dismissToast(id);
      }, toast.variant === "error" ? 5200 : 3600);
    }

    useEffect(function () {
      return function () {
        const timers = toastTimers.current || {};
        Object.keys(timers).forEach(function (id) {
          window.clearTimeout(timers[id]);
        });
        toastTimers.current = {};
      };
    }, []);

    function loadHistory(page, pageSize) {
      const safePage = Math.max(0, Math.trunc(Number(page) || 0));
      const safeSize = HISTORY_PAGE_SIZES.indexOf(Number(pageSize)) >= 0 ? Number(pageSize) : 25;
      const start = safePage * safeSize;
      setHistoryLoading(true);
      setHistoryError("");
      return api("/activity/datatables?draw=1&start=" + encodeURIComponent(start) + "&length=" + encodeURIComponent(safeSize))
        .then(function (payload) {
          setActivity(payload.data || []);
          setHistoryTotal(Number(payload.recordsFiltered || payload.recordsTotal || 0));
        })
        .catch(function (err) {
          setActivity([]);
          setHistoryTotal(0);
          setHistoryError(String(err.message || err));
        })
        .finally(function () {
          setHistoryLoading(false);
        });
    }

    const load = useCallback(function () {
      setLoading(true);
      setError("");
      return api("/policy").then(function (value) {
        setPolicy(value);
        setPrivacyMode(value.privacy_mode || value.privacy_policy || "strict");
      }).catch(function (err) {
        setError(String(err.message || err));
      }).finally(function () {
        setLoading(false);
      });
    }, []);

    useEffect(function () {
      load();
    }, [load]);

    useEffect(function () {
      if (tab === "history") loadHistory(historyPage, historyPageSize);
    }, [tab, historyPage, historyPageSize]);

    function saveMode() {
      const body = { mode: privacyMode };
      if (privacyMode === "off") {
        if (!window.confirm("Turn Guardian privacy egress checks off? Security-sensitive blocking remains active.")) return;
        body.confirm = "privacy-off";
      }
      setModeSaving(true);
      api("/privacy/mode", { method: "POST", body: JSON.stringify(body) })
        .then(function (payload) {
          showToast(payload.message || "Saved.");
          return load();
        })
        .catch(function (err) { showToast(String(err.message || err), "error"); })
        .finally(function () { setModeSaving(false); });
    }

    function openCreate() {
      setForm(Object.assign({}, DEFAULT_FORM));
      setFormError("");
      setShowModal(true);
    }

    function openEdit(rule) {
      setForm(ruleToForm(rule));
      setFormError("");
      setShowModal(true);
    }

    function submitRule(event) {
      event.preventDefault();
      if (!form.data_classes || !form.data_classes.length) {
        setFormError("Select at least one data class or choose All data classes.");
        return;
      }
      const payload = formToPayload(form);
      if (payloadIsWildcardAllow(payload)) {
        if (!window.confirm("Create a wildcard allow rule for all tools, destinations, and data classes?")) return;
        payload.confirm = "wildcard-allow";
      }
      const request = form.id
        ? api("/rules/" + encodeURIComponent(form.id), { method: "PATCH", body: JSON.stringify(payload) })
        : api("/rules", { method: "POST", body: JSON.stringify(Object.assign({ enabled: true }, payload)) });
      setFormError("");
      request.then(function (result) {
        showToast(result.message || "Rule saved.");
        setShowModal(false);
        return load();
      }).catch(function (err) {
        setFormError(String(err.message || err));
      });
    }

    function patchRule(ruleId, payload) {
      return api("/rules/" + encodeURIComponent(ruleId), { method: "PATCH", body: JSON.stringify(payload) })
        .then(function (result) {
          showToast(result.message || "Updated.");
          return load();
        }).catch(function (err) {
          showToast(String(err.message || err), "error");
        });
    }

    function patchSecurityRule(ruleId, enabled) {
      return api("/security/rules/" + encodeURIComponent(ruleId), { method: "PATCH", body: JSON.stringify({ enabled: enabled }) })
        .then(function (result) {
          showToast(result.message || "Updated.");
          return load();
        }).catch(function (err) {
          showToast(String(err.message || err), "error");
        });
    }

    function patchLanguagePack(packId, enabled) {
      return api("/language-packs/" + encodeURIComponent(packId), { method: "PATCH", body: JSON.stringify({ enabled: enabled }) })
        .then(function (result) {
          showToast(result.message || "Updated.");
          return load();
        }).catch(function (err) {
          showToast(String(err.message || err), "error");
        });
    }

    function deleteRule(ruleId) {
      if (!window.confirm("Delete this persistent Guardian privacy rule?")) return;
      api("/rules/" + encodeURIComponent(ruleId), { method: "DELETE" })
        .then(function (result) {
          showToast(result.message || "Deleted.");
          return load();
        }).catch(function (err) {
          showToast(String(err.message || err), "error");
        });
    }

    function moveRule(rule, direction) {
      const rules = (policy && policy.rules) || [];
      const index = rules.findIndex(function (candidate) { return candidate.rule_id === rule.rule_id; });
      const target = direction === "up" ? rules[index - 1] : rules[index + 1];
      if (!target) return;
      patchRule(rule.rule_id, { move: { where: direction === "up" ? "before" : "after", target_id: target.rule_id } });
    }

    function approvalAction(block, action) {
      const path = action === "dismiss"
        ? "/approvals/" + encodeURIComponent(block.id) + "/dismiss"
        : "/approvals/" + encodeURIComponent(block.id) + "/approve";
      const body = action === "approve-always" ? { scope: "always" } : { scope: "once" };
      api(path, { method: "POST", body: JSON.stringify(action === "dismiss" ? {} : body) })
        .then(function (result) {
          showToast(result.message || "Updated.");
          return load();
        }).catch(function (err) {
          showToast(String(err.message || err), "error");
        });
    }

    function coveredRuleTitle(block) {
      const ruleId = text(block.covered_rule_id);
      const source = text(block.covered_rule_source);
      const prefix = ruleId ? "Covered by " + ruleId : (source ? "Covered by " + source + " rule" : "Covered by an existing rule");
      return prefix + ". The matching allow rule already permits this retry, so approving this pending request is not needed.";
    }

    function approvalButton(block, action, label, disabled, title) {
      const button = h(Button, {
        key: action + "-button",
        disabled: disabled,
        title: title,
        onClick: disabled ? undefined : function () { approvalAction(block, action); },
      }, label);
      if (!disabled) return button;
      return h("span", { key: action, className: "hermes-guardian-disabled-action", title: title }, button);
    }

    function historyTargetCell(row) {
      const tool = text(row.tool_name || row.tool, "n/a");
      const action = text(row.action_family, "n/a");
      const destination = text(row.destination, "n/a");
      return h("div", { className: "hermes-guardian-history-target" },
        h("div", { className: "hermes-guardian-history-tool" }, tool),
        h("div", { className: "hermes-guardian-history-route" }, action + " -> " + destination),
      );
    }

    function historyReasonCell(row) {
      const full = text(row.reason || row.reason_short);
      const short = text(row.reason_short || row.reason);
      if (!full || full === short) return full;
      return h("details", { className: "hermes-guardian-history-reason", title: full },
        h("summary", null, short),
        h("div", { className: "hermes-guardian-history-reason-full" }, full),
      );
    }

    const rules = (policy && policy.rules) || [];
    const blocks = (policy && policy.recent_blocks) || [];

    function renderSettings() {
      const securityRules = (policy && policy.security_rules) || [];
      const languagePacks = (policy && policy.language_packs) || [];
      return h("div", { className: "hermes-guardian-grid" },
        h("div", { className: "hermes-guardian-card" },
          h("div", { className: "hermes-guardian-card-head" },
            h("div", null,
              h("div", { className: "hermes-guardian-card-title" }, "Privacy policy"),
              h("div", { className: "hermes-guardian-muted" }, "Security filtering remains active in every privacy mode."),
            ),
            h("div", { className: "hermes-guardian-actions" },
              h("select", { className: "hermes-guardian-select", value: privacyMode, onChange: function (event) { setPrivacyMode(event.target.value); } },
                ["strict", "read-only", "llm", "off"].map(function (mode) { return h("option", { key: mode, value: mode }, mode); }),
              ),
              h(Button, { onClick: saveMode, disabled: modeSaving }, modeSaving ? "Saving" : "Save"),
            ),
          ),
        ),
        h("div", { className: "hermes-guardian-card" },
          h("div", { className: "hermes-guardian-card-title" }, "Security policy"),
          securityRules.length ? h("div", { className: "hermes-guardian-grid" },
            securityRules.map(function (rule) {
              return h("label", { key: rule.id, className: "hermes-guardian-check hermes-guardian-security-check" },
                h("input", {
                  type: "checkbox",
                  checked: rule.enabled !== false,
                  onChange: function (event) { patchSecurityRule(rule.id, event.target.checked); },
                }),
                h("span", { className: "hermes-guardian-security-rule-text" },
                  h("span", null, text(rule.label || rule.id)),
                  rule.description ? h("span", { className: "hermes-guardian-muted" }, text(rule.description)) : null,
                ),
              );
            }),
          ) : h("div", { className: "hermes-guardian-muted" }, "No security policy rules."),
        ),
        h("div", { className: "hermes-guardian-card" },
          h("div", { className: "hermes-guardian-card-title" }, "Language packs"),
          languagePacks.length ? h("div", { className: "hermes-guardian-grid" },
            languagePacks.map(function (pack) {
              return h("label", { key: pack.id, className: "hermes-guardian-check hermes-guardian-security-check" },
                h("input", {
                  type: "checkbox",
                  checked: pack.enabled !== false,
                  disabled: pack.required === true,
                  onChange: function (event) { patchLanguagePack(pack.id, event.target.checked); },
                }),
                h("span", { className: "hermes-guardian-language-pack-text" },
                  h("span", null, text(pack.name || pack.id)),
                  h("span", { className: "hermes-guardian-muted" }, text(pack.id) + (pack.required ? " · required" : "")),
                ),
              );
            }),
          ) : h("div", { className: "hermes-guardian-muted" }, "No language packs."),
        ),
        h("div", { className: "hermes-guardian-card" },
          h("div", { className: "hermes-guardian-card-title" }, "Runtime"),
          h("div", { className: "hermes-guardian-rule-meta" },
            h("span", null, "Rows " + text(policy && policy.activity_max_rows)),
            h("span", null, "Retention " + text(policy && policy.activity_retention_days) + " days"),
            h("span", null, "Grouping " + text(policy && policy.activity_group_seconds) + " seconds"),
          ),
        ),
      );
    }

    function renderRules() {
      return h("div", { className: "hermes-guardian-grid" },
        h("div", { className: "hermes-guardian-topbar" },
          h("div", null),
          h(Button, { onClick: openCreate }, "New rule"),
        ),
        rules.length ? rules.map(function (rule, index) {
          const disabled = rule.enabled === false;
          const remaining = remainingPillText(rule);
          const classes = ["hermes-guardian-card"];
          if (disabled) classes.push("hermes-guardian-rule-disabled");
          return h("div", { key: rule.rule_id, className: classes.join(" ") },
            h("div", { className: "hermes-guardian-rule-head" },
              h("div", { className: "hermes-guardian-rule-main" },
                h("div", { className: "hermes-guardian-rule-title" }, text(rule.effect, "allow") + " " + displayText(rule.action_family, "*") + " -> " + displayText(rule.destination, "*")),
                h("div", { className: "hermes-guardian-rule-subline" },
                  h("span", { className: "hermes-guardian-rule-id" }, rule.rule_id),
                  remaining ? h("span", { className: "hermes-guardian-pill" }, remaining) : null,
                ),
              ),
              h("div", { className: "hermes-guardian-actions" },
                h(Button, { variant: "secondary", disabled: index === 0, onClick: function () { moveRule(rule, "up"); } }, "Up"),
                h(Button, { variant: "secondary", disabled: index === rules.length - 1, onClick: function () { moveRule(rule, "down"); } }, "Down"),
                h(Button, { variant: "secondary", onClick: function () { openEdit(rule); } }, "Edit"),
                h(Button, { variant: "secondary", onClick: function () { patchRule(rule.rule_id, { enabled: !rule.enabled }); } }, rule.enabled === false ? "Enable" : "Disable"),
                h(Button, { variant: "danger", onClick: function () { deleteRule(rule.rule_id); } }, "Delete"),
              ),
            ),
            h("div", { className: "hermes-guardian-rule-meta" },
              h("span", null, ruleScopeText(rule)),
            ),
            h("div", { className: "hermes-guardian-chips" }, (rule.data_classes || []).map(function (cls) {
              return h("span", { key: cls, className: "hermes-guardian-chip" }, cls === "*" ? "all data classes" : cls);
            })),
          );
        }) : h("div", { className: "hermes-guardian-card hermes-guardian-muted" }, "No privacy rules."),
      );
    }

    function renderBlocks() {
      return h("div", { className: "hermes-guardian-grid" },
        blocks.length ? blocks.map(function (block) {
          const pending = block.pending === true || !!block.approval_id;
          const covered = pending && block.covered_by_rule === true;
          const blockId = text(block.approval_id || block.id || block.activity_id);
          return h("div", { key: block.id, className: "hermes-guardian-card" },
            h("div", { className: "hermes-guardian-block-head" },
              h("div", null,
                h("div", { className: "hermes-guardian-block-title" }, text(block.action_family) + " -> " + text(block.destination)),
                h("div", { className: "hermes-guardian-rule-subline" },
                  blockId ? h("span", { className: "hermes-guardian-rule-id" }, blockId) : null,
                  h("span", { className: "hermes-guardian-pill" }, pending ? "pending approval" : text(block.decision, "blocked")),
                ),
              ),
              pending ? h("div", { className: "hermes-guardian-actions" },
                approvalButton(block, "approve-once", "Approve once", covered, covered ? coveredRuleTitle(block) : ""),
                approvalButton(block, "approve-always", "Approve always", covered, covered ? coveredRuleTitle(block) : ""),
                h(Button, { key: "dismiss", variant: "secondary", onClick: function () { approvalAction(block, "dismiss"); } }, "Dismiss"),
              ) : null,
            ),
            h("div", { className: "hermes-guardian-block-meta" },
              h("span", null, "Tool " + text(block.tool_name, "n/a")),
              block.module ? h("span", null, "Module " + text(block.module)) : null,
              h("span", null, "Taints " + classesText(block.data_classes)),
              h("span", null, "Created " + timeText(block.created_at)),
              h("span", null, "Reason " + text(block.reason, "n/a")),
            ),
          );
        }) : h("div", { className: "hermes-guardian-card hermes-guardian-muted" }, "No recent blocks."),
      );
    }

    function renderHistory() {
      const totalPages = Math.max(1, Math.ceil(historyTotal / historyPageSize));
      const currentPage = Math.min(historyPage, totalPages - 1);
      const start = historyTotal ? currentPage * historyPageSize + 1 : 0;
      const end = historyTotal ? Math.min(historyTotal, (currentPage + 1) * historyPageSize) : 0;
      return h("div", { className: "hermes-guardian-grid" },
        h("div", { className: "hermes-guardian-history-toolbar" },
          h("div", { className: "hermes-guardian-muted" },
            historyLoading ? "Loading history..." : (historyTotal ? "Showing " + start + "-" + end + " of " + historyTotal : "No history yet."),
          ),
          h("div", { className: "hermes-guardian-actions" },
            h("select", { className: "hermes-guardian-select", value: historyPageSize, onChange: function (event) {
              setHistoryPageSize(Number(event.target.value));
              setHistoryPage(0);
            } }, HISTORY_PAGE_SIZES.map(function (size) {
              return h("option", { key: size, value: size }, size + " per page");
            })),
            h(Button, { variant: "secondary", disabled: historyLoading || currentPage <= 0, onClick: function () { setHistoryPage(Math.max(0, currentPage - 1)); } }, "Previous"),
            h(Button, { variant: "secondary", disabled: historyLoading || currentPage >= totalPages - 1, onClick: function () { setHistoryPage(currentPage + 1); } }, "Next"),
          ),
        ),
        historyError ? h("div", { className: "hermes-guardian-banner" }, historyError) : null,
        h("div", { className: "hermes-guardian-table-wrap" },
          h("table", { className: "hermes-guardian-table" },
            h("colgroup", null,
              h("col", { className: "hermes-guardian-history-status-col" }),
              h("col", { className: "hermes-guardian-history-time-col" }),
              h("col", { className: "hermes-guardian-history-target-col" }),
              h("col", { className: "hermes-guardian-history-taints-col" }),
              h("col", { className: "hermes-guardian-history-reason-col" }),
            ),
            h("thead", null, h("tr", null,
              ["Status", "Time", "Tool / route", "Taints", "Reason"].map(function (label) {
                return h("th", { key: label }, label);
              }),
            )),
            h("tbody", null, activity.length ? activity.map(function (row, index) {
              return h("tr", { key: row.id || index },
                h("td", null, text(row.decision)),
                h("td", null, text(row.time, timeText(row.ts))),
                h("td", null, historyTargetCell(row)),
                h("td", null, text(row.data_classes)),
                h("td", null, historyReasonCell(row)),
              );
            }) : h("tr", null, h("td", { colSpan: 5, className: "hermes-guardian-muted" }, historyLoading ? "Loading history..." : "No history yet."))),
          ),
        ),
      );
    }

    if (loading && !policy) return h("div", { className: "hermes-guardian hermes-guardian-muted" }, "Loading Guardian...");

    return h("div", { className: "hermes-guardian" },
      h("div", { className: "hermes-guardian-topbar" },
        h("div", null,
          h("h1", { className: "hermes-guardian-title" }, "Hermes Guardian"),
          h("div", { className: "hermes-guardian-subtitle" }, "Security filtering and privacy egress rules"),
        ),
        h("div", { className: "hermes-guardian-actions" },
          h(Button, { variant: "secondary", onClick: function () {
            load();
            if (tab === "history") loadHistory(historyPage, historyPageSize);
          } }, "Refresh"),
        ),
      ),
      error ? h("div", { className: "hermes-guardian-banner" }, error) : null,
      h(ToastRegion, { toasts: toasts, onDismiss: dismissToast }),
      h("div", { className: "hermes-guardian-tabs", role: "tablist" },
        [["settings", "Settings"], ["rules", "Rules"], ["blocks", "Recent Blocks"], ["history", "History"]].map(function (item) {
          return h("button", { key: item[0], type: "button", className: "hermes-guardian-tab " + (tab === item[0] ? "hermes-guardian-tab-active" : ""), onClick: function () { setTab(item[0]); } }, item[1]);
        }),
      ),
      tab === "settings" ? renderSettings() : null,
      tab === "rules" ? renderRules() : null,
      tab === "blocks" ? renderBlocks() : null,
      tab === "history" ? renderHistory() : null,
      showModal ? h(RuleModal, {
        policy: policy || {},
        form: form,
        setForm: setForm,
        formError: formError,
        onSubmit: submitRule,
        onCancel: function () { setShowModal(false); },
      }) : null,
    );
  }

  window.__HERMES_PLUGINS__.register("hermes-guardian", GuardianPage);
})();
