import { useCallback, useEffect, useState } from "@/sdk";
import { api } from "@/api/client";
import type { Policy } from "@/types";

export interface PolicyController {
  policy: Policy | null;
  loading: boolean;
  error: string;
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
  load: () => Promise<void>;
}

// Loads the full policy snapshot and tracks the egress/source-classification modes it
// reports. The mode setters are exposed so the Settings/Tools tabs can apply
// optimistic updates (and roll back on failure).
export function usePolicy(): PolicyController {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [egressSafety, setEgressSafety] = useState("llm");
  const [taintClassification, setTaintClassification] = useState("balanced");
  const [llmSourceClassification, setLlmSourceClassification] = useState(true);
  const [llmUserContext, setLlmUserContext] = useState(true);
  const [llmCronContext, setLlmCronContext] = useState(true);
  const [persistPrompts, setPersistPrompts] = useState(false);
  const [llmVerifierModel, setLlmVerifierModel] = useState("");

  const load = useCallback(() => {
    setLoading(true);
    setError("");
    return api("/policy")
      .then((value: Policy) => {
        setPolicy(value);
        setEgressSafety(value.egress_safety || "llm");
        setTaintClassification(value.taint_classification || "balanced");
        setLlmSourceClassification(value.llm_source_classification !== false);
        setLlmUserContext(value.llm_user_context !== false);
        setLlmCronContext(value.llm_cron_context !== false);
        setPersistPrompts(value.persist_prompts === true);
        setLlmVerifierModel(value.llm_verifier_model || "");
      })
      .catch((err: unknown) => {
        setError(String((err as Error)?.message || err));
      })
      .finally(() => {
        setLoading(false);
      });
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return {
    policy,
    loading,
    error,
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
    load,
  };
}
