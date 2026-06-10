import { React } from "@/sdk";

// Inline monospace for literals/identifiers. We deliberately do NOT use a <code>
// element: the host Hermes dashboard styles <code> with a heavy, distracting box.
// This is plain manual styling (.hermes-guardian-mono) — monospace, no chrome.
export function Mono(props: { children: React.ReactNode; title?: string }) {
  return (
    <span className="hermes-guardian-mono" title={props.title}>
      {props.children}
    </span>
  );
}
