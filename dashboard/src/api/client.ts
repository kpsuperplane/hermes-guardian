import { fetchJSON } from "@/sdk";

const API = "/api/plugins/hermes-guardian";

// Thin wrapper over the host fetchJSON: prefixes the plugin route and ensures a
// JSON content-type header whenever a body is present.
export function api(path: string, options?: RequestInit): Promise<any> {
  const init: RequestInit = Object.assign({}, options || {});
  if (init.body) {
    const headers = new Headers(init.headers || {});
    if (!headers.has("Content-Type")) headers.set("Content-Type", "application/json");
    init.headers = headers;
  }
  return fetchJSON(API + path, init);
}

// --- Destinations & Trust routes (doc 03 §3.1) -----------------------------
// Mutations carry the confirmation token the backend requires for destination-trust
// edits (_require_dashboard_confirmation("destination_trust", ...) -> "destination-trust").
const DESTINATION_TRUST_CONFIRM = "destination-trust";

function postTrust(path: string, body: Record<string, unknown>): Promise<any> {
  return api(path, {
    method: "POST",
    body: JSON.stringify(Object.assign({ confirm: DESTINATION_TRUST_CONFIRM }, body)),
  });
}

export function getDestinations(): Promise<any> {
  return api("/destinations");
}

export function addSelfDestination(kind: string, value: string): Promise<any> {
  return postTrust("/destinations/self", { kind, value });
}

export function removeSelfDestination(kind: string, value: string): Promise<any> {
  return postTrust("/destinations/self/remove", { kind, value });
}

export function addTrustedRecipient(
  identity: string,
  classes?: string,
  note?: string,
): Promise<any> {
  return postTrust("/destinations/trusted", { kind: "identity", value: identity, classes, note });
}

export function addTrustedCommand(value: string, classes?: string, note?: string): Promise<any> {
  return postTrust("/destinations/trusted", { kind: "command", value, classes, note });
}

export function removeTrustedDestination(kind: string, value: string): Promise<any> {
  return postTrust("/destinations/trusted/remove", { kind, value });
}

export function getTrustedCommandSuggestions(): Promise<any> {
  return api("/destinations/suggestions");
}

export function addSharingSubtype(subtype: string): Promise<any> {
  return postTrust("/destinations/sharing", { subtype });
}

export function removeSharingSubtype(subtype: string): Promise<any> {
  return postTrust("/destinations/sharing/remove", { subtype });
}

// --- Activity tab (doc 02 §Tab1) -------------------------------------------
export function getApprovals(): Promise<any> {
  return api("/approvals");
}

export function clearTaint(): Promise<any> {
  return api("/privacy/clear-taint", { method: "POST", body: JSON.stringify({}) });
}

// --- Pure-function widgets (charter §5; doc 02 §Tab2/§Tab3) ----------------
// All read-only: they call the engine's pure decide / resolve functions with
// hypothetical inputs and mutate nothing, so no confirmation token is sent.
export function resolveDestination(value: string): Promise<any> {
  return api("/destinations/resolve?value=" + encodeURIComponent(value));
}

export function previewSend(
  action: string,
  destination: string,
  classes: string[],
): Promise<any> {
  const query =
    "/sharing/preview?action=" +
    encodeURIComponent(action) +
    "&destination=" +
    encodeURIComponent(destination) +
    "&classes=" +
    encodeURIComponent((classes || []).join(","));
  return api(query);
}

export function sharingImpact(candidate: Record<string, unknown>): Promise<any> {
  return api("/sharing/impact", { method: "POST", body: JSON.stringify(candidate) });
}
