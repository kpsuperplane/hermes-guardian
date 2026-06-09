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
