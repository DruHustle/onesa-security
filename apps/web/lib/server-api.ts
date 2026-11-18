import "server-only";
import { auth0 } from "./auth0";

export type ApiResult<T> = { ok: true; data: T } | { ok: false; status: number; error: string };

export async function securityApi<T>(path: string, init?: RequestInit): Promise<ApiResult<T>> {
  // Never fetch a URL or tenant ID supplied by a browser. Only known relative API paths.
  if (!/^\/v1\/[a-z0-9/-]+$/.test(path)) return {ok: false, status: 400, error: "Invalid API path"};
  const origin = process.env.ONESA_API_ORIGIN;
  const organization = process.env.ONESA_ORGANIZATION_ID;
  if (!origin || !organization) return {ok: false, status: 503, error: "Organization and API must be configured"};
  if (!/^https?:\/\/[^/]+$/.test(origin) || (process.env.NODE_ENV === "production" && !origin.startsWith("https://"))) {
    return {ok: false, status: 503, error: "API origin configuration rejected"};
  }
  try {
    const {token} = await auth0.getAccessToken();
    const response = await fetch(origin + path, {
      ...init, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(10000),
      headers: {
        "Authorization": `Bearer ${token}`,
        "X-Onesa-Organization": organization,
        "Accept": "application/json",
        ...(init?.body ? {"Content-Type": "application/json"} : {}),
      },
    });
    if (!response.ok) return {ok: false, status: response.status, error: response.status === 403 ? "Access to this organization was denied" : "Security API request failed"};
    return {ok: true, data: await response.json() as T};
  } catch {
    return {ok: false, status: 503, error: "Security API or identity session unavailable"};
  }
}
