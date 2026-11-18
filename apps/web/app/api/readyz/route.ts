import {NextResponse} from "next/server";
import {identityConfigured} from "../../../lib/auth0";

const headers = {"Cache-Control": "no-store, private"} as const;

// Readiness is separate from healthz: a built page is NOT a functional product.
// Never expose internal URLs, secrets, credentials, or database diagnostics.
export async function GET() {
  const origin = process.env.ONESA_API_ORIGIN;
  const tenant = process.env.ONESA_ORGANIZATION_ID;
  if (!identityConfigured || !origin || !tenant || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(tenant)) {
    return NextResponse.json({status: "not_ready", identity: identityConfigured ? "configured" : "unconfigured", backend: "unverified"}, {status: 503, headers});
  }
  try {
    const url = new URL(origin);
    if (url.username || url.password || url.search || url.hash || url.pathname !== "/" ||
        (process.env.NODE_ENV === "production" && url.protocol !== "https:")) {
      throw new Error("Invalid configured origin");
    }
    const response = await fetch(url.origin + "/readyz", {
      method: "GET",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
      headers: {"Accept": "application/json"},
    });
    if (response.ok && (await response.json()).status === "ready") {
      return NextResponse.json({status: "ready", identity: "configured", backend: "ready", authenticated_user_flow: "not_tested"}, {headers});
    }
  } catch {
    // No exception details; these might expose infrastructure paths.
  }
  return NextResponse.json({status: "not_ready", identity: "configured", backend: "unavailable"}, {status: 503, headers});
}
