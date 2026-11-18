import { NextRequest, NextResponse } from "next/server";
import { auth0, identityConfigured } from "../../../../lib/auth0";
import { securityApi } from "../../../../lib/server-api";

const readable = new Set(["overview", "assets", "events", "alerts", "findings", "remediation-proposals", "compliance/readiness", "ai/policy", "ai/agent-traces", "audit"]);
const uuid = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";

type RouteContext = {params: Promise<{path: string[]}>};

async function handleRequest(req: NextRequest, context: RouteContext) {
  if (!identityConfigured) return NextResponse.json({error: "Onesa Security identity is not configured"}, {status: 503, headers: {"Cache-Control": "no-store"}});
  const session = await auth0.getSession();
  if (!session) return NextResponse.json({error: "Sign in required"}, {status: 401});
  const relative = (await context.params).path.join("/");
  let method = req.method;
  let resource = relative;
  if (method === "GET") {
    if (!readable.has(relative)) return NextResponse.json({error: "Not found"}, {status: 404});
  } else {
    const base = process.env.APP_BASE_URL;
    if (!base || req.headers.get("origin") !== new URL(base).origin) {
      return NextResponse.json({error: "Origin verification failed"}, {status: 403});
    }
    if (method === "POST" && (relative === "ai/inspect" || relative === "ai/agent-traces")) { /* allowed */ }
    else if (method === "PATCH" && new RegExp(`^alerts/${uuid}$`).test(relative)) { /* allowed */ }
    else if (method === "POST" && relative === "remediation-proposals") { /* allowed */ }
    else if (method === "POST" && new RegExp(`^remediation-proposals/${uuid}/decision$`).test(relative)) { /* allowed */ }
    else if (method === "POST" && new RegExp(`^findings/${uuid}/resolve$`).test(relative)) { /* allowed */ }
    else return NextResponse.json({error: "Not found"}, {status: 404});
  }
  let body: string | undefined;
  if (method !== "GET") {
    const raw = await req.text();
    if (raw.length > 22000) return NextResponse.json({error: "Request too large"}, {status: 413});
    try { JSON.parse(raw); } catch { return NextResponse.json({error: "Invalid JSON"}, {status: 400}); }
    body = raw;
  }
  const result = await securityApi<unknown>(`/v1/${resource}`, {method, ...(body ? {body} : {})});
  if (!result.ok) return NextResponse.json({error: result.error}, {status: result.status});
  return NextResponse.json(result.data, {headers: {"Cache-Control": "no-store"}});
}

export async function GET(req: NextRequest, ctx: RouteContext) { return handleRequest(req, ctx); }
export async function POST(req: NextRequest, ctx: RouteContext) { return handleRequest(req, ctx); }
export async function PATCH(req: NextRequest, ctx: RouteContext) { return handleRequest(req, ctx); }
