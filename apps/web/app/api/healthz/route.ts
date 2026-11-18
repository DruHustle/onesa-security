import { NextResponse } from "next/server";

// Liveness only. A 200 here is not proof of authentication, security coverage,
// a reachable control plane, or customer-production readiness.
export function GET() {
  return NextResponse.json(
    {service: "onesa-security-web", status: "alive", readiness: "unverified"},
    {headers: {"Cache-Control": "no-store"}},
  );
}
