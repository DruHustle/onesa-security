import { Auth0Client } from "@auth0/nextjs-auth0/server";
import { NextRequest, NextResponse } from "next/server";

// No mock identity, browser fallback token, or insecure development credentials are allowed.
// A missing or incomplete production configuration must fail closed without crashing
// the public informational landing page or the deployment liveness endpoint.
const identitySettings = ["AUTH0_DOMAIN", "AUTH0_CLIENT_ID", "AUTH0_CLIENT_SECRET", "AUTH0_SECRET", "APP_BASE_URL"] as const;
export const identityConfigured = identitySettings.every(key => Boolean(process.env[key]?.trim()));
export const registrationReviewPath = "/?registration=review";

const client = identityConfigured ? new Auth0Client({
  authorizationParameters: {
    audience: process.env.OIDC_AUDIENCE ?? "https://security-api.onesa.eu",
    scope: "openid profile email offline_access",
  },
  async onCallback(error, context) {
    if (!context.appBaseUrl) return NextResponse.json({error: "Start sign-in again from Onesa Security."}, {status: 400});
    const base = new URL(context.appBaseUrl);
    const returnTo = new URL(context.returnTo || "/", base);
    const resumed = error
      ? new URL(context.returnTo === registrationReviewPath ? registrationReviewPath : "/?sign-in=retry", base)
      : returnTo.origin === base.origin ? returnTo : new URL("/", base);
    return NextResponse.redirect(resumed);
  },
}) : null;

export const auth0 = {
  async getSession() {
    return client ? client.getSession() : null;
  },
  async getAccessToken() {
    if (!client) throw new Error("Onesa Security identity is not configured");
    return client.getAccessToken();
  },
  async middleware(request: NextRequest) {
    if (client) return client.middleware(request);
    if (request.nextUrl.pathname === "/auth" || request.nextUrl.pathname.startsWith("/auth/")) {
      return NextResponse.json({error: "Onesa Security sign-in is not configured"}, {
        status: 503,
        headers: {"Cache-Control": "no-store"},
      });
    }
    return NextResponse.next();
  },
};
