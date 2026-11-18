import { Auth0Client } from "@auth0/nextjs-auth0/server";

// Authentication is performed by Onesa's existing Auth0 domain.
// API authorization belongs to the Onesa Security control plane, not this session.
export const auth0 = new Auth0Client({
  authorizationParameters: {
    audience: process.env.OIDC_AUDIENCE ?? "https://security-api.onesa.eu",
    scope: "openid profile email offline_access",
  },
});
