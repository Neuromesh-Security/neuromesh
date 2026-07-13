import { jwtVerify, type JWTPayload } from "jose";

import type { AuthenticatedPrincipal, DashboardRole } from "@/lib/auth/rbac";

const textEncoder = new TextEncoder();

export interface SessionClaims extends JWTPayload {
  sub: string;
  email: string;
  roles: DashboardRole[];
  iss: string;
  auth_protocol: "oidc" | "saml";
  sid: string;
}

export async function verifySessionToken(
  token: string,
): Promise<AuthenticatedPrincipal | null> {
  const secret = process.env.NEUROMESH_SESSION_SECRET;
  if (!secret) {
    return null;
  }

  try {
    const { payload } = await jwtVerify(token, textEncoder.encode(secret), {
      algorithms: ["HS256"],
    });

    const claims = payload as SessionClaims;
    if (!claims.sub || !claims.email || !Array.isArray(claims.roles)) {
      return null;
    }

    return {
      subject: claims.sub,
      email: claims.email,
      roles: claims.roles,
      issuer: claims.iss ?? "unknown",
      authProtocol: claims.auth_protocol ?? "oidc",
      sessionId: claims.sid ?? "unknown",
      issuedAt: claims.iat ?? 0,
      expiresAt: claims.exp ?? 0,
    };
  } catch {
    return null;
  }
}

export function getOidcLoginUrl(returnTo: string): string {
  const issuer = process.env.NEUROMESH_OIDC_ISSUER ?? "";
  const clientId = process.env.NEUROMESH_OIDC_CLIENT_ID ?? "";
  const redirectUri = process.env.NEUROMESH_OIDC_REDIRECT_URI ?? "";

  const params = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    scope: "openid profile email",
    redirect_uri: redirectUri,
    state: returnTo,
  });

  return `${issuer}/authorize?${params.toString()}`;
}

export function getSamlLoginUrl(returnTo: string): string {
  const entryPoint = process.env.NEUROMESH_SAML_ENTRY_POINT ?? "";
  const params = new URLSearchParams({ RelayState: returnTo });
  return `${entryPoint}?${params.toString()}`;
}
